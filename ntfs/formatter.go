package ntfs

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

// ProgressFunc reports formatting status and percentage.
type ProgressFunc func(phase string, currentCluster uint64, totalClusters uint64)

// FormatVolume executes the complete NTFS formatting process on an open handle.
func FormatVolume(h syscall.Handle, layout *VolumeLayout, progress ProgressFunc) error {
	clusterSize := uint64(layout.Config.ClusterSize)
	sectorSize := uint64(layout.Config.BytesPerSector)

	clusterToOffset := func(lcn uint64) uint64 {
		return lcn * clusterSize
	}

	report := func(phase string, lcn uint64) {
		if progress != nil {
			progress(phase, lcn, layout.TotalClusters)
		}
	}

	// 1. Write $Boot (LCN 0..1)
	report("Writing $Boot sector & BPB...", layout.BootLcn)
	vbr := BuildBootSector(
		layout.Config.TotalSectors-1,
		layout.Config.BytesPerSector,
		layout.Config.SectorPerClust,
		layout.MftLcn,
		layout.MftMirrLcn,
		layout.Config.SerialNumber,
	)
	if err := SeekAndWrite(h, 0, vbr); err != nil {
		return fmt.Errorf("failed writing boot sector: %w", err)
	}

	// Write backup boot sector inside the last 4KB cluster (aligned to physical sector boundary)
	lastClusterOffset := (layout.Config.TotalSectors * sectorSize) - clusterSize
	backupClusterBuf := make([]byte, clusterSize)
	sectorInCluster := (layout.Config.TotalSectors - 1) % uint64(layout.Config.SectorPerClust)
	copy(backupClusterBuf[sectorInCluster*sectorSize:], vbr[:512])
	if err := SeekAndWrite(h, lastClusterOffset, backupClusterBuf); err != nil {
		return fmt.Errorf("failed writing backup boot sector: %w", err)
	}

	// 2. Prepare System MFT Records (0..63)
	records, err := GenerateSystemRecords(layout)
	if err != nil {
		return fmt.Errorf("failed generating system MFT records: %w", err)
	}

	// 3. Write $MFTMirr (LCN 2) - 4 records (rec 0, 1, 2, 3)
	report("Writing $MFTMirr...", layout.MftMirrLcn)
	mirrBuf := make([]byte, 4096)
	for i := 0; i < 4; i++ {
		copy(mirrBuf[i*MftRecordSize:], records[i])
	}
	if err := SeekAndWrite(h, clusterToOffset(layout.MftMirrLcn), mirrBuf); err != nil {
		return fmt.Errorf("failed writing $MFTMirr: %w", err)
	}

	// 4. Write $LogFile (LCN 3) - filled entirely with 0xFF so Windows initializes clean transaction log on mount
	report("Initializing $LogFile (transaction log)...", layout.LogFileLcn)
	chunkClusters := uint64(256) // 1 MB chunks
	chunkBytes := chunkClusters * clusterSize
	ffChunk := make([]byte, chunkBytes)
	for i := range ffChunk {
		ffChunk[i] = 0xFF
	}

	var writtenClusters uint64
	for writtenClusters < layout.LogFileClusters {
		toWrite := layout.LogFileClusters - writtenClusters
		if toWrite > chunkClusters {
			toWrite = chunkClusters
		}
		offset := clusterToOffset(layout.LogFileLcn + writtenClusters)
		if err := SeekAndWrite(h, offset, ffChunk[:toWrite*clusterSize]); err != nil {
			return fmt.Errorf("failed writing $LogFile at cluster %d: %w", layout.LogFileLcn+writtenClusters, err)
		}
		writtenClusters += toWrite
	}

	// 5. Generate and Write Volume $Bitmap
	report("Generating Volume $Bitmap...", layout.BitmapLcn)
	bitmapTotalBytes := layout.BitmapClusters * clusterSize
	bitmapBuf := make([]byte, bitmapTotalBytes)

	markRange := func(start uint64, count uint64) {
		for c := start; c < start+count; c++ {
			bitmapBuf[c/8] |= (1 << (c % 8))
		}
	}

	markRange(layout.BootLcn, layout.BootClusters)
	markRange(layout.MftMirrLcn, layout.MftMirrClusters)
	markRange(layout.LogFileLcn, layout.LogFileClusters)
	markRange(layout.BitmapLcn, layout.BitmapClusters)
	markRange(layout.DeletedLcn, layout.DeletedClusters)
	markRange(layout.ObjIdLcn, layout.ObjIdClusters)
	if layout.ObjIdBitmapClusters > 0 {
		markRange(layout.ObjIdBitmapLcn, layout.ObjIdBitmapClusters)
	}
	markRange(layout.SdhLcn, layout.SdhClusters)
	markRange(layout.SiiLcn, layout.SiiClusters)
	markRange(layout.MftLcn, layout.MftClusters)
	// MftZone is left UNALLOCATED (0) as reserved free space for MFT growth
	markRange(layout.MftBitmapLcn, layout.MftBitmapClusters)
	markRange(layout.SdsLcn, layout.SdsClusters)
	markRange(layout.UpCaseLcn, layout.UpCaseClusters)
	markRange(layout.AttrDefLcn, layout.AttrDefClusters)
	markRange(layout.RootIndexLcn, layout.RootIndexClusters)

	// Mark trailing unused bits beyond TotalClusters as 1 (NTFS convention)
	for c := layout.TotalClusters; c < layout.BitmapClusters*clusterSize*8; c++ {
		byteIdx := c / 8
		bitIdx := c % 8
		if byteIdx < uint64(len(bitmapBuf)) {
			bitmapBuf[byteIdx] |= (1 << bitIdx)
		}
	}

	if err := SeekAndWrite(h, clusterToOffset(layout.BitmapLcn), bitmapBuf); err != nil {
		return fmt.Errorf("failed writing volume $Bitmap: %w", err)
	}

	// 6. Write $Extend\$Deleted:$I30:INDEX_ALLOCATION (64 KB = 16 clusters right after $Bitmap)
	report("Initializing $Extend\\$Deleted:$I30:INDEX_ALLOCATION...", layout.DeletedLcn)
	deletedBuf := make([]byte, layout.DeletedClusters*clusterSize)
	if err := SeekAndWrite(h, clusterToOffset(layout.DeletedLcn), deletedBuf); err != nil {
		return fmt.Errorf("failed zeroing $Extend\\$Deleted clusters: %w", err)
	}

	// 7. Write $ObjId:$O:INDEX_ALLOCATION (User pre-sized, contiguous unallocated space)
	report("Initializing $ObjId:$O:INDEX_ALLOCATION...", layout.ObjIdLcn)
	zeroObjChunk := make([]byte, chunkBytes)
	var objWritten uint64 = 0
	for objWritten < layout.ObjIdClusters {
		toWrite := layout.ObjIdClusters - objWritten
		if toWrite > chunkClusters {
			toWrite = chunkClusters
		}
		offset := clusterToOffset(layout.ObjIdLcn + objWritten)
		if err := SeekAndWrite(h, offset, zeroObjChunk[:toWrite*clusterSize]); err != nil {
			return fmt.Errorf("failed zeroing $ObjId clusters: %w", err)
		}
		objWritten += toWrite
	}

	if layout.ObjIdBitmapClusters > 0 {
		zeroBmChunk := make([]byte, layout.ObjIdBitmapClusters*clusterSize)
		if err := SeekAndWrite(h, clusterToOffset(layout.ObjIdBitmapLcn), zeroBmChunk); err != nil {
			return fmt.Errorf("failed zeroing $ObjId bitmap clusters: %w", err)
		}
	}

	// Prepare $Secure streams ($SDS, $SDH, $SII) patched with active user SID
	sdsStream, sdhStream, siiStream := BuildSecureStreams(GetCurrentUserSID())

	// 8. Write $Secure:$SDH:INDEX_ALLOCATION (From user sample)
	report("Writing $Secure:$SDH:INDEX_ALLOCATION...", layout.SdhLcn)
	sdhBuf := make([]byte, clusterSize)
	copy(sdhBuf, sdhStream)
	if err := SeekAndWrite(h, clusterToOffset(layout.SdhLcn), sdhBuf); err != nil {
		return fmt.Errorf("failed writing $SDH: %w", err)
	}

	// 9. Write $Secure:$SII:INDEX_ALLOCATION (From user sample)
	report("Writing $Secure:$SII:INDEX_ALLOCATION...", layout.SiiLcn)
	siiBuf := make([]byte, clusterSize)
	copy(siiBuf, siiStream)
	if err := SeekAndWrite(h, clusterToOffset(layout.SiiLcn), siiBuf); err != nil {
		return fmt.Errorf("failed writing $SII: %w", err)
	}

	// 10. Write $MFT (User pre-sized)
	report("Writing $MFT primary records...", layout.MftLcn)
	initMftBytes := make([]byte, 256*MftRecordSize)
	for i := 0; i < len(records); i++ {
		copy(initMftBytes[i*MftRecordSize:], records[i])
	}
	// Note: records len(records)..255 are left as clean all-zeros (unallocated)
	if err := SeekAndWrite(h, clusterToOffset(layout.MftLcn), initMftBytes); err != nil {
		return fmt.Errorf("failed writing initial MFT records: %w", err)
	}

	// Zero remaining pre-allocated MFT clusters
	zeroChunk := make([]byte, chunkBytes) // all zeros
	initClusters := uint64(len(initMftBytes)) / clusterSize
	if layout.MftClusters > initClusters {
		var mftWritten uint64 = initClusters
		for mftWritten < layout.MftClusters {
			toWrite := layout.MftClusters - mftWritten
			if toWrite > chunkClusters {
				toWrite = chunkClusters
			}
			offset := clusterToOffset(layout.MftLcn + mftWritten)
			if err := SeekAndWrite(h, offset, zeroChunk[:toWrite*clusterSize]); err != nil {
				return fmt.Errorf("failed zeroing MFT records at cluster %d: %w", layout.MftLcn+mftWritten, err)
			}
			mftWritten += toWrite
		}
	}

	// 11. Clear MFT RESERVED AREA (User pre-sized)
	report("Reserving MFT Zone area...", layout.MftZoneLcn)
	zeroZoneChunk := make([]byte, chunkBytes)
	var zoneWritten uint64 = 0
	for zoneWritten < layout.MftZoneClusters {
		toWrite := layout.MftZoneClusters - zoneWritten
		if toWrite > chunkClusters {
			toWrite = chunkClusters
		}
		offset := clusterToOffset(layout.MftZoneLcn + zoneWritten)
		if err := SeekAndWrite(h, offset, zeroZoneChunk[:toWrite*clusterSize]); err != nil {
			return fmt.Errorf("failed clearing MFT zone: %w", err)
		}
		zoneWritten += toWrite
	}

	// 12. Write $MFT:BITMAP
	report("Writing $MFT:BITMAP...", layout.MftBitmapLcn)
	mftBitmapBuf := make([]byte, layout.MftBitmapClusters*clusterSize)
	// Byte 0..1: Records 0..15 allocated (0xFF, 0xFF)
	// Byte 2: Records 16..23 unallocated (0x00)
	// Byte 3: Records 24..26 & 29 allocated (0x27); 27..28 & 30..31 left free for Windows TxF ($RmMetadata, $Repair, $TxfLog, $Txf)
	// Byte 4: Records 32..35 left free for Windows TxF ($Tops, $TxfLog.blf, $TxfLogContainer01/02); Records 36..39 allocated (0xF0)
	// Byte 5: Records 40..42 allocated (0x07)
	if len(mftBitmapBuf) >= 6 {
		mftBitmapBuf[0] = 0xFF
		mftBitmapBuf[1] = 0xFF
		mftBitmapBuf[2] = 0x00
		mftBitmapBuf[3] = 0x27
		mftBitmapBuf[4] = 0xF0
		mftBitmapBuf[5] = 0x07
	}
	if err := SeekAndWrite(h, clusterToOffset(layout.MftBitmapLcn), mftBitmapBuf); err != nil {
		return fmt.Errorf("failed writing $MFT:BITMAP: %w", err)
	}

	// 13. Write $Secure:$SDS (260 KB from user sample, patched with active User SID)
	report("Writing $Secure:$SDS data stream...", layout.SdsLcn)
	sdsBuf := make([]byte, layout.SdsClusters*clusterSize)
	copy(sdsBuf, sdsStream)
	if err := SeekAndWrite(h, clusterToOffset(layout.SdsLcn), sdsBuf); err != nil {
		return fmt.Errorf("failed writing $Secure:$SDS: %w", err)
	}

	// 14. Write $UpCase (128 KB uppercase table)
	report("Writing $UpCase table...", layout.UpCaseLcn)
	upCaseBuf := make([]byte, layout.UpCaseClusters*clusterSize)
	copy(upCaseBuf, UpCaseBin)
	if err := SeekAndWrite(h, clusterToOffset(layout.UpCaseLcn), upCaseBuf); err != nil {
		return fmt.Errorf("failed writing $UpCase: %w", err)
	}

	// 15. Write $AttrDef (Attribute definitions table)
	report("Writing $AttrDef table...", layout.AttrDefLcn)
	attrDefBuf := make([]byte, clusterSize)
	copy(attrDefBuf, AttrDefBin)
	if err := SeekAndWrite(h, clusterToOffset(layout.AttrDefLcn), attrDefBuf); err != nil {
		return fmt.Errorf("failed writing $AttrDef: %w", err)
	}

	// 16. Write $Root:$INDEX_ALLOCATION (Includes System Volume Information and $Recycle.Bin)
	report("Writing $Root directory index...", layout.RootIndexLcn)
	rootIndx, err := BuildRootIndxBlock(RootIndxBin, records[RecordSVI], records[RecordRecycleBin])
	if err != nil {
		return fmt.Errorf("failed building $Root index block: %w", err)
	}
	rootIndxBuf := make([]byte, clusterSize)
	copy(rootIndxBuf, rootIndx)
	if err := SeekAndWrite(h, clusterToOffset(layout.RootIndexLcn), rootIndxBuf); err != nil {
		return fmt.Errorf("failed writing $Root index: %w", err)
	}

	// Flush all buffers to physical disk
	FlushTarget(h)

	report("NTFS formatting complete!", layout.TotalClusters)
	return nil
}

// prepareLogFileRestart updates the file size and sequence bits in the RSTR restart pages to match logFileBytes.
func prepareLogFileRestart(data []byte, logFileBytes uint64) []byte {
	res := make([]byte, len(data))
	copy(res, data)

	// Calculate seq_bits: smallest power of 2 >= logFileBytes
	availBits := 0
	for (uint64(1) << availBits) < logFileBytes {
		availBits++
	}
	seqBits := uint32(67 - availBits)

	for page := 0; page < 2; page++ {
		off := page * 4096
		if off+80 <= len(res) {
			binary.LittleEndian.PutUint32(res[off+64:off+68], seqBits)
			binary.LittleEndian.PutUint64(res[off+72:off+80], logFileBytes)
		}
	}
	return res
}
