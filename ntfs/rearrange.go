package ntfs

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unicode/utf16"
)

// RearrangeVolume reorganizes an existing NTFS volume's metadata sequentially in-place,
// evacuating colliding files and preserving all existing user data.
func RearrangeVolume(h syscall.Handle, analysis *VolumeAnalysis, layout *VolumeLayout, progress ProgressFunc) error {
	clusterSize := uint64(analysis.ClusterSize)
	sectorSize := uint64(analysis.BytesPerSector)

	clusterToOffset := func(lcn uint64) uint64 {
		return lcn * clusterSize
	}

	report := func(phase string, lcn uint64) {
		if progress != nil {
			progress(phase, lcn, layout.TotalClusters)
		}
	}

	// 1. Read existing active MFT records
	report("Reading and verifying existing MFT records...", analysis.MftLcn)
	recordCount := analysis.MaxAllocRecord + 1
	if recordCount < 64 {
		recordCount = 64
	}

	existingRecords := make([][]byte, recordCount)
	for recIdx := uint64(0); recIdx < recordCount; recIdx++ {
		recordOffsetBytes := recIdx * uint64(MftRecordSize)
		targetClusterInMft := recordOffsetBytes / clusterSize
		offsetInCluster := recordOffsetBytes % clusterSize

		var raw []byte
		var err error
		var found bool
		var curVcn uint64
		for _, run := range analysis.ExistingMftRuns {
			if targetClusterInMft >= curVcn && targetClusterInMft < curVcn+run.Length {
				lcn := run.LCN + (targetClusterInMft - curVcn)
				raw, err = ReadAt(h, lcn*clusterSize+offsetInCluster, MftRecordSize)
				found = true
				break
			}
			curVcn += run.Length
		}
		if !found {
			raw, err = ReadAt(h, analysis.MftLcn*clusterSize+recordOffsetBytes, MftRecordSize)
		}
		if err != nil {
			return fmt.Errorf("failed reading MFT record %d: %w", recIdx, err)
		}

		rec := make([]byte, MftRecordSize)
		copy(rec, raw)
		_ = RemoveFixup(rec)
		existingRecords[recIdx] = rec
	}

	// 2. Generate pristine system records matching the sequential layout
	report("Generating updated system records for sequential layout...", layout.MftLcn)
	sysRecords, err := GenerateSystemRecords(layout)
	if err != nil {
		return fmt.Errorf("failed generating system records: %w", err)
	}
	for i := range sysRecords {
		if sysRecords[i] != nil {
			_ = RemoveFixup(sysRecords[i])
		}
	}

	// 3. Preserve Record 5 ($Root) directory index entries and relocate its $INDEX_ALLOCATION if non-resident
	rec5 := existingRecords[RecordRoot]
	var rootIndexData []byte
	if rec5 != nil && string(rec5[:4]) == "FILE" {
		off5 := int(binary.LittleEndian.Uint16(rec5[20:22]))
		for off5+8 <= len(rec5) {
			atype := binary.LittleEndian.Uint32(rec5[off5 : off5+4])
			alen := int(binary.LittleEndian.Uint32(rec5[off5+4 : off5+8]))
			if atype == AttrTypeEnd || alen == 0 || off5+alen > len(rec5) {
				break
			}
			if atype == AttrTypeIndexAllocation && rec5[off5+8] != 0 {
				ro := int(binary.LittleEndian.Uint16(rec5[off5+32 : off5+34]))
				runs := ParseRunlist(rec5[off5+ro : off5+alen])
				if len(runs) > 0 {
					oldLcn := runs[0].LCN
					rootIndexData, _ = ReadAt(h, oldLcn*clusterSize, int(clusterSize))
					pRec5, err := PatchNonResidentAttr(rec5, AttrTypeIndexAllocation, "$I30", []Run{{LCN: layout.RootIndexLcn, Length: 1}}, clusterSize, clusterSize)
					if err == nil {
						_ = RemoveFixup(pRec5)
						rec5 = pRec5
					}
					break
				}
			}
			off5 += alen
		}
	}

	// 4. Preserve Record 9 ($Secure) descriptors ($SDS, $SDH, $SII)
	rec9 := existingRecords[RecordSecure]
	var existingSdsData, existingSdhData, existingSiiData []byte
	var sdsReal uint64
	hasNonResSdh := false
	hasNonResSii := false

	if rec9 != nil && string(rec9[:4]) == "FILE" {
		off9 := int(binary.LittleEndian.Uint16(rec9[20:22]))
		for off9+8 <= len(rec9) {
			atype := binary.LittleEndian.Uint32(rec9[off9 : off9+4])
			alen := int(binary.LittleEndian.Uint32(rec9[off9+4 : off9+8]))
			if atype == AttrTypeEnd || alen == 0 || off9+alen > len(rec9) {
				break
			}
			nameLen := int(rec9[off9+9])
			nameOff := int(binary.LittleEndian.Uint16(rec9[off9+10 : off9+12]))
			var name string
			if nameLen > 0 && off9+nameOff+nameLen*2 <= len(rec9) {
				u16 := make([]uint16, nameLen)
				for i := 0; i < nameLen; i++ {
					u16[i] = binary.LittleEndian.Uint16(rec9[off9+nameOff+i*2 : off9+nameOff+i*2+2])
				}
				name = string(utf16.Decode(u16))
			}

			if rec9[off9+8] != 0 { // Non-resident
				ro := int(binary.LittleEndian.Uint16(rec9[off9+32 : off9+34]))
				runs := ParseRunlist(rec9[off9+ro : off9+alen])
				if atype == AttrTypeData && name == "$SDS" && len(runs) > 0 {
					sdsReal = binary.LittleEndian.Uint64(rec9[off9+48 : off9+56])
					var sdsBuf []byte
					for _, r := range runs {
						d, _ := ReadAt(h, r.LCN*clusterSize, int(r.Length*clusterSize))
						sdsBuf = append(sdsBuf, d...)
					}
					existingSdsData = sdsBuf
				} else if atype == AttrTypeIndexAllocation && name == "$SDH" && len(runs) > 0 {
					hasNonResSdh = true
					var sdhBuf []byte
					for _, r := range runs {
						d, _ := ReadAt(h, r.LCN*clusterSize, int(r.Length*clusterSize))
						sdhBuf = append(sdhBuf, d...)
					}
					existingSdhData = sdhBuf
				} else if atype == AttrTypeIndexAllocation && name == "$SII" && len(runs) > 0 {
					hasNonResSii = true
					var siiBuf []byte
					for _, r := range runs {
						d, _ := ReadAt(h, r.LCN*clusterSize, int(r.Length*clusterSize))
						siiBuf = append(siiBuf, d...)
					}
					existingSiiData = siiBuf
				}
			}
			off9 += alen
		}

		if len(existingSdsData) > 0 {
			pRec9, err1 := PatchNonResidentAttr(rec9, AttrTypeData, "$SDS", []Run{{LCN: layout.SdsLcn, Length: layout.SdsClusters}}, layout.SdsClusters*clusterSize, sdsReal)
			if err1 != nil {
				return fmt.Errorf("failed patching Record 9 $SDS: %w", err1)
			}
			rec9 = pRec9

			if hasNonResSdh {
				pRec9, err2 := PatchNonResidentAttr(rec9, AttrTypeIndexAllocation, "$SDH", []Run{{LCN: layout.SdhLcn, Length: 1}}, clusterSize, 4096)
				if err2 != nil {
					return fmt.Errorf("failed patching Record 9 $SDH: %w", err2)
				}
				rec9 = pRec9
			}

			if hasNonResSii {
				pRec9, err3 := PatchNonResidentAttr(rec9, AttrTypeIndexAllocation, "$SII", []Run{{LCN: layout.SiiLcn, Length: 1}}, clusterSize, 4096)
				if err3 != nil {
					return fmt.Errorf("failed patching Record 9 $SII: %w", err3)
				}
				rec9 = pRec9
			}
			_ = RemoveFixup(rec9)
		}
	}

	// 5. Relocate Record 29 ($Deleted) preserving sequence number
	rec29 := existingRecords[RecordDeleted]
	if rec29 != nil && string(rec29[:4]) == "FILE" && layout.DeletedClusters > 0 {
		pRec29, err := PatchNonResidentAttr(rec29, AttrTypeIndexAllocation, "$I30", []Run{{LCN: layout.DeletedLcn, Length: layout.DeletedClusters}}, layout.DeletedClusters*clusterSize, 0)
		if err == nil {
			_ = RemoveFixup(pRec29)
			rec29 = pRec29
		}
	}

	// 6. Relocate Record 25 ($ObjId) preserving sequence number
	rec25 := existingRecords[RecordObjId]
	if rec25 != nil && string(rec25[:4]) == "FILE" && layout.ObjIdClusters > 0 {
		pRec25, err := BuildObjIdRecord(rec25, layout)
		if err == nil {
			_ = RemoveFixup(pRec25)
			rec25 = pRec25
		}
	}

	// 7. Assemble finalRecords: overlay system records 0..4 and 6..10, preserving rec5, rec9, rec25, rec29, and user records
	finalRecords := make([][]byte, recordCount)
	for i := uint64(0); i < recordCount; i++ {
		if existingRecords[i] != nil {
			finalRecords[i] = existingRecords[i]
		}
	}
	for i := 0; i <= 10; i++ {
		if i != RecordRoot && i != RecordSecure && i < len(sysRecords) && sysRecords[i] != nil {
			finalRecords[i] = sysRecords[i]
		}
	}
	if rec5 != nil && string(rec5[:4]) == "FILE" {
		finalRecords[RecordRoot] = rec5
	}
	if rec9 != nil && string(rec9[:4]) == "FILE" {
		finalRecords[RecordSecure] = rec9
	}
	if rec25 != nil && string(rec25[:4]) == "FILE" {
		finalRecords[RecordObjId] = rec25
	}
	if rec29 != nil && string(rec29[:4]) == "FILE" {
		finalRecords[RecordDeleted] = rec29
	}

	// 8. Build volume $Bitmap
	report("Building sequential volume bitmap...", layout.BitmapLcn)
	volBitmap := make([]byte, layout.BitmapClusters*clusterSize)

	markBm := func(start uint64, count uint64) {
		for i := uint64(0); i < count; i++ {
			c := start + i
			if c < layout.TotalClusters {
				volBitmap[c/8] |= (1 << (c % 8))
			}
		}
	}

	// Mark sequential metadata zone in volume bitmap
	markBm(layout.BootLcn, 2)
	markBm(layout.MftMirrLcn, 1)
	markBm(layout.LogFileLcn, layout.LogFileClusters)
	markBm(layout.BitmapLcn, layout.BitmapClusters)
	if layout.DeletedClusters > 0 {
		markBm(layout.DeletedLcn, layout.DeletedClusters)
	}
	if layout.ObjIdClusters > 0 {
		markBm(layout.ObjIdLcn, layout.ObjIdClusters)
	}
	if layout.ObjIdBitmapClusters > 0 {
		markBm(layout.ObjIdBitmapLcn, layout.ObjIdBitmapClusters)
	}
	if hasNonResSdh {
		markBm(layout.SdhLcn, 1)
	}
	if hasNonResSii {
		markBm(layout.SiiLcn, 1)
	}
	markBm(layout.MftLcn, layout.MftClusters)
	// MftZone is left UNALLOCATED (0) as reserved free space for MFT growth
	markBm(layout.MftBitmapLcn, layout.MftBitmapClusters)
	markBm(layout.SdsLcn, layout.SdsClusters)
	markBm(layout.UpCaseLcn, layout.UpCaseClusters)
	markBm(layout.AttrDefLcn, 1)
	markBm(layout.RootIndexLcn, 1)

	// Mark trailing unused bits beyond TotalClusters as 1 (NTFS standard)
	for c := layout.TotalClusters; c < layout.BitmapClusters*clusterSize*8; c++ {
		byteIdx := c / 8
		bitIdx := c % 8
		if byteIdx < uint64(len(volBitmap)) {
			volBitmap[byteIdx] |= (1 << bitIdx)
		}
	}

	// Mark all non-colliding existing user data runs in volBitmap
	for recIdx := uint64(11); recIdx < recordCount; recIdx++ {
		if recIdx == RecordObjId || recIdx == RecordDeleted {
			continue
		}
		rec := finalRecords[recIdx]
		if rec == nil || string(rec[:4]) != "FILE" || (binary.LittleEndian.Uint16(rec[22:24])&1) == 0 {
			continue
		}
		off := int(binary.LittleEndian.Uint16(rec[20:22]))
		for off+8 <= len(rec) {
			atype := binary.LittleEndian.Uint32(rec[off : off+4])
			alen := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
			if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec) {
				break
			}
			if (atype == AttrTypeData || atype == AttrTypeIndexAllocation) && rec[off+8] != 0 {
				ro := int(binary.LittleEndian.Uint16(rec[off+32 : off+34]))
				runs := ParseRunlist(rec[off+ro : off+alen])
				for _, r := range runs {
					if r.LCN >= layout.DataStartLcn {
						markBm(r.LCN, r.Length)
					}
				}
			}
			off += alen
		}
	}

	// 9. Evacuate any colliding user clusters occupying [0 .. layout.DataStartLcn)
	report("Evacuating colliding user data clusters...", layout.DataStartLcn)
	searchLcn := layout.DataStartLcn
	allocFreeClusters := func(count uint64) (uint64, error) {
		total := layout.TotalClusters
		curRun := uint64(0)
		var startLcn uint64
		for c := searchLcn; c < total; c++ {
			if (volBitmap[c/8] & (1 << (c % 8))) == 0 {
				if curRun == 0 {
					startLcn = c
				}
				curRun++
				if curRun == count {
					markBm(startLcn, count)
					searchLcn = startLcn + count
					return startLcn, nil
				}
			} else {
				curRun = 0
			}
		}
		return 0, fmt.Errorf("insufficient contiguous free clusters to evacuate (needed %d)", count)
	}

	for recIdx := uint64(11); recIdx < recordCount; recIdx++ {
		if recIdx == RecordObjId || recIdx == RecordDeleted {
			continue
		}
		rec := finalRecords[recIdx]
		if rec == nil || string(rec[:4]) != "FILE" || (binary.LittleEndian.Uint16(rec[22:24])&1) == 0 {
			continue
		}
		off := int(binary.LittleEndian.Uint16(rec[20:22]))
		for off+8 <= len(rec) {
			atype := binary.LittleEndian.Uint32(rec[off : off+4])
			alen := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
			if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec) {
				break
			}
			if (atype == AttrTypeData || atype == AttrTypeIndexAllocation) && rec[off+8] != 0 {
				ro := int(binary.LittleEndian.Uint16(rec[off+32 : off+34]))
				runs := ParseRunlist(rec[off+ro : off+alen])
				needMove := false
				for _, r := range runs {
					if r.LCN < layout.DataStartLcn {
						needMove = true
						break
					}
				}
				if needMove {
					var newRuns []Run
					for _, r := range runs {
						if r.LCN < layout.DataStartLcn {
							destLcn, err := allocFreeClusters(r.Length)
							if err != nil {
								return fmt.Errorf("evacuation failed for record %d: %w", recIdx, err)
							}
							data, err := ReadAt(h, r.LCN*clusterSize, int(r.Length*clusterSize))
							if err != nil {
								return fmt.Errorf("failed reading colliding cluster %d: %w", r.LCN, err)
							}
							if err := SeekAndWrite(h, destLcn*clusterSize, data); err != nil {
								return fmt.Errorf("failed relocating cluster to %d: %w", destLcn, err)
							}
							newRuns = append(newRuns, Run{Length: r.Length, LCN: destLcn})
						} else {
							newRuns = append(newRuns, r)
						}
					}
					allocBytes := binary.LittleEndian.Uint64(rec[off+40 : off+48])
					realBytes := binary.LittleEndian.Uint64(rec[off+48 : off+56])
					initBytes := binary.LittleEndian.Uint64(rec[off+56 : off+64])
					nameLen := int(rec[off+9])
					nameOff := int(binary.LittleEndian.Uint16(rec[off+10 : off+12]))
					var name string
					if nameLen > 0 && off+nameOff+nameLen*2 <= len(rec) {
						u16 := make([]uint16, nameLen)
						for i := 0; i < nameLen; i++ {
							u16[i] = binary.LittleEndian.Uint16(rec[off+nameOff+i*2 : off+nameOff+i*2+2])
						}
						name = string(utf16.Decode(u16))
					}
					pRec, err := PatchNonResidentAttr(rec, atype, name, newRuns, allocBytes, realBytes)
					if err != nil {
						return fmt.Errorf("failed updating record %d after evacuation: %w", recIdx, err)
					}
					binary.LittleEndian.PutUint64(pRec[off+56:off+64], initBytes)
					_ = RemoveFixup(pRec)
					finalRecords[recIdx] = pRec
					rec = pRec
				}
			}
			off += alen
		}
	}

	// 10. Write Sequential Metadata Streams to disk
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

	// Backup boot sector in the last cluster
	lastClusterOffset := (layout.Config.TotalSectors * sectorSize) - clusterSize
	backupClusterBuf := make([]byte, clusterSize)
	sectorInCluster := (layout.Config.TotalSectors - 1) % uint64(layout.Config.SectorPerClust)
	copy(backupClusterBuf[sectorInCluster*sectorSize:], vbr[:512])
	_ = SeekAndWrite(h, lastClusterOffset, backupClusterBuf)

	// Write $MFTMirr (LCN 2)
	report("Writing $MFTMirr...", layout.MftMirrLcn)
	mirrBuf := make([]byte, 4096)
	for i := 0; i < 4; i++ {
		rCopy := make([]byte, MftRecordSize)
		copy(rCopy, finalRecords[i])
		usaOffset := binary.LittleEndian.Uint16(rCopy[4:6])
		usaCount := binary.LittleEndian.Uint16(rCopy[6:8])
		seq := binary.LittleEndian.Uint16(rCopy[usaOffset : usaOffset+2])
		if seq == 0 {
			seq = uint16(i + 1)
		}
		_ = ApplyFixup(rCopy, usaOffset, usaCount, seq)
		copy(mirrBuf[i*MftRecordSize:], rCopy)
	}
	if err := SeekAndWrite(h, clusterToOffset(layout.MftMirrLcn), mirrBuf); err != nil {
		return fmt.Errorf("failed writing $MFTMirr: %w", err)
	}

	// Write $LogFile (LCN 3) - filled with 0xFF so Windows resets it cleanly
	report("Initializing $LogFile (transaction log)...", layout.LogFileLcn)
	chunkClusters := uint64(256)
	ffChunk := make([]byte, chunkClusters*clusterSize)
	for i := range ffChunk {
		ffChunk[i] = 0xFF
	}
	var writtenLog uint64
	for writtenLog < layout.LogFileClusters {
		toWrite := layout.LogFileClusters - writtenLog
		if toWrite > chunkClusters {
			toWrite = chunkClusters
		}
		if err := SeekAndWrite(h, clusterToOffset(layout.LogFileLcn+writtenLog), ffChunk[:toWrite*clusterSize]); err != nil {
			return fmt.Errorf("failed writing $LogFile: %w", err)
		}
		writtenLog += toWrite
	}

	// Write Volume $Bitmap
	report("Writing Volume $Bitmap...", layout.BitmapLcn)
	if err := SeekAndWrite(h, clusterToOffset(layout.BitmapLcn), volBitmap); err != nil {
		return fmt.Errorf("failed writing Volume $Bitmap: %w", err)
	}

	// Write $Extend\$Deleted
	if layout.DeletedClusters > 0 {
		report("Initializing $Extend\\$Deleted:$I30...", layout.DeletedLcn)
		delBuf := make([]byte, layout.DeletedClusters*clusterSize)
		if err := SeekAndWrite(h, clusterToOffset(layout.DeletedLcn), delBuf); err != nil {
			return fmt.Errorf("failed writing $Deleted index: %w", err)
		}
	}

	// Write $ObjId:$O
	if layout.ObjIdClusters > 0 {
		report("Initializing $ObjId:$O:INDEX_ALLOCATION...", layout.ObjIdLcn)
		objBuf := make([]byte, layout.ObjIdClusters*clusterSize)
		if err := SeekAndWrite(h, clusterToOffset(layout.ObjIdLcn), objBuf); err != nil {
			return fmt.Errorf("failed writing $ObjId: %w", err)
		}
	}

	// Write $Secure streams ($SDS, $SDH, $SII)
	report("Writing $Secure streams...", layout.SdhLcn)
	if len(existingSdsData) > 0 {
		sdsBuf := make([]byte, layout.SdsClusters*clusterSize)
		copy(sdsBuf, existingSdsData)
		if err := SeekAndWrite(h, clusterToOffset(layout.SdsLcn), sdsBuf); err != nil {
			return fmt.Errorf("failed writing $SDS stream: %w", err)
		}

		if hasNonResSdh && len(existingSdhData) > 0 {
			sdhBuf := make([]byte, clusterSize)
			copy(sdhBuf, existingSdhData)
			if err := SeekAndWrite(h, clusterToOffset(layout.SdhLcn), sdhBuf); err != nil {
				return fmt.Errorf("failed writing $SDH stream: %w", err)
			}
		}

		if hasNonResSii && len(existingSiiData) > 0 {
			siiBuf := make([]byte, clusterSize)
			copy(siiBuf, existingSiiData)
			if err := SeekAndWrite(h, clusterToOffset(layout.SiiLcn), siiBuf); err != nil {
				return fmt.Errorf("failed writing $SII stream: %w", err)
			}
		}
	}

	// Write Relocated $Root Index Block if non-resident
	if len(rootIndexData) > 0 {
		report("Writing relocated $Root Index block...", layout.RootIndexLcn)
		_ = SeekAndWrite(h, clusterToOffset(layout.RootIndexLcn), rootIndexData)
	}

	// Write $MFT:BITMAP
	report("Writing $MFT:BITMAP...", layout.MftBitmapLcn)
	mftBmBuf := make([]byte, layout.MftBitmapClusters*clusterSize)
	for recIdx := uint64(0); recIdx < recordCount; recIdx++ {
		if finalRecords[recIdx] != nil && (binary.LittleEndian.Uint16(finalRecords[recIdx][22:24])&1) != 0 {
			mftBmBuf[recIdx/8] |= (1 << (recIdx % 8))
		}
	}
	if err := SeekAndWrite(h, clusterToOffset(layout.MftBitmapLcn), mftBmBuf); err != nil {
		return fmt.Errorf("failed writing $MFT:BITMAP: %w", err)
	}

	// Write $UpCase & $AttrDef
	report("Writing $UpCase and $AttrDef...", layout.UpCaseLcn)
	upCaseBuf := make([]byte, layout.UpCaseClusters*clusterSize)
	copy(upCaseBuf, UpCaseBin)
	_ = SeekAndWrite(h, clusterToOffset(layout.UpCaseLcn), upCaseBuf)

	attrDefBuf := make([]byte, clusterSize)
	copy(attrDefBuf, AttrDefBin)
	_ = SeekAndWrite(h, clusterToOffset(layout.AttrDefLcn), attrDefBuf)

	// 11. Write Relocated & Resized $MFT
	report("Writing relocated $MFT records...", layout.MftLcn)
	chunkRecords := uint64(256)
	mftChunkBuf := make([]byte, chunkRecords*MftRecordSize)

	totalMftRecords := (layout.MftClusters * clusterSize) / MftRecordSize
	for startRec := uint64(0); startRec < totalMftRecords; startRec += chunkRecords {
		for i := range mftChunkBuf {
			mftChunkBuf[i] = 0
		}
		for r := uint64(0); r < chunkRecords; r++ {
			recIdx := startRec + r
			if recIdx < recordCount && finalRecords[recIdx] != nil {
				rCopy := make([]byte, MftRecordSize)
				copy(rCopy, finalRecords[recIdx])
				usaOffset := binary.LittleEndian.Uint16(rCopy[4:6])
				usaCount := binary.LittleEndian.Uint16(rCopy[6:8])
				seq := binary.LittleEndian.Uint16(rCopy[usaOffset : usaOffset+2])
				if seq == 0 {
					seq = uint16(recIdx + 1)
				}
				_ = ApplyFixup(rCopy, usaOffset, usaCount, seq)
				copy(mftChunkBuf[r*MftRecordSize:(r+1)*MftRecordSize], rCopy)
			}
		}
		offset := clusterToOffset(layout.MftLcn) + startRec*MftRecordSize
		if err := SeekAndWrite(h, offset, mftChunkBuf); err != nil {
			return fmt.Errorf("failed writing MFT at record %d: %w", startRec, err)
		}
	}

	FlushTarget(h)
	report("NTFS rearrangement complete!", layout.TotalClusters)
	return nil
}
