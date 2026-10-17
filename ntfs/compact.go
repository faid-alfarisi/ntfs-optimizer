package ntfs

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

// CompactVolumeMFT compacts an existing NTFS volume's MFT records in-place without rearranging
// volume metadata layout or reordering system metadata.
// It fills all gaps between user files by shifting them forward, zeroing out vacated records,
// and optionally shrinking the MFT allocation on disk to the absolute minimum needed.
func CompactVolumeMFT(h syscall.Handle, analysis *VolumeAnalysis, shrinkMft bool, customMftMB uint64, progress ProgressFunc) error {
	clusterSize := uint64(analysis.ClusterSize)

	report := func(phase string, lcn uint64) {
		if progress != nil {
			progress(phase, lcn, analysis.TotalClusters)
		}
	}

	// 1. Read all existing MFT records up to MaxAllocRecord + 1
	report("Reading existing MFT records...", analysis.MftLcn)
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

	// 2. Identify active records and find gaps
	report("Analyzing record gaps and computing compacted positions...", analysis.MftLcn)
	remap := make(map[uint64]uint64)

	// Records 0..35 are fixed NTFS system files ($MFT..$Extend and $Extend subfiles)
	// They never move.
	firstCompactSlot := uint64(36)
	for r := uint64(0); r < firstCompactSlot && r < recordCount; r++ {
		remap[r] = r
	}

	// Find active records >= 36
	var activeRecs []uint64
	for r := firstCompactSlot; r < recordCount; r++ {
		rec := existingRecords[r]
		if rec == nil || len(rec) < 48 || string(rec[:4]) != "FILE" {
			continue
		}
		flags := binary.LittleEndian.Uint16(rec[22:24])
		if (flags & 1) != 0 { // In-use
			activeRecs = append(activeRecs, r)
		}
	}

	// Compact active records into contiguous slots starting from firstCompactSlot
	nextSlot := firstCompactSlot
	for _, oldRec := range activeRecs {
		remap[oldRec] = nextSlot
		nextSlot++
	}

	totalExistingMftClusters := uint64(0)
	for _, r := range analysis.ExistingMftRuns {
		totalExistingMftClusters += r.Length
	}

	minClustersNeeded := (nextSlot*uint64(MftRecordSize) + clusterSize - 1) / clusterSize
	if minClustersNeeded < 16 {
		minClustersNeeded = 16
	}

	targetMftClusters := totalExistingMftClusters
	if shrinkMft {
		if minClustersNeeded < totalExistingMftClusters {
			targetMftClusters = minClustersNeeded
		}
	} else if customMftMB > 0 {
		customClusters := (customMftMB * 1024 * 1024) / clusterSize
		if customClusters < totalExistingMftClusters && customClusters >= minClustersNeeded {
			targetMftClusters = customClusters
		}
	}

	targetMftBytes := targetMftClusters * clusterSize
	totalMftRecords := targetMftBytes / uint64(MftRecordSize)

	// 3. Assemble compactedRecords slice
	compactedRecords := make([][]byte, totalMftRecords)
	for r := uint64(0); r < firstCompactSlot && r < recordCount; r++ {
		if existingRecords[r] != nil {
			compactedRecords[r] = existingRecords[r]
		}
	}
	for _, oldRec := range activeRecs {
		newRec := remap[oldRec]
		compactedRecords[newRec] = existingRecords[oldRec]
	}

	getSeq := func(rnum uint64) uint16 {
		if rnum < uint64(len(compactedRecords)) && compactedRecords[rnum] != nil {
			seq := binary.LittleEndian.Uint16(compactedRecords[rnum][16:18])
			if seq > 0 {
				return seq
			}
		}
		return 1
	}

	// 4. Update Record Number and Attribute references across moved user records
	report("Updating record references and directory indexes...", analysis.MftLcn)
	for rnum := firstCompactSlot; rnum < nextSlot; rnum++ {
		rec := compactedRecords[rnum]
		if rec == nil || string(rec[:4]) != "FILE" {
			continue
		}
		binary.LittleEndian.PutUint32(rec[44:48], uint32(rnum))

		// Update base record reference if non-zero
		baseRef := binary.LittleEndian.Uint64(rec[32:40])
		baseNum := baseRef & 0xFFFFFFFFFFFF
		if baseNum != 0 {
			if newBase, ok := remap[baseNum]; ok {
				binary.LittleEndian.PutUint64(rec[32:40], (uint64(getSeq(newBase))<<48)|newBase)
			}
		}

		off := int(binary.LittleEndian.Uint16(rec[20:22]))
		for off+8 <= len(rec) {
			atype := binary.LittleEndian.Uint32(rec[off : off+4])
			alen := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
			if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec) {
				break
			}
			if atype == AttrTypeFileName && rec[off+8] == 0 {
				voff := int(binary.LittleEndian.Uint16(rec[off+20 : off+22]))
				if off+voff+8 <= len(rec) {
					pRef := binary.LittleEndian.Uint64(rec[off+voff : off+voff+8])
					oldP := pRef & 0xFFFFFFFFFFFF
					if newP, ok := remap[oldP]; ok {
						binary.LittleEndian.PutUint64(rec[off+voff:off+voff+8], (uint64(getSeq(newP))<<48)|newP)
					}
				}
			} else if atype == AttrTypeIndexRoot && rec[off+8] == 0 {
				nameLen := int(rec[off+9])
				nameOff := int(binary.LittleEndian.Uint16(rec[off+10 : off+12]))
				name := ""
				if nameLen > 0 && off+nameOff+nameLen*2 <= len(rec) {
					u16 := make([]uint16, nameLen)
					for i := 0; i < nameLen; i++ {
						u16[i] = binary.LittleEndian.Uint16(rec[off+nameOff+i*2 : off+nameOff+i*2+2])
					}
					name = string(decodeUTF16(u16))
				}
				if name == "$I30" {
					voff := int(binary.LittleEndian.Uint16(rec[off+20 : off+22]))
					irPayload := rec[off+voff : off+alen]
					if len(irPayload) >= 32 {
						nodeOff := 16 + int(binary.LittleEndian.Uint32(irPayload[16:20]))
						nodeTotal := 16 + int(binary.LittleEndian.Uint32(irPayload[20:24]))
						if nodeTotal <= len(irPayload) && nodeOff <= nodeTotal {
							updateIndexEntries(irPayload[nodeOff:nodeTotal], remap, getSeq)
						}
					}
				}
			}
			off += alen
		}
	}

	// 5. Update Root Directory ($Root, Record 5)
	rec5 := compactedRecords[RecordRoot]
	if rec5 != nil && string(rec5[:4]) == "FILE" {
		off5 := int(binary.LittleEndian.Uint16(rec5[20:22]))
		for off5+8 <= len(rec5) {
			atype := binary.LittleEndian.Uint32(rec5[off5 : off5+4])
			alen := int(binary.LittleEndian.Uint32(rec5[off5+4 : off5+8]))
			if atype == AttrTypeEnd || alen == 0 || off5+alen > len(rec5) {
				break
			}
			if atype == AttrTypeIndexRoot && rec5[off5+8] == 0 {
				voff := int(binary.LittleEndian.Uint16(rec5[off5+20 : off5+22]))
				irPayload := rec5[off5+voff : off5+alen]
				if len(irPayload) >= 32 {
					nodeOff := 16 + int(binary.LittleEndian.Uint32(irPayload[16:20]))
					nodeTotal := 16 + int(binary.LittleEndian.Uint32(irPayload[20:24]))
					if nodeTotal <= len(irPayload) && nodeOff <= nodeTotal {
						updateIndexEntries(irPayload[nodeOff:nodeTotal], remap, getSeq)
					}
				}
			} else if atype == AttrTypeIndexAllocation && rec5[off5+8] != 0 {
				ro := int(binary.LittleEndian.Uint16(rec5[off5+32 : off5+34]))
				runs := ParseRunlist(rec5[off5+ro : off5+alen])
				for _, run := range runs {
					runBytes := run.Length * clusterSize
					data, err := ReadAt(h, run.LCN*clusterSize, int(runBytes))
					if err == nil {
						modified := false
						for blkOff := 0; blkOff+4096 <= len(data); blkOff += 4096 {
							block := data[blkOff : blkOff+4096]
							if string(block[:4]) == "INDX" {
								_ = RemoveFixup(block)
								usaOff := binary.LittleEndian.Uint16(block[4:6])
								usaCount := binary.LittleEndian.Uint16(block[6:8])
								seq := binary.LittleEndian.Uint16(block[usaOff : usaOff+2])
								nodeOff := 24 + int(binary.LittleEndian.Uint32(block[24:28]))
								nodeTotal := 24 + int(binary.LittleEndian.Uint32(block[28:32]))
								if nodeTotal <= len(block) && nodeOff <= nodeTotal {
									updateIndexEntries(block[nodeOff:nodeTotal], remap, getSeq)
								}
								_ = ApplyFixup(block, usaOff, usaCount, seq)
								modified = true
							}
						}
						if modified {
							_ = SeekAndWrite(h, run.LCN*clusterSize, data)
						}
					}
				}
			}
			off5 += alen
		}
	}

	// 6. Update non-resident directory index allocation blocks in user directories
	for rnum := firstCompactSlot; rnum < nextSlot; rnum++ {
		rec := compactedRecords[rnum]
		if rec == nil || string(rec[:4]) != "FILE" || (binary.LittleEndian.Uint16(rec[22:24])&2) == 0 {
			continue // Not a directory
		}
		off := int(binary.LittleEndian.Uint16(rec[20:22]))
		for off+8 <= len(rec) {
			atype := binary.LittleEndian.Uint32(rec[off : off+4])
			alen := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
			if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec) {
				break
			}
			if atype == AttrTypeIndexAllocation && rec[off+8] != 0 {
				ro := int(binary.LittleEndian.Uint16(rec[off+32 : off+34]))
				runs := ParseRunlist(rec[off+ro : off+alen])
				for _, run := range runs {
					runBytes := run.Length * clusterSize
					data, err := ReadAt(h, run.LCN*clusterSize, int(runBytes))
					if err == nil {
						modified := false
						for blkOff := 0; blkOff+4096 <= len(data); blkOff += 4096 {
							block := data[blkOff : blkOff+4096]
							if string(block[:4]) == "INDX" {
								_ = RemoveFixup(block)
								usaOff := binary.LittleEndian.Uint16(block[4:6])
								usaCount := binary.LittleEndian.Uint16(block[6:8])
								seq := binary.LittleEndian.Uint16(block[usaOff : usaOff+2])
								nodeOff := 24 + int(binary.LittleEndian.Uint32(block[24:28]))
								nodeTotal := 24 + int(binary.LittleEndian.Uint32(block[28:32]))
								if nodeTotal <= len(block) && nodeOff <= nodeTotal {
									updateIndexEntries(block[nodeOff:nodeTotal], remap, getSeq)
								}
								_ = ApplyFixup(block, usaOff, usaCount, seq)
								modified = true
							}
						}
						if modified {
							_ = SeekAndWrite(h, run.LCN*clusterSize, data)
						}
					}
				}
			}
			off += alen
		}
	}

	// 7. Adjust $MFT allocation if resized/shrunk
	report("Adjusting $MFT sizing and volume bitmap...", analysis.MftLcn)
	mftRuns := make([]Run, len(analysis.ExistingMftRuns))
	copy(mftRuns, analysis.ExistingMftRuns)

	if targetMftClusters != totalExistingMftClusters {
		if targetMftClusters < totalExistingMftClusters {
			// Shrunk: truncate mftRuns from tail and free clusters in volume bitmap
			clustersToFree := totalExistingMftClusters - targetMftClusters
			var freed uint64
			type freedRange struct {
				lcn    uint64
				length uint64
			}
			var freedRanges []freedRange

			for i := len(mftRuns) - 1; i >= 0 && freed < clustersToFree; i-- {
				run := mftRuns[i]
				runFree := run.Length
				if freed+runFree > clustersToFree {
					runFree = clustersToFree - freed
					mftRuns[i].Length -= runFree
				} else {
					mftRuns = mftRuns[:i]
				}
				startLcn := run.LCN + run.Length - runFree
				freedRanges = append(freedRanges, freedRange{lcn: startLcn, length: runFree})
				freed += runFree
			}

			// Clear freed clusters in volume bitmap
			if analysis.BitmapAllocBytes > 0 && analysis.BitmapLcn > 0 {
				volBitmap, err := ReadAt(h, analysis.BitmapLcn*clusterSize, int(analysis.BitmapAllocBytes))
				if err == nil && len(volBitmap) > 0 {
					for _, fr := range freedRanges {
						for c := uint64(0); c < fr.length; c++ {
							clust := fr.lcn + c
							if clust < analysis.TotalClusters && clust/8 < uint64(len(volBitmap)) {
								volBitmap[clust/8] &^= (1 << (clust % 8))
							}
						}
					}
					_ = SeekAndWrite(h, analysis.BitmapLcn*clusterSize, volBitmap)
				}
			}

			// Zero out freed clusters on disk to erase stale records
			for _, fr := range freedRanges {
				chunkSize := uint64(64)
				zeroBuf := make([]byte, chunkSize*clusterSize)
				for done := uint64(0); done < fr.length; done += chunkSize {
					cur := chunkSize
					if done+cur > fr.length {
						cur = fr.length - done
					}
					_ = SeekAndWrite(h, (fr.lcn+done)*clusterSize, zeroBuf[:cur*clusterSize])
				}
			}
		}

		// Update Record 0 ($MFT) with new runs and size
		rec0 := compactedRecords[RecordMFT]
		if rec0 != nil && string(rec0[:4]) == "FILE" {
			pRec0, err := PatchNonResidentAttr(rec0, AttrTypeData, "", mftRuns, targetMftBytes, targetMftBytes)
			if err == nil {
				_ = RemoveFixup(pRec0)
				compactedRecords[RecordMFT] = pRec0
			}
		}
	}

	// 8. Update $MFT:BITMAP
	rec0 := compactedRecords[RecordMFT]
	var mftBmRuns []Run
	if rec0 != nil && string(rec0[:4]) == "FILE" {
		off0 := int(binary.LittleEndian.Uint16(rec0[20:22]))
		for off0+8 <= len(rec0) {
			atype := binary.LittleEndian.Uint32(rec0[off0 : off0+4])
			alen := int(binary.LittleEndian.Uint32(rec0[off0+4 : off0+8]))
			if atype == AttrTypeEnd || alen == 0 || off0+alen > len(rec0) {
				break
			}
			if atype == AttrTypeBitmap && rec0[off0+8] != 0 {
				ro := int(binary.LittleEndian.Uint16(rec0[off0+32 : off0+34]))
				mftBmRuns = ParseRunlist(rec0[off0+ro : off0+alen])
				break
			}
			off0 += alen
		}
	}

	if len(mftBmRuns) > 0 {
		var totalBmBytes uint64
		for _, r := range mftBmRuns {
			totalBmBytes += r.Length * clusterSize
		}
		mftBmBuf := make([]byte, totalBmBytes)
		for recIdx := uint64(0); recIdx < nextSlot && recIdx < totalMftRecords; recIdx++ {
			if recIdx >= 16 && recIdx <= 23 {
				continue
			}
			if compactedRecords[recIdx] != nil && (binary.LittleEndian.Uint16(compactedRecords[recIdx][22:24])&1) != 0 {
				mftBmBuf[recIdx/8] |= (1 << (recIdx % 8))
			}
		}
		var written uint64
		for _, r := range mftBmRuns {
			runBytes := r.Length * clusterSize
			if written+runBytes > totalBmBytes {
				runBytes = totalBmBytes - written
			}
			_ = SeekAndWrite(h, r.LCN*clusterSize, mftBmBuf[written:written+runBytes])
			written += runBytes
		}
	}

	// 9. Write $MFTMirr (first 4 records)
	mirrBuf := make([]byte, 4096)
	for i := 0; i < 4; i++ {
		rCopy := make([]byte, MftRecordSize)
		copy(rCopy, compactedRecords[i])
		usaOffset := binary.LittleEndian.Uint16(rCopy[4:6])
		usaCount := binary.LittleEndian.Uint16(rCopy[6:8])
		seq := binary.LittleEndian.Uint16(rCopy[usaOffset : usaOffset+2])
		if seq == 0 {
			seq = uint16(i + 1)
		}
		_ = ApplyFixup(rCopy, usaOffset, usaCount, seq)
		copy(mirrBuf[i*MftRecordSize:], rCopy)
	}
	vbr, _ := ReadAt(h, 0, 512)
	mirrLcn := binary.LittleEndian.Uint64(vbr[56:64])
	_ = SeekAndWrite(h, mirrLcn*clusterSize, mirrBuf)

	// 10. Write Compacted MFT records to disk
	report("Writing compacted MFT records...", analysis.MftLcn)
	chunkRecords := uint64(256)
	mftChunkBuf := make([]byte, chunkRecords*MftRecordSize)

	var curVcn uint64
	for _, run := range mftRuns {
		runRecords := (run.Length * clusterSize) / uint64(MftRecordSize)
		for rInRun := uint64(0); rInRun < runRecords; rInRun += chunkRecords {
			for i := range mftChunkBuf {
				mftChunkBuf[i] = 0
			}
			toProcess := chunkRecords
			if rInRun+toProcess > runRecords {
				toProcess = runRecords - rInRun
			}
			for r := uint64(0); r < toProcess; r++ {
				recIdx := (curVcn * clusterSize / uint64(MftRecordSize)) + rInRun + r
				if recIdx < totalMftRecords && recIdx < nextSlot && compactedRecords[recIdx] != nil {
					rCopy := make([]byte, MftRecordSize)
					copy(rCopy, compactedRecords[recIdx])
					usaOffset := binary.LittleEndian.Uint16(rCopy[4:6])
					usaCount := binary.LittleEndian.Uint16(rCopy[6:8])
					seq := binary.LittleEndian.Uint16(rCopy[usaOffset : usaOffset+2])
					if seq == 0 {
						seq = uint16(recIdx + 1)
					}
					_ = ApplyFixup(rCopy, usaOffset, usaCount, seq)
					copy(mftChunkBuf[r*uint64(MftRecordSize):(r+1)*uint64(MftRecordSize)], rCopy)
				}
			}
			offset := run.LCN*clusterSize + rInRun*uint64(MftRecordSize)
			if err := SeekAndWrite(h, offset, mftChunkBuf[:toProcess*uint64(MftRecordSize)]); err != nil {
				return fmt.Errorf("failed writing MFT at record %d: %w", rInRun, err)
			}
		}
		curVcn += run.Length
	}

	FlushTarget(h)
	report("MFT compaction complete!", analysis.TotalClusters)
	return nil
}

func decodeUTF16(u16 []uint16) string {
	runes := make([]rune, len(u16))
	for i, v := range u16 {
		runes[i] = rune(v)
	}
	return string(runes)
}
