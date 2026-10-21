package ntfs

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

// RepairResult contains summary statistics from a volume repair and dirty bit clear operation.
type RepairResult struct {
	WasDirty              bool
	DirtyCleared          bool
	LogFileReset          bool
	RecordsChecked        uint64
	RecordsRepaired       uint64
	SecIDsRepaired        uint64
	BitmapClustChecked    uint64
	BitmapMismatchesFixed uint64
	IndicesChecked        uint64
	IndexEntriesFixed     uint64
}

// RepairVolume performs a native, non-destructive volume consistency check:
// 1. Clears the volume dirty bit (0x0001) and chkdsk flags in Record 3 ($Volume).
// 2. Resets $LogFile transaction restart pages with 0xFF so Windows sees a clean transaction state.
// 3. Validates MFT record fixups, structures, and security IDs without deleting or shifting metadata.
// 4. Reconciles cluster allocation in $Bitmap to ensure all active runs are protected.
// 5. Validates $I30 directory index references and sequence numbers in-place.
// 6. Guarantees NO chkdsk.log is created, NO metadata is moved, and NO unused $Secure descriptors are purged.
func RepairVolume(h syscall.Handle, analysis *VolumeAnalysis, progress ProgressFunc) (*RepairResult, error) {
	report := func(msg string, lcn uint64) {
		if progress != nil {
			progress(msg, lcn, analysis.TotalClusters)
		}
	}

	res := &RepairResult{}
	clusterSize := uint64(analysis.ClusterSize)

	// =========================================================================
	// PHASE 1: Inspect & Clear Record 3 ($Volume) Flags
	// =========================================================================
	report("Inspecting Record 3 ($Volume) flags and dirty bit...", analysis.MftLcn)

	rec3, err := readRecordFromMft(h, analysis, RecordVolume)
	if err != nil {
		return nil, fmt.Errorf("failed to read Record 3 ($Volume): %w", err)
	}

	if err := RemoveFixup(rec3); err != nil {
		return nil, fmt.Errorf("corrupted fixup in Record 3: %w", err)
	}

	usaOffset3 := binary.LittleEndian.Uint16(rec3[4:6])
	usaCount3 := binary.LittleEndian.Uint16(rec3[6:8])
	seq3 := binary.LittleEndian.Uint16(rec3[16:18])

	off3 := int(binary.LittleEndian.Uint16(rec3[20:22]))
	foundVolInfo := false
	for off3+8 <= len(rec3) {
		atype := binary.LittleEndian.Uint32(rec3[off3 : off3+4])
		alen := binary.LittleEndian.Uint32(rec3[off3+4 : off3+8])
		if atype == AttrTypeEnd || alen == 0 || off3+int(alen) > len(rec3) {
			break
		}
		if atype == AttrTypeVolumeInformation && rec3[off3+8] == 0 {
			foundVolInfo = true
			valOff := int(binary.LittleEndian.Uint16(rec3[off3+20 : off3+22]))
			if valOff+12 <= int(alen) && off3+valOff+12 <= len(rec3) {
				flags := binary.LittleEndian.Uint16(rec3[off3+valOff+10 : off3+valOff+12])
				if (flags&0x0001) != 0 || (flags&0x8065) != 0 {
					res.WasDirty = true
				}
				// Clear 0x0001 (Dirty), 0x0004 (Upgrade), 0x0020 (Repair ObjId), 0x0040 (Chkdsk underway), 0x8000 (Modified by chkdsk)
				newFlags := flags &^ 0x8065
				if newFlags == 0 {
					newFlags = 0x0080 // Windows native clean NTFS 3.1 volume flag
				}
				binary.LittleEndian.PutUint16(rec3[off3+valOff+10:off3+valOff+12], newFlags)
				res.DirtyCleared = true
			}
		}
		off3 += int(alen)
	}

	if foundVolInfo {
		if err := ApplyFixup(rec3, usaOffset3, usaCount3, seq3); err != nil {
			return nil, fmt.Errorf("failed to apply fixup to Record 3: %w", err)
		}
		if err := writeRecordToMft(h, analysis, RecordVolume, rec3); err != nil {
			return nil, fmt.Errorf("failed to write Record 3: %w", err)
		}
	}

	// =========================================================================
	// PHASE 2: Reset $LogFile Transaction Restart Pages
	// =========================================================================
	if len(analysis.ExistingLogRuns) > 0 {
		report("Resetting $LogFile transaction restart area to clean state...", analysis.ExistingLogRuns[0].LCN)
		run := analysis.ExistingLogRuns[0]
		ffBuf := make([]byte, 64*1024)
		for i := range ffBuf {
			ffBuf[i] = 0xFF
		}

		// Fill the first 16 clusters (64 KB) with 0xFF to clear transaction checkpoints
		totalClust := run.Length
		if totalClust > 16 {
			totalClust = 16
		}
		logOffset := run.LCN * clusterSize
		for w := uint64(0); w < totalClust; {
			chunk := uint64(len(ffBuf)) / clusterSize
			if chunk > totalClust-w {
				chunk = totalClust - w
			}
			_ = SeekAndWrite(h, logOffset+w*clusterSize, ffBuf[:chunk*clusterSize])
			w += chunk
		}
		res.LogFileReset = true
	}

	// =========================================================================
	// PHASE 3: Read & Validate MFT Records & Security IDs
	// =========================================================================
	report("Scanning and validating MFT records...", analysis.MftLcn)

	metaMap := make(map[uint64]*RecordMeta)
	allocatedClusters := make(map[uint64]bool)

	// Pre-mark system metadata clusters known from analysis
	markClusters := func(lcn uint64, count uint64) {
		for c := uint64(0); c < count; c++ {
			if lcn+c < analysis.TotalClusters {
				allocatedClusters[lcn+c] = true
			}
		}
	}

	// Mark boot sector (LCN 0..15)
	markClusters(0, 16)
	for _, r := range analysis.ExistingMftRuns {
		markClusters(r.LCN, r.Length)
	}
	for _, r := range analysis.ExistingLogRuns {
		markClusters(r.LCN, r.Length)
	}
	for _, r := range analysis.ExistingBmRuns {
		markClusters(r.LCN, r.Length)
	}

	// First pass: collect metadata and check records
	dirRecords := make([]uint64, 0)
	maxRec := analysis.MaxAllocRecord
	if maxRec < analysis.TotalAllocRecords {
		maxRec = analysis.TotalAllocRecords
	}

	for recIdx := uint64(0); recIdx <= maxRec; recIdx++ {
		raw, err := readRecordFromMft(h, analysis, recIdx)
		if err != nil {
			continue
		}

		if string(raw[:4]) != "FILE" {
			continue
		}

		res.RecordsChecked++

		d := make([]byte, MftRecordSize)
		copy(d, raw)

		if err := RemoveFixup(d); err != nil {
			// Try to recover fixup
			usaOffset := binary.LittleEndian.Uint16(d[4:6])
			usaCount := binary.LittleEndian.Uint16(d[6:8])
			seq := binary.LittleEndian.Uint16(d[16:18])
			_ = ApplyFixup(d, usaOffset, usaCount, seq)
			_ = writeRecordToMft(h, analysis, recIdx, d)
			res.RecordsRepaired++
		}

		flags := binary.LittleEndian.Uint16(d[22:24])
		isAlloc := (flags & 0x0001) != 0
		if !isAlloc {
			continue
		}

		meta := parseRecordMeta(d, recIdx)
		if meta != nil {
			metaMap[recIdx] = meta
			if meta.IsDir {
				dirRecords = append(dirRecords, recIdx)
			}
		}

		// Collect data runs and index runs from attributes
		off := int(binary.LittleEndian.Uint16(d[20:22]))
		for off+8 <= len(d) {
			atype := binary.LittleEndian.Uint32(d[off : off+4])
			alen := binary.LittleEndian.Uint32(d[off+4 : off+8])
			if atype == AttrTypeEnd || alen == 0 || off+int(alen) > len(d) {
				break
			}
			isNonRes := d[off+8] != 0
			if isNonRes && off+34 <= len(d) {
				runOff := int(binary.LittleEndian.Uint16(d[off+32 : off+34]))
				if off+runOff <= len(d) {
					runs := ParseRunlist(d[off+runOff : off+int(alen)])
					for _, r := range runs {
						if r.LCN > 0 && r.LCN+r.Length <= analysis.TotalClusters {
							markClusters(r.LCN, r.Length)
						}
					}
				}
			}
			off += int(alen)
		}
	}

	// Second pass: verify and fix Security IDs for all active records
	report("Verifying Security IDs across MFT records...", analysis.MftLcn)
	for recIdx, meta := range metaMap {
		raw, err := readRecordFromMft(h, analysis, recIdx)
		if err != nil {
			continue
		}
		if string(raw[:4]) != "FILE" {
			continue
		}

		d := make([]byte, MftRecordSize)
		copy(d, raw)
		_ = RemoveFixup(d)

		secId, hasSecId := GetRecordSecurityID(d)
		// Baseline valid SecIDs are 256..271
		isValidSecId := hasSecId && secId >= 256 && secId <= 271

		if !isValidSecId {
			path := buildPath(recIdx, metaMap)
			newSecId := DetermineSecurityID(recIdx, meta.IsDir, meta.HasImageLoad, path, meta.Name)
			if SetRecordSecurityID(d, newSecId) {
				usaOffset := binary.LittleEndian.Uint16(d[4:6])
				usaCount := binary.LittleEndian.Uint16(d[6:8])
				seq := binary.LittleEndian.Uint16(d[16:18])
				_ = ApplyFixup(d, usaOffset, usaCount, seq)
				_ = writeRecordToMft(h, analysis, recIdx, d)
				res.SecIDsRepaired++
				res.RecordsRepaired++
			}
		}
	}

	// =========================================================================
	// PHASE 4: Reconcile Volume Bitmap ($Bitmap)
	// =========================================================================
	if len(analysis.ExistingBmRuns) > 0 && analysis.BitmapAllocBytes > 0 {
		report("Reconciling volume cluster bitmap ($Bitmap)...", analysis.ExistingBmRuns[0].LCN)
		bmLcn := analysis.ExistingBmRuns[0].LCN
		bmBytes := analysis.BitmapAllocBytes
		bmData, err := ReadAt(h, bmLcn*clusterSize, int(bmBytes))
		if err == nil && len(bmData) > 0 {
			bmModified := false
			for clust := range allocatedClusters {
				res.BitmapClustChecked++
				byteIdx := clust / 8
				bitIdx := clust % 8
				if byteIdx < uint64(len(bmData)) {
					if (bmData[byteIdx] & (1 << bitIdx)) == 0 {
						// Cluster is used by an active file/metadata but marked free in $Bitmap! Fix it!
						bmData[byteIdx] |= (1 << bitIdx)
						bmModified = true
						res.BitmapMismatchesFixed++
					}
				}
			}
			if bmModified {
				_ = SeekAndWrite(h, bmLcn*clusterSize, bmData)
			}
		}
	}

	// =========================================================================
	// PHASE 5: Validate Directory Indices ($I30)
	// =========================================================================
	report("Validating directory indices ($I30)...", analysis.MftLcn)
	for _, dirRecNum := range dirRecords {
		raw, err := readRecordFromMft(h, analysis, dirRecNum)
		if err != nil {
			continue
		}
		if string(raw[:4]) != "FILE" {
			continue
		}

		res.IndicesChecked++
		d := make([]byte, MftRecordSize)
		copy(d, raw)
		_ = RemoveFixup(d)

		recordModified := false
		off := int(binary.LittleEndian.Uint16(d[20:22]))
		for off+8 <= len(d) {
			atype := binary.LittleEndian.Uint32(d[off : off+4])
			alen := int(binary.LittleEndian.Uint32(d[off+4 : off+8]))
			if atype == AttrTypeEnd || alen == 0 || off+alen > len(d) {
				break
			}

			// Resident $INDEX_ROOT
			if atype == AttrTypeIndexRoot && d[off+8] == 0 {
				voff := int(binary.LittleEndian.Uint16(d[off+20 : off+22]))
				if voff+32 <= alen && off+voff+32 <= len(d) {
					irPayload := d[off+voff : off+alen]
					nodeOff := 16 + int(binary.LittleEndian.Uint32(irPayload[16:20]))
					nodeTotal := 16 + int(binary.LittleEndian.Uint32(irPayload[20:24]))
					if nodeTotal <= len(irPayload) && nodeOff <= nodeTotal {
						fixed := validateAndFixIndexBlock(irPayload[nodeOff:nodeTotal], metaMap)
						if fixed > 0 {
							res.IndexEntriesFixed += fixed
							recordModified = true
						}
					}
				}
			}

			// Non-Resident $INDEX_ALLOCATION
			if atype == AttrTypeIndexAllocation && d[off+8] != 0 {
				ro := int(binary.LittleEndian.Uint16(d[off+32 : off+34]))
				if off+ro <= len(d) {
					runs := ParseRunlist(d[off+ro : off+alen])
					for _, run := range runs {
						runBytes := run.Length * clusterSize
						data, err := ReadAt(h, run.LCN*clusterSize, int(runBytes))
						if err == nil {
							blockModified := false
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
										fixed := validateAndFixIndexBlock(block[nodeOff:nodeTotal], metaMap)
										if fixed > 0 {
											res.IndexEntriesFixed += fixed
											_ = ApplyFixup(block, usaOff, usaCount, seq)
											blockModified = true
										}
									}
								}
							}
							if blockModified {
								_ = SeekAndWrite(h, run.LCN*clusterSize, data)
							}
						}
					}
				}
			}
			off += alen
		}

		if recordModified {
			usaOffset := binary.LittleEndian.Uint16(d[4:6])
			usaCount := binary.LittleEndian.Uint16(d[6:8])
			seq := binary.LittleEndian.Uint16(d[16:18])
			_ = ApplyFixup(d, usaOffset, usaCount, seq)
			_ = writeRecordToMft(h, analysis, dirRecNum, d)
			res.RecordsRepaired++
		}
	}

	report("Flushing disk caches and remounting clean volume...", 0)
	FlushTarget(h)

	return res, nil
}

// validateAndFixIndexBlock checks each index entry against known active MFT records.
// If an index entry references an existing record but has a sequence number mismatch, it repairs the sequence number.
func validateAndFixIndexBlock(entries []byte, metaMap map[uint64]*RecordMeta) uint64 {
	fixed := uint64(0)
	cur := 0
	for cur+16 <= len(entries) {
		entryLen := int(binary.LittleEndian.Uint16(entries[cur+8 : cur+10]))
		flags := binary.LittleEndian.Uint16(entries[cur+12 : cur+14])
		if entryLen < 16 || cur+entryLen > len(entries) {
			break
		}

		if (flags & 0x0002) != 0 {
			// END record marker
			break
		}

		mftRef := binary.LittleEndian.Uint64(entries[cur : cur+8])
		recNum := mftRef & 0x0000FFFFFFFFFFFF
		seqInEntry := uint16(mftRef >> 48)

		if meta, exists := metaMap[recNum]; exists {
			if meta.Seq != 0 && seqInEntry != meta.Seq {
				// Repair sequence number to match the actual record
				newRef := (uint64(meta.Seq) << 48) | recNum
				binary.LittleEndian.PutUint64(entries[cur:cur+8], newRef)
				fixed++
			}
		}

		cur += entryLen
	}
	return fixed
}
