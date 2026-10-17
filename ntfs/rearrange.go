package ntfs

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unicode/utf16"
)

// FileInfo holds metadata about an existing MFT record during analysis and remapping.
type FileInfo struct {
	RecNum    uint64
	Seq       uint16
	IsDir     bool
	Name      string
	ParentNum uint64
}

// parseFileInfo inspects an MFT record to extract its basic identification.
func parseFileInfo(rec []byte, recNum uint64) *FileInfo {
	if rec == nil || len(rec) < 48 || string(rec[:4]) != "FILE" {
		return nil
	}
	flags := binary.LittleEndian.Uint16(rec[22:24])
	if (flags & 1) == 0 { // Unallocated record
		return nil
	}
	seq := binary.LittleEndian.Uint16(rec[16:18])
	isDir := (flags & 2) != 0

	var bestName string
	var bestParent uint64
	bestNs := -1

	off := int(binary.LittleEndian.Uint16(rec[20:22]))
	for off+8 <= len(rec) {
		atype := binary.LittleEndian.Uint32(rec[off : off+4])
		alen := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec) {
			break
		}
		if atype == AttrTypeFileName && rec[off+8] == 0 {
			voff := int(binary.LittleEndian.Uint16(rec[off+20 : off+22]))
			if off+voff+66 <= len(rec) {
				pRef := binary.LittleEndian.Uint64(rec[off+voff : off+voff+8])
				pNum := pRef & 0xFFFFFFFFFFFF
				ns := int(rec[off+voff+65])
				fnLen := int(rec[off+voff+64])
				if off+voff+66+fnLen*2 <= len(rec) {
					u16 := make([]uint16, fnLen)
					for j := 0; j < fnLen; j++ {
						u16[j] = binary.LittleEndian.Uint16(rec[off+voff+66+j*2 : off+voff+66+j*2+2])
					}
					fnStr := string(utf16.Decode(u16))
					if ns == 1 || ns == 3 || bestNs == -1 {
						bestName = fnStr
						bestParent = pNum
						bestNs = ns
					}
				}
			}
		}
		off += alen
	}

	return &FileInfo{
		RecNum:    recNum,
		Seq:       seq,
		IsDir:     isDir,
		Name:      bestName,
		ParentNum: bestParent,
	}
}

// updateIndexEntries rewrites IndexedFile and ParentDirectory references in an index buffer according to remap.
func updateIndexEntries(buf []byte, remap map[uint64]uint64, getSeq func(uint64) uint16) {
	cur := 0
	for cur+16 <= len(buf) {
		elen := int(binary.LittleEndian.Uint16(buf[cur+8 : cur+10]))
		if elen == 0 || cur+elen > len(buf) {
			break
		}
		flags := binary.LittleEndian.Uint32(buf[cur+12 : cur+16])
		if (flags & 2) == 0 { // Leaf / non-end entry
			mref := binary.LittleEndian.Uint64(buf[cur : cur+8])
			oldChild := mref & 0xFFFFFFFFFFFF
			if newChild, ok := remap[oldChild]; ok {
				newSeq := getSeq(newChild)
				newMref := (uint64(newSeq) << 48) | (newChild & 0xFFFFFFFFFFFF)
				binary.LittleEndian.PutUint64(buf[cur:cur+8], newMref)
			}
			vlen := int(binary.LittleEndian.Uint16(buf[cur+10 : cur+12]))
			if vlen >= 8 && cur+16+8 <= len(buf) {
				pRef := binary.LittleEndian.Uint64(buf[cur+16 : cur+24])
				oldParent := pRef & 0xFFFFFFFFFFFF
				if newParent, ok := remap[oldParent]; ok {
					newPSeq := getSeq(newParent)
					newPRef := (uint64(newPSeq) << 48) | (newParent & 0xFFFFFFFFFFFF)
					binary.LittleEndian.PutUint64(buf[cur+16:cur+24], newPRef)
				}
			}
		}
		cur += elen
	}
}

// patchSecurityId sets the SecurityId field in the standard information attribute of an MFT record.
func patchSecurityId(rec []byte, secId uint32) {
	if rec == nil {
		return
	}
	off := int(binary.LittleEndian.Uint16(rec[20:22]))
	for off+8 <= len(rec) {
		atype := binary.LittleEndian.Uint32(rec[off : off+4])
		alen := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec) {
			break
		}
		if atype == AttrTypeStandardInformation && rec[off+8] == 0 {
			voff := int(binary.LittleEndian.Uint16(rec[off+20 : off+22]))
			if off+voff+56 <= len(rec) {
				binary.LittleEndian.PutUint32(rec[off+voff+52:off+voff+56], secId)
			}
			break
		}
		off += alen
	}
}

// RearrangeVolume reorganizes an existing NTFS volume's metadata sequentially in-place,
// compacting MFT records into canonical order (metadata -> SVI -> RecycleBin -> user data)
// with zero gaps, evacuating colliding files, and preserving all existing user data.
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

	// 1. Read all existing active MFT records
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

	// 2. Classify existing files and directories
	report("Classifying files and computing canonical record reordering...", layout.MftLcn)
	files := make(map[uint64]*FileInfo)
	for i := uint64(0); i < recordCount; i++ {
		if fi := parseFileInfo(existingRecords[i], i); fi != nil {
			files[i] = fi
		}
	}

	var sviRec, wpRec, idxRec, trkRec uint64
	var recBinRec, recUserRec, deskIniRec uint64

	for r, f := range files {
		if f.ParentNum == RecordRoot && f.Name == "System Volume Information" {
			sviRec = r
		}
		if f.ParentNum == RecordRoot && f.Name == "$Recycle.Bin" {
			recBinRec = r
		}
	}

	if sviRec > 0 {
		for r, f := range files {
			if f.ParentNum == sviRec {
				switch f.Name {
				case "WPSettings.dat":
					wpRec = r
				case "IndexerVolumeGuid":
					idxRec = r
				case "tracking.log":
					trkRec = r
				}
			}
		}
	}

	if recBinRec > 0 {
		for r, f := range files {
			if f.ParentNum == recBinRec && f.IsDir {
				recUserRec = r
				break
			}
		}
		if recUserRec > 0 {
			for r, f := range files {
				if f.ParentNum == recUserRec && f.Name == "desktop.ini" {
					deskIniRec = r
					break
				}
			}
		}
	}

	// Active user records: all active records except system files and SVI/RecycleBin components
	var userRecords []uint64
	for r := uint64(0); r < recordCount; r++ {
		f, ok := files[r]
		if !ok {
			continue
		}
		if r <= 15 || (r >= 24 && r <= 35) {
			continue
		}
		if r == sviRec || r == wpRec || r == idxRec || r == trkRec {
			continue
		}
		if r == recBinRec || r == recUserRec || r == deskIniRec {
			continue
		}
		if recBinRec > 0 && (f.ParentNum == recBinRec || (recUserRec > 0 && f.ParentNum == recUserRec)) {
			continue
		}
		userRecords = append(userRecords, r)
	}

	// 3. Build canonical remap table
	remap := make(map[uint64]uint64)
	for i := uint64(0); i <= 15; i++ {
		remap[i] = i
	}
	for i := uint64(24); i <= 35; i++ {
		remap[i] = i
	}
	if sviRec > 0 {
		remap[sviRec] = 36
	}
	if wpRec > 0 {
		remap[wpRec] = 37
	}
	if idxRec > 0 {
		remap[idxRec] = 38
	}
	if trkRec > 0 {
		remap[trkRec] = 39
	}
	if recBinRec > 0 {
		remap[recBinRec] = 40
	}
	if recUserRec > 0 {
		remap[recUserRec] = 41
	}
	if deskIniRec > 0 {
		remap[deskIniRec] = 42
	}

	// User records >= 43 keep their existing slots (NOT compacted)
	// Only user records that were <= 42 are moved past the metadata zone
	occupied := make(map[uint64]bool)
	for i := uint64(0); i <= 42; i++ {
		occupied[i] = true
	}
	for _, r := range userRecords {
		if r >= 43 {
			occupied[r] = true
			remap[r] = r
		}
	}
	nextFreeSlot := uint64(43)
	for _, r := range userRecords {
		if r < 43 {
			for occupied[nextFreeSlot] {
				nextFreeSlot++
			}
			remap[r] = nextFreeSlot
			occupied[nextFreeSlot] = true
		}
	}

	maxAllocatedSlot := uint64(42)
	for _, newSlot := range remap {
		if newSlot > maxAllocatedSlot {
			maxAllocatedSlot = newSlot
		}
	}
	nextSlot := maxAllocatedSlot + 1

	// 4. Generate updated pristine system records matching the sequential layout
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

	// 5. Assemble compactedRecords slice
	totalAllocSlots := nextSlot
	if totalAllocSlots < 64 {
		totalAllocSlots = 64
	}
	compactedRecords := make([][]byte, totalAllocSlots)
	for i := uint64(0); i < recordCount && i < totalAllocSlots; i++ {
		if existingRecords[i] != nil {
			compactedRecords[i] = existingRecords[i]
		}
	}

	// Overlay 0..10 (excluding 5 and 9)
	for i := 0; i <= 10; i++ {
		if i != RecordRoot && i != RecordSecure && i < len(sysRecords) && sysRecords[i] != nil {
			compactedRecords[i] = sysRecords[i]
		}
	}

	// Patch Record 25 ($ObjId) and Record 29 ($Deleted)
	if compactedRecords[RecordObjId] != nil && layout.ObjIdClusters > 0 {
		pRec25, err := BuildObjIdRecord(compactedRecords[RecordObjId], layout)
		if err == nil {
			_ = RemoveFixup(pRec25)
			compactedRecords[RecordObjId] = pRec25
		}
	}
	if compactedRecords[RecordDeleted] != nil && layout.DeletedClusters > 0 {
		pRec29, err := PatchNonResidentAttr(compactedRecords[RecordDeleted], AttrTypeIndexAllocation, "$I30", []Run{{LCN: layout.DeletedLcn, Length: layout.DeletedClusters}}, layout.DeletedClusters*clusterSize, 0)
		if err == nil {
			_ = RemoveFixup(pRec29)
			compactedRecords[RecordDeleted] = pRec29
		}
	}

	// Synthesize canonical records 36..42
	userSID := GetCurrentUserSID()
	tmpRecs := make([][]byte, 64)
	if err := BuildInitialRootFoldersRecords(tmpRecs, userSID); err == nil {
		for i := range tmpRecs {
			if tmpRecs[i] != nil {
				_ = RemoveFixup(tmpRecs[i])
			}
		}
	}

	// Canonical 36..42: SVI and RecycleBin records
	compactedRecords[36] = tmpRecs[36]
	if wpRec > 0 && existingRecords[wpRec] != nil {
		compactedRecords[37] = existingRecords[wpRec]
	} else {
		compactedRecords[37] = tmpRecs[37]
	}
	if idxRec > 0 && existingRecords[idxRec] != nil {
		compactedRecords[38] = existingRecords[idxRec]
	} else {
		compactedRecords[38] = tmpRecs[38]
	}
	if trkRec > 0 && existingRecords[trkRec] != nil {
		compactedRecords[39] = existingRecords[trkRec]
	} else {
		compactedRecords[39] = tmpRecs[39]
	}
	compactedRecords[40] = tmpRecs[40]
	compactedRecords[41] = tmpRecs[41]
	compactedRecords[42] = tmpRecs[42]

	patchSecurityId(compactedRecords[36], 262)
	patchSecurityId(compactedRecords[37], 263)
	patchSecurityId(compactedRecords[38], 263)
	patchSecurityId(compactedRecords[39], 263)
	patchSecurityId(compactedRecords[40], 262)
	patchSecurityId(compactedRecords[41], 262)
	patchSecurityId(compactedRecords[42], 263)

	// Copy user records to their compacted positions
	for _, oldRec := range userRecords {
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

	// 6. Preserve Record 5 ($Root) directory index and relocate $INDEX_ALLOCATION if non-resident
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
	compactedRecords[RecordRoot] = rec5

	// 7. Preserve Record 9 ($Secure) descriptors ($SDS, $SDH, $SII)
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
			compactedRecords[RecordSecure] = rec9
		}
	}

	// 8. Update Record Number and Attribute references across user records
	report("Updating record numbers and directory references...", layout.MftLcn)
	for rnum := uint64(43); rnum < nextSlot; rnum++ {
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
					name = string(utf16.Decode(u16))
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

	// 9. Update Root Index Block
	if len(rootIndexData) > 0 {
		_ = RemoveFixup(rootIndexData)
		usaOff := binary.LittleEndian.Uint16(rootIndexData[4:6])
		usaCount := binary.LittleEndian.Uint16(rootIndexData[6:8])
		seq := binary.LittleEndian.Uint16(rootIndexData[usaOff : usaOff+2])
		nodeOff := 24 + int(binary.LittleEndian.Uint32(rootIndexData[24:28]))
		nodeTotal := 24 + int(binary.LittleEndian.Uint32(rootIndexData[28:32]))

		// Update existing root entries with new remapped record numbers
		updateIndexEntries(rootIndexData[nodeOff:nodeTotal], remap, getSeq)

		// Check if $Recycle.Bin is already present in the root directory index
		hasRecycleBin := false
		cur := nodeOff
		for cur+16 <= nodeTotal && cur+16 <= len(rootIndexData) {
			elen := int(binary.LittleEndian.Uint16(rootIndexData[cur+8 : cur+10]))
			vlen := int(binary.LittleEndian.Uint16(rootIndexData[cur+10 : cur+12]))
			if elen == 0 {
				break
			}
			if vlen > 66 {
				nlen := int(rootIndexData[cur+16+64])
				if cur+16+66+nlen*2 <= len(rootIndexData) {
					u16 := make([]uint16, nlen)
					for j := 0; j < nlen; j++ {
						u16[j] = binary.LittleEndian.Uint16(rootIndexData[cur+16+66+j*2:])
					}
					if string(utf16.Decode(u16)) == "$Recycle.Bin" {
						hasRecycleBin = true
						break
					}
				}
			}
			cur += elen
		}

		// Insert $Recycle.Bin right before $Secure if absent
		if !hasRecycleBin && compactedRecords[40] != nil {
			fnRecBin, seqRecBin, err := ExtractFileNamePayload(compactedRecords[40])
			if err == nil {
				valLen := len(fnRecBin)
				entryLen := (16 + valLen + 7) &^ 7
				recBinEntry := make([]byte, entryLen)
				binary.LittleEndian.PutUint64(recBinEntry[0:8], 40|(uint64(seqRecBin)<<48))
				binary.LittleEndian.PutUint16(recBinEntry[8:10], uint16(entryLen))
				binary.LittleEndian.PutUint16(recBinEntry[10:12], uint16(valLen))
				copy(recBinEntry[16:], fnRecBin)

				entriesOff := int(binary.LittleEndian.Uint32(rootIndexData[24:28]))
				totalSz := int(binary.LittleEndian.Uint32(rootIndexData[28:32]))
				off := 24 + entriesOff
				end := 24 + totalSz

				var newEntries []byte
				for off+16 <= end && off+16 <= len(rootIndexData) {
					mftRef := binary.LittleEndian.Uint64(rootIndexData[off : off+8])
					rnum := mftRef & 0xFFFFFFFFFFFF
					elen := int(binary.LittleEndian.Uint16(rootIndexData[off+8 : off+10]))
					if elen == 0 {
						break
					}
					if rnum == RecordSecure {
						newEntries = append(newEntries, recBinEntry...)
					}
					newEntries = append(newEntries, rootIndexData[off:off+elen]...)
					off += elen
				}
				newTotalSz := entriesOff + len(newEntries)
				binary.LittleEndian.PutUint32(rootIndexData[28:32], uint32(newTotalSz))
				for i := 24 + entriesOff; i < len(rootIndexData); i++ {
					rootIndexData[i] = 0
				}
				copy(rootIndexData[24+entriesOff:], newEntries)
			}
		}

		_ = ApplyFixup(rootIndexData, usaOff, usaCount, seq)
	}

	// 10. Build sequential volume bitmap
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
	// MftZone is left unallocated (0) as reserved free area
	markBm(layout.MftBitmapLcn, layout.MftBitmapClusters)
	markBm(layout.SdsLcn, layout.SdsClusters)
	markBm(layout.UpCaseLcn, layout.UpCaseClusters)
	markBm(layout.AttrDefLcn, 1)
	markBm(layout.RootIndexLcn, 1)

	// Mark trailing unused bits beyond TotalClusters
	for c := layout.TotalClusters; c < layout.BitmapClusters*clusterSize*8; c++ {
		byteIdx := c / 8
		bitIdx := c % 8
		if byteIdx < uint64(len(volBitmap)) {
			volBitmap[byteIdx] |= (1 << bitIdx)
		}
	}

	// Mark non-colliding existing user data runs in volBitmap
	for recIdx := uint64(11); recIdx < nextSlot; recIdx++ {
		if recIdx == RecordObjId || recIdx == RecordDeleted {
			continue
		}
		rec := compactedRecords[recIdx]
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

	// 11. Evacuate colliding user clusters occupying [0 .. layout.DataStartLcn)
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

	for recIdx := uint64(11); recIdx < nextSlot; recIdx++ {
		if recIdx == RecordObjId || recIdx == RecordDeleted {
			continue
		}
		rec := compactedRecords[recIdx]
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
					compactedRecords[recIdx] = pRec
					rec = pRec
				}
			}
			off += alen
		}
	}

	// 12. Update non-resident directory index allocation blocks (if any)
	for recIdx := uint64(43); recIdx < nextSlot; recIdx++ {
		rec := compactedRecords[recIdx]
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

	// 13. Write Sequential Metadata Streams to disk
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
	for recIdx := uint64(0); recIdx < nextSlot; recIdx++ {
		if recIdx >= 16 && recIdx <= 23 {
			continue
		}
		if compactedRecords[recIdx] != nil && (binary.LittleEndian.Uint16(compactedRecords[recIdx][22:24])&1) != 0 {
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

	// 14. Write Relocated, Resized & Compacted $MFT
	report("Writing compacted $MFT records...", layout.MftLcn)
	chunkRecords := uint64(256)
	mftChunkBuf := make([]byte, chunkRecords*MftRecordSize)

	totalMftRecords := (layout.MftClusters * clusterSize) / MftRecordSize
	for startRec := uint64(0); startRec < totalMftRecords; startRec += chunkRecords {
		for i := range mftChunkBuf {
			mftChunkBuf[i] = 0
		}
		for r := uint64(0); r < chunkRecords; r++ {
			recIdx := startRec + r
			if recIdx < nextSlot && compactedRecords[recIdx] != nil {
				rCopy := make([]byte, MftRecordSize)
				copy(rCopy, compactedRecords[recIdx])
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
	report("NTFS rearrangement and MFT compaction complete!", layout.TotalClusters)
	return nil
}
