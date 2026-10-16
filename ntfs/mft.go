package ntfs

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// PatchNonResidentAttr replaces the runlist and size fields of a matching non-resident attribute in an MFT record.
func PatchNonResidentAttr(rec []byte, targetType uint32, targetName string, runs []Run, allocSize uint64, realSize uint64) ([]byte, error) {
	d := make([]byte, len(rec))
	copy(d, rec)

	if err := RemoveFixup(d); err != nil {
		return nil, err
	}

	usaOffset := binary.LittleEndian.Uint16(d[4:6])
	usaCount := binary.LittleEndian.Uint16(d[6:8])
	attrOffset := binary.LittleEndian.Uint16(d[20:22])

	off := int(attrOffset)
	found := false

	for off < len(d) {
		if off+8 > len(d) {
			break
		}
		atype := binary.LittleEndian.Uint32(d[off : off+4])
		alen := binary.LittleEndian.Uint32(d[off+4 : off+8])
		if atype == AttrTypeEnd || alen == 0 || off+int(alen) > len(d) {
			break
		}

		nonRes := d[off+8]
		nameLen := int(d[off+9])
		nameOff := int(binary.LittleEndian.Uint16(d[off+10 : off+12]))

		var name string
		if nameLen > 0 && off+nameOff+nameLen*2 <= len(d) {
			u16 := make([]uint16, nameLen)
			for i := 0; i < nameLen; i++ {
				u16[i] = binary.LittleEndian.Uint16(d[off+nameOff+i*2 : off+nameOff+i*2+2])
			}
			name = string(utf16.Decode(u16))
		}

		if atype == targetType && name == targetName && nonRes == 1 {
			rlOff := int(binary.LittleEndian.Uint16(d[off+32 : off+34]))
			encodedRl := EncodeRunlist(runs)

			if off+rlOff+len(encodedRl) > off+int(alen) {
				return nil, fmt.Errorf("runlist (%d bytes) exceeds attribute allocation (%d bytes)", len(encodedRl), int(alen)-rlOff)
			}

			var totalClusters uint64 = 0
			for _, r := range runs {
				totalClusters += r.Length
			}
			binary.LittleEndian.PutUint64(d[off+16:off+24], 0)
			binary.LittleEndian.PutUint64(d[off+24:off+32], totalClusters-1)

			if allocSize > 0 {
				binary.LittleEndian.PutUint64(d[off+40:off+48], allocSize)
			}
			if realSize > 0 {
				binary.LittleEndian.PutUint64(d[off+48:off+56], realSize)
				binary.LittleEndian.PutUint64(d[off+56:off+64], realSize)
			}

			for i := off + rlOff; i < off+int(alen); i++ {
				d[i] = 0
			}
			copy(d[off+rlOff:], encodedRl)
			found = true
			break
		}
		off += int(alen)
	}

	if !found {
		return nil, fmt.Errorf("attribute 0x%X '%s' (non-resident) not found in record", targetType, targetName)
	}

	// Keep exact sequence number
	seq := binary.LittleEndian.Uint16(d[usaOffset : usaOffset+2])
	if seq == 0 {
		seq = 1
	}
	if err := ApplyFixup(d, usaOffset, usaCount, seq); err != nil {
		return nil, err
	}
	return d, nil
}

// BuildEmptyMftRecord creates a valid unallocated MFT record segment with FILE signature.
func BuildEmptyMftRecord(seq uint16) []byte {
	rec := make([]byte, MftRecordSize)
	copy(rec[0:4], []byte("FILE"))

	usaOffset := uint16(48)
	usaCount := uint16(3)
	binary.LittleEndian.PutUint16(rec[4:6], usaOffset)
	binary.LittleEndian.PutUint16(rec[6:8], usaCount)
	binary.LittleEndian.PutUint16(rec[16:18], seq)
	binary.LittleEndian.PutUint16(rec[18:20], 0)  // Link count
	binary.LittleEndian.PutUint16(rec[20:22], 56) // Attr offset
	binary.LittleEndian.PutUint16(rec[22:24], 0)  // Flags = 0 (NOT IN USE)
	binary.LittleEndian.PutUint32(rec[24:28], 64) // Bytes used
	binary.LittleEndian.PutUint32(rec[28:32], MftRecordSize)
	binary.LittleEndian.PutUint16(rec[40:42], 1)           // Next attr id
	binary.LittleEndian.PutUint32(rec[56:60], AttrTypeEnd) // 0xFFFFFFFF
	_ = ApplyFixup(rec, usaOffset, usaCount, seq)
	return rec
}

// BuildObjIdRecord updates MFT record 25 ($ObjId) from base template, pre-sizing with $O:INDEX_ALLOCATION.
func BuildObjIdRecord(baseRec []byte, layout *VolumeLayout) ([]byte, error) {
	d := make([]byte, MftRecordSize)
	copy(d, baseRec)

	if err := RemoveFixup(d); err != nil {
		return nil, err
	}

	usaOffset := binary.LittleEndian.Uint16(d[4:6])
	usaCount := binary.LittleEndian.Uint16(d[6:8])
	off := int(binary.LittleEndian.Uint16(d[20:22]))

	var stdInfo, fnInfo []byte

	for off < len(d) {
		atype := binary.LittleEndian.Uint32(d[off : off+4])
		alen := binary.LittleEndian.Uint32(d[off+4 : off+8])
		if atype == AttrTypeEnd || alen == 0 || off+int(alen) > len(d) {
			break
		}
		if atype == AttrTypeStandardInformation {
			stdInfo = make([]byte, alen)
			copy(stdInfo, d[off:off+int(alen)])
		} else if atype == AttrTypeFileName {
			fnInfo = make([]byte, alen)
			copy(fnInfo, d[off:off+int(alen)])
		}
		off += int(alen)
	}

	if stdInfo == nil || fnInfo == nil {
		return nil, fmt.Errorf("Attr 0x10 or 0x30 missing in Record 25 template")
	}

	newRec := make([]byte, MftRecordSize)
	copy(newRec[:56], d[:56])
	cur := 56

	copy(newRec[cur:], stdInfo)
	cur += len(stdInfo)

	copy(newRec[cur:], fnInfo)
	cur += len(fnInfo)

	var attrID uint16 = 3

	// Attr 0x90: IndexRoot "$O" (leaf root node, matching NTFS standard for pre-allocated index)
	// Header (16 bytes) + NodeHeader (16 bytes) + Entry (16 bytes) = 48 bytes
	irPayload := make([]byte, 48)
	// Header: attr_type=0, collation=19 (CollationObjectId), idx_alloc_sz=4096, clus_per_idx=1
	binary.LittleEndian.PutUint32(irPayload[0:4], 0)
	binary.LittleEndian.PutUint32(irPayload[4:8], 19)
	binary.LittleEndian.PutUint32(irPayload[8:12], 4096)
	irPayload[12] = 1
	// NodeHeader: entries_off=16, total_sz=32, alloc_sz=32, flags=0 (LEAF NODE)
	binary.LittleEndian.PutUint32(irPayload[16:20], 16)
	binary.LittleEndian.PutUint32(irPayload[20:24], 32)
	binary.LittleEndian.PutUint32(irPayload[24:28], 32)
	irPayload[28] = 0
	// Entry: mft_ref=0, entry_len=16, val_len=0, flags=2 (INDEX_ENTRY_END)
	binary.LittleEndian.PutUint64(irPayload[32:40], 0)
	binary.LittleEndian.PutUint16(irPayload[40:42], 16)
	binary.LittleEndian.PutUint16(irPayload[42:44], 0)
	binary.LittleEndian.PutUint32(irPayload[44:48], 2)

	newRec, cur, attrID = appendResidentAttr(newRec, cur, attrID, AttrTypeIndexRoot, "$O", irPayload)

	// Attr 0xA0: IndexAllocation "$O"
	runs := []Run{{LCN: layout.ObjIdLcn, Length: layout.ObjIdClusters}}
	allocSz := layout.ObjIdClusters * uint64(layout.Config.ClusterSize)
	newRec, cur, attrID = appendNonResidentAttr(newRec, cur, attrID, AttrTypeIndexAllocation, "$O", runs, allocSz, allocSz)

	// Attr 0xB0: Bitmap "$O" (all zeros indicating 0 blocks currently active)
	if layout.ObjIdBitmapClusters > 0 {
		// Non-resident bitmap for large index allocations (e.g. >= 128 MB)
		bmRuns := []Run{{LCN: layout.ObjIdBitmapLcn, Length: layout.ObjIdBitmapClusters}}
		bmAllocSz := layout.ObjIdBitmapClusters * uint64(layout.Config.ClusterSize)
		newRec, cur, attrID = appendNonResidentAttr(newRec, cur, attrID, AttrTypeBitmap, "$O", bmRuns, bmAllocSz, layout.ObjIdBitmapBytes)
	} else {
		// Resident bitmap for small index allocations
		bmBytes := layout.ObjIdBitmapBytes
		if bmBytes < 8 {
			bmBytes = 8
		}
		bmPayload := make([]byte, bmBytes)
		newRec, cur, attrID = appendResidentAttr(newRec, cur, attrID, AttrTypeBitmap, "$O", bmPayload)
	}

	// End marker
	binary.LittleEndian.PutUint32(newRec[cur:cur+4], AttrTypeEnd)
	binary.LittleEndian.PutUint32(newRec[cur+4:cur+8], 0)
	cur += 8

	binary.LittleEndian.PutUint32(newRec[24:28], uint32(cur))
	binary.LittleEndian.PutUint32(newRec[28:32], MftRecordSize)
	binary.LittleEndian.PutUint16(newRec[40:42], attrID)

	seq := binary.LittleEndian.Uint16(d[usaOffset : usaOffset+2])
	if seq == 0 {
		seq = 1
	}
	if err := ApplyFixup(newRec, usaOffset, usaCount, seq); err != nil {
		return nil, err
	}
	return newRec, nil
}

// BuildVolumeRecord sets the user-specified Volume Label in Record 3 ($Volume) Attr 0x60.
func BuildVolumeRecord(baseRec []byte, label string) ([]byte, error) {
	d := make([]byte, MftRecordSize)
	copy(d, baseRec)

	if err := RemoveFixup(d); err != nil {
		return nil, err
	}

	usaOffset := binary.LittleEndian.Uint16(d[4:6])
	usaCount := binary.LittleEndian.Uint16(d[6:8])
	off := int(binary.LittleEndian.Uint16(d[20:22]))

	var stdInfo, fnInfo, volInfo, dataAttr []byte

	for off < len(d) {
		atype := binary.LittleEndian.Uint32(d[off : off+4])
		alen := binary.LittleEndian.Uint32(d[off+4 : off+8])
		if atype == AttrTypeEnd || alen == 0 || off+int(alen) > len(d) {
			break
		}
		switch atype {
		case AttrTypeStandardInformation:
			stdInfo = make([]byte, alen)
			copy(stdInfo, d[off:off+int(alen)])
		case AttrTypeFileName:
			fnInfo = make([]byte, alen)
			copy(fnInfo, d[off:off+int(alen)])
		case AttrTypeVolumeInformation:
			volInfo = make([]byte, alen)
			copy(volInfo, d[off:off+int(alen)])
			// Ensure NTFS Version is 3.1 and flags are clean (0x0000)
			valOff := int(binary.LittleEndian.Uint16(volInfo[20:22]))
			if valOff+12 <= len(volInfo) {
				volInfo[valOff+8] = 3                                               // Major version 3
				volInfo[valOff+9] = 1                                               // Minor version 1
				binary.LittleEndian.PutUint16(volInfo[valOff+10:valOff+12], 0x0000) // Flags = 0 (clean)
			}
		case AttrTypeData:
			dataAttr = make([]byte, alen)
			copy(dataAttr, d[off:off+int(alen)])
		}
		off += int(alen)
	}

	newRec := make([]byte, MftRecordSize)
	copy(newRec[:56], d[:56])
	cur := 56

	if stdInfo != nil {
		copy(newRec[cur:], stdInfo)
		cur += len(stdInfo)
	}
	if fnInfo != nil {
		copy(newRec[cur:], fnInfo)
		cur += len(fnInfo)
	}

	// Attr 0x60: Volume Name (AttrID = 4)
	u16 := utf16.Encode([]rune(label))
	labelBytes := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(labelBytes[i*2:i*2+2], v)
	}
	newRec, cur, _ = appendResidentAttr(newRec, cur, 4, AttrTypeVolumeName, "", labelBytes)

	// Attr 0x70: Volume Information (AttrID = 5)
	if volInfo != nil {
		binary.LittleEndian.PutUint16(volInfo[14:16], 5)
		copy(newRec[cur:], volInfo)
		cur += len(volInfo)
	}

	// Attr 0x80: Data (AttrID = 6)
	if dataAttr != nil {
		binary.LittleEndian.PutUint16(dataAttr[14:16], 6)
		copy(newRec[cur:], dataAttr)
		cur += len(dataAttr)
	}

	// End marker
	binary.LittleEndian.PutUint32(newRec[cur:cur+4], AttrTypeEnd)
	binary.LittleEndian.PutUint32(newRec[cur+4:cur+8], 0)
	cur += 8

	binary.LittleEndian.PutUint32(newRec[24:28], uint32(cur))
	binary.LittleEndian.PutUint32(newRec[28:32], MftRecordSize)
	binary.LittleEndian.PutUint16(newRec[40:42], 7) // Next Attr ID = 7

	seq := binary.LittleEndian.Uint16(d[usaOffset : usaOffset+2])
	if seq == 0 {
		seq = 3
	}
	if err := ApplyFixup(newRec, usaOffset, usaCount, seq); err != nil {
		return nil, err
	}
	return newRec, nil
}

func appendResidentAttr(rec []byte, cur int, attrID uint16, atype uint32, name string, content []byte) ([]byte, int, uint16) {
	u16 := utf16.Encode([]rune(name))
	nameLen := len(u16)
	nameOff := 0
	if nameLen > 0 {
		nameOff = 24
	}
	valOff := (24 + nameLen*2 + 7) &^ 7
	totalLen := (valOff + len(content) + 7) &^ 7

	if cur+totalLen+8 > len(rec) {
		return rec, cur, attrID
	}

	binary.LittleEndian.PutUint32(rec[cur:cur+4], atype)
	binary.LittleEndian.PutUint32(rec[cur+4:cur+8], uint32(totalLen))
	rec[cur+8] = 0
	rec[cur+9] = byte(nameLen)
	binary.LittleEndian.PutUint16(rec[cur+10:cur+12], uint16(nameOff))
	binary.LittleEndian.PutUint16(rec[cur+12:cur+14], 0)
	binary.LittleEndian.PutUint16(rec[cur+14:cur+16], attrID)
	binary.LittleEndian.PutUint32(rec[cur+16:cur+20], uint32(len(content)))
	binary.LittleEndian.PutUint16(rec[cur+20:cur+22], uint16(valOff))
	rec[cur+22] = 0

	if nameLen > 0 {
		for i, v := range u16 {
			binary.LittleEndian.PutUint16(rec[cur+nameOff+i*2:], v)
		}
	}
	copy(rec[cur+valOff:], content)
	return rec, cur + totalLen, attrID + 1
}

func appendNonResidentAttr(rec []byte, cur int, attrID uint16, atype uint32, name string, runs []Run, allocSz uint64, realSz uint64) ([]byte, int, uint16) {
	u16 := utf16.Encode([]rune(name))
	nameLen := len(u16)
	nameOff := 0
	if nameLen > 0 {
		nameOff = 64
	}
	rlOff := (64 + nameLen*2 + 7) &^ 7
	rl := EncodeRunlist(runs)
	totalLen := (rlOff + len(rl) + 7) &^ 7

	if cur+totalLen+8 > len(rec) {
		return rec, cur, attrID
	}

	var totalClusters uint64 = 0
	for _, r := range runs {
		totalClusters += r.Length
	}

	binary.LittleEndian.PutUint32(rec[cur:cur+4], atype)
	binary.LittleEndian.PutUint32(rec[cur+4:cur+8], uint32(totalLen))
	rec[cur+8] = 1
	rec[cur+9] = byte(nameLen)
	binary.LittleEndian.PutUint16(rec[cur+10:cur+12], uint16(nameOff))
	binary.LittleEndian.PutUint16(rec[cur+12:cur+14], 0)
	binary.LittleEndian.PutUint16(rec[cur+14:cur+16], attrID)
	binary.LittleEndian.PutUint64(rec[cur+16:cur+24], 0)
	binary.LittleEndian.PutUint64(rec[cur+24:cur+32], totalClusters-1)
	binary.LittleEndian.PutUint16(rec[cur+32:cur+34], uint16(rlOff))
	binary.LittleEndian.PutUint16(rec[cur+34:cur+36], 0)
	binary.LittleEndian.PutUint32(rec[cur+36:cur+40], 0)
	binary.LittleEndian.PutUint64(rec[cur+40:cur+48], allocSz)
	binary.LittleEndian.PutUint64(rec[cur+48:cur+56], realSz)
	binary.LittleEndian.PutUint64(rec[cur+56:cur+64], realSz)

	if nameLen > 0 {
		for i, v := range u16 {
			binary.LittleEndian.PutUint16(rec[cur+nameOff+i*2:], v)
		}
	}
	copy(rec[cur+rlOff:], rl)
	return rec, cur + totalLen, attrID + 1
}

// extractFileNamePayload returns the resident $FILE_NAME (0x30) attribute value and sequence number from a raw MFT record.
func extractFileNamePayload(rec []byte) ([]byte, uint16, error) {
	d := make([]byte, len(rec))
	copy(d, rec)
	if err := RemoveFixup(d); err != nil {
		return nil, 0, err
	}
	seq := binary.LittleEndian.Uint16(d[16:18])
	off := int(binary.LittleEndian.Uint16(d[20:22]))
	for off+8 <= len(d) {
		atype := binary.LittleEndian.Uint32(d[off : off+4])
		alen := binary.LittleEndian.Uint32(d[off+4 : off+8])
		if atype == AttrTypeEnd || alen == 0 || off+int(alen) > len(d) {
			break
		}
		if atype == AttrTypeFileName && d[off+8] == 0 {
			valLen := int(binary.LittleEndian.Uint32(d[off+16 : off+20]))
			valOff := int(binary.LittleEndian.Uint16(d[off+20 : off+22]))
			if off+valOff+valLen <= len(d) {
				payload := make([]byte, valLen)
				copy(payload, d[off+valOff:off+valOff+valLen])
				return payload, seq, nil
			}
		}
		off += int(alen)
	}
	return nil, 0, fmt.Errorf("$FILE_NAME attribute not found in record")
}

// BuildExtendRecord updates Record 11 ($Extend) so its $I30 IndexRoot contains entries for
// $Deleted (29), $ObjId (25), $Quota (24), and $Reparse (26) in sorted order.
func BuildExtendRecord(baseRec []byte, childRecords map[uint64][]byte) ([]byte, error) {
	d := make([]byte, MftRecordSize)
	copy(d, baseRec)
	if err := RemoveFixup(d); err != nil {
		return nil, err
	}

	usaOffset := binary.LittleEndian.Uint16(d[4:6])
	usaCount := binary.LittleEndian.Uint16(d[6:8])
	off := int(binary.LittleEndian.Uint16(d[20:22]))

	var stdInfo, fnInfo []byte
	for off+8 <= len(d) {
		atype := binary.LittleEndian.Uint32(d[off : off+4])
		alen := binary.LittleEndian.Uint32(d[off+4 : off+8])
		if atype == AttrTypeEnd || alen == 0 || off+int(alen) > len(d) {
			break
		}
		if atype == AttrTypeStandardInformation {
			stdInfo = make([]byte, alen)
			copy(stdInfo, d[off:off+int(alen)])
		} else if atype == AttrTypeFileName {
			fnInfo = make([]byte, alen)
			copy(fnInfo, d[off:off+int(alen)])
		}
		off += int(alen)
	}

	if stdInfo == nil || fnInfo == nil {
		return nil, fmt.Errorf("Attr 0x10 or 0x30 missing in Record 11 ($Extend)")
	}

	// Build $I30 IndexRoot entries in exact NTFS $UpCase alphabetical order:
	// $Deleted (29), $ObjId (25), $Quota (24), $Reparse (26)
	orderedRecNums := []uint64{RecordDeleted, RecordObjId, RecordQuota, RecordReparse}
	var entriesBuf []byte
	for _, rnum := range orderedRecNums {
		crec, ok := childRecords[rnum]
		if !ok || len(crec) == 0 {
			continue
		}
		fnPayload, cseq, err := extractFileNamePayload(crec)
		if err != nil {
			return nil, fmt.Errorf("extracting $FILE_NAME for record %d: %w", rnum, err)
		}
		valLen := len(fnPayload)
		entryLen := (16 + valLen + 7) &^ 7
		entry := make([]byte, entryLen)
		mftRef := (rnum & 0xFFFFFFFFFFFF) | (uint64(cseq) << 48)
		binary.LittleEndian.PutUint64(entry[0:8], mftRef)
		binary.LittleEndian.PutUint16(entry[8:10], uint16(entryLen))
		binary.LittleEndian.PutUint16(entry[10:12], uint16(valLen))
		binary.LittleEndian.PutUint32(entry[12:16], 0) // flags = 0 (leaf entry)
		copy(entry[16:], fnPayload)
		entriesBuf = append(entriesBuf, entry...)
	}

	// End entry (16 bytes, flags = 2 INDEX_ENTRY_END)
	endEntry := make([]byte, 16)
	binary.LittleEndian.PutUint16(endEntry[8:10], 16)
	binary.LittleEndian.PutUint32(endEntry[12:16], 2)
	entriesBuf = append(entriesBuf, endEntry...)

	// IndexRoot Header (16 bytes) + NodeHeader (16 bytes) + entriesBuf
	nodeTotalSz := 16 + len(entriesBuf)
	irPayload := make([]byte, 16+nodeTotalSz)
	binary.LittleEndian.PutUint32(irPayload[0:4], AttrTypeFileName)  // 0x30
	binary.LittleEndian.PutUint32(irPayload[4:8], CollationFileName) // 1
	binary.LittleEndian.PutUint32(irPayload[8:12], IndexBlockSize)   // 4096
	irPayload[12] = 1                                                // clusters per index block
	// NodeHeader
	binary.LittleEndian.PutUint32(irPayload[16:20], 16)                  // entries offset
	binary.LittleEndian.PutUint32(irPayload[20:24], uint32(nodeTotalSz)) // total size
	binary.LittleEndian.PutUint32(irPayload[24:28], uint32(nodeTotalSz)) // alloc size
	irPayload[28] = 0                                                    // leaf node
	copy(irPayload[32:], entriesBuf)

	newRec := make([]byte, MftRecordSize)
	copy(newRec[:56], d[:56])
	cur := 56

	copy(newRec[cur:], stdInfo)
	cur += len(stdInfo)

	copy(newRec[cur:], fnInfo)
	cur += len(fnInfo)

	// Attr 0x90: IndexRoot "$I30" (attrID = 4)
	newRec, cur, _ = appendResidentAttr(newRec, cur, 4, AttrTypeIndexRoot, "$I30", irPayload)

	// End marker
	binary.LittleEndian.PutUint32(newRec[cur:cur+4], AttrTypeEnd)
	binary.LittleEndian.PutUint32(newRec[cur+4:cur+8], 0)
	cur += 8

	binary.LittleEndian.PutUint32(newRec[24:28], uint32(cur))
	binary.LittleEndian.PutUint32(newRec[28:32], MftRecordSize)
	binary.LittleEndian.PutUint16(newRec[40:42], 5) // nextAttrId = 5

	seq := binary.LittleEndian.Uint16(d[usaOffset : usaOffset+2])
	if seq == 0 {
		seq = 11
	}
	if err := ApplyFixup(newRec, usaOffset, usaCount, seq); err != nil {
		return nil, err
	}
	return newRec, nil
}

// GenerateSystemRecords prepares all 64 initial MFT records with updated runlists.
func GenerateSystemRecords(layout *VolumeLayout) ([][]byte, error) {
	records := make([][]byte, 64)
	clustBytes := uint64(layout.Config.ClusterSize)

	// Load records 0..15, 24..26, and 29 ($Deleted) from embedded templates; remaining records are all-zero free records
	for i := 0; i < 64; i++ {
		if (i <= 15) || (i >= 24 && i <= 26) || i == RecordDeleted {
			path := fmt.Sprintf("assets/system_records/rec_%02d.bin", i)
			data, err := SystemRecordsFS.ReadFile(path)
			if err == nil && len(data) == MftRecordSize && string(data[:4]) == "FILE" {
				recCopy := make([]byte, MftRecordSize)
				copy(recCopy, data)
				records[i] = recCopy
				continue
			}
		}
		records[i] = make([]byte, MftRecordSize)
	}

	// Record 0: $MFT (Pre-sized to layout.MftClusters)
	mftAllocSize := layout.MftClusters * clustBytes
	mftRealSize := mftAllocSize
	rec0, err := PatchNonResidentAttr(records[0], AttrTypeData, "", []Run{{LCN: layout.MftLcn, Length: layout.MftClusters}}, mftAllocSize, mftRealSize)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 0 $MFT DATA: %w", err)
	}
	mftBmAllocSize := layout.MftBitmapClusters * clustBytes
	mftBmRealSize := layout.MftBitmapBytes
	rec0, err = PatchNonResidentAttr(rec0, AttrTypeBitmap, "", []Run{{LCN: layout.MftBitmapLcn, Length: layout.MftBitmapClusters}}, mftBmAllocSize, mftBmRealSize)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 0 $MFT BITMAP: %w", err)
	}
	records[RecordMFT] = rec0

	// Record 1: $MFTMirr (Mirror copy of records 0..3)
	rec1, err := PatchNonResidentAttr(records[1], AttrTypeData, "", []Run{{LCN: layout.MftMirrLcn, Length: 1}}, clustBytes, 4096)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 1 $MFTMirr: %w", err)
	}
	records[RecordMFTMirr] = rec1

	// Record 2: $LogFile
	logFileSize := layout.LogFileClusters * clustBytes
	rec2, err := PatchNonResidentAttr(records[2], AttrTypeData, "", []Run{{LCN: layout.LogFileLcn, Length: layout.LogFileClusters}}, logFileSize, logFileSize)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 2 $LogFile: %w", err)
	}
	records[RecordLogFile] = rec2

	// Record 3: $Volume (Set user-specified Volume Label & clear dirty flags)
	volLabel := layout.Config.VolumeLabel
	if volLabel == "" {
		volLabel = "New Volume"
	}
	rec3, err := BuildVolumeRecord(records[RecordVolume], volLabel)
	if err != nil {
		return nil, fmt.Errorf("error building Record 3 $Volume: %w", err)
	}
	records[RecordVolume] = rec3

	// Record 4: $AttrDef
	rec4, err := PatchNonResidentAttr(records[4], AttrTypeData, "", []Run{{LCN: layout.AttrDefLcn, Length: 1}}, clustBytes, 2560)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 4 $AttrDef: %w", err)
	}
	records[RecordAttrDef] = rec4

	// Record 5: $Root (Using user's modified sample with Everyone Full Access!)
	rec5, err := PatchNonResidentAttr(RootMftBin, AttrTypeIndexAllocation, "$I30", []Run{{LCN: layout.RootIndexLcn, Length: 1}}, clustBytes, 4096)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 5 $Root: %w", err)
	}
	records[RecordRoot] = rec5

	// Record 6: $Bitmap (Volume cluster allocation table)
	rec6, err := PatchNonResidentAttr(records[6], AttrTypeData, "", []Run{{LCN: layout.BitmapLcn, Length: layout.BitmapClusters}}, layout.BitmapClusters*clustBytes, layout.BitmapBytes)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 6 $Bitmap: %w", err)
	}
	records[RecordBitmap] = rec6

	// Record 7: $Boot
	rec7, err := PatchNonResidentAttr(records[7], AttrTypeData, "", []Run{{LCN: 0, Length: layout.BootClusters}}, layout.BootClusters*clustBytes, 8192)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 7 $Boot: %w", err)
	}
	records[RecordBoot] = rec7

	// Record 9: $Secure (Using user's modified sample with SDS/SDH/SII!)
	sdsRealSize := uint64(264472)
	rec9, err := PatchNonResidentAttr(SecureMftBin, AttrTypeData, "$SDS", []Run{{LCN: layout.SdsLcn, Length: layout.SdsClusters}}, layout.SdsClusters*clustBytes, sdsRealSize)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 9 $Secure SDS: %w", err)
	}
	rec9, err = PatchNonResidentAttr(rec9, AttrTypeIndexAllocation, "$SDH", []Run{{LCN: layout.SdhLcn, Length: 1}}, clustBytes, 4096)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 9 $Secure SDH: %w", err)
	}
	rec9, err = PatchNonResidentAttr(rec9, AttrTypeIndexAllocation, "$SII", []Run{{LCN: layout.SiiLcn, Length: 1}}, clustBytes, 4096)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 9 $Secure SII: %w", err)
	}
	records[RecordSecure] = rec9

	// Record 10: $UpCase
	rec10, err := PatchNonResidentAttr(records[10], AttrTypeData, "", []Run{{LCN: layout.UpCaseLcn, Length: layout.UpCaseClusters}}, layout.UpCaseClusters*clustBytes, 131072)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 10 $UpCase: %w", err)
	}
	records[RecordUpCase] = rec10

	// Record 25: $ObjId (Pre-sized with $O:INDEX_ALLOCATION)
	rec25, err := BuildObjIdRecord(records[RecordObjId], layout)
	if err != nil {
		return nil, fmt.Errorf("error building Record 25 $ObjId: %w", err)
	}
	records[RecordObjId] = rec25

	// Record 29: $Deleted ($Extend\$Deleted with 64 KB $I30:INDEX_ALLOCATION right after $Bitmap, realSize=0, initSize=0)
	rec29, err := PatchNonResidentAttr(records[RecordDeleted], AttrTypeIndexAllocation, "$I30", []Run{{LCN: layout.DeletedLcn, Length: layout.DeletedClusters}}, layout.DeletedClusters*clustBytes, 0)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 29 $Deleted: %w", err)
	}
	records[RecordDeleted] = rec29

	// Record 11: $Extend (Update $I30 IndexRoot to include $Deleted, $ObjId, $Quota, $Reparse)
	rec11, err := BuildExtendRecord(records[RecordExtend], map[uint64][]byte{
		RecordDeleted: records[RecordDeleted],
		RecordObjId:   records[RecordObjId],
		RecordQuota:   records[RecordQuota],
		RecordReparse: records[RecordReparse],
	})
	if err != nil {
		return nil, fmt.Errorf("error building Record 11 $Extend: %w", err)
	}
	records[RecordExtend] = rec11

	return records, nil
}
