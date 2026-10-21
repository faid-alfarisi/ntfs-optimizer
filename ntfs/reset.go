package ntfs

import (
	"encoding/binary"
	"fmt"
	"strings"
	"syscall"
	"unicode/utf16"
)

// RecordMeta stores file identity and attributes extracted during MFT scanning.
type RecordMeta struct {
	RecNum       uint64
	Seq          uint16
	IsDir        bool
	ParentRec    uint64
	Name         string
	HasImageLoad bool
	SecId        uint32
	HasSecId     bool
	HasObjId     bool
}

// ResetSecureResult reports statistics from resetting $Secure.
type ResetSecureResult struct {
	TotalRecordsScanned uint64
	RecordsUpdated      uint64
	UserSID             string
	SdsLcn              uint64
	SdsClusters         uint64
	SdhLcn              uint64
	SiiLcn              uint64
}

// ResetObjIdResult reports statistics from resetting $ObjId.
type ResetObjIdResult struct {
	TotalRecordsScanned uint64
	ObjIdsRemoved       uint64
	ObjIdClusters       uint64
	ObjIdBytesPreserved uint64
}

// ResetCombinedResult reports statistics from resetting both $Secure and $ObjId.
type ResetCombinedResult struct {
	SecureResult ResetSecureResult
	ObjIdResult  ResetObjIdResult
}

// PatchResidentAttr replaces the value payload of an existing resident attribute in an MFT record.
func PatchResidentAttr(rec []byte, targetType uint32, targetName string, newPayload []byte) ([]byte, error) {
	d := make([]byte, len(rec))
	copy(d, rec)
	_ = RemoveFixup(d)

	usaOffset := binary.LittleEndian.Uint16(d[4:6])
	usaCount := binary.LittleEndian.Uint16(d[6:8])
	seq := binary.LittleEndian.Uint16(d[16:18])
	if seq == 0 {
		seq = 1
	}

	off := int(binary.LittleEndian.Uint16(d[20:22]))
	bytesUsed := int(binary.LittleEndian.Uint32(d[24:28]))
	found := false

	for off+8 <= len(d) {
		atype := binary.LittleEndian.Uint32(d[off : off+4])
		alen := int(binary.LittleEndian.Uint32(d[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 || off+alen > len(d) {
			break
		}
		if atype == targetType && d[off+8] == 0 { // Resident
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

			if targetName == "" || strings.EqualFold(name, targetName) {
				valOff := int(binary.LittleEndian.Uint16(d[off+20 : off+22]))
				newAttrLen := (valOff + len(newPayload) + 7) &^ 7
				diff := newAttrLen - alen

				if bytesUsed+diff > len(d) {
					return nil, fmt.Errorf("patched resident attribute exceeds MFT record size")
				}

				// Shift tail of record
				tailStart := off + alen
				copy(d[off+newAttrLen:], d[tailStart:bytesUsed])
				if diff < 0 {
					for i := bytesUsed + diff; i < bytesUsed; i++ {
						d[i] = 0
					}
				}

				// Update attribute header
				binary.LittleEndian.PutUint32(d[off+4:off+8], uint32(newAttrLen))
				binary.LittleEndian.PutUint32(d[off+16:off+20], uint32(len(newPayload)))
				copy(d[off+valOff:off+valOff+len(newPayload)], newPayload)

				// Zero padding between payload end and newAttrLen
				for i := off + valOff + len(newPayload); i < off+newAttrLen; i++ {
					d[i] = 0
				}

				bytesUsed += diff
				binary.LittleEndian.PutUint32(d[24:28], uint32(bytesUsed))
				found = true
				break
			}
		}
		off += alen
	}

	if !found {
		return nil, fmt.Errorf("resident attribute type 0x%X '%s' not found", targetType, targetName)
	}

	if err := ApplyFixup(d, usaOffset, usaCount, seq); err != nil {
		return nil, err
	}
	return d, nil
}

// RemoveAttr removes a matching attribute from an MFT record and updates bytesUsed and fixups.
func RemoveAttr(rec []byte, targetType uint32, targetName string) bool {
	_ = RemoveFixup(rec)

	usaOffset := binary.LittleEndian.Uint16(rec[4:6])
	usaCount := binary.LittleEndian.Uint16(rec[6:8])
	seq := binary.LittleEndian.Uint16(rec[16:18])
	if seq == 0 {
		seq = 1
	}

	off := int(binary.LittleEndian.Uint16(rec[20:22]))
	bytesUsed := int(binary.LittleEndian.Uint32(rec[24:28]))
	removedAny := false

	for off+8 <= len(rec) {
		atype := binary.LittleEndian.Uint32(rec[off : off+4])
		alen := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec) {
			break
		}

		match := false
		if atype == targetType {
			if targetName == "" {
				match = true
			} else {
				nameLen := int(rec[off+9])
				nameOff := int(binary.LittleEndian.Uint16(rec[off+10 : off+12]))
				if nameLen > 0 && off+nameOff+nameLen*2 <= len(rec) {
					u16 := make([]uint16, nameLen)
					for i := 0; i < nameLen; i++ {
						u16[i] = binary.LittleEndian.Uint16(rec[off+nameOff+i*2 : off+nameOff+i*2+2])
					}
					if strings.EqualFold(string(utf16.Decode(u16)), targetName) {
						match = true
					}
				}
			}
		}

		if match {
			copy(rec[off:], rec[off+alen:bytesUsed])
			for i := bytesUsed - alen; i < bytesUsed; i++ {
				rec[i] = 0
			}
			bytesUsed -= alen
			binary.LittleEndian.PutUint32(rec[24:28], uint32(bytesUsed))
			removedAny = true
			continue
		}
		off += alen
	}

	_ = ApplyFixup(rec, usaOffset, usaCount, seq)
	return removedAny
}

// GetRecordSecurityID retrieves the Security ID from an MFT record's $STANDARD_INFORMATION attribute.
func GetRecordSecurityID(rec []byte) (uint32, bool) {
	d := make([]byte, len(rec))
	copy(d, rec)
	_ = RemoveFixup(d)

	off := int(binary.LittleEndian.Uint16(d[20:22]))
	for off+8 <= len(d) {
		atype := binary.LittleEndian.Uint32(d[off : off+4])
		alen := int(binary.LittleEndian.Uint32(d[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 || off+alen > len(d) {
			break
		}
		if atype == AttrTypeStandardInformation && d[off+8] == 0 {
			valLen := int(binary.LittleEndian.Uint32(d[off+16 : off+20]))
			valOff := int(binary.LittleEndian.Uint16(d[off+20 : off+22]))
			payload := off + valOff
			if valLen >= 56 && payload+56 <= len(d) {
				secId := binary.LittleEndian.Uint32(d[payload+52 : payload+56])
				return secId, true
			}
		}
		off += alen
	}
	return 0, false
}

// SetRecordSecurityID updates the Security ID inside $STANDARD_INFORMATION attribute in-place.
func SetRecordSecurityID(rec []byte, newSecId uint32) bool {
	_ = RemoveFixup(rec)

	usaOffset := binary.LittleEndian.Uint16(rec[4:6])
	usaCount := binary.LittleEndian.Uint16(rec[6:8])
	seq := binary.LittleEndian.Uint16(rec[16:18])
	if seq == 0 {
		seq = 1
	}

	off := int(binary.LittleEndian.Uint16(rec[20:22]))
	updated := false
	for off+8 <= len(rec) {
		atype := binary.LittleEndian.Uint32(rec[off : off+4])
		alen := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec) {
			break
		}
		if atype == AttrTypeStandardInformation && rec[off+8] == 0 {
			valLen := int(binary.LittleEndian.Uint32(rec[off+16 : off+20]))
			valOff := int(binary.LittleEndian.Uint16(rec[off+20 : off+22]))
			payload := off + valOff
			if valLen >= 56 && payload+56 <= len(rec) {
				binary.LittleEndian.PutUint32(rec[payload+52:payload+56], newSecId)
				updated = true
				break
			}
		}
		off += alen
	}

	if updated {
		_ = ApplyFixup(rec, usaOffset, usaCount, seq)
	}
	return updated
}

// parseRecordMeta extracts metadata attributes from a raw MFT record.
func parseRecordMeta(rec []byte, recNum uint64) *RecordMeta {
	if rec == nil || len(rec) < 48 || string(rec[:4]) != "FILE" {
		return nil
	}
	flags := binary.LittleEndian.Uint16(rec[22:24])
	if (flags & 1) == 0 { // Unallocated record
		return nil
	}
	meta := &RecordMeta{
		RecNum: recNum,
		Seq:    binary.LittleEndian.Uint16(rec[16:18]),
		IsDir:  (flags & 2) != 0,
	}

	off := int(binary.LittleEndian.Uint16(rec[20:22]))
	bestNs := -1

	for off+8 <= len(rec) {
		atype := binary.LittleEndian.Uint32(rec[off : off+4])
		alen := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec) {
			break
		}

		nameLen := int(rec[off+9])
		nameOff := int(binary.LittleEndian.Uint16(rec[off+10 : off+12]))
		var attrName string
		if nameLen > 0 && off+nameOff+nameLen*2 <= len(rec) {
			u16 := make([]uint16, nameLen)
			for i := 0; i < nameLen; i++ {
				u16[i] = binary.LittleEndian.Uint16(rec[off+nameOff+i*2 : off+nameOff+i*2+2])
			}
			attrName = string(utf16.Decode(u16))
		}

		if strings.Contains(strings.ToUpper(attrName), "IMAGELOAD") {
			meta.HasImageLoad = true
		}

		if atype == AttrTypeObjectID {
			meta.HasObjId = true
		}

		if atype == AttrTypeStandardInformation && rec[off+8] == 0 {
			valLen := int(binary.LittleEndian.Uint32(rec[off+16 : off+20]))
			valOff := int(binary.LittleEndian.Uint16(rec[off+20 : off+22]))
			payload := off + valOff
			if valLen >= 56 && payload+56 <= len(rec) {
				meta.SecId = binary.LittleEndian.Uint32(rec[payload+52 : payload+56])
				meta.HasSecId = true
			}
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
						meta.Name = fnStr
						meta.ParentRec = pNum
						bestNs = ns
					}
				}
			}
		}
		off += alen
	}
	return meta
}

// buildPath resolves the full path from root (Record 5) using the metadata map.
func buildPath(recNum uint64, metaMap map[uint64]*RecordMeta) string {
	if recNum == RecordRoot {
		return ""
	}
	meta, ok := metaMap[recNum]
	if !ok || meta.Name == "" {
		return ""
	}

	visited := make(map[uint64]bool)
	var parts []string
	cur := meta
	for cur != nil {
		if cur.RecNum == RecordRoot || cur.RecNum == cur.ParentRec || visited[cur.RecNum] {
			break
		}
		visited[cur.RecNum] = true
		parts = append([]string{cur.Name}, parts...)
		if cur.ParentRec == RecordRoot {
			break
		}
		cur = metaMap[cur.ParentRec]
	}
	return strings.Join(parts, "\\")
}

// DetermineSecurityID maps a record to its target Security ID based on "security id list.txt".
func DetermineSecurityID(recNum uint64, isDir bool, hasImageLoad bool, path string, name string) uint32 {
	normPath := strings.ToLower(strings.ReplaceAll(path, "/", "\\"))
	normName := strings.ToLower(name)

	// $Secure (Record 9) -> 257
	if recNum == RecordSecure || normName == "$secure" {
		return 257
	}

	// Under $Extend or $Extends
	if strings.HasPrefix(normPath, "$extend\\") || strings.HasPrefix(normPath, "$extends\\") ||
		normName == "$extend" || normName == "$extends" || recNum == RecordExtend {

		if normName == "$extend" || normName == "$extends" || recNum == RecordExtend {
			return 257
		}

		// Check subpaths under $Extend
		if strings.Contains(normPath, "$rmmetadata") {
			if normName == "$repair" || strings.HasSuffix(normPath, "\\$repair") {
				return 257
			}
			if strings.Contains(normPath, "$txflog") {
				if normName == "$tops" || strings.HasSuffix(normPath, "\\$tops") {
					return 258
				}
				if normName == "$txflog.blf" || strings.HasSuffix(normPath, "\\$txflog.blf") {
					return 259
				}
				if strings.Contains(normName, "txflogcontainer") {
					return 260
				}
				return 258
			}
			return 258
		}
		return 257
	}

	// Root system files ($*)
	if recNum < 16 || (strings.HasPrefix(name, "$") && !strings.HasPrefix(normPath, "$recycle.bin") && normName != "$recycle.bin") {
		return 256
	}

	// $RECYCLE.BIN
	if normName == "$recycle.bin" || strings.HasPrefix(normPath, "$recycle.bin") {
		if normPath == "$recycle.bin" || normName == "$recycle.bin" {
			return 264
		}
		if normName == "desktop.ini" {
			return 266
		}
		return 265
	}

	// System Volume Information
	if normName == "system volume information" || strings.HasPrefix(normPath, "system volume information") {
		if normPath == "system volume information" || normName == "system volume information" {
			return 261
		}
		if normName == "tracking.log" {
			return 263
		}
		return 262
	}

	// Auslogics Temp File
	if strings.Contains(normName, "auslogics") || strings.Contains(normPath, "auslogics") {
		return 270
	}

	// Alternate stream IMAGELOAD:1
	if hasImageLoad {
		return 269
	}

	// Standard User Files and Folders
	if isDir {
		return 267 // Standard Folder
	}
	return 268 // Standard File
}

// readRecordFromMft reads an MFT record by its index using the volume's MFT runs.
func readRecordFromMft(h syscall.Handle, analysis *VolumeAnalysis, recIdx uint64) ([]byte, error) {
	clusterSize := uint64(analysis.ClusterSize)
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
	return raw, err
}

// writeRecordToMft writes an MFT record to disk by its index using the volume's MFT runs.
func writeRecordToMft(h syscall.Handle, analysis *VolumeAnalysis, recIdx uint64, rec []byte) error {
	clusterSize := uint64(analysis.ClusterSize)
	recordOffsetBytes := recIdx * uint64(MftRecordSize)
	targetClusterInMft := recordOffsetBytes / clusterSize
	offsetInCluster := recordOffsetBytes % clusterSize

	var curVcn uint64
	for _, run := range analysis.ExistingMftRuns {
		if targetClusterInMft >= curVcn && targetClusterInMft < curVcn+run.Length {
			lcn := run.LCN + (targetClusterInMft - curVcn)
			return SeekAndWrite(h, lcn*clusterSize+offsetInCluster, rec)
		}
		curVcn += run.Length
	}
	return SeekAndWrite(h, analysis.MftLcn*clusterSize+recordOffsetBytes, rec)
}

// ResetSecure recreates $Secure ($SDS, $SDH, $SII) and updates any non-existent Security IDs.
func ResetSecure(h syscall.Handle, analysis *VolumeAnalysis, progress ProgressFunc) (*ResetSecureResult, error) {
	clusterSize := uint64(analysis.ClusterSize)

	report := func(phase string, lcn uint64) {
		if progress != nil {
			progress(phase, lcn, analysis.TotalClusters)
		}
	}

	report("Reading Record 9 ($Secure)...", analysis.MftLcn)
	rawRec9, err := readRecordFromMft(h, analysis, RecordSecure)
	if err != nil {
		return nil, fmt.Errorf("failed reading Record 9: %w", err)
	}

	rec9 := make([]byte, MftRecordSize)
	copy(rec9, rawRec9)
	_ = RemoveFixup(rec9)

	// Extract existing cluster runs for $SDS, $SDH, $SII
	var sdsRuns, sdhRuns, siiRuns []Run
	var sdsAlloc, sdhAlloc, siiAlloc uint64

	off := int(binary.LittleEndian.Uint16(rec9[20:22]))
	for off+8 <= len(rec9) {
		atype := binary.LittleEndian.Uint32(rec9[off : off+4])
		alen := int(binary.LittleEndian.Uint32(rec9[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec9) {
			break
		}
		nameLen := int(rec9[off+9])
		nameOff := int(binary.LittleEndian.Uint16(rec9[off+10 : off+12]))
		var name string
		if nameLen > 0 && off+nameOff+nameLen*2 <= len(rec9) {
			u16 := make([]uint16, nameLen)
			for i := 0; i < nameLen; i++ {
				u16[i] = binary.LittleEndian.Uint16(rec9[off+nameOff+i*2 : off+nameOff+i*2+2])
			}
			name = string(utf16.Decode(u16))
		}

		if rec9[off+8] != 0 { // Non-resident
			ro := int(binary.LittleEndian.Uint16(rec9[off+32 : off+34]))
			runs := ParseRunlist(rec9[off+ro : off+alen])
			allocSz := binary.LittleEndian.Uint64(rec9[off+40 : off+48])
			if atype == AttrTypeData && name == "$SDS" {
				sdsRuns = runs
				sdsAlloc = allocSz
			} else if atype == AttrTypeIndexAllocation && name == "$SDH" {
				sdhRuns = runs
				sdhAlloc = allocSz
			} else if atype == AttrTypeIndexAllocation && name == "$SII" {
				siiRuns = runs
				siiAlloc = allocSz
			}
		}
		off += alen
	}

	if len(sdsRuns) == 0 || len(sdhRuns) == 0 || len(siiRuns) == 0 {
		return nil, fmt.Errorf("Record 9 missing $SDS, $SDH, or $SII stream allocations")
	}

	activeSid := GetCurrentUserSID()
	report("Generating clean $Secure streams ($SDS, $SDH, $SII)...", sdsRuns[0].LCN)
	sdsStream, sdhStream, siiStream := BuildSecureStreams(activeSid)

	// Write $SDS stream
	report("Writing $Secure:$SDS stream...", sdsRuns[0].LCN)
	var sdsOffset uint64 = 0
	for _, run := range sdsRuns {
		chunkLen := run.Length * clusterSize
		dataToWrite := make([]byte, chunkLen)
		if sdsOffset < uint64(len(sdsStream)) {
			avail := uint64(len(sdsStream)) - sdsOffset
			if avail > chunkLen {
				avail = chunkLen
			}
			copy(dataToWrite, sdsStream[sdsOffset:sdsOffset+avail])
		}
		if err := SeekAndWrite(h, run.LCN*clusterSize, dataToWrite); err != nil {
			return nil, fmt.Errorf("failed writing $SDS at LCN %d: %w", run.LCN, err)
		}
		sdsOffset += chunkLen
	}

	// Write $SDH stream
	report("Writing $Secure:$SDH index allocation...", sdhRuns[0].LCN)
	sdhBuf := make([]byte, sdhRuns[0].Length*clusterSize)
	copy(sdhBuf, sdhStream)
	if err := SeekAndWrite(h, sdhRuns[0].LCN*clusterSize, sdhBuf); err != nil {
		return nil, fmt.Errorf("failed writing $SDH at LCN %d: %w", sdhRuns[0].LCN, err)
	}

	// Write $SII stream
	report("Writing $Secure:$SII index allocation...", siiRuns[0].LCN)
	siiBuf := make([]byte, siiRuns[0].Length*clusterSize)
	copy(siiBuf, siiStream)
	if err := SeekAndWrite(h, siiRuns[0].LCN*clusterSize, siiBuf); err != nil {
		return nil, fmt.Errorf("failed writing $SII at LCN %d: %w", siiRuns[0].LCN, err)
	}

	// Rebuild clean Record 9 from template
	report("Updating MFT Record 9 ($Secure)...", analysis.MftLcn)
	sdsRealSize := uint64(264472)
	pRec9, err := PatchNonResidentAttr(SecureMftBin, AttrTypeData, "$SDS", sdsRuns, sdsAlloc, sdsRealSize)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 9 $SDS: %w", err)
	}
	pRec9, err = PatchNonResidentAttr(pRec9, AttrTypeIndexAllocation, "$SDH", sdhRuns, sdhAlloc, 4096)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 9 $SDH: %w", err)
	}
	pRec9, err = PatchNonResidentAttr(pRec9, AttrTypeIndexAllocation, "$SII", siiRuns, siiAlloc, 4096)
	if err != nil {
		return nil, fmt.Errorf("error patching Record 9 $SII: %w", err)
	}

	if err := writeRecordToMft(h, analysis, RecordSecure, pRec9); err != nil {
		return nil, fmt.Errorf("error writing Record 9: %w", err)
	}

	// Step 2: Scan all records and verify Security IDs
	report("Scanning MFT records and checking Security IDs...", analysis.MftLcn)
	recordCount := analysis.MaxAllocRecord + 1
	if recordCount < 64 {
		recordCount = 64
	}

	metaMap := make(map[uint64]*RecordMeta)
	rawRecords := make([][]byte, recordCount)

	for r := uint64(0); r < recordCount; r++ {
		raw, err := readRecordFromMft(h, analysis, r)
		if err != nil {
			continue
		}
		rawRecords[r] = raw
		meta := parseRecordMeta(raw, r)
		if meta != nil {
			metaMap[r] = meta
		}
	}

	// Valid Security IDs generated in the recreated $Secure
	validSecIDs := make(map[uint32]bool)
	for id := uint32(256); id <= 271; id++ {
		validSecIDs[id] = true
	}

	var updatedCount uint64 = 0
	report("Updating missing or non-existent Security IDs...", analysis.MftLcn)

	for r := uint64(0); r < recordCount; r++ {
		meta, ok := metaMap[r]
		if !ok {
			continue
		}

		// Check if Security ID exists in our recreated $Secure (256..271)
		if !meta.HasSecId || !validSecIDs[meta.SecId] {
			path := buildPath(r, metaMap)
			targetSecId := DetermineSecurityID(r, meta.IsDir, meta.HasImageLoad, path, meta.Name)

			recCopy := make([]byte, MftRecordSize)
			copy(recCopy, rawRecords[r])
			if SetRecordSecurityID(recCopy, targetSecId) {
				if err := writeRecordToMft(h, analysis, r, recCopy); err == nil {
					updatedCount++
				}
			}
		}
	}

	res := &ResetSecureResult{
		TotalRecordsScanned: recordCount,
		RecordsUpdated:      updatedCount,
		UserSID:             activeSid,
		SdsLcn:              sdsRuns[0].LCN,
		SdsClusters:         sdsAlloc / clusterSize,
		SdhLcn:              sdhRuns[0].LCN,
		SiiLcn:              siiRuns[0].LCN,
	}
	return res, nil
}

// ResetObjId removes all ObjectID attributes from records and clears the $ObjId:$O index without shrinking.
func ResetObjId(h syscall.Handle, analysis *VolumeAnalysis, progress ProgressFunc) (*ResetObjIdResult, error) {
	clusterSize := uint64(analysis.ClusterSize)

	report := func(phase string, lcn uint64) {
		if progress != nil {
			progress(phase, lcn, analysis.TotalClusters)
		}
	}

	report("Reading Record 25 ($Extend\\$ObjId)...", analysis.MftLcn)
	rawRec25, err := readRecordFromMft(h, analysis, RecordObjId)
	if err != nil {
		return nil, fmt.Errorf("failed reading Record 25: %w", err)
	}

	rec25 := make([]byte, MftRecordSize)
	copy(rec25, rawRec25)
	_ = RemoveFixup(rec25)

	var objRuns []Run
	var objAllocSz uint64
	var bmRuns []Run
	hasIndexAlloc := false

	off := int(binary.LittleEndian.Uint16(rec25[20:22]))
	for off+8 <= len(rec25) {
		atype := binary.LittleEndian.Uint32(rec25[off : off+4])
		alen := int(binary.LittleEndian.Uint32(rec25[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 || off+alen > len(rec25) {
			break
		}

		nameLen := int(rec25[off+9])
		nameOff := int(binary.LittleEndian.Uint16(rec25[off+10 : off+12]))
		var name string
		if nameLen > 0 && off+nameOff+nameLen*2 <= len(rec25) {
			u16 := make([]uint16, nameLen)
			for i := 0; i < nameLen; i++ {
				u16[i] = binary.LittleEndian.Uint16(rec25[off+nameOff+i*2 : off+nameOff+i*2+2])
			}
			name = string(utf16.Decode(u16))
		}

		if rec25[off+8] != 0 { // Non-resident
			ro := int(binary.LittleEndian.Uint16(rec25[off+32 : off+34]))
			runs := ParseRunlist(rec25[off+ro : off+alen])
			allocSz := binary.LittleEndian.Uint64(rec25[off+40 : off+48])
			if atype == AttrTypeIndexAllocation && name == "$O" {
				objRuns = runs
				objAllocSz = allocSz
				hasIndexAlloc = true
			} else if atype == AttrTypeBitmap && name == "$O" {
				bmRuns = runs
			}
		}
		off += alen
	}

	// 1. Zero out $ObjId:$O:INDEX_ALLOCATION clusters on disk (keeping exact pre-sized clusters!)
	if hasIndexAlloc && len(objRuns) > 0 {
		report("Clearing $ObjId:$O:INDEX_ALLOCATION blocks (preserving pre-sized allocation)...", objRuns[0].LCN)
		zeroChunk := make([]byte, 64*1024) // 64KB zero buffer
		for _, r := range objRuns {
			var written uint64 = 0
			totalBytes := r.Length * clusterSize
			for written < totalBytes {
				toWrite := totalBytes - written
				if toWrite > uint64(len(zeroChunk)) {
					toWrite = uint64(len(zeroChunk))
				}
				if err := SeekAndWrite(h, r.LCN*clusterSize+written, zeroChunk[:toWrite]); err != nil {
					return nil, fmt.Errorf("failed zeroing $ObjId clusters at LCN %d: %w", r.LCN, err)
				}
				written += toWrite
			}
		}
	}

	// 2. Zero out $ObjId:$O:BITMAP (resident or non-resident)
	if len(bmRuns) > 0 {
		report("Clearing $ObjId:$O:BITMAP clusters...", bmRuns[0].LCN)
		zeroBmChunk := make([]byte, 64*1024)
		for _, r := range bmRuns {
			var written uint64 = 0
			totalBytes := r.Length * clusterSize
			for written < totalBytes {
				toWrite := totalBytes - written
				if toWrite > uint64(len(zeroBmChunk)) {
					toWrite = uint64(len(zeroBmChunk))
				}
				if err := SeekAndWrite(h, r.LCN*clusterSize+written, zeroBmChunk[:toWrite]); err != nil {
					return nil, fmt.Errorf("failed zeroing $ObjId bitmap at LCN %d: %w", r.LCN, err)
				}
				written += toWrite
			}
		}
	}

	// 3. Reset $INDEX_ROOT "$O" to an empty leaf root
	report("Resetting Record 25 ($ObjId) $INDEX_ROOT '$O' to empty leaf...", analysis.MftLcn)
	emptyIrPayload := make([]byte, 48)
	binary.LittleEndian.PutUint32(emptyIrPayload[0:4], 0)
	binary.LittleEndian.PutUint32(emptyIrPayload[4:8], 19) // CollationObjectId
	binary.LittleEndian.PutUint32(emptyIrPayload[8:12], 4096)
	emptyIrPayload[12] = 1 // 1 cluster per index block
	// NodeHeader: entries_off=16, total_sz=32, alloc_sz=32, flags=0 (LEAF NODE)
	binary.LittleEndian.PutUint32(emptyIrPayload[16:20], 16)
	binary.LittleEndian.PutUint32(emptyIrPayload[20:24], 32)
	binary.LittleEndian.PutUint32(emptyIrPayload[24:28], 32)
	emptyIrPayload[28] = 0
	// Entry: mft_ref=0, entry_len=16, val_len=0, flags=2 (INDEX_ENTRY_END)
	binary.LittleEndian.PutUint64(emptyIrPayload[32:40], 0)
	binary.LittleEndian.PutUint16(emptyIrPayload[40:42], 16)
	binary.LittleEndian.PutUint16(emptyIrPayload[42:44], 0)
	binary.LittleEndian.PutUint32(emptyIrPayload[44:48], 2)

	pRec25, err := PatchResidentAttr(rec25, AttrTypeIndexRoot, "$O", emptyIrPayload)
	if err != nil {
		return nil, fmt.Errorf("failed patching Record 25 $INDEX_ROOT: %w", err)
	}

	// If resident bitmap exists, zero it
	_ = RemoveFixup(pRec25)
	off25 := int(binary.LittleEndian.Uint16(pRec25[20:22]))
	for off25+8 <= len(pRec25) {
		atype := binary.LittleEndian.Uint32(pRec25[off25 : off25+4])
		alen := int(binary.LittleEndian.Uint32(pRec25[off25+4 : off25+8]))
		if atype == AttrTypeEnd || alen == 0 || off25+alen > len(pRec25) {
			break
		}
		if atype == AttrTypeBitmap && pRec25[off25+8] == 0 {
			valLen := int(binary.LittleEndian.Uint32(pRec25[off25+16 : off25+20]))
			valOff := int(binary.LittleEndian.Uint16(pRec25[off25+20 : off25+22]))
			for i := 0; i < valLen; i++ {
				pRec25[off25+valOff+i] = 0
			}
			break
		}
		off25 += alen
	}

	// Preserve exact sequence number from original record (never increment in-place)
	seq25 := binary.LittleEndian.Uint16(rec25[16:18])
	if seq25 == 0 {
		seq25 = 1
	}
	binary.LittleEndian.PutUint16(pRec25[16:18], seq25)
	usaOffset := binary.LittleEndian.Uint16(pRec25[4:6])
	usaCount := binary.LittleEndian.Uint16(pRec25[6:8])
	_ = ApplyFixup(pRec25, usaOffset, usaCount, seq25)

	if err := writeRecordToMft(h, analysis, RecordObjId, pRec25); err != nil {
		return nil, fmt.Errorf("failed writing Record 25: %w", err)
	}

	// 4. Scan all MFT records and remove AttrTypeObjectID (0x40)
	report("Scanning MFT records and removing ObjectID attributes...", analysis.MftLcn)
	recordCount := analysis.MaxAllocRecord + 1
	if recordCount < 64 {
		recordCount = 64
	}

	var removedCount uint64 = 0
	for r := uint64(0); r < recordCount; r++ {
		raw, err := readRecordFromMft(h, analysis, r)
		if err != nil {
			continue
		}
		if len(raw) < 48 || string(raw[:4]) != "FILE" {
			continue
		}
		flags := binary.LittleEndian.Uint16(raw[22:24])
		if (flags & 1) == 0 {
			continue
		}

		recCopy := make([]byte, MftRecordSize)
		copy(recCopy, raw)
		if RemoveAttr(recCopy, AttrTypeObjectID, "") {
			if err := writeRecordToMft(h, analysis, r, recCopy); err == nil {
				removedCount++
			}
		}
	}

	var totalObjClusters uint64 = 0
	for _, r := range objRuns {
		totalObjClusters += r.Length
	}

	res := &ResetObjIdResult{
		TotalRecordsScanned: recordCount,
		ObjIdsRemoved:       removedCount,
		ObjIdClusters:       totalObjClusters,
		ObjIdBytesPreserved: objAllocSz,
	}
	return res, nil
}

// ResetBoth coordinates resetting both $Secure and $ObjId in a clean, unified execution.
func ResetBoth(h syscall.Handle, analysis *VolumeAnalysis, progress ProgressFunc) (*ResetCombinedResult, error) {
	secRes, err := ResetSecure(h, analysis, progress)
	if err != nil {
		return nil, fmt.Errorf("reset $Secure failed: %w", err)
	}

	objRes, err := ResetObjId(h, analysis, progress)
	if err != nil {
		return nil, fmt.Errorf("reset $ObjId failed: %w", err)
	}

	return &ResetCombinedResult{
		SecureResult: *secRes,
		ObjIdResult:  *objRes,
	}, nil
}
