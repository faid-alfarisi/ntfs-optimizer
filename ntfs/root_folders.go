package ntfs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

const defaultNtfsTimestamp = uint64(0x01d5c0929c757800)

func buildStandardInfoPayload(stdFlags uint32, secId uint32) []byte {
	buf := make([]byte, 72)
	binary.LittleEndian.PutUint64(buf[0:8], defaultNtfsTimestamp)
	binary.LittleEndian.PutUint64(buf[8:16], defaultNtfsTimestamp)
	binary.LittleEndian.PutUint64(buf[16:24], defaultNtfsTimestamp)
	binary.LittleEndian.PutUint64(buf[24:32], defaultNtfsTimestamp)
	binary.LittleEndian.PutUint32(buf[32:36], stdFlags)
	binary.LittleEndian.PutUint32(buf[52:56], secId)
	return buf
}

func buildFileNamePayload(parentRec uint64, parentSeq uint16, allocSz uint64, realSz uint64, fnFlags uint32, namespace byte, name string) []byte {
	u16 := utf16.Encode([]rune(name))
	buf := make([]byte, 66+len(u16)*2)
	parentRef := (parentRec & 0xFFFFFFFFFFFF) | (uint64(parentSeq) << 48)
	binary.LittleEndian.PutUint64(buf[0:8], parentRef)
	binary.LittleEndian.PutUint64(buf[8:16], defaultNtfsTimestamp)
	binary.LittleEndian.PutUint64(buf[16:24], defaultNtfsTimestamp)
	binary.LittleEndian.PutUint64(buf[24:32], defaultNtfsTimestamp)
	binary.LittleEndian.PutUint64(buf[32:40], defaultNtfsTimestamp)
	binary.LittleEndian.PutUint64(buf[40:48], allocSz)
	binary.LittleEndian.PutUint64(buf[48:56], realSz)
	binary.LittleEndian.PutUint32(buf[56:60], fnFlags)
	binary.LittleEndian.PutUint32(buf[60:64], 0)
	buf[64] = byte(len(u16))
	buf[65] = namespace
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(buf[66+i*2:], v)
	}
	return buf
}

func buildLeafIndexRootI30(children []struct {
	recNum uint64
	seq    uint16
	fn     []byte
}) []byte {
	var entriesBuf []byte
	for _, c := range children {
		valLen := len(c.fn)
		entryLen := (16 + valLen + 7) &^ 7
		entry := make([]byte, entryLen)
		mftRef := (c.recNum & 0xFFFFFFFFFFFF) | (uint64(c.seq) << 48)
		binary.LittleEndian.PutUint64(entry[0:8], mftRef)
		binary.LittleEndian.PutUint16(entry[8:10], uint16(entryLen))
		binary.LittleEndian.PutUint16(entry[10:12], uint16(valLen))
		binary.LittleEndian.PutUint32(entry[12:16], 0) // leaf entry
		copy(entry[16:], c.fn)
		entriesBuf = append(entriesBuf, entry...)
	}
	endEntry := make([]byte, 16)
	binary.LittleEndian.PutUint16(endEntry[8:10], 16)
	binary.LittleEndian.PutUint32(endEntry[12:16], 2) // INDEX_ENTRY_END
	entriesBuf = append(entriesBuf, endEntry...)

	nodeTotalSz := 16 + len(entriesBuf)
	irPayload := make([]byte, 16+nodeTotalSz)
	binary.LittleEndian.PutUint32(irPayload[0:4], AttrTypeFileName)
	binary.LittleEndian.PutUint32(irPayload[4:8], CollationFileName)
	binary.LittleEndian.PutUint32(irPayload[8:12], IndexBlockSize)
	irPayload[12] = 1
	binary.LittleEndian.PutUint32(irPayload[16:20], 16)
	binary.LittleEndian.PutUint32(irPayload[20:24], uint32(nodeTotalSz))
	binary.LittleEndian.PutUint32(irPayload[24:28], uint32(nodeTotalSz))
	irPayload[28] = 0 // leaf
	copy(irPayload[32:], entriesBuf)
	return irPayload
}

func buildMftRecordHeader(recNum uint32, seq uint16, flags uint16) []byte {
	rec := make([]byte, MftRecordSize)
	copy(rec[0:4], []byte("FILE"))
	binary.LittleEndian.PutUint16(rec[4:6], 48)   // usaOffset
	binary.LittleEndian.PutUint16(rec[6:8], 3)    // usaCount
	binary.LittleEndian.PutUint64(rec[8:16], 0)   // LSN
	binary.LittleEndian.PutUint16(rec[16:18], seq) // Sequence number
	binary.LittleEndian.PutUint16(rec[18:20], 1)  // Link count = 1
	binary.LittleEndian.PutUint16(rec[20:22], 56) // First attribute offset = 56
	binary.LittleEndian.PutUint16(rec[22:24], flags)
	binary.LittleEndian.PutUint32(rec[28:32], MftRecordSize)
	binary.LittleEndian.PutUint32(rec[44:48], recNum)
	return rec
}

func finalizeMftRecord(rec []byte, cur int, nextAttrId uint16, seq uint16) ([]byte, error) {
	binary.LittleEndian.PutUint32(rec[cur:cur+4], AttrTypeEnd)
	binary.LittleEndian.PutUint32(rec[cur+4:cur+8], 0)
	cur += 8
	binary.LittleEndian.PutUint32(rec[24:28], uint32(cur))
	binary.LittleEndian.PutUint16(rec[40:42], nextAttrId)
	if err := ApplyFixup(rec, 48, 3, seq); err != nil {
		return nil, err
	}
	return rec, nil
}

func generateRandomGUIDUTF16LE() []byte {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := fmt.Sprintf("{%08X-%04X-%04X-%04X-%012X}",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
	u16 := utf16.Encode([]rune(s))
	out := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func generateWPSettingsData() []byte {
	out := make([]byte, 12)
	binary.LittleEndian.PutUint32(out[0:4], 12)
	_, _ = rand.Read(out[4:12])
	return out
}

// BuildInitialRootFoldersRecords constructs MFT Records 36..42 in exact sequential order:
//   36: System Volume Information (SecID 261)
//   37: System Volume Information\WPSettings.dat (SecID 262)
//   38: System Volume Information\IndexerVolumeGuid (SecID 262)
//   39: System Volume Information\tracking.log (SecID 263, empty resident $DATA)
//   40: $Recycle.Bin (SecID 264)
//   41: $Recycle.Bin\<UserSID> (SecID 265)
//   42: $Recycle.Bin\<UserSID>\desktop.ini (SecID 266)
func BuildInitialRootFoldersRecords(records [][]byte, userSID string) error {
	// --- Record 37: WPSettings.dat (SecID 262) ---
	wpData := generateWPSettingsData()
	fnWP := buildFileNamePayload(RecordSVI, 1, 16, 12, 0x00002020, 0, "WPSettings.dat")
	rec37 := buildMftRecordHeader(RecordWPSettings, 1, 0x0001)
	cur := 56
	rec37, cur, _ = appendResidentAttr(rec37, cur, 0, AttrTypeStandardInformation, "", buildStandardInfoPayload(0x00002020, 262))
	rec37, cur, _ = appendResidentAttr(rec37, cur, 2, AttrTypeFileName, "", fnWP)
	rec37, cur, _ = appendResidentAttr(rec37, cur, 1, AttrTypeData, "", wpData)
	var err error
	if records[RecordWPSettings], err = finalizeMftRecord(rec37, cur, 3, 1); err != nil {
		return err
	}

	// --- Record 38: IndexerVolumeGuid (SecID 262) ---
	guidData := generateRandomGUIDUTF16LE()
	fnIdx := buildFileNamePayload(RecordSVI, 1, 80, 76, 0x00002020, 0, "IndexerVolumeGuid")
	rec38 := buildMftRecordHeader(RecordIndexerVolumeGuid, 1, 0x0001)
	cur = 56
	rec38, cur, _ = appendResidentAttr(rec38, cur, 0, AttrTypeStandardInformation, "", buildStandardInfoPayload(0x00002020, 262))
	rec38, cur, _ = appendResidentAttr(rec38, cur, 2, AttrTypeFileName, "", fnIdx)
	rec38, cur, _ = appendResidentAttr(rec38, cur, 1, AttrTypeData, "", guidData)
	if records[RecordIndexerVolumeGuid], err = finalizeMftRecord(rec38, cur, 3, 1); err != nil {
		return err
	}

	// --- Record 39: tracking.log (SecID 263, empty on first format) ---
	fnTrk := buildFileNamePayload(RecordSVI, 1, 0, 0, 0x00002026, 0, "tracking.log")
	rec39 := buildMftRecordHeader(RecordTrackingLog, 1, 0x0001)
	cur = 56
	rec39, cur, _ = appendResidentAttr(rec39, cur, 0, AttrTypeStandardInformation, "", buildStandardInfoPayload(0x00002026, 263))
	rec39, cur, _ = appendResidentAttr(rec39, cur, 2, AttrTypeFileName, "", fnTrk)
	rec39, cur, _ = appendResidentAttr(rec39, cur, 1, AttrTypeData, "", []byte{})
	if records[RecordTrackingLog], err = finalizeMftRecord(rec39, cur, 3, 1); err != nil {
		return err
	}

	// --- Record 36: System Volume Information (SecID 261) ---
	fnSVI := buildFileNamePayload(RecordRoot, 5, 0, 0, 0x10002006, 0, "System Volume Information")
	sviIndexRoot := buildLeafIndexRootI30([]struct {
		recNum uint64
		seq    uint16
		fn     []byte
	}{
		{recNum: RecordIndexerVolumeGuid, seq: 1, fn: fnIdx},
		{recNum: RecordTrackingLog, seq: 1, fn: fnTrk},
		{recNum: RecordWPSettings, seq: 1, fn: fnWP},
	})
	rec36 := buildMftRecordHeader(RecordSVI, 1, 0x0003)
	cur = 56
	rec36, cur, _ = appendResidentAttr(rec36, cur, 0, AttrTypeStandardInformation, "", buildStandardInfoPayload(0x00002006, 261))
	rec36, cur, _ = appendResidentAttr(rec36, cur, 2, AttrTypeFileName, "", fnSVI)
	rec36, cur, _ = appendResidentAttr(rec36, cur, 1, AttrTypeIndexRoot, "$I30", sviIndexRoot)
	if records[RecordSVI], err = finalizeMftRecord(rec36, cur, 3, 1); err != nil {
		return err
	}

	// --- Record 42: $Recycle.Bin\<UserSID>\desktop.ini (SecID 266) ---
	desktopIniContent := []byte("[.ShellClassInfo]\r\nCLSID={645FF040-5081-101B-9F08-00AA002F954E}\r\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-8964\r\n")
	fnIniForRec := buildFileNamePayload(RecordRecycleBinSID, 1, 0, 0, 0x00002020, 0, "desktop.ini")
	fnIniForIdx := buildFileNamePayload(RecordRecycleBinSID, 1, 136, 129, 0x00002026, 0, "desktop.ini")
	rec42 := buildMftRecordHeader(RecordDesktopIni, 1, 0x0001)
	cur = 56
	rec42, cur, _ = appendResidentAttr(rec42, cur, 0, AttrTypeStandardInformation, "", buildStandardInfoPayload(0x00002026, 266))
	rec42, cur, _ = appendResidentAttr(rec42, cur, 2, AttrTypeFileName, "", fnIniForRec)
	rec42, cur, _ = appendResidentAttr(rec42, cur, 1, AttrTypeData, "", desktopIniContent)
	if records[RecordDesktopIni], err = finalizeMftRecord(rec42, cur, 3, 1); err != nil {
		return err
	}

	// --- Record 41: $Recycle.Bin\<UserSID> (SecID 265) ---
	fnSid := buildFileNamePayload(RecordRecycleBin, 1, 0, 0, 0x10002006, 0, userSID)
	sidIndexRoot := buildLeafIndexRootI30([]struct {
		recNum uint64
		seq    uint16
		fn     []byte
	}{
		{recNum: RecordDesktopIni, seq: 1, fn: fnIniForIdx},
	})
	rec41 := buildMftRecordHeader(RecordRecycleBinSID, 1, 0x0003)
	cur = 56
	rec41, cur, _ = appendResidentAttr(rec41, cur, 0, AttrTypeStandardInformation, "", buildStandardInfoPayload(0x00002006, 265))
	rec41, cur, _ = appendResidentAttr(rec41, cur, 2, AttrTypeFileName, "", fnSid)
	rec41, cur, _ = appendResidentAttr(rec41, cur, 3, AttrTypeIndexRoot, "$I30", sidIndexRoot)
	if records[RecordRecycleBinSID], err = finalizeMftRecord(rec41, cur, 4, 1); err != nil {
		return err
	}

	// --- Record 40: $Recycle.Bin (SecID 264) ---
	fnRecBin := buildFileNamePayload(RecordRoot, 5, 0, 0, 0x10002006, 0, "$Recycle.Bin")
	recBinIndexRoot := buildLeafIndexRootI30([]struct {
		recNum uint64
		seq    uint16
		fn     []byte
	}{
		{recNum: RecordRecycleBinSID, seq: 1, fn: fnSid},
	})
	rec40 := buildMftRecordHeader(RecordRecycleBin, 1, 0x0003)
	cur = 56
	rec40, cur, _ = appendResidentAttr(rec40, cur, 0, AttrTypeStandardInformation, "", buildStandardInfoPayload(0x00002006, 264))
	rec40, cur, _ = appendResidentAttr(rec40, cur, 2, AttrTypeFileName, "", fnRecBin)
	rec40, cur, _ = appendResidentAttr(rec40, cur, 1, AttrTypeIndexRoot, "$I30", recBinIndexRoot)
	if records[RecordRecycleBin], err = finalizeMftRecord(rec40, cur, 3, 1); err != nil {
		return err
	}

	return nil
}

// BuildRootIndxBlock updates the $Root $I30 INDX block so it contains the 12 system entries
// plus $Recycle.Bin (Record 40) and System Volume Information (Record 36) in exact $UpCase order.
func BuildRootIndxBlock(baseIndx []byte, recSVI, recRecycleBin []byte) ([]byte, error) {
	indx := make([]byte, IndexBlockSize)
	copy(indx, baseIndx)
	if err := RemoveFixup(indx); err != nil {
		return nil, err
	}

	usaOffset := binary.LittleEndian.Uint16(indx[4:6])
	usaCount := binary.LittleEndian.Uint16(indx[6:8])
	seq := binary.LittleEndian.Uint16(indx[usaOffset : usaOffset+2])
	if seq == 0 {
		seq = 1
	}

	fnSVI, seqSVI, err := extractFileNamePayload(recSVI)
	if err != nil {
		return nil, err
	}
	fnRecBin, seqRecBin, err := extractFileNamePayload(recRecycleBin)
	if err != nil {
		return nil, err
	}

	makeEntry := func(rnum uint64, rseq uint16, fn []byte) []byte {
		valLen := len(fn)
		entryLen := (16 + valLen + 7) &^ 7
		e := make([]byte, entryLen)
		mftRef := (rnum & 0xFFFFFFFFFFFF) | (uint64(rseq) << 48)
		binary.LittleEndian.PutUint64(e[0:8], mftRef)
		binary.LittleEndian.PutUint16(e[8:10], uint16(entryLen))
		binary.LittleEndian.PutUint16(e[10:12], uint16(valLen))
		binary.LittleEndian.PutUint32(e[12:16], 0)
		copy(e[16:], fn)
		return e
	}

	recBinEntry := makeEntry(RecordRecycleBin, seqRecBin, fnRecBin)
	sviEntry := makeEntry(RecordSVI, seqSVI, fnSVI)

	entriesOff := int(binary.LittleEndian.Uint32(indx[24:28]))
	totalSz := int(binary.LittleEndian.Uint32(indx[28:32]))
	off := 24 + entriesOff
	end := 24 + totalSz

	var newEntries []byte
	for off+16 <= end && off+16 <= len(indx) {
		mftRef := binary.LittleEndian.Uint64(indx[off : off+8])
		rnum := mftRef & 0xFFFFFFFFFFFF
		elen := int(binary.LittleEndian.Uint16(indx[off+8 : off+10]))
		eflags := binary.LittleEndian.Uint32(indx[off+12 : off+16])
		if elen == 0 {
			break
		}
		if eflags&2 != 0 {
			// Insert System Volume Information right before the END entry (after ".")
			newEntries = append(newEntries, sviEntry...)
			newEntries = append(newEntries, indx[off:off+elen]...)
			break
		}
		// Insert $Recycle.Bin right before $Secure (Record 9), which comes right after $MFTMirr (Record 1)
		if rnum == RecordSecure {
			newEntries = append(newEntries, recBinEntry...)
		}
		newEntries = append(newEntries, indx[off:off+elen]...)
		off += elen
	}

	newTotalSz := entriesOff + len(newEntries)
	binary.LittleEndian.PutUint32(indx[28:32], uint32(newTotalSz))
	for i := 24 + entriesOff; i < len(indx); i++ {
		indx[i] = 0
	}
	copy(indx[24+entriesOff:], newEntries)

	if err := ApplyFixup(indx, usaOffset, usaCount, seq); err != nil {
		return nil, err
	}
	return indx, nil
}

