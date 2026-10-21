package ntfs

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDetermineSecurityID(t *testing.T) {
	tests := []struct {
		name         string
		recNum       uint64
		isDir        bool
		hasImageLoad bool
		path         string
		fileName     string
		expectedSec  uint32
	}{
		{"$MFT root", 0, false, false, "$MFT", "$MFT", 256},
		{"$LogFile root", 2, false, false, "$LogFile", "$LogFile", 256},
		{"$Secure record 9", 9, false, false, "$Secure", "$Secure", 257},
		{"$Extend record 11", 11, true, false, "$Extend", "$Extend", 257},
		{"$Extend subfile", 24, false, false, "$Extend\\$Quota", "$Quota", 257},
		{"$RmMetadata subfolder", 30, true, false, "$Extend\\$RmMetadata", "$RmMetadata", 258},
		{"$RmMetadata general", 31, false, false, "$Extend\\$RmMetadata\\something", "something", 258},
		{"$RmMetadata $Repair", 28, false, false, "$Extend\\$RmMetadata\\$Repair", "$Repair", 257},
		{"$TxfLog $Tops", 32, false, false, "$Extend\\$RmMetadata\\$TxfLog\\$Tops", "$Tops", 258},
		{"$TxfLog $TxfLog.blf", 33, false, false, "$Extend\\$RmMetadata\\$TxfLog\\$TxfLog.blf", "$TxfLog.blf", 259},
		{"$TxfLogContainer01", 34, false, false, "$Extend\\$RmMetadata\\$TxfLog\\$TxfLogContainer00000000000000000001", "$TxfLogContainer00000000000000000001", 260},
		{"$TxfLogContainer02", 35, false, false, "$Extend\\$RmMetadata\\$TxfLog\\$TxfLogContainer00000000000000000002", "$TxfLogContainer00000000000000000002", 260},
		{"$RECYCLE.BIN root", 40, true, false, "$RECYCLE.BIN", "$RECYCLE.BIN", 264},
		{"$RECYCLE.BIN user folder", 41, true, false, "$RECYCLE.BIN\\S-1-5-21-1234", "S-1-5-21-1234", 265},
		{"$RECYCLE.BIN desktop.ini", 42, false, false, "$RECYCLE.BIN\\S-1-5-21-1234\\desktop.ini", "desktop.ini", 266},
		{"System Volume Information root", 36, true, false, "System Volume Information", "System Volume Information", 261},
		{"SVI tracking.log", 37, false, false, "System Volume Information\\tracking.log", "tracking.log", 263},
		{"SVI other file", 38, false, false, "System Volume Information\\IndexerVolumeGuid", "IndexerVolumeGuid", 262},
		{"Standard folder", 100, true, false, "MyFolder", "MyFolder", 267},
		{"Standard file", 101, false, false, "MyFolder\\doc.txt", "doc.txt", 268},
		{"File with IMAGELOAD", 102, false, true, "app.exe", "app.exe", 269},
		{"Auslogics temp file", 103, false, false, "auslogics_temp.dat", "auslogics_temp.dat", 270},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetermineSecurityID(tt.recNum, tt.isDir, tt.hasImageLoad, tt.path, tt.fileName)
			if got != tt.expectedSec {
				t.Errorf("DetermineSecurityID(%s) = %d, expected %d", tt.name, got, tt.expectedSec)
			}
		})
	}
}

func TestRecordSecurityIDGetSet(t *testing.T) {
	rec := make([]byte, MftRecordSize)
	copy(rec[:4], "FILE")
	binary.LittleEndian.PutUint16(rec[4:6], 48)
	binary.LittleEndian.PutUint16(rec[6:8], 3)
	binary.LittleEndian.PutUint16(rec[16:18], 1)
	binary.LittleEndian.PutUint16(rec[20:22], 56)
	binary.LittleEndian.PutUint16(rec[22:24], 1)

	cur := 56
	stdPayload := make([]byte, 72)
	binary.LittleEndian.PutUint32(stdPayload[52:56], 999) // initial SecID = 999
	rec, cur, _ = appendResidentAttr(rec, cur, 1, AttrTypeStandardInformation, "", stdPayload)

	binary.LittleEndian.PutUint32(rec[cur:cur+4], AttrTypeEnd)
	cur += 8
	binary.LittleEndian.PutUint32(rec[24:28], uint32(cur))
	binary.LittleEndian.PutUint32(rec[28:32], MftRecordSize)

	_ = ApplyFixup(rec, 48, 3, 1)

	// Get SecID
	secId, found := GetRecordSecurityID(rec)
	if !found || secId != 999 {
		t.Fatalf("expected secId 999, got %d (found=%v)", secId, found)
	}

	// Set SecID to 268
	updated := SetRecordSecurityID(rec, 268)
	if !updated {
		t.Fatalf("expected SetRecordSecurityID to succeed")
	}

	secId2, found2 := GetRecordSecurityID(rec)
	if !found2 || secId2 != 268 {
		t.Fatalf("expected secId 268, got %d (found=%v)", secId2, found2)
	}
}

func TestRemoveAttr(t *testing.T) {
	rec := make([]byte, MftRecordSize)
	copy(rec[:4], "FILE")
	binary.LittleEndian.PutUint16(rec[4:6], 48)
	binary.LittleEndian.PutUint16(rec[6:8], 3)
	binary.LittleEndian.PutUint16(rec[16:18], 1)
	binary.LittleEndian.PutUint16(rec[20:22], 56)
	binary.LittleEndian.PutUint16(rec[22:24], 1)

	cur := 56
	var attrID uint16 = 1

	rec, cur, attrID = appendResidentAttr(rec, cur, attrID, AttrTypeStandardInformation, "", make([]byte, 72))
	rec, cur, attrID = appendResidentAttr(rec, cur, attrID, AttrTypeObjectID, "", make([]byte, 64))
	rec, cur, attrID = appendResidentAttr(rec, cur, attrID, AttrTypeFileName, "", make([]byte, 66))

	binary.LittleEndian.PutUint32(rec[cur:cur+4], AttrTypeEnd)
	cur += 8
	binary.LittleEndian.PutUint32(rec[24:28], uint32(cur))
	binary.LittleEndian.PutUint32(rec[28:32], MftRecordSize)

	_ = ApplyFixup(rec, 48, 3, 1)

	removed := RemoveAttr(rec, AttrTypeObjectID, "")
	if !removed {
		t.Fatalf("expected RemoveAttr to return true")
	}

	// Verify Attr 0x40 is gone
	_ = RemoveFixup(rec)
	off := int(binary.LittleEndian.Uint16(rec[20:22]))
	for off+8 <= len(rec) {
		atype := binary.LittleEndian.Uint32(rec[off : off+4])
		alen := int(binary.LittleEndian.Uint32(rec[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 {
			break
		}
		if atype == AttrTypeObjectID {
			t.Fatalf("Attr 0x40 still present after RemoveAttr")
		}
		off += alen
	}
}

func TestPatchResidentAttr(t *testing.T) {
	rec := make([]byte, MftRecordSize)
	copy(rec[:4], "FILE")
	binary.LittleEndian.PutUint16(rec[4:6], 48)
	binary.LittleEndian.PutUint16(rec[6:8], 3)
	binary.LittleEndian.PutUint16(rec[16:18], 1)
	binary.LittleEndian.PutUint16(rec[20:22], 56)
	binary.LittleEndian.PutUint16(rec[22:24], 1)

	cur := 56
	var attrID uint16 = 1

	rec, cur, attrID = appendResidentAttr(rec, cur, attrID, AttrTypeStandardInformation, "", make([]byte, 72))
	initialPayload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	rec, cur, attrID = appendResidentAttr(rec, cur, attrID, AttrTypeIndexRoot, "$O", initialPayload)

	binary.LittleEndian.PutUint32(rec[cur:cur+4], AttrTypeEnd)
	cur += 8
	binary.LittleEndian.PutUint32(rec[24:28], uint32(cur))
	binary.LittleEndian.PutUint32(rec[28:32], MftRecordSize)

	_ = ApplyFixup(rec, 48, 3, 1)

	newPayload := []byte{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	patched, err := PatchResidentAttr(rec, AttrTypeIndexRoot, "$O", newPayload)
	if err != nil {
		t.Fatalf("PatchResidentAttr failed: %v", err)
	}

	_ = RemoveFixup(patched)
	off := int(binary.LittleEndian.Uint16(patched[20:22]))
	found := false
	for off+8 <= len(patched) {
		atype := binary.LittleEndian.Uint32(patched[off : off+4])
		alen := int(binary.LittleEndian.Uint32(patched[off+4 : off+8]))
		if atype == AttrTypeEnd || alen == 0 {
			break
		}
		if atype == AttrTypeIndexRoot {
			valLen := int(binary.LittleEndian.Uint32(patched[off+16 : off+20]))
			valOff := int(binary.LittleEndian.Uint16(patched[off+20 : off+22]))
			got := patched[off+valOff : off+valOff+valLen]
			if !bytes.Equal(got, newPayload) {
				t.Fatalf("expected payload %v, got %v", newPayload, got)
			}
			found = true
			break
		}
		off += alen
	}
	if !found {
		t.Fatalf("patched AttrTypeIndexRoot not found")
	}
}

