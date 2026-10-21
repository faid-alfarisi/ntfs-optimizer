package ntfs

import (
	"encoding/binary"
	"os/exec"
	"strings"
	"testing"
)

func TestValidateAndFixIndexBlock(t *testing.T) {
	metaMap := map[uint64]*RecordMeta{
		30: {RecNum: 30, Seq: 4, Name: "test.txt"},
	}

	entry := make([]byte, 32)
	oldRef := (uint64(2) << 48) | 30
	binary.LittleEndian.PutUint64(entry[0:8], oldRef)
	binary.LittleEndian.PutUint16(entry[8:10], 32)
	binary.LittleEndian.PutUint16(entry[12:14], 0)

	fixed := validateAndFixIndexBlock(entry, metaMap)
	if fixed != 1 {
		t.Fatalf("Expected 1 fixed entry, got %d", fixed)
	}

	newRef := binary.LittleEndian.Uint64(entry[0:8])
	newSeq := uint16(newRef >> 48)
	newRec := newRef & 0x0000FFFFFFFFFFFF
	if newSeq != 4 || newRec != 30 {
		t.Fatalf("Expected ref with seq 4 and rec 30, got seq %d rec %d", newSeq, newRec)
	}
}

func TestLiveRepairVolume(t *testing.T) {
	// 1. Mark F: dirty using fsutil
	_ = exec.Command("fsutil", "dirty", "set", "F:").Run()

	out, err := exec.Command("fsutil", "dirty", "query", "F:").Output()
	if err != nil || !strings.Contains(string(out), "is Dirty") {
		t.Fatalf("Failed to mark F: dirty: %s", string(out))
	}

	// 2. Run RepairVolume directly
	h, _, isVol, err := OpenTarget("F:")
	if err != nil {
		t.Fatalf("OpenTarget failed: %v", err)
	}
	defer CloseTarget(h, isVol)

	an, err := AnalyzeVolume(h, "F:")
	if err != nil {
		t.Fatalf("AnalyzeVolume failed: %v", err)
	}

	res, err := RepairVolume(h, an, func(msg string, cur uint64, total uint64) {
		t.Logf("[%s] %d / %d", msg, cur, total)
	})
	if err != nil {
		t.Fatalf("RepairVolume failed: %v", err)
	}

	if !res.WasDirty {
		t.Errorf("Expected WasDirty to be true")
	}
	if !res.DirtyCleared {
		t.Errorf("Expected DirtyCleared to be true")
	}

	// Close handle to allow Windows to inspect
	CloseTarget(h, isVol)

	// 3. Query fsutil dirty state
	outClean, err := exec.Command("fsutil", "dirty", "query", "F:").Output()
	if err != nil || !strings.Contains(string(outClean), "is NOT Dirty") {
		t.Fatalf("Expected F: to be NOT Dirty, got: %s", string(outClean))
	}
	t.Logf("fsutil dirty query output: %s", strings.TrimSpace(string(outClean)))

	// 4. Run chkdsk F: to ensure Windows integrity check passes with 0 errors
	chkOut, _ := exec.Command("chkdsk", "F:").CombinedOutput()
	t.Logf("chkdsk summary:\n%s", string(chkOut))
	if strings.Contains(string(chkOut), "Windows found errors") {
		t.Fatalf("chkdsk reported errors:\n%s", string(chkOut))
	}
}
