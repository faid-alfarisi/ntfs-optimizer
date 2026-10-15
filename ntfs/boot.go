package ntfs

import (
	"encoding/binary"
	"math/rand"
	"time"
)

// BuildBootSector generates an 8192-byte boot area containing valid BPB parameters.
func BuildBootSector(totalSectors uint64, bytesPerSec uint16, secPerClus uint8, mftLcn uint64, mftMirrLcn uint64, serial uint64) []byte {
	vbr := make([]byte, 8192)
	copy(vbr, BootCodeBin)

	// Ensure standard OEM identifier
	copy(vbr[3:11], []byte("NTFS    "))

	// Keep existing geometry/hidden sectors from BootCodeBin, only updating cluster & LCN fields
	binary.LittleEndian.PutUint16(vbr[11:13], bytesPerSec)
	vbr[13] = secPerClus
	vbr[21] = 0xF8 // Media descriptor (Fixed disk)

	binary.LittleEndian.PutUint64(vbr[40:48], totalSectors)
	binary.LittleEndian.PutUint64(vbr[48:56], mftLcn)
	binary.LittleEndian.PutUint64(vbr[56:64], mftMirrLcn)

	vbr[64] = 0xF6 // Clusters per file record (-10 => 1024 bytes)
	vbr[68] = 1    // Clusters per index buffer (1 cluster = 4096 bytes)

	if serial == 0 {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		serial = r.Uint64()
	}
	binary.LittleEndian.PutUint64(vbr[72:80], serial)

	// End of sector 0 boot signature
	vbr[510] = 0x55
	vbr[511] = 0xAA

	return vbr
}

