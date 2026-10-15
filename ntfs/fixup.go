package ntfs

import (
	"encoding/binary"
	"fmt"
)

// ApplyFixup recalculates the Update Sequence Array (USA) for an MFT record or INDX block.
// Each 512-byte sector's last 2 bytes are copied to the USA and replaced by the sequence number.
func ApplyFixup(buf []byte, usaOffset uint16, usaCount uint16, seq uint16) error {
	totalLen := len(buf)
	expectedSectors := int(usaCount - 1)
	if expectedSectors*SectorSize > totalLen {
		return fmt.Errorf("buffer too small for USA count: %d sectors needed, %d bytes provided", expectedSectors, totalLen)
	}
	if int(usaOffset)+int(usaCount)*2 > totalLen {
		return fmt.Errorf("USA table exceeds buffer bounds")
	}

	// Write sequence number at usaOffset
	binary.LittleEndian.PutUint16(buf[usaOffset:], seq)

	// For each 512-byte sector:
	for i := 1; i <= expectedSectors; i++ {
		secEnd := i*SectorSize - 2
		orig := binary.LittleEndian.Uint16(buf[secEnd:])
		// Store original bytes in USA
		binary.LittleEndian.PutUint16(buf[int(usaOffset)+i*2:], orig)
		// Overwrite end of sector with sequence number
		binary.LittleEndian.PutUint16(buf[secEnd:], seq)
	}
	return nil
}

// RemoveFixup restores the original bytes replaced by the sequence number.
func RemoveFixup(buf []byte) error {
	if len(buf) < 8 {
		return fmt.Errorf("buffer too small for USA header")
	}
	usaOffset := binary.LittleEndian.Uint16(buf[4:6])
	usaCount := binary.LittleEndian.Uint16(buf[6:8])
	expectedSectors := int(usaCount - 1)
	if expectedSectors*SectorSize > len(buf) {
		return fmt.Errorf("buffer too small for USA sectors")
	}

	for i := 1; i <= expectedSectors; i++ {
		secEnd := i*SectorSize - 2
		orig := binary.LittleEndian.Uint16(buf[int(usaOffset)+i*2:])
		binary.LittleEndian.PutUint16(buf[secEnd:], orig)
	}
	return nil
}

