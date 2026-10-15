package ntfs

import (
	"encoding/binary"
)

// BuildEmptyIndxBlock constructs a 4096-byte INDX leaf block with an end-of-node entry.
func BuildEmptyIndxBlock(vcn uint64) []byte {
	buf := make([]byte, IndexBlockSize)
	copy(buf[0:4], []byte("INDX"))

	usaOffset := uint16(0x28) // 40
	usaCount := uint16(9)     // 1 seq + 8 sectors
	binary.LittleEndian.PutUint16(buf[4:6], usaOffset)
	binary.LittleEndian.PutUint16(buf[6:8], usaCount)

	binary.LittleEndian.PutUint64(buf[8:16], 0)   // LSN
	binary.LittleEndian.PutUint64(buf[16:24], vcn) // VCN

	// Index Header (relative to 0x18)
	entriesOffset := uint32(0x28)                      // 0x18 + 0x28 = 0x40 (64)
	totalSize := uint32(0x28 + 16)                     // 56 bytes
	allocSize := uint32(IndexBlockSize - 0x18)         // 4072 bytes
	binary.LittleEndian.PutUint32(buf[24:28], entriesOffset)
	binary.LittleEndian.PutUint32(buf[28:32], totalSize)
	binary.LittleEndian.PutUint32(buf[32:36], allocSize)
	buf[36] = 0 // Flags (Leaf node: no subnodes)

	// End of node entry at offset 64 (0x40)
	// Entry: MftRef(8)=0, EntryLen(2)=16, ValueLen(2)=0, Flags(4)=2 (INDEX_ENTRY_END)
	binary.LittleEndian.PutUint64(buf[64:72], 0)
	binary.LittleEndian.PutUint16(buf[72:74], 16)
	binary.LittleEndian.PutUint16(buf[74:76], 0)
	binary.LittleEndian.PutUint32(buf[76:80], 2)

	// Apply USA fixup
	_ = ApplyFixup(buf, usaOffset, usaCount, 1)
	return buf
}



