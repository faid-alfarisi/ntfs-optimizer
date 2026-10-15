package ntfs

import (
	"bytes"
	"fmt"
)

// EncodeRunlist converts a slice of contiguous runs into compact NTFS data run format.
func EncodeRunlist(runs []Run) []byte {
	var buf bytes.Buffer
	var prevLcn int64 = 0

	for _, r := range runs {
		delta := int64(r.LCN) - prevLcn
		prevLcn = int64(r.LCN)

		// Encode length (unsigned, ensuring positive sign bit in last byte)
		var lenBytes []byte
		tempLen := r.Length
		for {
			b := byte(tempLen & 0xFF)
			lenBytes = append(lenBytes, b)
			tempLen >>= 8
			if tempLen == 0 && (b&0x80) == 0 {
				break
			}
		}

		// Encode delta offset (signed)
		var offBytes []byte
		tempOff := delta
		for {
			b := byte(tempOff & 0xFF)
			offBytes = append(offBytes, b)
			tempOff >>= 8
			if (delta >= 0 && tempOff == 0 && (b&0x80) == 0) ||
				(delta < 0 && tempOff == -1 && (b&0x80) != 0) {
				break
			}
		}

		header := byte(len(lenBytes)) | byte(len(offBytes)<<4)
		buf.WriteByte(header)
		buf.Write(lenBytes)
		buf.Write(offBytes)
	}

	// 0x00 terminates the runlist
	buf.WriteByte(0x00)
	return buf.Bytes()
}

// DecodeRunlist parses raw NTFS runlist bytes into a list of absolute runs.
func DecodeRunlist(data []byte) ([]Run, error) {
	var runs []Run
	var curLcn int64 = 0
	idx := 0

	for idx < len(data) && data[idx] != 0 {
		header := data[idx]
		lenLen := int(header & 0x0F)
		offLen := int((header >> 4) & 0x0F)
		idx++

		if idx+lenLen+offLen > len(data) {
			return nil, fmt.Errorf("truncated runlist at offset %d", idx)
		}

		var runLen uint64 = 0
		for i := 0; i < lenLen; i++ {
			runLen |= uint64(data[idx+i]) << (8 * i)
		}
		idx += lenLen

		var delta int64 = 0
		for i := 0; i < offLen; i++ {
			delta |= int64(data[idx+i]) << (8 * i)
		}
		// Sign extend
		if offLen > 0 && (data[idx+offLen-1]&0x80) != 0 {
			for i := offLen; i < 8; i++ {
				delta |= int64(0xFF) << (8 * i)
			}
		}
		idx += offLen

		curLcn += delta
		runs = append(runs, Run{
			LCN:    uint64(curLcn),
			Length: runLen,
		})
	}
	return runs, nil
}
