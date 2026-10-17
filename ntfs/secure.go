package ntfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const templateUserSID = "S-1-5-21-2109798714-3862275685-1452596448-1001"

// ParseSIDToBytes encodes a Windows SID string (e.g. "S-1-5-21-...-1001") into binary SID format.
func ParseSIDToBytes(sidStr string) ([]byte, error) {
	parts := strings.Split(sidStr, "-")
	if len(parts) < 4 || parts[0] != "S" {
		return nil, fmt.Errorf("invalid SID: %s", sidStr)
	}
	rev, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}
	auth, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return nil, err
	}
	subCount := len(parts) - 3
	out := make([]byte, 8+subCount*4)
	out[0] = byte(rev)
	out[1] = byte(subCount)
	for i := 0; i < 6; i++ {
		out[7-i] = byte(auth & 0xFF)
		auth >>= 8
	}
	for i := 0; i < subCount; i++ {
		sub, err := strconv.ParseUint(parts[3+i], 10, 32)
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(out[8+i*4:12+i*4], uint32(sub))
	}
	return out, nil
}

// NtfsSecurityHash computes the standard NTFS $Secure 32-bit security descriptor hash (ROR 29 / ROL 3).
func NtfsSecurityHash(sd []byte) uint32 {
	var hash uint32 = 0
	for i := 0; i+4 <= len(sd); i += 4 {
		val := binary.LittleEndian.Uint32(sd[i : i+4])
		hash = ((hash << 3) | (hash >> 29)) + val
	}
	return hash
}

// BuildSecureStreams patches $Secure:$SDS and rebuilds $SDH and $SII cleanly with unique Security IDs 256..271
// (matching the actual SDS descriptors at both offset 0 and mirror offset 262144), substituting the active user's SID.
func BuildSecureStreams(activeSidStr string) (sdsOut []byte, sdhOut []byte, siiOut []byte) {
	sdsOut = make([]byte, len(SecureSdsBin))
	copy(sdsOut, SecureSdsBin)

	sdhOut = make([]byte, len(SecureSdhBin))
	copy(sdhOut, SecureSdhBin)

	siiOut = make([]byte, len(SecureSiiBin))
	copy(siiOut, SecureSiiBin)

	oldSid, err1 := ParseSIDToBytes(templateUserSID)
	newSid, err2 := ParseSIDToBytes(activeSidStr)
	replaceSid := err1 == nil && err2 == nil && len(oldSid) == len(newSid) && !bytes.Equal(oldSid, newSid)

	type sdsRecord struct {
		hash   uint32
		secId  uint32
		sdsOff uint64
		sdsSz  uint32
		pad    uint32
	}
	var records []sdsRecord

	// Scan and patch both the primary SDS block (offset 0) and mirror SDS block (offset 262144)
	for _, baseOff := range []int{0, 262144} {
		off := baseOff
		for off+20 <= baseOff+4096 && off+20 <= len(sdsOut) {
			secId := binary.LittleEndian.Uint32(sdsOut[off+4 : off+8])
			sdsOff := binary.LittleEndian.Uint64(sdsOut[off+8 : off+16])
			entrySize := binary.LittleEndian.Uint32(sdsOut[off+16 : off+20])
			if secId == 0 || entrySize <= 20 || off+int(entrySize) > len(sdsOut) {
				break
			}
			sd := sdsOut[off+20 : off+int(entrySize)]
			if replaceSid {
				replaced := bytes.ReplaceAll(sd, oldSid, newSid)
				copy(sd, replaced)
			}
			hash := NtfsSecurityHash(sd)
			binary.LittleEndian.PutUint32(sdsOut[off:off+4], hash)
			if baseOff == 0 {
				var pad uint32 = 0
				if (secId >= 256 && secId <= 262) || secId == 271 {
					pad = 0x00490049
				}
				records = append(records, sdsRecord{
					hash:   hash,
					secId:  secId,
					sdsOff: sdsOff,
					sdsSz:  entrySize,
					pad:    pad,
				})
			}
			off += int((entrySize + 15) &^ 15)
		}
	}

	// Rebuild $SII INDX block cleanly sorted by strictly increasing SecID (256..271)
	if err := RemoveFixup(siiOut); err == nil {
		usaOffset := binary.LittleEndian.Uint16(siiOut[4:6])
		usaCount := binary.LittleEndian.Uint16(siiOut[6:8])
		seq := binary.LittleEndian.Uint16(siiOut[usaOffset : usaOffset+2])
		if seq == 0 {
			seq = 1
		}
		entriesOff := int(binary.LittleEndian.Uint32(siiOut[24:28]))

		siiList := make([]sdsRecord, len(records))
		copy(siiList, records)
		sort.Slice(siiList, func(i, j int) bool {
			return siiList[i].secId < siiList[j].secId
		})

		for i := 24 + entriesOff; i < len(siiOut); i++ {
			siiOut[i] = 0
		}
		w := 24 + entriesOff
		for _, r := range siiList {
			binary.LittleEndian.PutUint16(siiOut[w:w+2], 20)   // data offset
			binary.LittleEndian.PutUint16(siiOut[w+2:w+4], 20) // data length
			binary.LittleEndian.PutUint32(siiOut[w+4:w+8], 0)
			binary.LittleEndian.PutUint16(siiOut[w+8:w+10], 40) // entry length
			binary.LittleEndian.PutUint16(siiOut[w+10:w+12], 4) // key length
			binary.LittleEndian.PutUint32(siiOut[w+12:w+16], 0) // flags
			binary.LittleEndian.PutUint32(siiOut[w+16:w+20], r.secId)
			binary.LittleEndian.PutUint32(siiOut[w+20:w+24], r.hash)
			binary.LittleEndian.PutUint32(siiOut[w+24:w+28], r.secId)
			binary.LittleEndian.PutUint64(siiOut[w+28:w+36], r.sdsOff)
			binary.LittleEndian.PutUint32(siiOut[w+36:w+40], r.sdsSz)
			w += 40
		}
		// End entry (16 bytes, flags = 2)
		binary.LittleEndian.PutUint16(siiOut[w+8:w+10], 16)
		binary.LittleEndian.PutUint32(siiOut[w+12:w+16], 2)
		w += 16

		binary.LittleEndian.PutUint32(siiOut[28:32], uint32(w-24))
		_ = ApplyFixup(siiOut, usaOffset, usaCount, seq)
	}

	// Rebuild $SDH INDX block cleanly sorted by (Hash, SecID)
	if err := RemoveFixup(sdhOut); err == nil {
		usaOffset := binary.LittleEndian.Uint16(sdhOut[4:6])
		usaCount := binary.LittleEndian.Uint16(sdhOut[6:8])
		seq := binary.LittleEndian.Uint16(sdhOut[usaOffset : usaOffset+2])
		if seq == 0 {
			seq = 1
		}
		entriesOff := int(binary.LittleEndian.Uint32(sdhOut[24:28]))

		sdhList := make([]sdsRecord, len(records))
		copy(sdhList, records)
		sort.Slice(sdhList, func(i, j int) bool {
			if sdhList[i].hash != sdhList[j].hash {
				return sdhList[i].hash < sdhList[j].hash
			}
			return sdhList[i].secId < sdhList[j].secId
		})

		for i := 24 + entriesOff; i < len(sdhOut); i++ {
			sdhOut[i] = 0
		}
		w := 24 + entriesOff
		for _, r := range sdhList {
			binary.LittleEndian.PutUint16(sdhOut[w:w+2], 24)   // data offset
			binary.LittleEndian.PutUint16(sdhOut[w+2:w+4], 20) // data length
			binary.LittleEndian.PutUint32(sdhOut[w+4:w+8], 0)
			binary.LittleEndian.PutUint16(sdhOut[w+8:w+10], 48) // entry length
			binary.LittleEndian.PutUint16(sdhOut[w+10:w+12], 8) // key length
			binary.LittleEndian.PutUint32(sdhOut[w+12:w+16], 0) // flags
			binary.LittleEndian.PutUint32(sdhOut[w+16:w+20], r.hash)
			binary.LittleEndian.PutUint32(sdhOut[w+20:w+24], r.secId)
			binary.LittleEndian.PutUint32(sdhOut[w+24:w+28], r.hash)
			binary.LittleEndian.PutUint32(sdhOut[w+28:w+32], r.secId)
			binary.LittleEndian.PutUint64(sdhOut[w+32:w+40], r.sdsOff)
			binary.LittleEndian.PutUint32(sdhOut[w+40:w+44], r.sdsSz)
			binary.LittleEndian.PutUint32(sdhOut[w+44:w+48], r.pad)
			w += 48
		}
		// End entry (16 bytes, flags = 2)
		binary.LittleEndian.PutUint16(sdhOut[w+8:w+10], 16)
		binary.LittleEndian.PutUint32(sdhOut[w+12:w+16], 2)
		w += 16

		binary.LittleEndian.PutUint32(sdhOut[28:32], uint32(w-24))
		_ = ApplyFixup(sdhOut, usaOffset, usaCount, seq)
	}

	return sdsOut, sdhOut, siiOut
}

