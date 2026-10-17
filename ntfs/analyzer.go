package ntfs

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// VolumeAnalysis stores the inspection metrics of an existing NTFS volume.
type VolumeAnalysis struct {
	Target            string
	VolumeLabel       string
	BytesPerSector    uint32
	SectorPerClust    uint8
	ClusterSize       uint32
	TotalSectors      uint64
	TotalClusters     uint64
	TotalBytes        uint64
	FreeBytes         uint64
	SerialNumber      uint64

	MftLcn            uint64
	MftAllocBytes     uint64
	MftRealBytes      uint64
	MaxAllocRecord    uint64
	TotalAllocRecords uint64
	MinMftMB          uint64
	CurrentMftMB      uint64

	CurrentMftZoneMB  uint64
	MinMftZoneMB      uint64

	LogFileLcn        uint64
	LogFileAllocBytes uint64
	CurrentLogFileMB  uint64
	MinLogFileMB      uint64

	ObjIdLcn          uint64
	ObjIdAllocBytes   uint64
	CurrentObjIdMB    uint64
	MinObjIdMB        uint64

	BitmapLcn         uint64
	BitmapAllocBytes  uint64

	ExistingMftRuns   []Run
	ExistingLogRuns   []Run
	ExistingBmRuns    []Run
}

// ReadAt reads a buffer of data at a specific byte offset on the volume handle.
func ReadAt(h syscall.Handle, offset uint64, size int) ([]byte, error) {
	var newPos int64
	r1, _, err := procSetFilePointerEx.Call(
		uintptr(h),
		uintptr(offset),
		uintptr(unsafe.Pointer(&newPos)),
		0, // FILE_BEGIN
	)
	if r1 == 0 {
		return nil, fmt.Errorf("SetFilePointerEx failed at %d: %w", offset, err)
	}

	buf := make([]byte, size)
	var read uint32
	err = syscall.ReadFile(h, buf, &read, nil)
	if err != nil {
		return nil, fmt.Errorf("ReadFile failed at %d: %w", offset, err)
	}
	return buf[:read], nil
}

// ParseRunlist extracts runs from a standard NTFS runlist byte slice.
func ParseRunlist(buf []byte) []Run {
	var runs []Run
	idx := 0
	var curLcn int64
	for idx < len(buf) && buf[idx] != 0 {
		b := buf[idx]
		lenLen := int(b & 0x0F)
		lcnLen := int((b >> 4) & 0x0F)
		idx++
		var rLen uint64
		for i := 0; i < lenLen; i++ {
			rLen |= uint64(buf[idx+i]) << (i * 8)
		}
		idx += lenLen
		var rLcnOff int64
		for i := 0; i < lcnLen; i++ {
			rLcnOff |= int64(buf[idx+i]) << (i * 8)
		}
		// Sign extend if negative offset
		if lcnLen > 0 && (buf[idx+lcnLen-1]&0x80) != 0 {
			for i := lcnLen; i < 8; i++ {
				rLcnOff |= int64(0xFF) << (i * 8)
			}
		}
		idx += lcnLen
		curLcn += rLcnOff
		runs = append(runs, Run{Length: rLen, LCN: uint64(curLcn)})
	}
	return runs
}

// AnalyzeVolume inspects an existing NTFS volume handle to retrieve its current sizes and minimum requirements.
func AnalyzeVolume(h syscall.Handle, target string) (*VolumeAnalysis, error) {
	vbr, err := ReadAt(h, 0, 512)
	if err != nil {
		return nil, fmt.Errorf("failed reading VBR: %w", err)
	}
	if string(vbr[3:7]) != "NTFS" {
		return nil, fmt.Errorf("target is not a valid NTFS volume (OEM ID is '%s')", string(vbr[3:11]))
	}

	bytesPerSec := uint32(binary.LittleEndian.Uint16(vbr[11:13]))
	secPerClus := vbr[13]
	clusterSize := bytesPerSec * uint32(secPerClus)
	totalSectors := binary.LittleEndian.Uint64(vbr[40:48])
	totalClusters := totalSectors / uint64(secPerClus)
	mftLcn := binary.LittleEndian.Uint64(vbr[48:56])
	serial := binary.LittleEndian.Uint64(vbr[72:80])

	analysis := &VolumeAnalysis{
		Target:         target,
		BytesPerSector: bytesPerSec,
		SectorPerClust: secPerClus,
		ClusterSize:    clusterSize,
		TotalSectors:   totalSectors,
		TotalClusters:  totalClusters,
		TotalBytes:     totalSectors * uint64(bytesPerSec),
		SerialNumber:   serial,
		MftLcn:         mftLcn,
		MinLogFileMB:   2,
		MinMftZoneMB:   10,
		MinObjIdMB:     4,
	}

	// Read Record 0 ($MFT)
	rec0Raw, err := ReadAt(h, mftLcn*uint64(clusterSize), MftRecordSize)
	if err != nil {
		return nil, fmt.Errorf("failed reading MFT Record 0: %w", err)
	}
	rec0 := make([]byte, MftRecordSize)
	copy(rec0, rec0Raw)
	if err := RemoveFixup(rec0); err != nil {
		return nil, fmt.Errorf("failed removing fixup from Record 0: %w", err)
	}

	off0 := int(binary.LittleEndian.Uint16(rec0[20:22]))
	var mftBmRuns []Run
	for off0+8 <= len(rec0) {
		atype := binary.LittleEndian.Uint32(rec0[off0 : off0+4])
		alen := binary.LittleEndian.Uint32(rec0[off0+4 : off0+8])
		if atype == AttrTypeEnd || alen == 0 || off0+int(alen) > len(rec0) {
			break
		}
		if atype == AttrTypeData && rec0[off0+8] != 0 {
			analysis.MftAllocBytes = binary.LittleEndian.Uint64(rec0[off0+40 : off0+48])
			analysis.MftRealBytes = binary.LittleEndian.Uint64(rec0[off0+48 : off0+56])
			ro := int(binary.LittleEndian.Uint16(rec0[off0+32 : off0+34]))
			analysis.ExistingMftRuns = ParseRunlist(rec0[off0+ro : off0+int(alen)])
		} else if atype == AttrTypeBitmap && rec0[off0+8] != 0 {
			ro := int(binary.LittleEndian.Uint16(rec0[off0+32 : off0+34]))
			mftBmRuns = ParseRunlist(rec0[off0+ro : off0+int(alen)])
		}
		off0 += int(alen)
	}

	analysis.CurrentMftMB = analysis.MftAllocBytes / (1024 * 1024)

	// Scan $MFT:BITMAP to find max allocated record
	if len(mftBmRuns) > 0 {
		bmData, err := ReadAt(h, mftBmRuns[0].LCN*uint64(clusterSize), int(mftBmRuns[0].Length*uint64(clusterSize)))
		if err == nil {
			var maxRec uint64
			var count uint64
			for byteIdx, b := range bmData {
				if b != 0 {
					for bit := 0; bit < 8; bit++ {
						if (b & (1 << bit)) != 0 {
							recIdx := uint64(byteIdx*8 + bit)
							count++
							if recIdx > maxRec {
								maxRec = recIdx
							}
						}
					}
				}
			}
			analysis.TotalAllocRecords = count
			analysis.MaxAllocRecord = maxRec
		}
	}

	minMftBytes := (analysis.MaxAllocRecord + 1) * MftRecordSize
	analysis.MinMftMB = (minMftBytes + 1024*1024 - 1) / (1024 * 1024)
	if analysis.MinMftMB == 0 {
		analysis.MinMftMB = 1
	}

	// Read Record 2 ($LogFile)
	rec2Raw, err := ReadAt(h, mftLcn*uint64(clusterSize)+2*MftRecordSize, MftRecordSize)
	if err == nil {
		rec2 := make([]byte, MftRecordSize)
		copy(rec2, rec2Raw)
		if err := RemoveFixup(rec2); err == nil {
			off2 := int(binary.LittleEndian.Uint16(rec2[20:22]))
			for off2+8 <= len(rec2) {
				atype := binary.LittleEndian.Uint32(rec2[off2 : off2+4])
				alen := binary.LittleEndian.Uint32(rec2[off2+4 : off2+8])
				if atype == AttrTypeEnd || alen == 0 || off2+int(alen) > len(rec2) {
					break
				}
				if atype == AttrTypeData && rec2[off2+8] != 0 {
					analysis.LogFileAllocBytes = binary.LittleEndian.Uint64(rec2[off2+40 : off2+48])
					ro := int(binary.LittleEndian.Uint16(rec2[off2+32 : off2+34]))
					analysis.ExistingLogRuns = ParseRunlist(rec2[off2+ro : off2+int(alen)])
					if len(analysis.ExistingLogRuns) > 0 {
						analysis.LogFileLcn = analysis.ExistingLogRuns[0].LCN
					}
				}
				off2 += int(alen)
			}
		}
	}
	analysis.CurrentLogFileMB = analysis.LogFileAllocBytes / (1024 * 1024)
	if analysis.CurrentLogFileMB == 0 {
		analysis.CurrentLogFileMB = 64
	}

	// Read Record 3 ($Volume) to get Volume Label
	rec3Raw, err := ReadAt(h, mftLcn*uint64(clusterSize)+3*MftRecordSize, MftRecordSize)
	if err == nil {
		rec3 := make([]byte, MftRecordSize)
		copy(rec3, rec3Raw)
		if err := RemoveFixup(rec3); err == nil {
			off3 := int(binary.LittleEndian.Uint16(rec3[20:22]))
			for off3+8 <= len(rec3) {
				atype := binary.LittleEndian.Uint32(rec3[off3 : off3+4])
				alen := binary.LittleEndian.Uint32(rec3[off3+4 : off3+8])
				if atype == AttrTypeEnd || alen == 0 || off3+int(alen) > len(rec3) {
					break
				}
				if atype == AttrTypeVolumeName {
					voff := int(binary.LittleEndian.Uint16(rec3[off3+20 : off3+22]))
					vlen := int(binary.LittleEndian.Uint32(rec3[off3+16 : off3+20]))
					val := rec3[off3+voff : off3+voff+vlen]
					u16 := make([]uint16, len(val)/2)
					for i := range u16 {
						u16[i] = binary.LittleEndian.Uint16(val[i*2:])
					}
					analysis.VolumeLabel = syscall.UTF16ToString(u16)
				}
				off3 += int(alen)
			}
		}
	}

	// Read Record 25 ($ObjId)
	rec25Raw, err := ReadAt(h, mftLcn*uint64(clusterSize)+25*MftRecordSize, MftRecordSize)
	if err == nil {
		rec25 := make([]byte, MftRecordSize)
		copy(rec25, rec25Raw)
		if err := RemoveFixup(rec25); err == nil {
			off25 := int(binary.LittleEndian.Uint16(rec25[20:22]))
			for off25+8 <= len(rec25) {
				atype := binary.LittleEndian.Uint32(rec25[off25 : off25+4])
				alen := binary.LittleEndian.Uint32(rec25[off25+4 : off25+8])
				if atype == AttrTypeEnd || alen == 0 || off25+int(alen) > len(rec25) {
					break
				}
				if atype == AttrTypeIndexAllocation && rec25[off25+8] != 0 {
					analysis.ObjIdAllocBytes = binary.LittleEndian.Uint64(rec25[off25+40 : off25+48])
				}
				off25 += int(alen)
			}
		}
	}
	analysis.CurrentObjIdMB = analysis.ObjIdAllocBytes / (1024 * 1024)
	if analysis.CurrentObjIdMB == 0 {
		analysis.CurrentObjIdMB = 4
	}

	analysis.CurrentMftZoneMB = 200 // Standard default

	return analysis, nil
}

