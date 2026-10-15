package ntfs

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetLogicalDriveStringsW = modkernel32.NewProc("GetLogicalDriveStringsW")
	procGetDriveTypeW           = modkernel32.NewProc("GetDriveTypeW")
	procGetVolumeInformationW   = modkernel32.NewProc("GetVolumeInformationW")
	procGetDiskFreeSpaceExW     = modkernel32.NewProc("GetDiskFreeSpaceExW")
	procSetFilePointerEx        = modkernel32.NewProc("SetFilePointerEx")
	procWriteFile               = modkernel32.NewProc("WriteFile")
)

const (
	FSCTL_LOCK_VOLUME            = 0x00090018
	FSCTL_UNLOCK_VOLUME          = 0x0009001C
	FSCTL_DISMOUNT_VOLUME        = 0x00090020
	FSCTL_ALLOW_EXTENDED_DASD_IO = 0x00090083

	IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0
	IOCTL_DISK_GET_LENGTH_INFO       = 0x0007405C

	DRIVE_FIXED     = 3
	DRIVE_REMOVABLE = 2
)

// VolumeInfo describes an online drive partition.
type VolumeInfo struct {
	Letter     string
	Label      string
	FileSystem string
	TotalBytes uint64
	FreeBytes  uint64
	IsFixed    bool
}

// DiskInfo describes a physical offline/online disk.
type DiskInfo struct {
	Index      int
	Path       string
	TotalBytes uint64
	IsOffline  bool
}

// ListVolumes returns all available fixed/removable drive letters.
func ListVolumes() ([]VolumeInfo, error) {
	buf := make([]uint16, 256)
	r1, _, _ := procGetLogicalDriveStringsW.Call(uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])))
	if r1 == 0 {
		return nil, fmt.Errorf("GetLogicalDriveStringsW failed")
	}

	var volumes []VolumeInfo
	start := 0
	for i, c := range buf[:r1] {
		if c == 0 {
			if i > start {
				drive := syscall.UTF16ToString(buf[start:i])
				drivePtr, _ := syscall.UTF16PtrFromString(drive)
				dt, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(drivePtr)))
				if dt == DRIVE_FIXED || dt == DRIVE_REMOVABLE {
					volNameBuf := make([]uint16, 256)
					fsNameBuf := make([]uint16, 256)
					var serial, maxComp, flags uint32

					procGetVolumeInformationW.Call(
						uintptr(unsafe.Pointer(drivePtr)),
						uintptr(unsafe.Pointer(&volNameBuf[0])),
						uintptr(len(volNameBuf)),
						uintptr(unsafe.Pointer(&serial)),
						uintptr(unsafe.Pointer(&maxComp)),
						uintptr(unsafe.Pointer(&flags)),
						uintptr(unsafe.Pointer(&fsNameBuf[0])),
						uintptr(len(fsNameBuf)),
					)

					var freeCaller, total, totalFree uint64
					procGetDiskFreeSpaceExW.Call(
						uintptr(unsafe.Pointer(drivePtr)),
						uintptr(unsafe.Pointer(&freeCaller)),
						uintptr(unsafe.Pointer(&total)),
						uintptr(unsafe.Pointer(&totalFree)),
					)

					volName := syscall.UTF16ToString(volNameBuf)
					fsName := syscall.UTF16ToString(fsNameBuf)
					letter := drive
					if len(letter) >= 2 && letter[1] == ':' {
						letter = letter[:2]
					}

					volumes = append(volumes, VolumeInfo{
						Letter:     letter,
						Label:      volName,
						FileSystem: fsName,
						TotalBytes: total,
						FreeBytes:  totalFree,
						IsFixed:    dt == DRIVE_FIXED,
					})
				}
			}
			start = i + 1
		}
	}
	return volumes, nil
}

// ListDisks scans for physical drives (\\.\PhysicalDrive0..16)
func ListDisks() []DiskInfo {
	var disks []DiskInfo
	for i := 0; i < 16; i++ {
		path := fmt.Sprintf(`\\.\PhysicalDrive%d`, i)
		pathPtr, err := syscall.UTF16PtrFromString(path)
		if err != nil {
			continue
		}
		h, err := syscall.CreateFile(
			pathPtr,
			syscall.GENERIC_READ,
			syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
			nil,
			syscall.OPEN_EXISTING,
			0,
			0,
		)
		if err != nil {
			continue
		}

		var lengthBytes [8]byte
		var bytesRet uint32
		err = syscall.DeviceIoControl(
			h,
			IOCTL_DISK_GET_LENGTH_INFO,
			nil,
			0,
			&lengthBytes[0],
			uint32(len(lengthBytes)),
			&bytesRet,
			nil,
		)
		syscall.CloseHandle(h)

		var total uint64
		if err == nil {
			total = binary.LittleEndian.Uint64(lengthBytes[:])
		}
		if total > 0 {
			disks = append(disks, DiskInfo{
				Index:      i,
				Path:       path,
				TotalBytes: total,
			})
		}
	}
	return disks
}

// OpenTarget opens either a drive letter (e.g. "E:" or "E:\") or physical drive path (e.g. "\\.\PhysicalDrive1").
// If target is a volume, it locks and dismounts it.
func OpenTarget(target string) (syscall.Handle, uint64, bool, error) {
	isVolume := false
	openPath := target

	if len(target) == 1 || (len(target) >= 2 && target[1] == ':') {
		letter := string(target[0])
		openPath = fmt.Sprintf(`\\.\%s:`, letter)
		isVolume = true
	}

	pathPtr, err := syscall.UTF16PtrFromString(openPath)
	if err != nil {
		return 0, 0, false, err
	}

	h, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0, 0, false, fmt.Errorf("failed to open target '%s': %w (Make sure to Run as Administrator)", openPath, err)
	}

	if isVolume {
		var bytesRet uint32
		// Lock volume
		_ = syscall.DeviceIoControl(h, FSCTL_LOCK_VOLUME, nil, 0, nil, 0, &bytesRet, nil)
		// Dismount volume
		_ = syscall.DeviceIoControl(h, FSCTL_DISMOUNT_VOLUME, nil, 0, nil, 0, &bytesRet, nil)
		// Allow raw extended DASD I/O to avoid filesystem boundary restrictions
		_ = syscall.DeviceIoControl(h, FSCTL_ALLOW_EXTENDED_DASD_IO, nil, 0, nil, 0, &bytesRet, nil)
		// Settle delay to let Windows storage subsystem complete dismount transition
		time.Sleep(100 * time.Millisecond)
	}

	// Get total length
	var lengthBytes [8]byte
	var bytesRet uint32
	err = syscall.DeviceIoControl(
		h,
		IOCTL_DISK_GET_LENGTH_INFO,
		nil,
		0,
		&lengthBytes[0],
		uint32(len(lengthBytes)),
		&bytesRet,
		nil,
	)
	if err != nil {
		syscall.CloseHandle(h)
		return 0, 0, false, fmt.Errorf("failed to get volume length info: %w", err)
	}

	totalSize := binary.LittleEndian.Uint64(lengthBytes[:])
	return h, totalSize, isVolume, nil
}

// FlushTarget flushes all cached writes directly to disk.
func FlushTarget(h syscall.Handle) {
	_ = syscall.FlushFileBuffers(h)
}

// CloseTarget unlocks volume if needed and closes handle.
func CloseTarget(h syscall.Handle, isVolume bool) {
	_ = syscall.FlushFileBuffers(h)
	if isVolume {
		var bytesRet uint32
		_ = syscall.DeviceIoControl(h, FSCTL_UNLOCK_VOLUME, nil, 0, nil, 0, &bytesRet, nil)
	}
	_ = syscall.CloseHandle(h)
}

// SeekAndWrite writes a byte buffer to the given byte offset on disk with retry on transient storage busy states.
func SeekAndWrite(h syscall.Handle, offset uint64, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}

	for attempt := 0; attempt < 5; attempt++ {
		var newPos int64
		r1, _, err := procSetFilePointerEx.Call(
			uintptr(h),
			uintptr(offset),
			uintptr(unsafe.Pointer(&newPos)),
			0, // FILE_BEGIN
		)
		if r1 == 0 {
			return fmt.Errorf("SetFilePointerEx failed at offset %d: %w", offset, err)
		}

		var written uint32
		r1, _, err = procWriteFile.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&written)),
			0,
		)
		if r1 != 0 && int(written) == len(buf) {
			return nil
		}

		// Check if error is transient (ERROR_NOT_READY = 21, ERROR_BUSY = 170)
		if errno, ok := err.(syscall.Errno); ok && (errno == 21 || errno == 170 || errno == 142) {
			time.Sleep(time.Duration((attempt+1)*150) * time.Millisecond)
			continue
		}
		if int(written) != len(buf) {
			return fmt.Errorf("partial write at offset %d (newPos=%d): requested %d, wrote %d (err: %v)", offset, newPos, len(buf), written, err)
		}
		return fmt.Errorf("WriteFile failed at offset %d (newPos=%d): %w", offset, newPos, err)
	}
	return fmt.Errorf("WriteFile failed at offset %d after 5 attempts", offset)
}

// SeekAndRead reads a byte buffer from the given byte offset on disk.
func SeekAndRead(h syscall.Handle, offset uint64, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	var newPos int64
	r1, _, err := procSetFilePointerEx.Call(
		uintptr(h),
		uintptr(offset),
		uintptr(unsafe.Pointer(&newPos)),
		0, // FILE_BEGIN
	)
	if r1 == 0 {
		return fmt.Errorf("SetFilePointerEx failed at offset %d: %w", offset, err)
	}

	var bytesRead uint32
	r1, _, err = syscall.SyscallN(
		modkernel32.NewProc("ReadFile").Addr(),
		uintptr(h),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&bytesRead)),
		0,
	)
	if r1 == 0 {
		return fmt.Errorf("ReadFile failed at offset %d: %w", offset, err)
	}
	return nil
}

// GetExistingVolumeSerial reads the 64-bit volume serial number from the existing boot sector, if valid.
func GetExistingVolumeSerial(h syscall.Handle) uint64 {
	buf := make([]byte, 512)
	if err := SeekAndRead(h, 0, buf); err == nil {
		if buf[510] == 0x55 && buf[511] == 0xAA && string(buf[3:7]) == "NTFS" {
			return binary.LittleEndian.Uint64(buf[72:80])
		}
	}
	return 0
}

