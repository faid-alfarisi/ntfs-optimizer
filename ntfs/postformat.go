package ntfs

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// SetHiddenAndSystem sets FILE_ATTRIBUTE_HIDDEN and FILE_ATTRIBUTE_SYSTEM on a file or folder.
func SetHiddenAndSystem(path string) error {
	pUtf16, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	const (
		FILE_ATTRIBUTE_HIDDEN = 0x02
		FILE_ATTRIBUTE_SYSTEM = 0x04
	)
	return syscall.SetFileAttributes(pUtf16, FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM)
}

// GetCurrentUserSID retrieves the active Windows user's Security Identifier.
func GetCurrentUserSID() string {
	u, err := user.Current()
	if err == nil && u.Uid != "" && strings.HasPrefix(u.Uid, "S-1-") {
		return u.Uid
	}
	// Fallback to standard interactive user SID if not directly detectable
	return "S-1-5-21-2109798714-3862275685-1452596448-1001"
}

// PopulatePostFormatStructures sets up $Recycle.Bin and System Volume Information contents on mounted volumes.
func PopulatePostFormatStructures(target string) error {
	// Clean target to a volume root path (e.g. "F:\")
	t := strings.TrimPrefix(target, `\\.\`)
	t = strings.TrimRight(t, `/\`)
	if len(t) != 2 || t[1] != ':' {
		// Not a mounted drive letter (e.g. raw PhysicalDrive), skip Win32 file creation
		return nil
	}
	volRoot := t + `\`

	fmt.Printf("\n[*] Initializing standard Windows system folders on %s...\n", volRoot)

	// Wait briefly for Windows automounter to detect the new filesystem
	time.Sleep(300 * time.Millisecond)

	// 1. Configure $Recycle.Bin with active User SID and desktop.ini
	sid := GetCurrentUserSID()
	recycleDir := filepath.Join(volRoot, "$Recycle.Bin")
	userDir := filepath.Join(recycleDir, sid)

	if err := os.MkdirAll(userDir, 0777); err != nil {
		fmt.Printf(" [-] Note: could not create $Recycle.Bin directory: %v\n", err)
	} else {
		desktopIniPath := filepath.Join(userDir, "desktop.ini")
		desktopIniContent := []byte("[.ShellClassInfo]\r\nCLSID={645FF040-5081-101B-9F08-00AA002F954E}\r\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-8964\r\n")
		if err := os.WriteFile(desktopIniPath, desktopIniContent, 0666); err == nil {
			_ = SetHiddenAndSystem(desktopIniPath)
		}
		_ = SetHiddenAndSystem(userDir)
		_ = SetHiddenAndSystem(recycleDir)
		fmt.Printf(" [+] Configured $Recycle.Bin with User SID (%s) and desktop.ini (Hidden+System).\n", sid)
	}

	// 2. Ensure System Volume Information
	sviDir := filepath.Join(volRoot, "System Volume Information")
	trackingLog := filepath.Join(sviDir, "tracking.log")
	if _, err := os.Stat(sviDir); err == nil {
		// Try creating tracking.log (empty on first format)
		if f, err := os.OpenFile(trackingLog, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0666); err == nil {
			f.Close()
			_ = SetHiddenAndSystem(trackingLog)
			fmt.Println(" [+] Created empty tracking.log in System Volume Information.")
		}
	}

	return nil
}

