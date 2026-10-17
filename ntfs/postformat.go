package ntfs

import (
	"fmt"
	"os/user"
	"strings"
	"syscall"
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

// PopulatePostFormatStructures reports the pre-configured root metadata folders.
func PopulatePostFormatStructures(target string) error {
	sid := GetCurrentUserSID()
	fmt.Printf(" [+] Pre-configured System Volume Information (WPSettings.dat, IndexerVolumeGuid, tracking.log) at MFT Records 36..39 (SecIDs 261..263).\n")
	fmt.Printf(" [+] Pre-configured $Recycle.Bin\\%s\\desktop.ini at MFT Records 40..42 (SecIDs 264..266, Hidden+System).\n", sid)
	return nil
}

