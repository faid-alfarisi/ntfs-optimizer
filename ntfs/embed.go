package ntfs

import (
	"embed"
	_ "embed"
)

// Embedded static user templates and tables
//
//go:embed assets/boot_code.bin
var BootCodeBin []byte

//go:embed assets/logfile_restart.bin
var LogFileRestartBin []byte

//go:embed assets/attrdef.bin
var AttrDefBin []byte

//go:embed assets/upcase.bin
var UpCaseBin []byte

//go:embed assets/root_mft.bin
var RootMftBin []byte

//go:embed assets/root_indx.bin
var RootIndxBin []byte

//go:embed assets/secure_mft.bin
var SecureMftBin []byte

//go:embed assets/secure_sds.bin
var SecureSdsBin []byte

//go:embed assets/secure_sdh.bin
var SecureSdhBin []byte

//go:embed assets/secure_sii.bin
var SecureSiiBin []byte

// All 64 reference system records (rec_00.bin .. rec_63.bin)
//
//go:embed assets/system_records/rec_*.bin
var SystemRecordsFS embed.FS
