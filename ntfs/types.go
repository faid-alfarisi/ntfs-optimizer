package ntfs

// Common NTFS Attribute Types
const (
	AttrTypeStandardInformation = 0x10
	AttrTypeAttributeList       = 0x20
	AttrTypeFileName            = 0x30
	AttrTypeObjectID            = 0x40
	AttrTypeSecurityDescriptor  = 0x50
	AttrTypeVolumeName          = 0x60
	AttrTypeVolumeInformation   = 0x70
	AttrTypeData                = 0x80
	AttrTypeIndexRoot           = 0x90
	AttrTypeIndexAllocation     = 0xA0
	AttrTypeBitmap              = 0xB0
	AttrTypeReparsePoint        = 0xC0
	AttrTypeEAInformation       = 0xD0
	AttrTypeEA                  = 0xE0
	AttrTypeLoggedUtilityStream = 0x100
	AttrTypeEnd                 = 0xFFFFFFFF
)

// Common NTFS Collation Rules
const (
	CollationBinary       = 0
	CollationFileName     = 1
	CollationUnicode      = 2
	CollationUlongs       = 16
	CollationSecurityHash = 18
	CollationObjectId     = 19
)

// Record & Cluster standard constants
const (
	SectorSize             = 512
	DefaultClusterSize     = 4096
	DefaultSectorsPerClust = 8
	MftRecordSize          = 1024
	IndexBlockSize         = 4096
)

// Standard MFT Record numbers
const (
	RecordMFT        = 0
	RecordMFTMirr    = 1
	RecordLogFile    = 2
	RecordVolume     = 3
	RecordAttrDef    = 4
	RecordRoot       = 5
	RecordBitmap     = 6
	RecordBoot       = 7
	RecordBadClust   = 8
	RecordSecure     = 9
	RecordUpCase     = 10
	RecordExtend     = 11
	RecordQuota      = 24
	RecordObjId      = 25
	RecordReparse    = 26
	RecordRmMetadata = 27
	RecordDeleted    = 29
)

// Run represents a single non-resident data extent in clusters.
type Run struct {
	LCN    uint64 // Logical Cluster Number (absolute)
	Length uint64 // Number of clusters in this extent
}
