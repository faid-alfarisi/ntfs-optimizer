package ntfs

import (
	"fmt"
)

// LayoutConfig defines configuration parameters for formatting.
type LayoutConfig struct {
	TotalSectors   uint64
	BytesPerSector uint16
	SectorPerClust uint8
	ClusterSize    uint32

	MftSizeMB     uint64
	MftZoneSizeMB uint64
	ObjIdSizeMB   uint64
	LogFileSizeMB uint64
	VolumeLabel   string
	SerialNumber  uint64
}

// VolumeLayout contains the calculated LCNs and cluster counts for every structure.
type VolumeLayout struct {
	Config LayoutConfig

	TotalClusters uint64

	// Sequential ordered structures at the front:
	// 1. $Boot
	BootLcn      uint64
	BootClusters uint64

	// 2. $MFTMirr
	MftMirrLcn      uint64
	MftMirrClusters uint64

	// 3. $LogFile
	LogFileLcn      uint64
	LogFileClusters uint64

	// 4. $Bitmap (Volume allocation bitmap)
	BitmapLcn      uint64
	BitmapClusters uint64
	BitmapBytes    uint64

	// 5. $Extend\$Deleted:$I30:INDEX_ALLOCATION
	DeletedLcn      uint64
	DeletedClusters uint64

	// 6. $ObjId:$O:INDEX_ALLOCATION
	ObjIdLcn            uint64
	ObjIdClusters       uint64
	ObjIdBitmapLcn      uint64
	ObjIdBitmapClusters uint64
	ObjIdBitmapBytes    uint64

	// 7. $Secure:$SDH:INDEX_ALLOCATION
	SdhLcn      uint64
	SdhClusters uint64

	// 8. $Secure:$SII:INDEX_ALLOCATION
	SiiLcn      uint64
	SiiClusters uint64

	// 9. $MFT
	MftLcn      uint64
	MftClusters uint64

	// 10. MFT RESERVED AREA
	MftZoneLcn      uint64
	MftZoneClusters uint64

	// 11. $MFT:BITMAP
	MftBitmapLcn      uint64
	MftBitmapClusters uint64
	MftBitmapBytes    uint64

	// 12. Subsequent metadata in order:
	// $Secure:$SDS
	SdsLcn      uint64
	SdsClusters uint64

	// $UpCase
	UpCaseLcn      uint64
	UpCaseClusters uint64

	// $AttrDef
	AttrDefLcn      uint64
	AttrDefClusters uint64

	// $Root:$INDEX_ALLOCATION
	RootIndexLcn      uint64
	RootIndexClusters uint64

	// User data start LCN
	DataStartLcn uint64
	FreeClusters uint64
}

// CalculateLayout computes the exact cluster layout according to the user's ordered requirements.
func CalculateLayout(cfg LayoutConfig) (*VolumeLayout, error) {
	if cfg.BytesPerSector == 0 {
		cfg.BytesPerSector = SectorSize
	}
	if cfg.SectorPerClust == 0 {
		cfg.SectorPerClust = DefaultSectorsPerClust
	}
	cfg.ClusterSize = uint32(cfg.BytesPerSector) * uint32(cfg.SectorPerClust)

	// NTFS reserves the last sector for the backup boot sector
	usableSectors := cfg.TotalSectors - 1
	totalClusters := usableSectors / uint64(cfg.SectorPerClust)
	if totalClusters < 10000 {
		return nil, fmt.Errorf("volume too small: %d clusters (%d sectors)", totalClusters, cfg.TotalSectors)
	}

	layout := &VolumeLayout{
		Config:        cfg,
		TotalClusters: totalClusters,
	}

	var curLcn uint64 = 0

	// 1. $Boot (Sectors 0..15 = 8192 bytes = 2 clusters at 4KB/cluster)
	layout.BootLcn = curLcn
	layout.BootClusters = 8192 / uint64(cfg.ClusterSize)
	if layout.BootClusters == 0 {
		layout.BootClusters = 1
	}
	curLcn += layout.BootClusters

	// 2. $MFTMirr (4 records = 4096 bytes = 1 cluster)
	layout.MftMirrLcn = curLcn
	layout.MftMirrClusters = 1
	curLcn += layout.MftMirrClusters

	// 3. $LogFile
	logFileBytes := cfg.LogFileSizeMB * 1024 * 1024
	if logFileBytes == 0 {
		logFileBytes = 64 * 1024 * 1024 // Default 64 MB
	}
	layout.LogFileLcn = curLcn
	layout.LogFileClusters = (logFileBytes + uint64(cfg.ClusterSize) - 1) / uint64(cfg.ClusterSize)
	curLcn += layout.LogFileClusters

	// 4. $Bitmap (Volume Cluster Allocation Bitmap)
	bitmapBytes := (totalClusters + 7) / 8
	layout.BitmapBytes = bitmapBytes
	layout.BitmapLcn = curLcn
	layout.BitmapClusters = (bitmapBytes + uint64(cfg.ClusterSize) - 1) / uint64(cfg.ClusterSize)
	curLcn += layout.BitmapClusters

	// 5. $Extend\$Deleted:$I30:INDEX_ALLOCATION (64 KB = 16 clusters)
	deletedBytes := uint64(65536)
	layout.DeletedLcn = curLcn
	layout.DeletedClusters = (deletedBytes + uint64(cfg.ClusterSize) - 1) / uint64(cfg.ClusterSize)
	curLcn += layout.DeletedClusters

	// 6. $ObjId:$O:INDEX_ALLOCATION (User pre-sized)
	objIdBytes := cfg.ObjIdSizeMB * 1024 * 1024
	if objIdBytes == 0 {
		objIdBytes = 4 * 1024 * 1024 // Default 4 MB
	}
	layout.ObjIdLcn = curLcn
	layout.ObjIdClusters = (objIdBytes + uint64(cfg.ClusterSize) - 1) / uint64(cfg.ClusterSize)
	curLcn += layout.ObjIdClusters

	objIdBmBytes := (layout.ObjIdClusters + 7) / 8
	layout.ObjIdBitmapBytes = objIdBmBytes

	// 7. $Secure:$SDH:INDEX_ALLOCATION
	layout.SdhLcn = curLcn
	layout.SdhClusters = 1 // 4096 bytes
	curLcn += layout.SdhClusters

	// 8. $Secure:$SII:INDEX_ALLOCATION
	layout.SiiLcn = curLcn
	layout.SiiClusters = 1 // 4096 bytes
	curLcn += layout.SiiClusters

	// 9. $MFT (User pre-sized)
	mftBytes := cfg.MftSizeMB * 1024 * 1024
	if mftBytes == 0 {
		mftBytes = 512 * 1024 * 1024 // Default 512 MB
	}
	layout.MftLcn = curLcn
	layout.MftClusters = (mftBytes + uint64(cfg.ClusterSize) - 1) / uint64(cfg.ClusterSize)
	curLcn += layout.MftClusters

	// 10. MFT RESERVED AREA (User pre-sized)
	mftZoneBytes := cfg.MftZoneSizeMB * 1024 * 1024
	if mftZoneBytes == 0 {
		mftZoneBytes = 200 * 1024 * 1024 // Default 200 MB
	}
	layout.MftZoneLcn = curLcn
	layout.MftZoneClusters = (mftZoneBytes + uint64(cfg.ClusterSize) - 1) / uint64(cfg.ClusterSize)
	curLcn += layout.MftZoneClusters

	// 11. $MFT:BITMAP (Bitmap for MFT records: MftClusters * 4 records)
	totalMftRecords := layout.MftClusters * uint64(cfg.ClusterSize/MftRecordSize)
	mftBitmapBytes := (totalMftRecords + 7) / 8
	layout.MftBitmapBytes = mftBitmapBytes
	layout.MftBitmapLcn = curLcn
	layout.MftBitmapClusters = (mftBitmapBytes + uint64(cfg.ClusterSize) - 1) / uint64(cfg.ClusterSize)
	curLcn += layout.MftBitmapClusters

	// 12. Subsequent movable metadata in order:
	// $Secure:$SDS (266,240 bytes = 65 clusters)
	sdsBytes := uint64(len(SecureSdsBin))
	if sdsBytes == 0 {
		sdsBytes = 266240
	}
	layout.SdsLcn = curLcn
	layout.SdsClusters = (sdsBytes + uint64(cfg.ClusterSize) - 1) / uint64(cfg.ClusterSize)
	curLcn += layout.SdsClusters

	// $UpCase (131,072 bytes = 32 clusters)
	upCaseBytes := uint64(len(UpCaseBin))
	if upCaseBytes == 0 {
		upCaseBytes = 131072
	}
	layout.UpCaseLcn = curLcn
	layout.UpCaseClusters = (upCaseBytes + uint64(cfg.ClusterSize) - 1) / uint64(cfg.ClusterSize)
	curLcn += layout.UpCaseClusters

	// $ObjId:$O:BITMAP (Placed here with movable metadata if non-resident, matching Drive E: layout)
	if objIdBmBytes > 256 {
		layout.ObjIdBitmapLcn = curLcn
		layout.ObjIdBitmapClusters = (objIdBmBytes + uint64(cfg.ClusterSize) - 1) / uint64(cfg.ClusterSize)
		curLcn += layout.ObjIdBitmapClusters
	}

	// $AttrDef (2560 bytes = 1 cluster)
	layout.AttrDefLcn = curLcn
	layout.AttrDefClusters = 1
	curLcn += layout.AttrDefClusters

	// $Root:$INDEX_ALLOCATION (4096 bytes = 1 cluster)
	layout.RootIndexLcn = curLcn
	layout.RootIndexClusters = 1
	curLcn += layout.RootIndexClusters

	// End of front metadata -> User data starts here
	layout.DataStartLcn = curLcn
	if curLcn >= totalClusters {
		return nil, fmt.Errorf("requested pre-sizes (%d clusters) exceed total volume capacity (%d clusters)", curLcn, totalClusters)
	}
	layout.FreeClusters = totalClusters - curLcn

	return layout, nil
}
