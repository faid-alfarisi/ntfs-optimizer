package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"ntfs-optimizer/ntfs"
)

func formatSize(bytes uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
		TB = 1024 * GB
	)
	switch {
	case bytes >= TB:
		return fmt.Sprintf("%.2f TB", float64(bytes)/float64(TB))
	case bytes >= GB:
		return fmt.Sprintf("%.2f GB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2f MB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2f KB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func main() {
	driveFlag := flag.String("drive", "", "Drive letter to format (e.g. E:)")
	targetFlag := flag.String("target", "", "Target volume or physical drive (e.g. \\\\.\\PhysicalDrive1 or E:)")
	mftSizeFlag := flag.Uint64("mft", 512, "Pre-sized MFT size in MB (default: 512)")
	mftZoneFlag := flag.Uint64("mft-zone", 200, "Pre-sized MFT Reserved Area in MB (default: 200)")
	objIdSizeFlag := flag.Uint64("objid", 4, "Pre-sized $ObjId:$O:INDEX_ALLOCATION in MB (default: 4)")
	logFileSizeFlag := flag.Uint64("logfile", 64, "Pre-sized $LogFile in MB (default: 64)")
	labelFlag := flag.String("label", "New Volume", "Volume label")
	yesFlag := flag.Bool("yes", false, "Skip confirmation prompt")
	interactiveFlag := flag.Bool("interactive", false, "Force interactive selector")

	flag.Parse()

	reader := bufio.NewReader(os.Stdin)

	// Check if CLI flags were provided
	target := *targetFlag
	if target == "" && *driveFlag != "" {
		target = *driveFlag
	}

	isInteractive := *interactiveFlag || target == ""

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("\n[-] Unexpected Fatal Error: %v\n", r)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}
	}()

	if isInteractive {
		printBanner()

		// 1. List volumes and physical drives
		fmt.Println("[*] Scanning system for online drives and offline disks...")
		volumes, _ := ntfs.ListVolumes()
		disks := ntfs.ListDisks()

		type Choice struct {
			Tag         string
			DisplayName string
			Target      string
			TotalBytes  uint64
		}
		var choices []Choice

		fmt.Println("\nAvailable Online Volumes:")
		fmt.Println("---------------------------------------------------------------------------------")
		fmt.Printf(" #   %-6s %-18s %-8s %-12s %-12s\n", "Drive", "Label", "FS", "Total Size", "Free Size")
		fmt.Println("---------------------------------------------------------------------------------")
		idx := 1
		for _, v := range volumes {
			fmt.Printf("[%2d] %-6s %-18s %-8s %-12s %-12s\n",
				idx,
				v.Letter,
				truncate(v.Label, 18),
				v.FileSystem,
				formatSize(v.TotalBytes),
				formatSize(v.FreeBytes),
			)
			choices = append(choices, Choice{
				Tag:         fmt.Sprintf("%d", idx),
				DisplayName: fmt.Sprintf("Volume %s (%s, %s)", v.Letter, v.Label, formatSize(v.TotalBytes)),
				Target:      v.Letter,
				TotalBytes:  v.TotalBytes,
			})
			idx++
		}

		if len(disks) > 0 {
			fmt.Println("\nAvailable Physical Drives (Online / Offline / VHD):")
			fmt.Println("---------------------------------------------------------------------------------")
			fmt.Printf(" #   %-22s %-15s\n", "Device Path", "Total Size")
			fmt.Println("---------------------------------------------------------------------------------")
			for _, d := range disks {
				fmt.Printf("[%2d] %-22s %-15s\n",
					idx,
					d.Path,
					formatSize(d.TotalBytes),
				)
				choices = append(choices, Choice{
					Tag:         fmt.Sprintf("%d", idx),
					DisplayName: fmt.Sprintf("Physical Drive %s (%s)", d.Path, formatSize(d.TotalBytes)),
					Target:      d.Path,
					TotalBytes:  d.TotalBytes,
				})
				idx++
			}
		}

		if len(choices) == 0 {
			fmt.Println("\n[-] No drives found. Make sure to run this tool as Administrator.")
			pauseAndExit(reader)
			return
		}

		fmt.Print("\nSelect target number to format: ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		choiceIdx, err := strconv.Atoi(input)
		if err != nil || choiceIdx < 1 || choiceIdx > len(choices) {
			fmt.Println("[-] Invalid selection.")
			pauseAndExit(reader)
			return
		}

		selectedChoice := choices[choiceIdx-1]
		target = selectedChoice.Target
		fmt.Printf("\n[+] Selected: %s\n", selectedChoice.DisplayName)

		// Ask for pre-sizes
		*mftSizeFlag = promptUint(reader, "Pre-size for $MFT (MB)", *mftSizeFlag)
		*mftZoneFlag = promptUint(reader, "Pre-size for MFT RESERVED AREA (MB)", *mftZoneFlag)
		*objIdSizeFlag = promptUint(reader, "Pre-size for $ObjId:$O:INDEX_ALLOCATION (MB)", *objIdSizeFlag)
		*logFileSizeFlag = promptUint(reader, "Pre-size for $LogFile (MB)", *logFileSizeFlag)
		*labelFlag = promptString(reader, "Volume Label", *labelFlag)
	}

	// Open target
	fmt.Printf("\n[*] Opening target '%s' (Locking & Dismounting if active volume)...\n", target)
	h, totalBytes, isVol, err := ntfs.OpenTarget(target)
	if err != nil {
		fmt.Printf("[-] Error: %v\n", err)
		if isInteractive {
			pauseAndExit(reader)
		}
		os.Exit(1)
	}

	totalSectors := totalBytes / ntfs.SectorSize
	cfg := ntfs.LayoutConfig{
		TotalSectors:   totalSectors,
		BytesPerSector: ntfs.SectorSize,
		SectorPerClust: ntfs.DefaultSectorsPerClust,
		MftSizeMB:      *mftSizeFlag,
		MftZoneSizeMB:  *mftZoneFlag,
		ObjIdSizeMB:    *objIdSizeFlag,
		LogFileSizeMB:  *logFileSizeFlag,
		VolumeLabel:    *labelFlag,
	}

	layout, err := ntfs.CalculateLayout(cfg)
	if err != nil {
		fmt.Printf("[-] Layout error: %v\n", err)
		ntfs.CloseTarget(h, isVol)
		if isInteractive {
			pauseAndExit(reader)
		}
		os.Exit(1)
	}

	// Display Sequential Layout Summary
	printLayoutTable(layout)

	if !*yesFlag {
		fmt.Println("\n==========================================================================")
		fmt.Println(" WARNING: ALL DATA ON THE TARGET WILL BE COMPLETELY DESTROYED!")
		fmt.Printf(" Target: %s (%s)\n", target, formatSize(totalBytes))
		fmt.Println("==========================================================================")
		fmt.Print("Type 'YES' to confirm and proceed with formatting: ")
		confirm, _ := reader.ReadString('\n')
		confirm = strings.TrimSpace(confirm)
		if confirm != "YES" {
			fmt.Println("\n[*] Formatting aborted by user.")
			ntfs.CloseTarget(h, isVol)
			if isInteractive {
				pauseAndExit(reader)
			}
			return
		}
	}

	fmt.Println("\n[*] Starting Custom Sequential NTFS Format...")
	progress := func(phase string, curCluster uint64, totalClusters uint64) {
		pct := float64(curCluster) / float64(totalClusters) * 100.0
		if pct > 100.0 {
			pct = 100.0
		}
		fmt.Printf(" -> [%5.1f%%] %s\n", pct, phase)
	}

	err = ntfs.FormatVolume(h, layout, progress)
	// Dismount and close volume handle so Windows can remount it cleanly
	ntfs.CloseTarget(h, isVol)

	if err != nil {
		fmt.Printf("\n[-] Formatting failed: %v\n", err)
		if isInteractive {
			pauseAndExit(reader)
		}
		os.Exit(1)
	}

	// Initialize standard Windows folders: $Recycle.Bin with User SID & desktop.ini, and System Volume Information
	_ = ntfs.PopulatePostFormatStructures(target)

	fmt.Println("\n[+] SUCCESS! NTFS Volume formatted successfully with exact sequential layout.")
	fmt.Println("[+] Root permissions set to 'Everyone' Full Access.")
	fmt.Println("[+] All unmovable system metadata placed contiguously at the front of the disk.")

	if isInteractive {
		pauseAndExit(reader)
	}
}

func printBanner() {
	fmt.Println("==========================================================================")
	fmt.Println("      CUSTOM SEQUENTIAL NTFS OPTIMIZER & FORMATTER (Go Native)            ")
	fmt.Println("==========================================================================")
	fmt.Println(" Features:")
	fmt.Println("  - Unmovable NTFS Metadata in sequential front order")
	fmt.Println("  - Pre-sized $MFT, MFT RESERVED AREA, and $ObjId:$O:INDEX_ALLOCATION")
	fmt.Println("  - Root directory with 'Everyone' Full Access permissions")
	fmt.Println("  - Supports Online Volumes, Offlined Disks, VHDs, and Raw Physical Drives")
	fmt.Println("==========================================================================")
}

func printLayoutTable(l *ntfs.VolumeLayout) {
	fmt.Println("\n==========================================================================")
	fmt.Println("                  CALCULATED SEQUENTIAL CLUSTER LAYOUT                    ")
	fmt.Println("==========================================================================")
	fmt.Printf(" Total Capacity : %s (%d Clusters, %d Sectors)\n",
		formatSize(l.TotalClusters*uint64(l.Config.ClusterSize)), l.TotalClusters, l.Config.TotalSectors)
	fmt.Println("--------------------------------------------------------------------------")
	fmt.Printf(" #   %-30s %-12s %-12s %-12s\n", "Metadata Structure", "Start LCN", "Clusters", "Size")
	fmt.Println("--------------------------------------------------------------------------")

	row := func(idx int, name string, start uint64, count uint64) {
		fmt.Printf("[%2d] %-30s %-12d %-12d %-12s\n",
			idx, name, start, count, formatSize(count*uint64(l.Config.ClusterSize)))
	}

	row(1, "$Boot", l.BootLcn, l.BootClusters)
	row(2, "$MFTMirr", l.MftMirrLcn, l.MftMirrClusters)
	row(3, "$LogFile", l.LogFileLcn, l.LogFileClusters)
	row(4, "$Bitmap", l.BitmapLcn, l.BitmapClusters)
	row(5, "$ObjId:$O:INDEX_ALLOCATION", l.ObjIdLcn, l.ObjIdClusters)
	if l.ObjIdBitmapClusters > 0 {
		row(6, "$ObjId:$O:BITMAP", l.ObjIdBitmapLcn, l.ObjIdBitmapClusters)
	}
	row(7, "$SDH:INDEX_ALLOCATION", l.SdhLcn, l.SdhClusters)
	row(8, "$SII:INDEX_ALLOCATION", l.SiiLcn, l.SiiClusters)
	row(9, "$MFT (Pre-sized)", l.MftLcn, l.MftClusters)
	row(10, "MFT RESERVED AREA", l.MftZoneLcn, l.MftZoneClusters)
	row(11, "$MFT:BITMAP", l.MftBitmapLcn, l.MftBitmapClusters)
	row(12, "$Secure:$SDS (from sample)", l.SdsLcn, l.SdsClusters)
	row(13, "$UpCase", l.UpCaseLcn, l.UpCaseClusters)
	row(14, "$AttrDef", l.AttrDefLcn, l.AttrDefClusters)
	row(15, "$Root:$INDEX_ALLOCATION", l.RootIndexLcn, l.RootIndexClusters)
	row(16, "User Data Free Space", l.DataStartLcn, l.FreeClusters)
	fmt.Println("==========================================================================")
}

func promptUint(r *bufio.Reader, label string, defaultVal uint64) uint64 {
	fmt.Printf("%s [%d]: ", label, defaultVal)
	text, _ := r.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return defaultVal
	}
	val, err := strconv.ParseUint(text, 10, 64)
	if err != nil {
		return defaultVal
	}
	return val
}

func promptString(r *bufio.Reader, label string, defaultVal string) string {
	fmt.Printf("%s [%s]: ", label, defaultVal)
	text, _ := r.ReadString('\n')
	text = strings.TrimSpace(text)
	if text == "" {
		return defaultVal
	}
	return text
}

func pauseAndExit(r *bufio.Reader) {
	fmt.Print("\nPress Enter to exit...")
	_, _ = r.ReadString('\n')
}

func truncate(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen-3] + "..."
	}
	return s
}

