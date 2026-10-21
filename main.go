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

const AppVersion = "1.2"

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
	modeFlag := flag.String("mode", "", "Operation mode: 'compact', 'rearrange', 'reset-secure', 'reset-objid', 'reset-both', 'repair', or 'format'")
	driveFlag := flag.String("drive", "", "Drive letter to format or rearrange (e.g. F:)")
	targetFlag := flag.String("target", "", "Target volume or physical drive (e.g. \\\\.\\PhysicalDrive1 or F:)")
	mftSizeFlag := flag.Uint64("mft", 512, "Pre-sized MFT size in MB (default: 512)")
	mftZoneFlag := flag.Uint64("mft-zone", 200, "Pre-sized MFT Reserved Area in MB (default: 200)")
	objIdSizeFlag := flag.Uint64("objid", 4, "Pre-sized $ObjId:$O:INDEX_ALLOCATION in MB (default: 4)")
	logFileSizeFlag := flag.Uint64("logfile", 64, "Pre-sized $LogFile in MB (default: 64)")
	labelFlag := flag.String("label", "New Volume", "Volume label")
	compactMftFlag := flag.Bool("compact-mft", false, "Reduce MFT size to the absolute minimum after compacting (default: false)")
	yesFlag := flag.Bool("yes", false, "Skip confirmation prompt")
	interactiveFlag := flag.Bool("interactive", false, "Force interactive selector")
	versionFlag := flag.Bool("version", false, "Print version information and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("NTFS Optimizer v%s\n", AppVersion)
		return
	}

	reader := bufio.NewReader(os.Stdin)

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

	mode := strings.ToLower(*modeFlag)

	if isInteractive {
		printBanner()

		if mode == "" {
			fmt.Println(" Select Operation Mode:")
			fmt.Println("  [1] Compact MFT (Non-Destructive - Fill gaps, shrink MFT)")
			fmt.Println("  [2] Rearrange / Optimize Volume Metadata (Non-Destructive - Sequential layout)")
			fmt.Println("  [3] Reset $Secure (Non-Destructive - Recreate SDS/SDH/SII & restore Security IDs)")
			fmt.Println("  [4] Reset $ObjId (Non-Destructive - Delete Object IDs & wipe $ObjId:$O index)")
			fmt.Println("  [5] Reset Both $Secure & $ObjId (Non-Destructive - Combined metadata reset)")
			fmt.Println("  [6] Repair Volume & Clear Dirty Bit (Non-Destructive - Fix without chkdsk)")
			fmt.Println("  [7] Clean Sequential Format (Destructive - Fresh low-level format)")
			fmt.Println("--------------------------------------------------------------------------")
			fmt.Print("Choose mode [1-7, default: 1]: ")
			modeInput, _ := reader.ReadString('\n')
			modeInput = strings.TrimSpace(modeInput)
			switch modeInput {
			case "2":
				mode = "rearrange"
			case "3":
				mode = "reset-secure"
			case "4":
				mode = "reset-objid"
			case "5":
				mode = "reset-both"
			case "6":
				mode = "repair"
			case "7":
				mode = "format"
			default:
				mode = "compact"
			}
		}

		// Normalize aliases
		switch mode {
		case "secure", "sds", "reset-secure":
			mode = "reset-secure"
		case "objid", "oid", "reset-objid":
			mode = "reset-objid"
		case "reset", "both", "reset-all", "reset-both":
			mode = "reset-both"
		case "repair", "fix", "clear-dirty", "clean", "doctor", "chkdsk":
			mode = "repair"
		}

		// 1. List targets
		fmt.Println("\n[*] Scanning system for online drives...")
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

		if mode == "format" && len(disks) > 0 {
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

		fmt.Printf("\nSelect target number to %s: ", mode)
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
	}

	// Normalize aliases for CLI flags
	switch mode {
	case "secure", "sds", "reset-secure":
		mode = "reset-secure"
	case "objid", "oid", "reset-objid":
		mode = "reset-objid"
	case "reset", "both", "reset-all", "reset-both":
		mode = "reset-both"
	case "repair", "fix", "clear-dirty", "clean", "doctor", "chkdsk":
		mode = "repair"
	case "":
		mode = "compact"
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

	progress := func(phase string, curCluster uint64, totalClusters uint64) {
		pct := float64(curCluster) / float64(totalClusters) * 100.0
		if pct > 100.0 {
			pct = 100.0
		}
		fmt.Printf(" -> [%5.1f%%] %s\n", pct, phase)
	}

	if mode == "compact" {
		// Compact MFT Mode (Non-destructive)
		fmt.Println("[*] Inspecting existing volume structures and analyzing MFT record allocation...")
		analysis, err := ntfs.AnalyzeVolume(h, target)
		if err != nil {
			fmt.Printf("[-] Volume analysis failed: %v\n", err)
			ntfs.CloseTarget(h, isVol)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		printCompactAnalysisTable(analysis)

		shrinkMft := *compactMftFlag
		customMftMB := uint64(0)

		if isInteractive {
			fmt.Println("--------------------------------------------------------------------------")
			fmt.Print("Reduce MFT size to the absolute minimum after compacting? [y/N, default: N]: ")
			compactInput, _ := reader.ReadString('\n')
			compactInput = strings.ToLower(strings.TrimSpace(compactInput))
			if compactInput == "yes" || compactInput == "y" {
				shrinkMft = true
				customMftMB = analysis.CompactMinMftMB
				fmt.Printf("[+] $MFT size will be reduced to absolute minimum: %d MB\n", customMftMB)
			} else {
				shrinkMft = false
				customMftMB = promptUintWithMin(reader, "Pre-size for $MFT (MB)", analysis.CurrentMftMB, analysis.CompactMinMftMB)
			}
		} else {
			if shrinkMft {
				customMftMB = analysis.CompactMinMftMB
			} else if *mftSizeFlag >= analysis.CompactMinMftMB {
				customMftMB = *mftSizeFlag
			} else {
				customMftMB = analysis.CurrentMftMB
			}
		}

		if !*yesFlag {
			fmt.Println("\n==========================================================================")
			fmt.Println(" WARNING: IN-PLACE MFT COMPACTION WILL FILL GAPS AND RELOCATE MFT RECORDS")
			fmt.Printf(" Target: %s (%s)\n", target, formatSize(totalBytes))
			fmt.Println("==========================================================================")
			fmt.Print("Type 'yes' to confirm and proceed with compacting: ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.ToLower(strings.TrimSpace(confirm))
			if confirm != "yes" && confirm != "y" {
				fmt.Println("\n[*] Compaction aborted by user.")
				ntfs.CloseTarget(h, isVol)
				if isInteractive {
					pauseAndExit(reader)
				}
				return
			}
		}

		fmt.Println("\n[*] Starting Non-Destructive In-Place MFT Compaction...")
		err = ntfs.CompactVolumeMFT(h, analysis, shrinkMft, customMftMB, progress)
		ntfs.CloseTarget(h, isVol)

		if err != nil {
			fmt.Printf("\n[-] MFT Compaction failed: %v\n", err)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		fmt.Println("\n[+] SUCCESS! MFT records compacted into contiguous front layout with zero gaps.")
		fmt.Println("[+] All existing user files and directory trees preserved intact.")

	} else if mode == "rearrange" {
		// Rearrange Mode (Non-destructive)
		fmt.Println("[*] Inspecting existing volume structures and calculating minimum required sizes...")
		analysis, err := ntfs.AnalyzeVolume(h, target)
		if err != nil {
			fmt.Printf("[-] Volume analysis failed: %v\n", err)
			ntfs.CloseTarget(h, isVol)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		// Display current metadata status vs minimums
		printAnalysisTable(analysis)

		if isInteractive {
			*mftSizeFlag = promptUintWithMin(reader, "Pre-size for $MFT (MB)", analysis.CurrentMftMB, analysis.MinMftMB)
			*mftZoneFlag = promptUintWithMin(reader, "Pre-size for MFT RESERVED AREA (MB)", analysis.CurrentMftZoneMB, analysis.MinMftZoneMB)
			*objIdSizeFlag = promptUintWithMin(reader, "Pre-size for $ObjId:$O:INDEX_ALLOCATION (MB)", analysis.CurrentObjIdMB, analysis.MinObjIdMB)
			*logFileSizeFlag = promptUintWithMin(reader, "Pre-size for $LogFile (MB)", analysis.CurrentLogFileMB, analysis.MinLogFileMB)
			defLabel := analysis.VolumeLabel
			if defLabel == "" {
				defLabel = *labelFlag
			}
			*labelFlag = promptString(reader, "Volume Label", defLabel)
		} else {
			// Enforce minimums in non-interactive mode
			if *mftSizeFlag < analysis.MinMftMB {
				*mftSizeFlag = analysis.MinMftMB
			}
			if *logFileSizeFlag < analysis.MinLogFileMB {
				*logFileSizeFlag = analysis.MinLogFileMB
			}
			if *objIdSizeFlag < analysis.MinObjIdMB {
				*objIdSizeFlag = analysis.MinObjIdMB
			}
		}

		cfg := ntfs.LayoutConfig{
			TotalSectors:   analysis.TotalSectors,
			BytesPerSector: uint16(analysis.BytesPerSector),
			SectorPerClust: analysis.SectorPerClust,
			MftSizeMB:      *mftSizeFlag,
			MftZoneSizeMB:  *mftZoneFlag,
			ObjIdSizeMB:    *objIdSizeFlag,
			LogFileSizeMB:  *logFileSizeFlag,
			VolumeLabel:    *labelFlag,
			SerialNumber:   analysis.SerialNumber,
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

		printLayoutTable(layout)

		if !*yesFlag {
			fmt.Println("\n==========================================================================")
			fmt.Println(" WARNING: IN-PLACE REARRANGEMENT WILL RELOCATE METADATA AND COLLIDING FILES")
			fmt.Printf(" Target: %s (%s)\n", target, formatSize(totalBytes))
			fmt.Println("==========================================================================")
			fmt.Print("Type 'yes' to confirm and proceed with rearrangement: ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.ToLower(strings.TrimSpace(confirm))
			if confirm != "yes" && confirm != "y" {
				fmt.Println("\n[*] Rearrangement aborted by user.")
				ntfs.CloseTarget(h, isVol)
				if isInteractive {
					pauseAndExit(reader)
				}
				return
			}
		}

		fmt.Println("\n[*] Starting Non-Destructive In-Place NTFS Rearrangement...")
		err = ntfs.RearrangeVolume(h, analysis, layout, progress)
		ntfs.CloseTarget(h, isVol)

		if err != nil {
			fmt.Printf("\n[-] Rearrangement failed: %v\n", err)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		fmt.Println("\n[+] SUCCESS! NTFS Volume metadata rearranged into exact sequential front layout.")
		fmt.Println("[+] All existing user files and directory trees preserved intact.")

	} else if mode == "reset-secure" {
		// Reset $Secure Mode (Non-destructive)
		fmt.Println("[*] Inspecting existing volume structures and analyzing $Secure streams...")
		analysis, err := ntfs.AnalyzeVolume(h, target)
		if err != nil {
			fmt.Printf("[-] Volume analysis failed: %v\n", err)
			ntfs.CloseTarget(h, isVol)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		userSID := ntfs.GetCurrentUserSID()
		printResetSecureTable(analysis, userSID)

		if !*yesFlag {
			fmt.Println("\n==========================================================================")
			fmt.Println(" WARNING: IN-PLACE $SECURE RESET WILL RECREATE SDS/SDH/SII STREAMS")
			fmt.Printf(" Target: %s (%s)\n", target, formatSize(totalBytes))
			fmt.Printf(" - Active User SID : %s\n", userSID)
			fmt.Println(" - Any unmatched Security ID will be updated according to security list")
			fmt.Println("==========================================================================")
			fmt.Print("Type 'yes' to confirm and proceed with resetting $Secure: ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.ToLower(strings.TrimSpace(confirm))
			if confirm != "yes" && confirm != "y" {
				fmt.Println("\n[*] $Secure reset aborted by user.")
				ntfs.CloseTarget(h, isVol)
				if isInteractive {
					pauseAndExit(reader)
				}
				return
			}
		}

		fmt.Println("\n[*] Starting In-Place $Secure Recreation & Security ID Verification...")
		res, err := ntfs.ResetSecure(h, analysis, progress)
		ntfs.CloseTarget(h, isVol)

		if err != nil {
			fmt.Printf("\n[-] Reset $Secure failed: %v\n", err)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		fmt.Println("\n[+] SUCCESS! $Secure streams recreated and Security IDs verified.")
		fmt.Printf(" - Active User SID Applied : %s\n", res.UserSID)
		fmt.Printf(" - $SDS Stream Location    : LCN %d (%d clusters / 260 KB)\n", res.SdsLcn, res.SdsClusters)
		fmt.Printf(" - $SDH / $SII Allocations : LCN %d / %d (sorted index blocks)\n", res.SdhLcn, res.SiiLcn)
		fmt.Printf(" - Total Records Scanned   : %d\n", res.TotalRecordsScanned)
		fmt.Printf(" - Security IDs Repaired   : %d (Updated to valid list)\n", res.RecordsUpdated)
		fmt.Println("[+] All existing user files and directory trees preserved intact.")

	} else if mode == "reset-objid" {
		// Reset $ObjId Mode (Non-destructive)
		fmt.Println("[*] Inspecting existing volume structures and analyzing $ObjId:$O allocation...")
		analysis, err := ntfs.AnalyzeVolume(h, target)
		if err != nil {
			fmt.Printf("[-] Volume analysis failed: %v\n", err)
			ntfs.CloseTarget(h, isVol)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		printResetObjIdTable(analysis)

		if !*yesFlag {
			fmt.Println("\n==========================================================================")
			fmt.Println(" WARNING: IN-PLACE $OBJID RESET WILL REMOVE ALL OBJECT IDS FROM RECORDS")
			fmt.Printf(" Target: %s (%s)\n", target, formatSize(totalBytes))
			fmt.Println(" - $ObjId:$O Index blocks will be cleared")
			fmt.Println(" - Existing $ObjId cluster allocation will NOT be shrunk (preserved as-is)")
			fmt.Println("==========================================================================")
			fmt.Print("Type 'yes' to confirm and proceed with resetting $ObjId: ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.ToLower(strings.TrimSpace(confirm))
			if confirm != "yes" && confirm != "y" {
				fmt.Println("\n[*] $ObjId reset aborted by user.")
				ntfs.CloseTarget(h, isVol)
				if isInteractive {
					pauseAndExit(reader)
				}
				return
			}
		}

		fmt.Println("\n[*] Starting In-Place $ObjId Reset...")
		res, err := ntfs.ResetObjId(h, analysis, progress)
		ntfs.CloseTarget(h, isVol)

		if err != nil {
			fmt.Printf("\n[-] Reset $ObjId failed: %v\n", err)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		fmt.Println("\n[+] SUCCESS! Object IDs reset across volume.")
		fmt.Printf(" - Record 25 ($ObjId)      : $INDEX_ROOT '$O' reset to empty leaf\n")
		fmt.Printf(" - Allocation Preserved    : %s (%d clusters / no shrinking)\n", formatSize(res.ObjIdBytesPreserved), res.ObjIdClusters)
		fmt.Printf(" - Total Records Scanned   : %d\n", res.TotalRecordsScanned)
		fmt.Printf(" - Object IDs Removed      : %d (Stripped from MFT records)\n", res.ObjIdsRemoved)
		fmt.Println("[+] All existing user files and directory trees preserved intact.")

	} else if mode == "reset-both" {
		// Reset Both $Secure & $ObjId Mode (Non-destructive)
		fmt.Println("[*] Inspecting existing volume structures for metadata reset...")
		analysis, err := ntfs.AnalyzeVolume(h, target)
		if err != nil {
			fmt.Printf("[-] Volume analysis failed: %v\n", err)
			ntfs.CloseTarget(h, isVol)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		userSID := ntfs.GetCurrentUserSID()
		printResetCombinedTable(analysis, userSID)

		if !*yesFlag {
			fmt.Println("\n==========================================================================")
			fmt.Println(" WARNING: IN-PLACE RESET OF BOTH $SECURE AND $OBJID METADATA")
			fmt.Printf(" Target: %s (%s)\n", target, formatSize(totalBytes))
			fmt.Printf(" - Active User SID : %s\n", userSID)
			fmt.Println(" - Recreates $Secure streams (SDS/SDH/SII) and maps missing Security IDs")
			fmt.Println(" - Removes Object IDs from all records and clears $ObjId:$O (no shrinking)")
			fmt.Println("==========================================================================")
			fmt.Print("Type 'yes' to confirm and proceed with combined reset: ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.ToLower(strings.TrimSpace(confirm))
			if confirm != "yes" && confirm != "y" {
				fmt.Println("\n[*] Combined reset aborted by user.")
				ntfs.CloseTarget(h, isVol)
				if isInteractive {
					pauseAndExit(reader)
				}
				return
			}
		}

		fmt.Println("\n[*] Starting In-Place Reset of $Secure and $ObjId...")
		res, err := ntfs.ResetBoth(h, analysis, progress)
		ntfs.CloseTarget(h, isVol)

		if err != nil {
			fmt.Printf("\n[-] Combined reset failed: %v\n", err)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		fmt.Println("\n[+] SUCCESS! Both $Secure and $ObjId reset successfully.")
		fmt.Printf(" - $SDS Stream Location    : LCN %d (%d clusters / 260 KB)\n", res.SecureResult.SdsLcn, res.SecureResult.SdsClusters)
		fmt.Printf(" - Security IDs Repaired   : %d\n", res.SecureResult.RecordsUpdated)
		fmt.Printf(" - $ObjId Allocation       : %s (%d clusters preserved)\n", formatSize(res.ObjIdResult.ObjIdBytesPreserved), res.ObjIdResult.ObjIdClusters)
		fmt.Printf(" - Object IDs Removed      : %d\n", res.ObjIdResult.ObjIdsRemoved)
		fmt.Println("[+] All existing user files and directory trees preserved intact.")

	} else if mode == "repair" {
		// Repair & Clear Dirty Bit Mode (Non-destructive)
		fmt.Println("[*] Inspecting existing volume structures and dirty state...")
		analysis, err := ntfs.AnalyzeVolume(h, target)
		if err != nil {
			fmt.Printf("[-] Volume analysis failed: %v\n", err)
			ntfs.CloseTarget(h, isVol)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		printRepairTable(analysis)

		if !*yesFlag {
			fmt.Println("\n==========================================================================")
			fmt.Println(" NATIVE VOLUME REPAIR & DIRTY BIT CLEAR (NON-DESTRUCTIVE)")
			fmt.Printf(" Target: %s (%s, Label: %s)\n", target, formatSize(totalBytes), analysis.VolumeLabel)
			fmt.Println(" - Clears volume dirty bit and chkdsk flags in Record 3 ($Volume)")
			fmt.Println(" - Resets $LogFile transaction restart pages to clean state")
			fmt.Println(" - Validates MFT records, Security IDs, and $Bitmap consistency in-place")
			fmt.Println(" - Validates $I30 directory index sequence numbers")
			fmt.Println(" - Zero metadata shifting, zero $Secure purging, NO chkdsk.log created")
			fmt.Println("==========================================================================")
			fmt.Print("Type 'yes' to confirm and proceed with repair: ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.ToLower(strings.TrimSpace(confirm))
			if confirm != "yes" && confirm != "y" {
				fmt.Println("\n[*] Repair operation aborted by user.")
				ntfs.CloseTarget(h, isVol)
				if isInteractive {
					pauseAndExit(reader)
				}
				return
			}
		}

		fmt.Println("\n[*] Starting Native Volume Repair & Dirty Bit Clear...")
		res, err := ntfs.RepairVolume(h, analysis, progress)
		ntfs.CloseTarget(h, isVol)

		if err != nil {
			fmt.Printf("\n[-] Repair operation failed: %v\n", err)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		fmt.Println("\n[+] SUCCESS! Volume repaired and marked clean.")
		dirtyStatus := "Already Clean"
		if res.WasDirty {
			dirtyStatus = "Dirty -> Cleared & Marked Clean"
		}
		fmt.Printf(" - Volume Dirty State     : %s\n", dirtyStatus)
		fmt.Printf(" - $LogFile Restart Area  : Reset to clean state (0xFF)\n")
		fmt.Printf(" - MFT Records Checked    : %d\n", res.RecordsChecked)
		fmt.Printf(" - MFT Records Repaired   : %d\n", res.RecordsRepaired)
		fmt.Printf(" - Security IDs Restored  : %d\n", res.SecIDsRepaired)
		fmt.Printf(" - $Bitmap Clusters Fixed : %d\n", res.BitmapMismatchesFixed)
		fmt.Printf(" - Directory Indices Checked: %d\n", res.IndicesChecked)
		fmt.Printf(" - Index Entries Fixed    : %d\n", res.IndexEntriesFixed)
		fmt.Println("[+] Windows will now recognize the drive as 100% clean without prompting chkdsk.")

	} else {
		// Format Mode (Destructive)
		if isInteractive {
			*mftSizeFlag = promptUint(reader, "Pre-size for $MFT (MB)", *mftSizeFlag)
			*mftZoneFlag = promptUint(reader, "Pre-size for MFT RESERVED AREA (MB)", *mftZoneFlag)
			*objIdSizeFlag = promptUint(reader, "Pre-size for $ObjId:$O:INDEX_ALLOCATION (MB)", *objIdSizeFlag)
			*logFileSizeFlag = promptUint(reader, "Pre-size for $LogFile (MB)", *logFileSizeFlag)
			*labelFlag = promptString(reader, "Volume Label", *labelFlag)
		}

		totalSectors := totalBytes / ntfs.SectorSize
		existingSerial := ntfs.GetExistingVolumeSerial(h)
		cfg := ntfs.LayoutConfig{
			TotalSectors:   totalSectors,
			BytesPerSector: ntfs.SectorSize,
			SectorPerClust: ntfs.DefaultSectorsPerClust,
			MftSizeMB:      *mftSizeFlag,
			MftZoneSizeMB:  *mftZoneFlag,
			ObjIdSizeMB:    *objIdSizeFlag,
			LogFileSizeMB:  *logFileSizeFlag,
			VolumeLabel:    *labelFlag,
			SerialNumber:   existingSerial,
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

		printLayoutTable(layout)

		if !*yesFlag {
			fmt.Println("\n==========================================================================")
			fmt.Println(" WARNING: ALL DATA ON THE TARGET WILL BE COMPLETELY DESTROYED!")
			fmt.Printf(" Target: %s (%s)\n", target, formatSize(totalBytes))
			fmt.Println("==========================================================================")
			fmt.Print("Type 'yes' to confirm and proceed with formatting: ")
			confirm, _ := reader.ReadString('\n')
			confirm = strings.ToLower(strings.TrimSpace(confirm))
			if confirm != "yes" && confirm != "y" {
				fmt.Println("\n[*] Formatting aborted by user.")
				ntfs.CloseTarget(h, isVol)
				if isInteractive {
					pauseAndExit(reader)
				}
				return
			}
		}

		fmt.Println("\n[*] Starting Custom Sequential NTFS Format...")
		err = ntfs.FormatVolume(h, layout, progress)
		ntfs.CloseTarget(h, isVol)

		if err != nil {
			fmt.Printf("\n[-] Formatting failed: %v\n", err)
			if isInteractive {
				pauseAndExit(reader)
			}
			os.Exit(1)
		}

		_ = ntfs.PopulatePostFormatStructures(target)

		fmt.Println("\n[+] SUCCESS! NTFS Volume formatted successfully with exact sequential layout.")
		fmt.Println("[+] Root permissions set to 'Everyone' Full Access.")
		fmt.Println("[+] All unmovable system metadata placed contiguously at the front of the disk.")
	}

	if isInteractive {
		pauseAndExit(reader)
	}
}

func printBanner() {
	fmt.Println("==========================================================================")
	fmt.Printf("   NTFS OPTIMIZER v%-6s - DIRECT DISK SEQUENTIAL ENGINE & FORMATTER\n", AppVersion)
	fmt.Println("==========================================================================")
	fmt.Println(" Features:")
	fmt.Println("  - Optimization : Compact MFT & Rearrange metadata contiguously")
	fmt.Println("  - Maintenance  : Reset $Secure, Reset $ObjId & Repair/Clear Dirty Bit")
	fmt.Println("  - Formatting   : Clean sequential low-level NTFS format")
	fmt.Println("  - Unmovable NTFS Metadata in sequential front order")
	fmt.Println("  - Pre-sized $MFT, MFT RESERVED AREA, and $ObjId:$O:INDEX_ALLOCATION")
	fmt.Println("  - Root directory with 'Everyone' Full Access permissions")
	fmt.Println("==========================================================================")
}

func printCompactAnalysisTable(a *ntfs.VolumeAnalysis) {
	fmt.Println("\n==========================================================================")
	fmt.Println("                   CURRENT VOLUME MFT RECORD STATUS                       ")
	fmt.Println("==========================================================================")
	fmt.Printf(" Target Volume          : %s\n", a.Target)
	fmt.Printf(" Current Volume Label   : %s\n", a.VolumeLabel)
	fmt.Printf(" Total Capacity         : %s (%d clusters, %d sectors)\n",
		formatSize(a.TotalBytes), a.TotalClusters, a.TotalSectors)
	fmt.Printf(" Cluster Size           : %d bytes\n", a.ClusterSize)
	fmt.Printf(" Total Allocated Records: %d (Highest Record ID: #%d)\n",
		a.TotalAllocRecords, a.MaxAllocRecord)
	fmt.Println("--------------------------------------------------------------------------")
	fmt.Printf(" %-24s %-16s %-16s\n", "Structure", "Current Size", "Compacted Minimum")
	fmt.Println("--------------------------------------------------------------------------")
	fmt.Printf(" %-24s %-16s %-16s\n", "$MFT", fmt.Sprintf("%d MB", a.CurrentMftMB), fmt.Sprintf("%d MB", a.CompactMinMftMB))
	fmt.Println("==========================================================================")
}

func printResetSecureTable(a *ntfs.VolumeAnalysis, userSID string) {
	fmt.Println("\n==========================================================================")
	fmt.Println("                   $SECURE METADATA CONFIGURATION                         ")
	fmt.Println("==========================================================================")
	fmt.Printf(" Target Volume          : %s\n", a.Target)
	fmt.Printf(" Current Volume Label   : %s\n", a.VolumeLabel)
	fmt.Printf(" Active User SID        : %s\n", userSID)
	fmt.Printf(" Total Allocated Records: %d (Highest Record ID: #%d)\n",
		a.TotalAllocRecords, a.MaxAllocRecord)
	fmt.Println("--------------------------------------------------------------------------")
	fmt.Println(" $Secure Plan           : Recreate $SDS (260 KB), $SDH (4 KB), $SII (4 KB)")
	fmt.Println(" Security ID Policy     : Verified against valid set (SecIDs 256..271)")
	fmt.Println(" Mapped IDs from list   : Root system files, $Extend, $Recycle.Bin, SVI,")
	fmt.Println("                          Standard Folder (267), Standard File (268),")
	fmt.Println("                          IMAGELOAD (269), Auslogics Temp (270)")
	fmt.Println("==========================================================================")
}

func printResetObjIdTable(a *ntfs.VolumeAnalysis) {
	fmt.Println("\n==========================================================================")
	fmt.Println("                    $OBJID METADATA CONFIGURATION                         ")
	fmt.Println("==========================================================================")
	fmt.Printf(" Target Volume          : %s\n", a.Target)
	fmt.Printf(" Current Volume Label   : %s\n", a.VolumeLabel)
	fmt.Printf(" Total Allocated Records: %d (Highest Record ID: #%d)\n",
		a.TotalAllocRecords, a.MaxAllocRecord)
	fmt.Printf(" Current $ObjId Size    : %d MB (%d clusters)\n",
		a.CurrentObjIdMB, a.ObjIdAllocBytes/uint64(a.ClusterSize))
	fmt.Println("--------------------------------------------------------------------------")
	fmt.Println(" Action                 : Remove ObjectID attributes (0x40) from all records")
	fmt.Println(" Index Reset            : Wipe $ObjId:$O allocation & reset root to empty leaf")
	fmt.Println(" Allocation Policy      : Preserved intact (No shrinking)")
	fmt.Println("==========================================================================")
}

func printResetCombinedTable(a *ntfs.VolumeAnalysis, userSID string) {
	fmt.Println("\n==========================================================================")
	fmt.Println("             COMBINED $SECURE & $OBJID METADATA RESET                     ")
	fmt.Println("==========================================================================")
	fmt.Printf(" Target Volume          : %s\n", a.Target)
	fmt.Printf(" Current Volume Label   : %s\n", a.VolumeLabel)
	fmt.Printf(" Active User SID        : %s\n", userSID)
	fmt.Printf(" Total Allocated Records: %d (Highest Record ID: #%d)\n",
		a.TotalAllocRecords, a.MaxAllocRecord)
	fmt.Printf(" Current $ObjId Size    : %d MB (Allocation preserved intact)\n", a.CurrentObjIdMB)
	fmt.Println("--------------------------------------------------------------------------")
	fmt.Println(" 1. $Secure             : Recreate SDS/SDH/SII & restore Security IDs")
	fmt.Println(" 2. $ObjId              : Remove Object IDs & clear $ObjId:$O (no shrinking)")
	fmt.Println("==========================================================================")
}

func printAnalysisTable(a *ntfs.VolumeAnalysis) {
	fmt.Println("\n==========================================================================")
	fmt.Println("                   CURRENT VOLUME METADATA CONFIGURATION                  ")
	fmt.Println("==========================================================================")
	fmt.Printf(" Target Volume          : %s\n", a.Target)
	fmt.Printf(" Current Volume Label   : %s\n", a.VolumeLabel)
	fmt.Printf(" Total Capacity         : %s (%d clusters, %d sectors)\n",
		formatSize(a.TotalBytes), a.TotalClusters, a.TotalSectors)
	fmt.Printf(" Cluster Size           : %d bytes\n", a.ClusterSize)
	fmt.Printf(" Total Allocated Records: %d (Highest Record ID: #%d)\n",
		a.TotalAllocRecords, a.MaxAllocRecord)
	fmt.Println("--------------------------------------------------------------------------")
	fmt.Printf(" %-24s %-16s %-16s %-16s\n", "Structure", "Current Size", "Minimum Size", "Recommended")
	fmt.Println("--------------------------------------------------------------------------")
	fmt.Printf(" %-24s %-16s %-16s %-16s\n", "$MFT", fmt.Sprintf("%d MB", a.CurrentMftMB), fmt.Sprintf("%d MB", a.MinMftMB), "512 MB")
	fmt.Printf(" %-24s %-16s %-16s %-16s\n", "MFT Reserved Area", fmt.Sprintf("%d MB", a.CurrentMftZoneMB), fmt.Sprintf("%d MB", a.MinMftZoneMB), "200 MB")
	fmt.Printf(" %-24s %-16s %-16s %-16s\n", "$ObjId:$O", fmt.Sprintf("%d MB", a.CurrentObjIdMB), fmt.Sprintf("%d MB", a.MinObjIdMB), "4 MB")
	fmt.Printf(" %-24s %-16s %-16s %-16s\n", "$LogFile", fmt.Sprintf("%d MB", a.CurrentLogFileMB), fmt.Sprintf("%d MB", a.MinLogFileMB), "64 MB")
	fmt.Println("==========================================================================")
	fmt.Println(" Note: Sizes cannot be set smaller than their Minimum Size.")
	fmt.Println("--------------------------------------------------------------------------")
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

	idx := 1
	row := func(name string, start uint64, count uint64) {
		fmt.Printf("[%2d] %-30s %-12d %-12d %-12s\n",
			idx, name, start, count, formatSize(count*uint64(l.Config.ClusterSize)))
		idx++
	}

	row("$Boot", l.BootLcn, l.BootClusters)
	row("$MFTMirr", l.MftMirrLcn, l.MftMirrClusters)
	row("$LogFile", l.LogFileLcn, l.LogFileClusters)
	row("$Bitmap", l.BitmapLcn, l.BitmapClusters)
	row("$Extend\\$Deleted:$I30", l.DeletedLcn, l.DeletedClusters)
	row("$ObjId:$O:INDEX_ALLOCATION", l.ObjIdLcn, l.ObjIdClusters)
	row("$SDH:INDEX_ALLOCATION", l.SdhLcn, l.SdhClusters)
	row("$SII:INDEX_ALLOCATION", l.SiiLcn, l.SiiClusters)
	row("$MFT (Pre-sized)", l.MftLcn, l.MftClusters)
	row("MFT RESERVED AREA", l.MftZoneLcn, l.MftZoneClusters)
	row("$MFT:BITMAP", l.MftBitmapLcn, l.MftBitmapClusters)
	row("$Secure:$SDS (from sample)", l.SdsLcn, l.SdsClusters)
	row("$UpCase", l.UpCaseLcn, l.UpCaseClusters)
	if l.ObjIdBitmapClusters > 0 {
		row("$ObjId:$O:BITMAP", l.ObjIdBitmapLcn, l.ObjIdBitmapClusters)
	}
	row("$AttrDef", l.AttrDefLcn, l.AttrDefClusters)
	row("$Root:$INDEX_ALLOCATION", l.RootIndexLcn, l.RootIndexClusters)
	row("User Data Free Space", l.DataStartLcn, l.FreeClusters)
	fmt.Println("==========================================================================")
}

func promptUintWithMin(r *bufio.Reader, label string, defaultVal uint64, minVal uint64) uint64 {
	for {
		fmt.Printf("%s [Current/Default: %d MB, Min: %d MB]: ", label, defaultVal, minVal)
		text, _ := r.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			if defaultVal < minVal {
				defaultVal = minVal
			}
			return defaultVal
		}
		val, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			fmt.Println("[-] Invalid number. Please enter a valid positive integer.")
			continue
		}
		if val < minVal {
			fmt.Printf("[-] Error: Value (%d MB) cannot be smaller than minimum required size of %d MB. Please enter a larger size.\n", val, minVal)
			continue
		}
		return val
	}
}

func printRepairTable(a *ntfs.VolumeAnalysis) {
	fmt.Println("\n==========================================================================")
	fmt.Println("              NATIVE VOLUME REPAIR & DIRTY BIT INSPECTION                ")
	fmt.Println("==========================================================================")
	fmt.Printf(" Target Volume          : %s\n", a.Target)
	fmt.Printf(" Current Volume Label   : %s\n", a.VolumeLabel)
	fmt.Printf(" Total Capacity         : %s (%d clusters, %d sectors)\n",
		formatSize(a.TotalBytes), a.TotalClusters, a.TotalSectors)
	fmt.Printf(" Cluster Size           : %d bytes\n", a.ClusterSize)
	fmt.Printf(" Total Records in MFT   : %d (Highest Record ID: #%d)\n",
		a.TotalAllocRecords, a.MaxAllocRecord)
	fmt.Printf(" $LogFile Size          : %d MB (LCN: %d)\n", a.CurrentLogFileMB, a.LogFileLcn)
	fmt.Printf(" Volume Bitmap Location : LCN %d (%s)\n", a.BitmapLcn, formatSize(a.BitmapAllocBytes))
	fmt.Println(" Action                 : Clear Dirty Bit, Reset $LogFile, Validate MFT & Indices")
	fmt.Println(" Integrity Guarantee   : Non-destructive, preserve metadata layout & $Secure")
	fmt.Println("--------------------------------------------------------------------------")
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
