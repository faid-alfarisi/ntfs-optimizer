# NTFS Optimizer & Formatter

A high-performance, low-level NTFS volume optimizer and formatter written in Go for Windows.

Standard Windows NTFS formatting and routine disk usage scatter unmovable system metadata files (such as `$MFT`, `$LogFile`, `$Bitmap`, `$Secure`, and directory indices) across different areas of a disk. Over time, file deletions also leave fragmented gaps inside the Master File Table (MFT).

**NTFS Optimizer** solves this by offering low-level control over NTFS disk structures: it can compact fragmented MFT record gaps in-place, reorganize all system metadata into a strictly sequential layout at the front of the volume, or perform a clean, zero-fragmentation sequential format from scratch.

---

## Key Features

- **Sequential Front Metadata**: Positions all essential NTFS system files contiguously at the very beginning of the partition, keeping the remainder of the volume completely free and contiguous for user data.
- **In-Place MFT Compaction (Non-Destructive)**: Scans for gaps between allocated records, shifts user records forward, updates `$I30` B-tree directory indices, and optionally shrinks `$MFT` cluster allocation down to the absolute minimum needed.
- **In-Place Metadata Rearrangement (Non-Destructive)**: Safely evacuates user data clusters out of the reserved metadata area and arranges system metadata into a deterministic sequential order while preserving all existing files and directories intact.
- **Custom Sequential Formatter (Clean/Destructive)**: Direct low-level NTFS volume formatting with custom pre-allocated sizes for `$MFT`, MFT Reserved Zone, `$LogFile`, and `$ObjId`, setting root directory permissions to Full Access for `Everyone`.
- **Interactive & CLI Modes**: Easy-to-use menu-driven terminal interface with automatic drive scanning, or fully automatable command-line flags.

---

## Sequential Metadata Layout

When formatting or rearranging a volume, **NTFS Optimizer** places system structures in the following contiguous order starting at LCN 0:

| Order | Structure | Description |
|:-----:|:---------|:------------|
| 1 | `$Boot` | VBR and BPB (Sectors 0–15) |
| 2 | `$MFTMirr` | Mirror copy of the first 4 MFT records (LCN 2) |
| 3 | `$LogFile` | Transaction journaling log (pre-sized, e.g., 64 MB) |
| 4 | `$Bitmap` | Cluster allocation bitmap for the volume |
| 5 | `$Extend\$Deleted` | Deleted files index (`$I30:INDEX_ALLOCATION`) |
| 6 | `$ObjId:$O` | Object ID index allocation and index bitmap |
| 7 | `$Secure:$SDH` | Security Descriptor Hash index allocation |
| 8 | `$Secure:$SII` | Security ID Index allocation |
| 9 | `$MFT` | Master File Table (pre-sized or custom) |
| 10 | `MFT Zone` | Contiguous reserved area for MFT growth |
| 11 | `$MFT:BITMAP` | MFT record allocation bitmap |
| 12 | `$Secure:$SDS` | Security descriptor data stream |
| 13 | `$UpCase` | Unicode uppercase conversion table (128 KB) |
| 14 | `$AttrDef` | Attribute definition table (2.5 KB) |
| 15 | `$Root` | Volume root directory (`$I30` index block) |
| 16 | **User Data Area** | Unfragmented contiguous free space for user files |

---

## Operating Modes

### 1. Compact MFT (Non-Destructive)
- **Goal**: Eliminate holes and fragmented gaps inside the Master File Table.
- **How it works**:
  - Traverses the entire MFT, identifying active and empty record slots.
  - Relocates records from higher numbers into vacated slots towards the front.
  - Patches all parent directory index trees (`$I30`) and cross-record references so file paths remain valid.
  - Zeroes out vacated records.
  - *Optional*: Shrinks the `$MFT` file allocation size on disk down to the minimum cluster count required.

### 2. Rearrange / Optimize Volume (Non-Destructive)
- **Goal**: Relocate unmovable system metadata files on an existing NTFS volume to the front of the disk.
- **How it works**:
  - Analyzes existing volume metadata geometry, cluster sizes, and record allocations.
  - Calculates the minimum required sizes for `$MFT`, `$LogFile`, `$ObjId`, and metadata streams.
  - Safely evacuates any user data clusters residing in the target metadata zones to free clusters further down the volume.
  - Re-writes and re-maps system files into sequential order.
  - Updates the boot sector and volume structures in place without losing existing user files.

### 3. Clean Sequential Format (Destructive)
- **Goal**: Initialize a new partition or physical drive with zero metadata fragmentation from day one.
- **How it works**:
  - Writes a standard NTFS VBR and boot sector with an aligned backup sector at the volume end.
  - Generates initial MFT records (`$MFT`, `$MFTMirr`, `$LogFile`, `$Volume`, `$AttrDef`, `$Root`, `$Bitmap`, `$Boot`, `$BadClust`, `$Secure`, `$UpCase`, `$Extend`).
  - Pre-allocates contiguous runs for `$LogFile`, `$ObjId`, `$Secure`, `$MFT`, and the MFT Reserved Area.
  - Initializes root folders (including `$RECYCLE.BIN` and `System Volume Information`) and sets root security permissions to `Everyone` (Full Control).

---

## Requirements

- **Operating System**: Windows 10 / 11 or Windows Server (x64 / ARM64).
- **Privileges**: Must be executed **as Administrator** (requires direct access to `\\.\<Drive>:` or `\\.\PhysicalDrive<N>`, volume locking, and volume dismounting).
- **Go Toolchain**: Go 1.20+ (only required if building from source).

---

## Building

You can compile the binary using Go or the included batch script:

### Using Go CLI:
```powershell
go build -ldflags="-s -w" -o ntfs-optimizer.exe .
```

### Using the Batch Script:
Double-click or run:
```cmd
"Build EXE.bat"
```

---

## How to Use

> [!IMPORTANT]
> Always run your command prompt or terminal **as Administrator**. Ensure that open applications or explorer windows are not actively locking files on the target drive before operating on it.

### Interactive Mode (Recommended)

Simply run the executable without flags:

```powershell
.\ntfs-optimizer.exe
```

The tool will display a guided menu:
1. Choose an operation mode (`[1] Compact MFT`, `[2] Rearrange Volume`, or `[3] Clean Format`).
2. Select your target drive from the auto-detected list of online volumes.
3. Review the current metadata metrics and layout preview.
4. Confirm the operation to proceed.

---

### Command-Line / Scripting Usage

You can automate operations or run non-interactively using CLI flags:

```text
Flags:
  -mode string
        Operation mode: 'compact', 'rearrange', or 'format'
  -drive string
        Drive letter (e.g. F: or D:)
  -target string
        Target volume or physical disk (e.g. F: or \\.\PhysicalDrive1)
  -compact-mft
        Reduce MFT size to absolute minimum after compacting (default: false)
  -mft uint
        Pre-sized MFT size in MB (default: 512)
  -mft-zone uint
        Pre-sized MFT Reserved Area in MB (default: 200)
  -logfile uint
        Pre-sized $LogFile in MB (default: 64)
  -objid uint
        Pre-sized $ObjId:$O:INDEX_ALLOCATION in MB (default: 4)
  -label string
        Volume label (default: "New Volume")
  -yes
        Skip confirmation prompt (unattended mode)
  -interactive
        Force interactive selector
```

#### Examples

**1. Compact MFT records on drive `E:` and shrink MFT to minimum:**
```powershell
.\ntfs-optimizer.exe -mode compact -drive E: -compact-mft -yes
```

**2. Rearrange existing volume `G:` with custom pre-sized MFT:**
```powershell
.\ntfs-optimizer.exe -mode rearrange -drive G: -mft 1024 -mft-zone 400 -yes
```

**3. Perform a clean sequential format on drive `F:` with label "Storage":**
```powershell
.\ntfs-optimizer.exe -mode format -drive F: -label "Storage" -mft 512 -logfile 64 -yes
```

---

## Safety & Precautions

- **Exclusive Volume Lock**: The tool automatically attempts to lock (`FSCTL_LOCK_VOLUME`) and dismount (`FSCTL_DISMOUNT_VOLUME`) the target volume before performing low-level block operations. Close any active programs, command prompts, or File Explorer windows using the drive.
- **System Drive Protection**: Do not attempt to rearrange or format the Windows system volume (`C:`) while Windows is actively running from it.
- **Data Backups**: While `compact` and `rearrange` are non-destructive, low-level disk operations can be interrupted by sudden power losses or hardware faults. It is always recommended to have a current backup of important data before running low-level volume modifications.

---

## License

This project is licensed under the [MIT License](LICENSE).

