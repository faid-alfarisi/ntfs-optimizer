# NTFS Optimizer & Formatter

A high-performance, low-level NTFS volume optimizer and formatter written in Go for Windows.

Standard Windows NTFS formatting and routine disk usage scatter unmovable system metadata files (such as `$MFT`, `$LogFile`, `$Bitmap`, `$Secure`, and directory indices) across different areas of a disk. Over time, file deletions also leave fragmented gaps inside the Master File Table (MFT), and metadata indexes (such as `$Secure` security descriptors and `$ObjId` object identifiers) accumulate orphaned entries.

**NTFS Optimizer** solves this by offering low-level control over NTFS disk structures: it can compact fragmented MFT record gaps in-place, reset and clean metadata streams (`$Secure` and `$ObjId`) non-destructively, reorganize all system metadata into a strictly sequential layout at the front of the volume, or perform a clean, zero-fragmentation sequential format from scratch.

---

## Key Features

- **Sequential Front Metadata**: Positions all essential NTFS system files contiguously at the very beginning of the partition, keeping the remainder of the volume completely free and contiguous for user data.
- **In-Place MFT Compaction (Non-Destructive)**: Scans for gaps between allocated records, shifts user records forward, updates `$I30` B-tree directory indices, and optionally shrinks `$MFT` cluster allocation down to the absolute minimum needed.
- **In-Place Metadata Rearrangement (Non-Destructive)**: Safely evacuates user data clusters out of the reserved metadata area and arranges system metadata into a deterministic sequential order while preserving all existing files and directories intact.
- **Reset $Secure Streams & Security IDs (Non-Destructive)**: Recreates `$Secure` (`$SDS`, `$SDH`, and `$SII`) cleanly with the active user's SID, verifies all MFT records, and repairs any non-existent or corrupted Security IDs using the official path/file mapping list.
- **Reset $ObjId & Clear Index (Non-Destructive)**: Strips `$OBJECT_ID` attributes from all MFT records (acting like an ultra-fast bulk `fsutil objectid delete`) and resets the `$ObjId:$O` B-tree root to an empty leaf without shrinking the pre-allocated index clusters.
- **Combined Metadata Reset (Non-Destructive)**: Recreates `$Secure` and clears `$ObjId` simultaneously in a single, high-speed unified pass.
- **Custom Sequential Formatter (Clean/Destructive)**: Direct low-level NTFS volume formatting with custom pre-allocated sizes for `$MFT`, MFT Reserved Zone, `$LogFile`, and `$ObjId`, setting root directory permissions to Full Access for `Everyone`.
- **Interactive & CLI Modes**: Clean, intuitive terminal menu interface with auto-detected drive listings and safety prompts, or fully automatable command-line flags.

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

### 3. Reset $Secure (Non-Destructive)
- **Goal**: Recreate `$Secure` security descriptors from scratch and ensure all records have valid Security IDs.
- **How it works**:
  - Rebuilds `$Secure:$SDS` (primary at offset 0 and mirror at offset 262144), patched with the active Windows user's SID.
  - Rebuilds and sorts `$Secure:$SDH` (by Hash, SecID) and `$Secure:$SII` (by SecID 256..271).
  - Updates Record 9 (`$Secure`) non-resident runs and size.
  - Scans all allocated MFT records: if any record's Security ID does not exist in the recreated `$Secure` (or is invalid/0), it automatically maps and updates the record to the correct Security ID based on the path and file type:
    - `256`: Root system files (`$*`)
    - `257`: `$Extend`, `$Extend\$*`, `$Secure`, `$Extend\$RmMetadata\$Repair`
    - `258`: `$Extend\$RmMetadata\$*`, `$Extend\$RmMetadata\$TxfLog\$Tops`
    - `259`: `$Extend\$RmMetadata\$TxfLog\$TxfLog.blf`
    - `260`: `$Extend\$RmMetadata\$TxfLog\$TxfLogContainer*01` & `*02`
    - `261`: `System Volume Information`
    - `262`: `System Volume Information\*`
    - `263`: `System Volume Information\tracking.log`
    - `264`: `$RECYCLE.BIN`
    - `265`: `$RECYCLE.BIN\<UserSID>`
    - `266`: `$RECYCLE.BIN\<UserSID>\desktop.ini`
    - `267`: Standard Folder
    - `268`: Standard File
    - `269`: Standard File with `IMAGELOAD` stream
    - `270`: Auslogics Temp File

### 4. Reset $ObjId (Non-Destructive)
- **Goal**: Remove all ObjectID attributes from files and clear `$ObjId:$O` without looping `fsutil`.
- **How it works**:
  - Scans all MFT records and strips the `$OBJECT_ID` (0x40) attribute in-place.
  - Clears all allocated index blocks inside `$ObjId:$O:INDEX_ALLOCATION`.
  - Resets `$INDEX_ROOT` named `$O` in Record 25 to an empty leaf root node.
  - Zeroes the `$ObjId:$O:BITMAP`.
  - **Does NOT shrink** the pre-allocated clusters or size of `$ObjId:$O` (preserving fast contiguous allocation for future use).

### 5. Reset Both $Secure & $ObjId (Non-Destructive)
- **Goal**: Run both metadata reset operations in a single coordinated, high-speed execution.

### 6. Clean Sequential Format (Destructive)
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
```text
 Select Operation Mode:
  [1] Compact MFT                                (Non-Destructive - Fill gaps, shrink MFT)
  [2] Rearrange / Optimize Volume Metadata       (Non-Destructive - Sequential layout)
  [3] Reset $Secure (Security Descriptors)       (Non-Destructive - Recreate SDS/SDH/SII)
  [4] Reset $ObjId (Object Identifiers)          (Non-Destructive - Clear Object IDs & $ObjId:$O)
  [5] Reset Both $Secure & $ObjId                (Non-Destructive - Combined metadata reset)
  [6] Clean Sequential Format                    (Destructive     - Fresh low-level format)
```
1. Choose an operation mode (`1`–`6`).
2. Select your target drive from the auto-detected list of online volumes.
3. Review the current metadata metrics and layout preview.
4. Confirm the operation to proceed.

---

### Command-Line / Scripting Usage

You can automate operations or run non-interactively using CLI flags:

```text
Flags:
  -mode string
        Operation mode: 'compact', 'rearrange', 'reset-secure', 'reset-objid', 'reset-both', or 'format'
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

**1. Reset $Secure and repair non-existent Security IDs on drive `F:`:**
```powershell
.\ntfs-optimizer.exe -mode reset-secure -drive F: -yes
```

**2. Reset Object IDs and wipe `$ObjId:$O` index without shrinking on drive `F:`:**
```powershell
.\ntfs-optimizer.exe -mode reset-objid -drive F: -yes
```

**3. Reset both `$Secure` and `$ObjId` simultaneously:**
```powershell
.\ntfs-optimizer.exe -mode reset-both -drive F: -yes
```

**4. Compact MFT records on drive `E:` and shrink MFT to minimum:**
```powershell
.\ntfs-optimizer.exe -mode compact -drive E: -compact-mft -yes
```

**5. Rearrange existing volume `G:` with custom pre-sized MFT:**
```powershell
.\ntfs-optimizer.exe -mode rearrange -drive G: -mft 1024 -mft-zone 400 -yes
```

**6. Perform a clean sequential format on drive `F:` with label "Storage":**
```powershell
.\ntfs-optimizer.exe -mode format -drive F: -label "Storage" -mft 512 -logfile 64 -yes
```

---

## Administrator Privileges & Double-Click Elevation

Direct raw volume and physical disk operations on Windows require elevated administrator rights (`GENERIC_READ | GENERIC_WRITE`).

The executable embeds a native **Windows Application Manifest** configured with:
```xml
<requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
```
- **UAC Shield Badge**: Windows Explorer automatically displays the administrator shield icon overlay on `ntfs-optimizer.exe`.
- **Automatic Double-Click Elevation**: When double-clicked in File Explorer, Windows automatically displays the UAC prompt to run elevated as Administrator. Right-clicking and selecting "Run as administrator" is no longer required.

---

## Building from Source

Prerequisites: Go 1.20+ on Windows.

1. Install `go-winres` (for embedding the Windows manifest and version info):
   ```powershell
   go install github.com/tc-hib/go-winres@latest
   ```
2. Generate the Windows resource object file:
   ```powershell
   go-winres make
   ```
3. Compile the executable:
   ```powershell
   go build -ldflags="-s -w" -o ntfs-optimizer.exe .
   ```

---

## Safety & Precautions

- **Exclusive Volume Lock**: The tool automatically attempts to lock (`FSCTL_LOCK_VOLUME`) and dismount (`FSCTL_DISMOUNT_VOLUME`) the target volume before performing low-level block operations. Close any active programs, command prompts, or File Explorer windows using the drive.
- **System Drive Protection**: Do not attempt to rearrange or format the Windows system volume (`C:`) while Windows is actively running from it.
- **Data Backups**: While maintenance and optimization modes (`compact`, `rearrange`, `reset-secure`, and `reset-objid`) are non-destructive, low-level disk operations can be interrupted by sudden power losses or hardware faults. It is always recommended to have a current backup of important data before running low-level volume modifications.

---

## License

This project is licensed under the [MIT License](LICENSE).
