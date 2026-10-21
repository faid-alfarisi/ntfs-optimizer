package gui

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"ntfs-optimizer/ntfs"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")

	procRegisterClassExW     = user32.NewProc("RegisterClassExW")
	procCreateWindowExW      = user32.NewProc("CreateWindowExW")
	procDefWindowProcW       = user32.NewProc("DefWindowProcW")
	procGetMessageW          = user32.NewProc("GetMessageW")
	procTranslateMessage     = user32.NewProc("TranslateMessage")
	procDispatchMessageW     = user32.NewProc("DispatchMessageW")
	procPostQuitMessage      = user32.NewProc("PostQuitMessage")
	procDestroyWindow        = user32.NewProc("DestroyWindow")
	procSendMessageW         = user32.NewProc("SendMessageW")
	procPostMessageW         = user32.NewProc("PostMessageW")
	procSetWindowTextW       = user32.NewProc("SetWindowTextW")
	procGetWindowTextW       = user32.NewProc("GetWindowTextW")
	procGetWindowTextLengthW = user32.NewProc("GetWindowTextLengthW")
	procEnableWindow         = user32.NewProc("EnableWindow")
	procShowWindow           = user32.NewProc("ShowWindow")
	procUpdateWindow         = user32.NewProc("UpdateWindow")
	procMessageBoxW          = user32.NewProc("MessageBoxW")
	procLoadCursorW          = user32.NewProc("LoadCursorW")
	procLoadIconW            = user32.NewProc("LoadIconW")
	procGetSystemMetrics     = user32.NewProc("GetSystemMetrics")
	procAdjustWindowRectEx   = user32.NewProc("AdjustWindowRectEx")
	procSystemParametersInfoW = user32.NewProc("SystemParametersInfoW")
	procGetDpiForSystem      = user32.NewProc("GetDpiForSystem")
	procGetDC                = user32.NewProc("GetDC")
	procReleaseDC            = user32.NewProc("ReleaseDC")

	procGetModuleHandleW     = kernel32.NewProc("GetModuleHandleW")
	procGetConsoleWindow     = kernel32.NewProc("GetConsoleWindow")
	procInitCommonControlsEx = comctl32.NewProc("InitCommonControlsEx")
	procCreateFontW          = gdi32.NewProc("CreateFontW")
	procDeleteObject         = gdi32.NewProc("DeleteObject")
	procGetDeviceCaps        = gdi32.NewProc("GetDeviceCaps")
)

const (
	WS_OVERLAPPED  = 0x00000000
	WS_CHILD       = 0x40000000
	WS_VISIBLE     = 0x10000000
	WS_CAPTION     = 0x00C00000
	WS_BORDER      = 0x00800000
	WS_VSCROLL     = 0x00200000
	WS_SYSMENU     = 0x00080000
	WS_MINIMIZEBOX = 0x00020000
	WS_GROUP       = 0x00020000
	WS_TABSTOP     = 0x00010000

	WS_EX_CLIENTEDGE = 0x00000200

	BS_PUSHBUTTON      = 0x00000000
	BS_DEFPUSHBUTTON   = 0x00000001
	BS_AUTOCHECKBOX    = 0x00000003
	BS_AUTORADIOBUTTON = 0x00000009
	BS_GROUPBOX        = 0x00000007

	CBS_DROPDOWNLIST = 0x0003
	CB_ADDSTRING     = 0x0143
	CB_SETCURSEL     = 0x014E
	CB_GETCURSEL     = 0x0147
	CB_RESETCONTENT  = 0x014B

	BM_GETCHECK = 0x00F0
	BM_SETCHECK = 0x00F1
	BST_CHECKED = 1

	ES_LEFT        = 0x0000
	ES_MULTILINE   = 0x0004
	ES_AUTOVSCROLL = 0x0040
	ES_READONLY    = 0x0800
	ES_NUMBER      = 0x2000
	EM_SETSEL      = 0x00B1
	EM_REPLACESEL  = 0x00C2
	EM_SCROLLCARET = 0x00B7

	SS_LEFT = 0x00000000

	WM_DESTROY = 0x0002
	WM_COMMAND = 0x0111
	WM_SETFONT = 0x0030
	WM_CLOSE   = 0x0010

	PBM_SETPOS     = 0x0402
	PBM_SETRANGE32 = 0x0406

	MB_OK              = 0x00000000
	MB_YESNO           = 0x00000004
	MB_ICONINFORMATION = 0x00000040
	MB_ICONWARNING     = 0x00000030
	MB_ICONERROR       = 0x00000010
	IDYES              = 6

	WM_APP_PROGRESS = 0x8001
	WM_APP_LOG      = 0x8002
	WM_APP_COMPLETE = 0x8003
)

type WNDCLASSEXW struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     syscall.Handle
	HIcon         syscall.Handle
	HCursor       syscall.Handle
	HbrBackground syscall.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       syscall.Handle
}

type POINT struct {
	X int32
	Y int32
}

type MSG struct {
	Hwnd     syscall.Handle
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       POINT
	LPrivate uint32
}

type RECT struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

type INITCOMMONCONTROLSEX struct {
	DwSize uint32
	DwICC  uint32
}

type DriveItem struct {
	Letter     string
	Label      string
	FileSystem string
	TotalBytes uint64
	FreeBytes  uint64
	IsDirty    bool
	IsSystem   bool
}

type guiState struct {
	hwndMain      syscall.Handle
	hFont         syscall.Handle
	hComboDrives  syscall.Handle
	hBtnRefresh   syscall.Handle
	hLblDriveInfo syscall.Handle

	hRadioCompact   syscall.Handle
	hRadioRearrange syscall.Handle
	hRadioResetSec  syscall.Handle
	hRadioResetOid  syscall.Handle
	hRadioResetBoth syscall.Handle
	hRadioRepair    syscall.Handle
	hRadioFormat    syscall.Handle

	hChkShrinkMft syscall.Handle
	hEditMft      syscall.Handle
	hEditMftZone  syscall.Handle
	hEditObjId    syscall.Handle
	hEditLogFile  syscall.Handle
	hEditLabel    syscall.Handle

	hLblStatus   syscall.Handle
	hProgressBar syscall.Handle
	hEditLog     syscall.Handle

	hBtnStart syscall.Handle
	hBtnClose syscall.Handle

	drives          []DriveItem
	running         bool
	logLock         sync.Mutex
	pendingLogs     []string
	pendingProgMsg  string
	pendingProgPct  float64
	completeSuccess bool
	completeMsg     string
}

var (
	gState     *guiState
	currentDPI uint32 = 96
)

func initDPI() {
	if procGetDpiForSystem.Find() == nil {
		dpi, _, _ := procGetDpiForSystem.Call()
		if dpi > 0 {
			currentDPI = uint32(dpi)
			return
		}
	}
	hdc, _, _ := procGetDC.Call(0)
	if hdc != 0 {
		dpi, _, _ := procGetDeviceCaps.Call(hdc, 90) // LOGPIXELSY = 90
		procReleaseDC.Call(0, hdc)
		if dpi > 0 {
			currentDPI = uint32(dpi)
			return
		}
	}
	currentDPI = 96
}

// dp scales a logical 96-DPI pixel dimension to the active display scaling factor (e.g. 150% -> * 1.5).
func dp(val int32) int32 {
	return int32((int64(val)*int64(currentDPI) + 48) / 96)
}

func isDriveDirty(driveLetter string) bool {
	cleanLetter := strings.TrimSuffix(driveLetter, "\\")
	path, _ := syscall.UTF16PtrFromString(`\\.\` + cleanLetter)
	h, err := syscall.CreateFile(path, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(h)
	var dirtyResult uint32
	var bytesRet uint32
	err = syscall.DeviceIoControl(h, 0x00090078, nil, 0, (*byte)(unsafe.Pointer(&dirtyResult)), 4, &bytesRet, nil)
	if err != nil {
		return false
	}
	return (dirtyResult & 1) != 0
}

func hideConsoleWindow() {
	hConsole, _, _ := procGetConsoleWindow.Call()
	if hConsole != 0 {
		procShowWindow.Call(hConsole, 0) // SW_HIDE = 0
	}
}

func RunGUI() {
	// 1. Lock goroutine to OS thread permanently for Win32 message pump integrity
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// 2. Hide the black console window
	hideConsoleWindow()

	// 3. Query system DPI (e.g. 144 for 150% scaling, 120 for 125%, 96 for 100%)
	initDPI()

	// 4. Initialize Common Controls v6
	iccex := INITCOMMONCONTROLSEX{
		DwSize: uint32(unsafe.Sizeof(INITCOMMONCONTROLSEX{})),
		DwICC:  0x00000001 | 0x00000020, // ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS
	}
	procInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&iccex)))

	hInstance, _, _ := procGetModuleHandleW.Call(0)

	className := syscall.StringToUTF16Ptr("NTFS_OPTIMIZER_NATIVE_WND")
	wndTitle := syscall.StringToUTF16Ptr("NTFS Optimizer v1.2")

	hIcon, _, _ := procLoadIconW.Call(hInstance, 1)
	if hIcon == 0 {
		hIcon, _, _ = procLoadIconW.Call(0, 32512) // IDI_APPLICATION
	}
	hCursor, _, _ := procLoadCursorW.Call(0, 32512) // IDC_ARROW

	wc := WNDCLASSEXW{
		CbSize:        uint32(unsafe.Sizeof(WNDCLASSEXW{})),
		Style:         0x0002 | 0x0001, // CS_HREDRAW | CS_VREDRAW
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     syscall.Handle(hInstance),
		HIcon:         syscall.Handle(hIcon),
		HCursor:       syscall.Handle(hCursor),
		HbrBackground: syscall.Handle(15 + 1), // COLOR_BTNFACE + 1
		LpszClassName: className,
		HIconSm:       syscall.Handle(hIcon),
	}

	procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	// Calculate DPI-scaled window dimensions for side-by-side 2-column layout (840 x 458 base)
	wndStyle := uint32(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX)
	rc := RECT{Left: 0, Top: 0, Right: dp(840), Bottom: dp(458)}
	procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&rc)), uintptr(wndStyle), 0, 0)
	winW := rc.Right - rc.Left
	winH := rc.Bottom - rc.Top

	// Query desktop work area (screen excluding taskbar)
	var workArea RECT
	procSystemParametersInfoW.Call(0x0030, 0, uintptr(unsafe.Pointer(&workArea)), 0) // SPI_GETWORKAREA = 0x0030
	workW := workArea.Right - workArea.Left
	workH := workArea.Bottom - workArea.Top

	if workW <= 0 {
		scrW, _, _ := procGetSystemMetrics.Call(0)
		workW = int32(scrW)
	}
	if workH <= 0 {
		scrH, _, _ := procGetSystemMetrics.Call(1)
		workH = int32(scrH)
	}

	winX := workArea.Left + (workW-winW)/2
	winY := workArea.Top + (workH-winH)/2
	if winY < workArea.Top+dp(10) {
		winY = workArea.Top + dp(10)
	}

	gState = &guiState{}

	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(wndTitle)),
		uintptr(wndStyle|WS_VISIBLE),
		uintptr(winX),
		uintptr(winY),
		uintptr(winW),
		uintptr(winH),
		0, 0, hInstance, 0,
	)

	gState.hwndMain = syscall.Handle(hwnd)

	// Create DPI-aware anti-aliased Segoe UI font (standard 9pt character height: -MulDiv(9, DPI, 72))
	fontName := syscall.StringToUTF16Ptr("Segoe UI")
	fontHeight := -int32((int64(9)*int64(currentDPI) + 36) / 72)
	hFont, _, _ := procCreateFontW.Call(
		uintptr(fontHeight), 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 2, 0,
		uintptr(unsafe.Pointer(fontName)),
	)
	gState.hFont = syscall.Handle(hFont)

	createControls(gState, hInstance)
	refreshDriveList(gState)
	updateOptionsState(gState)

	procShowWindow.Call(hwnd, 5) // SW_SHOW
	procUpdateWindow.Call(hwnd)

	// Pump Windows messages
	var msg MSG
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&msg)))
	}

	if gState.hFont != 0 {
		procDeleteObject.Call(uintptr(gState.hFont))
	}
}

func createControl(className string, text string, style uint32, exStyle uint32, x, y, w, h int32, id int, hParent, hInst uintptr) syscall.Handle {
	cName := syscall.StringToUTF16Ptr(className)
	cText := syscall.StringToUTF16Ptr(text)
	hwnd, _, _ := procCreateWindowExW.Call(
		uintptr(exStyle),
		uintptr(unsafe.Pointer(cName)),
		uintptr(unsafe.Pointer(cText)),
		uintptr(style|WS_CHILD|WS_VISIBLE),
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		hParent,
		uintptr(id),
		hInst,
		0,
	)
	if gState != nil && gState.hFont != 0 {
		procSendMessageW.Call(hwnd, WM_SETFONT, uintptr(gState.hFont), 1)
	}
	return syscall.Handle(hwnd)
}

func createControls(s *guiState, hInst uintptr) {
	hp := uintptr(s.hwndMain)

	// =========================================================================
	// LEFT COLUMN (w: 440, x: 12..452)
	// =========================================================================

	// 1. Target Drive Section
	createControl("BUTTON", "Target Volume", BS_GROUPBOX, 0, dp(12), dp(8), dp(440), dp(82), 100, hp, hInst)
	createControl("STATIC", "Drive:", SS_LEFT, 0, dp(24), dp(28), dp(45), dp(20), 101, hp, hInst)

	s.hComboDrives = createControl("COMBOBOX", "", CBS_DROPDOWNLIST|WS_VSCROLL|WS_TABSTOP, 0, dp(70), dp(26), dp(288), dp(220), 102, hp, hInst)
	s.hBtnRefresh = createControl("BUTTON", "Refresh", BS_PUSHBUTTON|WS_TABSTOP, 0, dp(364), dp(25), dp(76), dp(26), 103, hp, hInst)
	s.hLblDriveInfo = createControl("STATIC", "Scanning volumes...", SS_LEFT, 0, dp(24), dp(58), dp(416), dp(20), 104, hp, hInst)

	// 2. Operation Mode Section
	createControl("BUTTON", "Operation Mode", BS_GROUPBOX, 0, dp(12), dp(94), dp(440), dp(182), 200, hp, hInst)

	s.hRadioCompact = createControl("BUTTON", "Compact MFT (Fill gaps && shrink in-place)", BS_AUTORADIOBUTTON|WS_GROUP|WS_TABSTOP, 0, dp(24), dp(112), dp(416), dp(21), 201, hp, hInst)
	s.hRadioRearrange = createControl("BUTTON", "Rearrange Volume (Sequential metadata layout)", BS_AUTORADIOBUTTON, 0, dp(24), dp(134), dp(416), dp(21), 202, hp, hInst)
	s.hRadioResetSec = createControl("BUTTON", "Reset $Secure (Rebuild SDS/SDH/SII && SecIDs)", BS_AUTORADIOBUTTON, 0, dp(24), dp(156), dp(416), dp(21), 203, hp, hInst)
	s.hRadioResetOid = createControl("BUTTON", "Reset $ObjId (Strip Object IDs && wipe index)", BS_AUTORADIOBUTTON, 0, dp(24), dp(178), dp(416), dp(21), 204, hp, hInst)
	s.hRadioResetBoth = createControl("BUTTON", "Reset Both ($Secure && $ObjId combined)", BS_AUTORADIOBUTTON, 0, dp(24), dp(200), dp(416), dp(21), 205, hp, hInst)
	s.hRadioRepair = createControl("BUTTON", "Repair Volume && Clear Dirty Bit (No chkdsk)", BS_AUTORADIOBUTTON, 0, dp(24), dp(222), dp(416), dp(21), 206, hp, hInst)
	s.hRadioFormat = createControl("BUTTON", "Clean Sequential Format (Destructive - Erase all data)", BS_AUTORADIOBUTTON, 0, dp(24), dp(244), dp(416), dp(21), 207, hp, hInst)

	// Default to Compact MFT
	procSendMessageW.Call(uintptr(s.hRadioCompact), BM_SETCHECK, BST_CHECKED, 0)

	// 3. Parameters Section
	createControl("BUTTON", "Options && Parameters", BS_GROUPBOX, 0, dp(12), dp(280), dp(440), dp(122), 300, hp, hInst)

	s.hChkShrinkMft = createControl("BUTTON", "Reduce MFT size to absolute minimum after compacting", BS_AUTOCHECKBOX|WS_TABSTOP, 0, dp(24), dp(300), dp(416), dp(20), 301, hp, hInst)

	// Row 2: MFT, Zone, ObjId, Log
	createControl("STATIC", "MFT:", SS_LEFT, 0, dp(24), dp(328), dp(35), dp(20), 302, hp, hInst)
	s.hEditMft = createControl("EDIT", "512", ES_LEFT|ES_NUMBER|WS_BORDER|WS_TABSTOP, WS_EX_CLIENTEDGE, dp(60), dp(326), dp(44), dp(22), 303, hp, hInst)

	createControl("STATIC", "Zone:", SS_LEFT, 0, dp(112), dp(328), dp(38), dp(20), 304, hp, hInst)
	s.hEditMftZone = createControl("EDIT", "200", ES_LEFT|ES_NUMBER|WS_BORDER|WS_TABSTOP, WS_EX_CLIENTEDGE, dp(152), dp(326), dp(44), dp(22), 305, hp, hInst)

	createControl("STATIC", "ObjId:", SS_LEFT, 0, dp(204), dp(328), dp(40), dp(20), 306, hp, hInst)
	s.hEditObjId = createControl("EDIT", "4", ES_LEFT|ES_NUMBER|WS_BORDER|WS_TABSTOP, WS_EX_CLIENTEDGE, dp(246), dp(326), dp(38), dp(22), 307, hp, hInst)

	createControl("STATIC", "Log:", SS_LEFT, 0, dp(292), dp(328), dp(30), dp(20), 308, hp, hInst)
	s.hEditLogFile = createControl("EDIT", "64", ES_LEFT|ES_NUMBER|WS_BORDER|WS_TABSTOP, WS_EX_CLIENTEDGE, dp(324), dp(326), dp(38), dp(22), 309, hp, hInst)

	// Row 3: Volume Label
	createControl("STATIC", "Volume Label:", SS_LEFT, 0, dp(24), dp(358), dp(85), dp(20), 310, hp, hInst)
	s.hEditLabel = createControl("EDIT", "New Volume", ES_LEFT|WS_BORDER|WS_TABSTOP, WS_EX_CLIENTEDGE, dp(112), dp(356), dp(250), dp(22), 311, hp, hInst)

	// 4. Action Buttons (Left column bottom - always visible)
	s.hBtnStart = createControl("BUTTON", "Start Operation", BS_DEFPUSHBUTTON|WS_TABSTOP, 0, dp(12), dp(410), dp(260), dp(38), 501, hp, hInst)
	s.hBtnClose = createControl("BUTTON", "Close", BS_PUSHBUTTON|WS_TABSTOP, 0, dp(280), dp(410), dp(172), dp(38), 502, hp, hInst)

	// =========================================================================
	// RIGHT COLUMN (w: 366, x: 462..828)
	// =========================================================================

	// 5. Progress & Log Section
	createControl("BUTTON", "Progress && Log", BS_GROUPBOX, 0, dp(462), dp(8), dp(366), dp(440), 400, hp, hInst)

	s.hLblStatus = createControl("STATIC", "Ready", SS_LEFT, 0, dp(474), dp(28), dp(342), dp(18), 401, hp, hInst)
	s.hProgressBar = createControl("msctls_progress32", "", 0x01, 0, dp(474), dp(48), dp(342), dp(16), 402, hp, hInst)
	procSendMessageW.Call(uintptr(s.hProgressBar), PBM_SETRANGE32, 0, 1000)

	s.hEditLog = createControl("EDIT", "", ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL|WS_BORDER, WS_EX_CLIENTEDGE, dp(474), dp(70), dp(342), dp(366), 403, hp, hInst)

	appendLog(s, fmt.Sprintf("[*] NTFS Optimizer v1.2 initialized. Native Win32 Engine active (DPI: %d).", currentDPI))
}

func refreshDriveList(s *guiState) {
	procSendMessageW.Call(uintptr(s.hComboDrives), CB_RESETCONTENT, 0, 0)
	s.drives = nil

	vols, err := ntfs.ListVolumes()
	if err != nil {
		setWindowText(s.hLblDriveInfo, fmt.Sprintf("Error listing drives: %v", err))
		return
	}

	sysDrive := os.Getenv("SystemDrive")
	if sysDrive == "" {
		sysDrive = "C:"
	}

	defaultIdx := -1

	for _, v := range vols {
		isSys := strings.EqualFold(v.Letter, sysDrive)
		isDirty := false
		if !isSys {
			isDirty = isDriveDirty(v.Letter)
		}

		item := DriveItem{
			Letter:     v.Letter,
			Label:      v.Label,
			FileSystem: v.FileSystem,
			TotalBytes: v.TotalBytes,
			FreeBytes:  v.FreeBytes,
			IsDirty:    isDirty,
			IsSystem:   isSys,
		}
		s.drives = append(s.drives, item)
		idx := len(s.drives) - 1

		statusStr := "Clean"
		if isSys {
			statusStr = "System"
		} else if isDirty {
			statusStr = "DIRTY"
		}

		displayStr := fmt.Sprintf("%s [%s] (%s) - %s", v.Letter, v.Label, formatSize(v.TotalBytes), statusStr)
		u16 := syscall.StringToUTF16Ptr(displayStr)
		procSendMessageW.Call(uintptr(s.hComboDrives), CB_ADDSTRING, 0, uintptr(unsafe.Pointer(u16)))

		if !isSys && defaultIdx == -1 {
			defaultIdx = idx
		}
	}

	if defaultIdx == -1 {
		defaultIdx = 0
	}

	if len(s.drives) > 0 {
		procSendMessageW.Call(uintptr(s.hComboDrives), CB_SETCURSEL, uintptr(defaultIdx), 0)
		updateDriveInfoLabel(s, defaultIdx)
	} else {
		setWindowText(s.hLblDriveInfo, "No accessible NTFS volumes found.")
	}
}

func updateDriveInfoLabel(s *guiState, idx int) {
	if idx < 0 || idx >= len(s.drives) {
		setWindowText(s.hLblDriveInfo, "")
		return
	}
	d := s.drives[idx]
	statusStr := "Clean"
	if d.IsSystem {
		statusStr = "Windows System Drive (Protected)"
	} else if d.IsDirty {
		statusStr = "DIRTY (Windows requests check)"
	}

	info := fmt.Sprintf("Volume: %s | Label: %s | Capacity: %s | Free: %s | State: %s",
		d.Letter, d.Label, formatSize(d.TotalBytes), formatSize(d.FreeBytes), statusStr)
	setWindowText(s.hLblDriveInfo, info)

	updateOptionsState(s)
}

func getSelectedMode(s *guiState) string {
	if isChecked(s.hRadioFormat) {
		return "format"
	}
	if isChecked(s.hRadioRepair) {
		return "repair"
	}
	if isChecked(s.hRadioResetBoth) {
		return "reset-both"
	}
	if isChecked(s.hRadioResetOid) {
		return "reset-objid"
	}
	if isChecked(s.hRadioResetSec) {
		return "reset-secure"
	}
	if isChecked(s.hRadioRearrange) {
		return "rearrange"
	}
	return "compact"
}

func updateOptionsState(s *guiState) {
	mode := getSelectedMode(s)

	curSel, _, _ := procSendMessageW.Call(uintptr(s.hComboDrives), CB_GETCURSEL, 0, 0)
	selIdx := int(int32(curSel))
	isSystemDrive := false
	if selIdx >= 0 && selIdx < len(s.drives) {
		isSystemDrive = s.drives[selIdx].IsSystem
	}

	isCompact := (mode == "compact")
	isRearrangeOrFormat := (mode == "rearrange" || mode == "format")

	procEnableWindow.Call(uintptr(s.hChkShrinkMft), boolToUintptr(isCompact))
	procEnableWindow.Call(uintptr(s.hEditMft), boolToUintptr(isRearrangeOrFormat))
	procEnableWindow.Call(uintptr(s.hEditMftZone), boolToUintptr(isRearrangeOrFormat))
	procEnableWindow.Call(uintptr(s.hEditObjId), boolToUintptr(isRearrangeOrFormat))
	procEnableWindow.Call(uintptr(s.hEditLogFile), boolToUintptr(isRearrangeOrFormat))
	procEnableWindow.Call(uintptr(s.hEditLabel), boolToUintptr(isRearrangeOrFormat))

	if isSystemDrive && (mode == "format" || mode == "rearrange") {
		procEnableWindow.Call(uintptr(s.hBtnStart), 0)
		setWindowText(s.hBtnStart, "System Drive Protected")
	} else if mode == "format" {
		procEnableWindow.Call(uintptr(s.hBtnStart), 1)
		setWindowText(s.hBtnStart, "FORMAT VOLUME")
	} else {
		procEnableWindow.Call(uintptr(s.hBtnStart), 1)
		setWindowText(s.hBtnStart, "Start Operation")
	}
}

func isChecked(h syscall.Handle) bool {
	res, _, _ := procSendMessageW.Call(uintptr(h), BM_GETCHECK, 0, 0)
	return res == BST_CHECKED
}

func boolToUintptr(b bool) uintptr {
	if b {
		return 1
	}
	return 0
}

func setWindowText(h syscall.Handle, text string) {
	u16 := syscall.StringToUTF16Ptr(text)
	procSetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(u16)))
}

func getWindowText(h syscall.Handle) string {
	lenRes, _, _ := procGetWindowTextLengthW.Call(uintptr(h))
	length := int(lenRes)
	if length == 0 {
		return ""
	}
	buf := make([]uint16, length+1)
	procGetWindowTextW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(length+1))
	return syscall.UTF16ToString(buf)
}

func appendLog(s *guiState, line string) {
	u16 := syscall.StringToUTF16Ptr(line + "\r\n")
	procSendMessageW.Call(uintptr(s.hEditLog), EM_SETSEL, ^uintptr(0), ^uintptr(0))
	procSendMessageW.Call(uintptr(s.hEditLog), EM_REPLACESEL, 0, uintptr(unsafe.Pointer(u16)))
	procSendMessageW.Call(uintptr(s.hEditLog), EM_SCROLLCARET, 0, 0)
}

func setControlsEnabled(s *guiState, enabled bool) {
	v := boolToUintptr(enabled)
	procEnableWindow.Call(uintptr(s.hComboDrives), v)
	procEnableWindow.Call(uintptr(s.hBtnRefresh), v)
	procEnableWindow.Call(uintptr(s.hRadioCompact), v)
	procEnableWindow.Call(uintptr(s.hRadioRearrange), v)
	procEnableWindow.Call(uintptr(s.hRadioResetSec), v)
	procEnableWindow.Call(uintptr(s.hRadioResetOid), v)
	procEnableWindow.Call(uintptr(s.hRadioResetBoth), v)
	procEnableWindow.Call(uintptr(s.hRadioRepair), v)
	procEnableWindow.Call(uintptr(s.hRadioFormat), v)
	procEnableWindow.Call(uintptr(s.hBtnStart), v)

	if enabled {
		updateOptionsState(s)
	} else {
		procEnableWindow.Call(uintptr(s.hChkShrinkMft), 0)
		procEnableWindow.Call(uintptr(s.hEditMft), 0)
		procEnableWindow.Call(uintptr(s.hEditMftZone), 0)
		procEnableWindow.Call(uintptr(s.hEditObjId), 0)
		procEnableWindow.Call(uintptr(s.hEditLogFile), 0)
		procEnableWindow.Call(uintptr(s.hEditLabel), 0)
	}
}

func onStartOperation(s *guiState) {
	curSel, _, _ := procSendMessageW.Call(uintptr(s.hComboDrives), CB_GETCURSEL, 0, 0)
	selIdx := int(int32(curSel))
	if selIdx < 0 || selIdx >= len(s.drives) {
		procMessageBoxW.Call(uintptr(s.hwndMain), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Please select a target drive."))), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Error"))), MB_OK|MB_ICONERROR)
		return
	}

	target := s.drives[selIdx].Letter
	mode := getSelectedMode(s)

	if s.drives[selIdx].IsSystem && (mode == "format" || mode == "rearrange") {
		procMessageBoxW.Call(uintptr(s.hwndMain), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("The active Windows system volume cannot be formatted or rearranged."))), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Protected Volume"))), MB_OK|MB_ICONWARNING)
		return
	}

	if mode == "format" {
		msg := fmt.Sprintf("WARNING: Destructive Format!\n\nAll data on drive %s (%s) will be permanently destroyed.\n\nAre you sure you want to proceed?", target, formatSize(s.drives[selIdx].TotalBytes))
		r, _, _ := procMessageBoxW.Call(uintptr(s.hwndMain), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(msg))), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Confirm Format"))), MB_YESNO|MB_ICONWARNING)
		if r != IDYES {
			return
		}
	}

	s.running = true
	setControlsEnabled(s, false)

	// Read input params
	shrinkMft := isChecked(s.hChkShrinkMft)
	mftMB, _ := strconv.ParseUint(strings.TrimSpace(getWindowText(s.hEditMft)), 10, 64)
	if mftMB == 0 {
		mftMB = 512
	}
	mftZoneMB, _ := strconv.ParseUint(strings.TrimSpace(getWindowText(s.hEditMftZone)), 10, 64)
	if mftZoneMB == 0 {
		mftZoneMB = 200
	}
	objIdMB, _ := strconv.ParseUint(strings.TrimSpace(getWindowText(s.hEditObjId)), 10, 64)
	if objIdMB == 0 {
		objIdMB = 4
	}
	logFileMB, _ := strconv.ParseUint(strings.TrimSpace(getWindowText(s.hEditLogFile)), 10, 64)
	if logFileMB == 0 {
		logFileMB = 64
	}
	volLabel := strings.TrimSpace(getWindowText(s.hEditLabel))
	if volLabel == "" {
		volLabel = "New Volume"
	}

	// Reset progress
	procSendMessageW.Call(uintptr(s.hProgressBar), PBM_SETPOS, 0, 0)
	setWindowText(s.hLblStatus, "Starting...")

	appendLog(s, "----------------------------------------------------------------------")
	appendLog(s, fmt.Sprintf("[*] Starting %s on drive %s...", strings.ToUpper(mode), target))

	go func() {
		postLog := func(text string) {
			s.logLock.Lock()
			s.pendingLogs = append(s.pendingLogs, text)
			s.logLock.Unlock()
			procPostMessageW.Call(uintptr(s.hwndMain), WM_APP_LOG, 0, 0)
		}

		progress := func(phase string, cur uint64, total uint64) {
			pct := 0.0
			if total > 0 {
				pct = float64(cur) / float64(total) * 100.0
			}
			s.logLock.Lock()
			s.pendingProgMsg = phase
			s.pendingProgPct = pct
			s.logLock.Unlock()
			procPostMessageW.Call(uintptr(s.hwndMain), WM_APP_PROGRESS, 0, 0)
		}

		postLog(fmt.Sprintf("[*] Locking and dismounting volume %s...", target))
		h, totalBytes, isVol, err := ntfs.OpenTarget(target)
		if err != nil {
			postLog(fmt.Sprintf("[-] Failed to open volume: %v", err))
			s.completeSuccess = false
			s.completeMsg = err.Error()
			procPostMessageW.Call(uintptr(s.hwndMain), WM_APP_COMPLETE, 0, 0)
			return
		}
		defer ntfs.CloseTarget(h, isVol)

		if mode == "format" {
			totalSectors := totalBytes / ntfs.SectorSize
			existingSerial := ntfs.GetExistingVolumeSerial(h)
			cfg := ntfs.LayoutConfig{
				TotalSectors:   totalSectors,
				BytesPerSector: ntfs.SectorSize,
				SectorPerClust: ntfs.DefaultSectorsPerClust,
				MftSizeMB:      mftMB,
				MftZoneSizeMB:  mftZoneMB,
				ObjIdSizeMB:    objIdMB,
				LogFileSizeMB:  logFileMB,
				VolumeLabel:    volLabel,
				SerialNumber:   existingSerial,
			}
			layout, err := ntfs.CalculateLayout(cfg)
			if err != nil {
				postLog(fmt.Sprintf("[-] Layout error: %v", err))
				s.completeSuccess = false
				s.completeMsg = err.Error()
				procPostMessageW.Call(uintptr(s.hwndMain), WM_APP_COMPLETE, 0, 0)
				return
			}
			postLog(fmt.Sprintf("[*] Formatting volume %s with sequential layout...", target))
			if err := ntfs.FormatVolume(h, layout, progress); err != nil {
				postLog(fmt.Sprintf("[-] Format error: %v", err))
				s.completeSuccess = false
				s.completeMsg = err.Error()
				procPostMessageW.Call(uintptr(s.hwndMain), WM_APP_COMPLETE, 0, 0)
				return
			}
			s.completeSuccess = true
			s.completeMsg = fmt.Sprintf("Clean format completed successfully on %s.", target)
			procPostMessageW.Call(uintptr(s.hwndMain), WM_APP_COMPLETE, 0, 0)
			return
		}

		postLog("[*] Inspecting volume metadata structures...")
		analysis, err := ntfs.AnalyzeVolume(h, target)
		if err != nil {
			postLog(fmt.Sprintf("[-] Analysis error: %v", err))
			s.completeSuccess = false
			s.completeMsg = err.Error()
			procPostMessageW.Call(uintptr(s.hwndMain), WM_APP_COMPLETE, 0, 0)
			return
		}

		switch mode {
		case "compact":
			postLog(fmt.Sprintf("[*] Compacting MFT record layout on %s...", target))
			err := ntfs.CompactVolumeMFT(h, analysis, shrinkMft, 0, progress)
			if err != nil {
				postLog(fmt.Sprintf("[-] Compaction failed: %v", err))
				s.completeSuccess = false
				s.completeMsg = err.Error()
			} else {
				s.completeSuccess = true
				s.completeMsg = "MFT compaction completed successfully."
			}

		case "rearrange":
			postLog(fmt.Sprintf("[*] Rearranging metadata to sequential front layout on %s...", target))
			totalSectors := totalBytes / ntfs.SectorSize
			cfg := ntfs.LayoutConfig{
				TotalSectors:   totalSectors,
				BytesPerSector: ntfs.SectorSize,
				SectorPerClust: ntfs.DefaultSectorsPerClust,
				MftSizeMB:      mftMB,
				MftZoneSizeMB:  mftZoneMB,
				ObjIdSizeMB:    objIdMB,
				LogFileSizeMB:  logFileMB,
				VolumeLabel:    analysis.VolumeLabel,
				SerialNumber:   analysis.SerialNumber,
			}
			layout, err := ntfs.CalculateLayout(cfg)
			if err != nil {
				postLog(fmt.Sprintf("[-] Layout error: %v", err))
				s.completeSuccess = false
				s.completeMsg = err.Error()
			} else if err := ntfs.RearrangeVolume(h, analysis, layout, progress); err != nil {
				postLog(fmt.Sprintf("[-] Rearrange failed: %v", err))
				s.completeSuccess = false
				s.completeMsg = err.Error()
			} else {
				s.completeSuccess = true
				s.completeMsg = "Volume rearrangement completed successfully."
			}

		case "reset-secure":
			postLog(fmt.Sprintf("[*] Rebuilding $Secure (SDS/SDH/SII) on %s...", target))
			res, err := ntfs.ResetSecure(h, analysis, progress)
			if err != nil {
				postLog(fmt.Sprintf("[-] Reset $Secure failed: %v", err))
				s.completeSuccess = false
				s.completeMsg = err.Error()
			} else {
				postLog(fmt.Sprintf("[+] $Secure rebuilt at LCN %d. Repaired %d records.", res.SdsLcn, res.RecordsUpdated))
				s.completeSuccess = true
				s.completeMsg = fmt.Sprintf("$Secure reset completed. %d records updated.", res.RecordsUpdated)
			}

		case "reset-objid":
			postLog(fmt.Sprintf("[*] Stripping Object IDs and clearing $ObjId:$O on %s...", target))
			res, err := ntfs.ResetObjId(h, analysis, progress)
			if err != nil {
				postLog(fmt.Sprintf("[-] Reset $ObjId failed: %v", err))
				s.completeSuccess = false
				s.completeMsg = err.Error()
			} else {
				postLog(fmt.Sprintf("[+] Object IDs removed: %d. Pre-allocated index preserved (%d clusters).", res.ObjIdsRemoved, res.ObjIdClusters))
				s.completeSuccess = true
				s.completeMsg = fmt.Sprintf("$ObjId reset completed. %d object IDs stripped.", res.ObjIdsRemoved)
			}

		case "reset-both":
			postLog(fmt.Sprintf("[*] Resetting both $Secure and $ObjId on %s...", target))
			res, err := ntfs.ResetBoth(h, analysis, progress)
			if err != nil {
				postLog(fmt.Sprintf("[-] Combined reset failed: %v", err))
				s.completeSuccess = false
				s.completeMsg = err.Error()
			} else {
				postLog(fmt.Sprintf("[+] Combined reset done. SecIDs fixed: %d, Object IDs removed: %d", res.SecureResult.RecordsUpdated, res.ObjIdResult.ObjIdsRemoved))
				s.completeSuccess = true
				s.completeMsg = "Combined reset of $Secure and $ObjId completed successfully."
			}

		case "repair":
			postLog(fmt.Sprintf("[*] Running native volume doctor & dirty bit clear on %s...", target))
			res, err := ntfs.RepairVolume(h, analysis, progress)
			if err != nil {
				postLog(fmt.Sprintf("[-] Repair failed: %v", err))
				s.completeSuccess = false
				s.completeMsg = err.Error()
			} else {
				postLog(fmt.Sprintf("[+] Volume repaired. WasDirty: %t, Records checked: %d, SecIDs restored: %d, Bitmap fixed: %d",
					res.WasDirty, res.RecordsChecked, res.SecIDsRepaired, res.BitmapMismatchesFixed))
				s.completeSuccess = true
				s.completeMsg = "Volume integrity repaired and marked clean."
			}
		}

		procPostMessageW.Call(uintptr(s.hwndMain), WM_APP_COMPLETE, 0, 0)
	}()
}

func wndProc(hwnd syscall.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	s := gState
	if s == nil {
		r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
		return r
	}

	switch msg {
	case WM_COMMAND:
		id := int(wParam & 0xFFFF)
		code := int((wParam >> 16) & 0xFFFF)

		if id == 102 && code == 1 { // ComboBox CBN_SELCHANGE
			curSel, _, _ := procSendMessageW.Call(uintptr(s.hComboDrives), CB_GETCURSEL, 0, 0)
			updateDriveInfoLabel(s, int(int32(curSel)))
		} else if id == 103 { // Refresh button
			refreshDriveList(s)
		} else if id >= 201 && id <= 207 { // Radio buttons
			updateOptionsState(s)
		} else if id == 501 { // Start Operation
			onStartOperation(s)
		} else if id == 502 { // Close button
			procDestroyWindow.Call(uintptr(hwnd))
		}
		return 0

	case WM_APP_LOG:
		s.logLock.Lock()
		logs := s.pendingLogs
		s.pendingLogs = nil
		s.logLock.Unlock()
		for _, l := range logs {
			appendLog(s, l)
		}
		return 0

	case WM_APP_PROGRESS:
		s.logLock.Lock()
		pMsg := s.pendingProgMsg
		pPct := s.pendingProgPct
		s.logLock.Unlock()

		intPos := int(pPct * 10) // 0..1000
		if intPos > 1000 {
			intPos = 1000
		}
		procSendMessageW.Call(uintptr(s.hProgressBar), PBM_SETPOS, uintptr(intPos), 0)
		setWindowText(s.hLblStatus, fmt.Sprintf("[%5.1f%%] %s", pPct, pMsg))
		return 0

	case WM_APP_COMPLETE:
		s.running = false
		setControlsEnabled(s, true)
		procSendMessageW.Call(uintptr(s.hProgressBar), PBM_SETPOS, 1000, 0)

		if s.completeSuccess {
			setWindowText(s.hLblStatus, "Completed successfully.")
			appendLog(s, "[+] SUCCESS: "+s.completeMsg)
			procMessageBoxW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(s.completeMsg))), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Operation Complete"))), MB_OK|MB_ICONINFORMATION)
		} else {
			setWindowText(s.hLblStatus, "Operation failed.")
			appendLog(s, "[-] ERROR: "+s.completeMsg)
			procMessageBoxW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Operation failed:\n\n"+s.completeMsg))), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Operation Failed"))), MB_OK|MB_ICONERROR)
		}
		refreshDriveList(s)
		return 0

	case WM_CLOSE:
		if s.running {
			r, _, _ := procMessageBoxW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("An operation is currently in progress on the volume. Closing now may leave the volume in an incomplete state.\n\nAre you sure you want to close?"))), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("Confirm Exit"))), MB_YESNO|MB_ICONWARNING)
			if r != IDYES {
				return 0
			}
		}
		procDestroyWindow.Call(uintptr(hwnd))
		return 0

	case WM_DESTROY:
		procPostQuitMessage.Call(0)
		return 0
	}

	r, _, _ := procDefWindowProcW.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
	return r
}

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
