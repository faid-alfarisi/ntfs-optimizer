@echo off
cd /d "%~dp0"
echo Building ntfs-formatter.exe...
go build -ldflags="-s -w" -o ntfs-formatter.exe .
if %ERRORLEVEL% EQU 0 (
    echo [OK] Build successful: ntfs-formatter.exe
) else (
    echo [ERROR] Build failed!
)
pause