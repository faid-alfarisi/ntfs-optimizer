@echo off
cd /d "%~dp0"
echo Building ntfs-optimizer.exe...
go build -ldflags="-s -w" -o ntfs-optimizer.exe .
if %ERRORLEVEL% EQU 0 (
    echo [OK] Build successful: ntfs-optimizer.exe
) else (
    echo [ERROR] Build failed!
)
pause