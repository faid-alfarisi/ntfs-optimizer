@echo off
cd /d "%~dp0"
where go-winres >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Compiling Windows resources...
    go-winres make
)
echo Building ntfs-optimizer.exe...
go build -ldflags="-s -w" -o ntfs-optimizer.exe .
if %ERRORLEVEL% EQU 0 (
    echo [OK] Build successful: ntfs-optimizer.exe
) else (
    echo [ERROR] Build failed!
)
pause
