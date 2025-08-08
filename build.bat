@echo off
REM Terminal-Link Cross-Compilation Build Script for Windows
REM Builds binaries for Linux, macOS, Windows, and Android

setlocal enabledelayedexpansion

REM Build directory
set BUILD_DIR=dist
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo Building Terminal-Link for all platforms...

REM Function to build for a specific platform
:build_platform
set os=%1
set arch=%2
set output_name=%3
set env_vars=%4

echo Building for %os%/%arch%...

REM Set environment variables for cross-compilation
if not "%env_vars%"=="" (
    for /f "tokens=1,2 delims==" %%a in ("%env_vars%") do set %%a=%%b
)

REM Build the binary
set GOOS=%os%
set GOARCH=%arch%
go build -ldflags="-s -w" -o "%BUILD_DIR%\%output_name%" main.go

REM Show file size
for %%A in ("%BUILD_DIR%\%output_name%") do set size=%%~zA
echo ✓ Built %output_name% (!size! bytes)

goto :eof

REM Clean previous builds
echo Cleaning previous builds...
if exist %BUILD_DIR%\* del /q %BUILD_DIR%\*

REM Linux builds
call :build_platform linux amd64 terminal-link-linux-amd64 ""
call :build_platform linux arm64 terminal-link-linux-arm64 ""

REM macOS builds
call :build_platform darwin amd64 terminal-link-darwin-amd64 ""
call :build_platform darwin arm64 terminal-link-darwin-arm64 ""

REM Windows builds
call :build_platform windows amd64 terminal-link-windows-amd64.exe ""
call :build_platform windows arm64 terminal-link-windows-arm64.exe ""

REM Android builds (for Termux)
call :build_platform linux arm64 terminal-link-android-arm64 "CGO_ENABLED=0"

echo Build complete! Binaries in %BUILD_DIR%\:
dir %BUILD_DIR%

REM Create checksums
echo Creating checksums...
cd %BUILD_DIR%
if exist checksums.txt del checksums.txt
for %%f in (*) do (
    certutil -hashfile "%%f" SHA256 | findstr /v "CertUtil" | findstr /v "SHA256" | findstr /v "CertUtil" >> checksums.txt
)
cd ..

echo ✓ All builds completed successfully!
pause 