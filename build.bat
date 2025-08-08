@echo off
REM Terminal-Link Cross-Compilation Build Script for Windows
REM Builds binaries for Linux, macOS, Windows, and Android

setlocal enabledelayedexpansion

REM Build directory
set BUILD_DIR=dist
if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo Building Terminal-Link for all platforms...

REM Clean previous builds
echo Cleaning previous builds...
if exist %BUILD_DIR%\* del /q %BUILD_DIR%\*

REM Linux builds
echo Building for linux/amd64...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -o %BUILD_DIR%\terminal-link-linux-amd64 main.go
for %%A in ("%BUILD_DIR%\terminal-link-linux-amd64") do set size=%%~zA
echo ✓ Built terminal-link-linux-amd64 (!size! bytes)

echo Building for linux/arm64...
set GOOS=linux
set GOARCH=arm64
go build -ldflags="-s -w" -o %BUILD_DIR%\terminal-link-linux-arm64 main.go
for %%A in ("%BUILD_DIR%\terminal-link-linux-arm64") do set size=%%~zA
echo ✓ Built terminal-link-linux-arm64 (!size! bytes)

REM macOS builds
echo Building for darwin/amd64...
set GOOS=darwin
set GOARCH=amd64
set CGO_ENABLED=0
go build -ldflags="-s -w" -o %BUILD_DIR%\terminal-link-darwin-amd64 main.go
for %%A in ("%BUILD_DIR%\terminal-link-darwin-amd64") do set size=%%~zA
echo ✓ Built terminal-link-darwin-amd64 (!size! bytes)

echo Building for darwin/arm64...
set GOOS=darwin
set GOARCH=arm64
set CGO_ENABLED=0
go build -ldflags="-s -w" -o %BUILD_DIR%\terminal-link-darwin-arm64 main.go
for %%A in ("%BUILD_DIR%\terminal-link-darwin-arm64") do set size=%%~zA
echo ✓ Built terminal-link-darwin-arm64 (!size! bytes)

REM Windows builds
echo Building for windows/amd64...
set GOOS=windows
set GOARCH=amd64
set CGO_ENABLED=
go build -ldflags="-s -w" -o %BUILD_DIR%\terminal-link-windows-arm64.exe main.go
for %%A in ("%BUILD_DIR%\terminal-link-windows-arm64.exe") do set size=%%~zA
echo ✓ Built terminal-link-windows-arm64.exe (!size! bytes)

echo Building for windows/arm64...
set GOOS=windows
set GOARCH=arm64
set CGO_ENABLED=
go build -ldflags="-s -w" -o %BUILD_DIR%\terminal-link-windows-arm64.exe main.go
for %%A in ("%BUILD_DIR%\terminal-link-windows-arm64.exe") do set size=%%~zA
echo ✓ Built terminal-link-windows-arm64.exe (!size! bytes)

REM Android builds (for Termux)
echo Building for android/arm64...
set GOOS=linux
set GOARCH=arm64
set CGO_ENABLED=0
go build -ldflags="-s -w" -o %BUILD_DIR%\terminal-link-android-arm64 main.go
for %%A in ("%BUILD_DIR%\terminal-link-android-arm64") do set size=%%~zA
echo ✓ Built terminal-link-android-arm64 (!size! bytes)

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
