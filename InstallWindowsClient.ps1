# Mycelium VPN Installer

# Check Administrator Privileges
$Current = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]$Current
if (-not $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Host "ERROR: Please run as Administrator" -ForegroundColor Red
    exit 1
}

$ErrorActionPreference = "Stop"
$InstallDir = "C:\Program Files\Mycelium"

Write-Host "--- Mycelium VPN Installer ---" -ForegroundColor Cyan

#  Build Binaries
Write-Host "Building Binaries..." -ForegroundColor Yellow

# Build Client
go build -o dist/mycelium-client.exe ./cmd/windowsClient/WindowsClient.go
if (-not (Test-Path "dist/mycelium-client.exe")) {
    Write-Error "Client build failed."
    exit 1
}

# Build CLI
go build -o dist/mycelium.exe ./windowsClient-cli/main.go 
if (-not (Test-Path "dist/mycelium.exe")) {
    Write-Error "CLI build failed."
    exit 1
}

Write-Host "Build Successful." -ForegroundColor Green

# Download Wintun Driver
$DllPath = "dist/wintun.dll"
if (-not (Test-Path $DllPath)) {
    Write-Host "Downloading Wintun Driver..." -ForegroundColor Yellow
    $Url = "https://www.wintun.net/builds/wintun-0.14.1.zip"
    $Zip = "dist/wintun.zip"
    
    Invoke-WebRequest -Uri $Url -OutFile $Zip
    Expand-Archive -Path $Zip -DestinationPath "dist/temp" -Force
    Copy-Item "dist/temp/wintun/bin/amd64/wintun.dll" -Destination $DllPath
    
    Remove-Item "dist/temp" -Recurse -Force
    Remove-Item $Zip
    Write-Host "Driver Downloaded." -ForegroundColor Green
}

# Install Files
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
}

Write-Host "Installing to Program Files..."
Copy-Item "dist/mycelium-client.exe" -Destination "$InstallDir\mycelium-client.exe" -Force
Copy-Item "dist/mycelium.exe" -Destination "$InstallDir\mycelium.exe" -Force
Copy-Item "dist/wintun.dll" -Destination "$InstallDir\wintun.dll" -Force
Copy-Item "src/config/ClientConfig.json" -Destination "$InstallDir\ClientConfig.json" -Force

# Update PATH
$Scope = "Machine"
$OldPath = [Environment]::GetEnvironmentVariable("Path", $Scope)

if ($OldPath -notlike "*$InstallDir*") {
    Write-Host "Adding to System PATH..." -ForegroundColor Yellow
    $NewPath = $OldPath + ";" + $InstallDir
    [Environment]::SetEnvironmentVariable("Path", $NewPath, $Scope)
    Write-Host "PATH Updated." -ForegroundColor Green
} else {
    Write-Host "Already in PATH." -ForegroundColor Gray
}

Write-Host "--- Installation Complete! ---" -ForegroundColor Cyan
Write-Host "Run this command in a NEW terminal:"
Write-Host "    mycelium connect --server <IP> --key <KEY>" -ForegroundColor White