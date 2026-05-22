# Nudgebee Forager Installer for Windows
# Usage (run from an Administrator PowerShell):
#   $env:NB_ACCESS_KEY = "xxx"
#   $env:NB_ACCESS_SECRET = "yyy"
#   iwr -useb https://github.com/nudgebee/forager/releases/latest/download/install.ps1 | iex

param(
    [string]$AccessKey = $env:NB_ACCESS_KEY,
    [string]$AccessSecret = $env:NB_ACCESS_SECRET,
    [string]$RelayUrl = $(if ($env:NB_RELAY_URL) { $env:NB_RELAY_URL } else { "wss://relay.nudgebee.com/register" }),
    [string]$Version = $(if ($env:NB_VERSION) { $env:NB_VERSION } else { "latest" }),
    # Default downloads come from GitHub Releases. Mirror users can point
    # NB_DOWNLOAD_URL at any host that mirrors the same path layout
    # (/download/<tag>/<file> and /latest/download/<file>).
    [string]$DownloadBase = $(if ($env:NB_DOWNLOAD_URL) { $env:NB_DOWNLOAD_URL } else { "https://github.com/nudgebee/forager/releases" })
)

$ErrorActionPreference = "Stop"

$ServiceName = "NudgebeeForager"
$DisplayName = "Nudgebee Forager"
$BinaryName = "nudgebee-forager.exe"
$InstallDir = "$env:ProgramFiles\Nudgebee"
$ConfigDir = "$env:ProgramData\Nudgebee"
$DataDir = "$env:ProgramData\Nudgebee"

function Write-Log { param([string]$Message) Write-Host "[nudgebee] $Message" -ForegroundColor Green }
function Write-Warn { param([string]$Message) Write-Host "[nudgebee] $Message" -ForegroundColor Yellow }
function Write-Err { param([string]$Message) Write-Host "[nudgebee] $Message" -ForegroundColor Red }

# Check administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "This script must be run as Administrator"
    exit 1
}

# Check required vars
if (-not $AccessKey) {
    Write-Err "NB_ACCESS_KEY is required"
    Write-Err 'Usage: $env:NB_ACCESS_KEY="xxx"; $env:NB_ACCESS_SECRET="yyy"; .\install.ps1'
    exit 1
}
if (-not $AccessSecret) {
    Write-Err "NB_ACCESS_SECRET is required"
    exit 1
}

Write-Log "Nudgebee Forager Installer (Windows)"
Write-Host ""

# Detect architecture
$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
Write-Log "Detected platform: windows/$arch"

# Download binary
if ($Version -eq "latest") {
    $url = "$DownloadBase/latest/download/nudgebee-forager-windows-$arch.exe"
} else {
    $url = "$DownloadBase/download/$Version/nudgebee-forager-windows-$arch.exe"
}
Write-Log "Downloading forager from $url..."

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$binaryPath = Join-Path $InstallDir $BinaryName

# Stop existing service before overwriting binary
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -eq "Running") {
    Write-Log "Stopping existing service..."
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 2
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $binaryPath -UseBasicParsing
} catch {
    Write-Err "Failed to download binary: $_"
    exit 1
}
Write-Log "Installed binary to $binaryPath"

# Create config
New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null

$configPath = Join-Path $ConfigDir "forager.yaml"
if (-not (Test-Path $configPath)) {
    Write-Log "Writing config to $configPath..."
    @"
relay_url: $RelayUrl
access_key: $AccessKey
access_secret: $AccessSecret
data_dir: $DataDir
"@ | Set-Content -Path $configPath -Encoding UTF8

    # Restrict config file permissions to Administrators only
    $acl = Get-Acl $configPath
    $acl.SetAccessRuleProtection($true, $false)
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\Administrators", "FullControl", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl -Path $configPath -AclObject $acl
} else {
    Write-Warn "Config file already exists at $configPath, skipping (upgrade mode)"
}

# Register Windows Service
$binPathArg = "`"$binaryPath`" --config `"$configPath`""

if ($existingService) {
    Write-Log "Updating existing service..."
    sc.exe config $ServiceName binPath= $binPathArg | Out-Null
} else {
    Write-Log "Creating Windows Service..."
    New-Service -Name $ServiceName -BinaryPathName $binPathArg -DisplayName $DisplayName -StartupType Automatic -Description "Nudgebee Forager Agent - monitors and proxies datasource connections"
    sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
}

# Start service
Write-Log "Starting service..."
Start-Service -Name $ServiceName

Write-Host ""
Write-Log "Installation complete!"
Write-Host ""
Write-Host "  Binary:  $binaryPath"
Write-Host "  Config:  $configPath"
Write-Host "  Data:    $DataDir"
Write-Host "  Service: $ServiceName"
Write-Host ""
Write-Host "  Check status:  Get-Service $ServiceName"
Write-Host "  View logs:     Get-WinEvent -LogName Application -FilterXPath '*[System[Provider[@Name=""$ServiceName""]]]' -MaxEvents 50"
Write-Host "  Restart:       Restart-Service $ServiceName"
Write-Host ""

$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq "Running") {
    Write-Log "Agent is running"
} else {
    Write-Warn "Agent is not running. Check: Get-Service $ServiceName"
}
