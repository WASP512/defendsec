<#
.SYNOPSIS
  DefendSec host agent installer for Windows (roadmap 5.1).

.DESCRIPTION
  Downloads defendsec-agentd for this architecture from your DefendSec server
  (or GitHub Releases), verifies it against SHA256SUMS, installs it as the
  DefendSecAgent service running as LocalSystem, and waits for enrollment.
  The MSI (defendsec-agent-windows-amd64.msi) does the same for fleet tools.

  Run from an elevated PowerShell:

    .\install-agent.ps1 -ServerHttp https://SERVER:47262 -ServerGrpc SERVER:47263 `
      -TlsServerName SERVER -EnrollSecret SECRET `
      -DownloadBase https://SERVER:47261/downloads

  If the console uses its self-signed certificate, import console.crt into
  the machine's Trusted Root store first, or pass -DownloadCa. There is no
  option to skip verification: the checksum travels over the same connection
  as the binary and does not protect against an attacker who can intercept it.

.PARAMETER Binary
  Install a local defendsec-agentd.exe instead of downloading one.
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$ServerHttp,
  [Parameter(Mandatory = $true)][string]$ServerGrpc,
  [Parameter(Mandatory = $true)][string]$TlsServerName,
  [Parameter(Mandatory = $true)][string]$EnrollSecret,
  [string]$DownloadBase = '',
  [string]$DownloadCa = '',
  [string]$GitHubRepo = 'WASP512/defendsec',
  [string]$Binary = '',
  [string]$InstallDir = (Join-Path $env:ProgramFiles 'DefendSec'),
  [string]$StateDir = (Join-Path $env:ProgramData 'DefendSec\agent')
)

$ErrorActionPreference = 'Stop'
$ServiceName = 'DefendSecAgent'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script from an elevated PowerShell (Run as administrator).'
}

function Info([string]$msg) { Write-Host "==> $msg" }

switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { $arch = 'amd64' }
  'ARM64' { $arch = 'arm64' }
  default { throw "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
}
$assetName = "defendsec-agentd-windows-$arch.exe"

# Windows PowerShell 5.1 on older .NET has no Tls13 member; TLS 1.2 is the floor.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]'Tls13' } catch {}
if ($DownloadCa -and $PSVersionTable.PSEdition -eq 'Core') {
  # PowerShell 7's web cmdlets ignore ServicePointManager, so the pin below
  # would silently not apply. Refuse rather than download unverified.
  throw 'With -DownloadCa, run this script in Windows PowerShell (powershell.exe), not PowerShell 7.'
}
if ($DownloadCa) {
  # Trust the given certificate for this process only, by pinning it, rather
  # than adding it to the machine store behind the operator's back.
  $pinned = New-Object Security.Cryptography.X509Certificates.X509Certificate2($DownloadCa)
  [Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $cert, $chain, $errors)
    if ($errors -eq [Net.Security.SslPolicyErrors]::None) { return $true }
    $c2 = New-Object Security.Cryptography.X509Certificates.X509Certificate2($cert)
    $ch = New-Object Security.Cryptography.X509Certificates.X509Chain
    $ch.ChainPolicy.RevocationMode = 'NoCheck'
    $ch.ChainPolicy.VerificationFlags = 'AllowUnknownCertificateAuthority'
    [void]$ch.ChainPolicy.ExtraStore.Add($pinned)
    if (-not $ch.Build($c2)) { return $false }
    $root = $ch.ChainElements[$ch.ChainElements.Count - 1].Certificate
    return ($root.Thumbprint -eq $pinned.Thumbprint) -and (($errors -band [Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -eq 0)
  }.GetNewClosure()
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("defendsec-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $exe = Join-Path $tmp 'defendsec-agentd.exe'
  if ($Binary) {
    Copy-Item $Binary $exe
  } else {
    if ($DownloadBase) {
      $base = $DownloadBase.TrimEnd('/')
      $binUrl = "$base/$assetName"; $sumsUrl = "$base/SHA256SUMS"
    } else {
      Info "Looking up the latest release of $GitHubRepo"
      $rel = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$GitHubRepo/releases/latest"
      $binUrl = ($rel.assets | Where-Object name -eq $assetName | Select-Object -First 1).browser_download_url
      $sumsUrl = ($rel.assets | Where-Object name -eq 'SHA256SUMS' | Select-Object -First 1).browser_download_url
      if (-not $binUrl) { throw "the latest release has no $assetName; pass -DownloadBase or -Binary" }
      if (-not $sumsUrl) { throw 'the latest release has no SHA256SUMS' }
    }
    Info "Downloading $assetName"
    Invoke-WebRequest -UseBasicParsing -Uri $binUrl -OutFile $exe
    $sums = Join-Path $tmp 'SHA256SUMS'
    Invoke-WebRequest -UseBasicParsing -Uri $sumsUrl -OutFile $sums
    $expected = $null
    foreach ($line in Get-Content $sums) {
      $parts = $line -split '\s+', 2
      if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $assetName) { $expected = $parts[0].ToLower() }
    }
    if ($expected -notmatch '^[0-9a-f]{64}$') { throw "SHA256SUMS has no valid entry for $assetName" }
    $actual = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLower()
    if ($actual -ne $expected) { throw "checksum mismatch for $assetName" }
    Info "Verified $assetName SHA256"
  }

  $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($existing) {
    Info 'Stopping the existing agent service'
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
  }

  Info "Installing to $InstallDir"
  New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
  $target = Join-Path $InstallDir 'defendsec-agentd.exe'
  Copy-Item -Force $exe $target
  $uninstaller = Join-Path $PSScriptRoot 'uninstall-agent.ps1'
  if (Test-Path $uninstaller) { Copy-Item -Force $uninstaller (Join-Path $InstallDir 'uninstall-agent.ps1') }

  # State directory: SYSTEM and Administrators only, inheritance removed, so
  # the client key is not readable by ordinary users.
  New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  & icacls.exe $StateDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls failed on $StateDir" }

  $quote = { param($s) '"' + ($s -replace '"', '\"') + '"' }
  $binPath = (& $quote $target) + ' -server-http ' + (& $quote $ServerHttp) + ' -server-grpc ' + (& $quote $ServerGrpc) +
    ' -tls-server-name ' + (& $quote $TlsServerName) + ' -state-dir ' + (& $quote $StateDir) +
    ' -enroll-secret ' + (& $quote $EnrollSecret)

  if ($existing) {
    & sc.exe config $ServiceName binPath= $binPath start= auto | Out-Null
  } else {
    New-Service -Name $ServiceName -BinaryPathName $binPath -DisplayName 'DefendSec Agent' `
      -Description 'DefendSec mTLS host agent' -StartupType Automatic | Out-Null
  }
  if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw "sc.exe config failed ($LASTEXITCODE)" }
  & sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/10000/restart/60000 | Out-Null

  Info 'Starting the agent and waiting for enrollment'
  Start-Service -Name $ServiceName
  $deviceId = Join-Path $StateDir 'device-id'
  $ok = $false
  for ($i = 1; $i -le 30; $i++) {
    $svc = Get-Service -Name $ServiceName
    if ($svc.Status -eq 'Running' -and (Test-Path $deviceId) -and (Get-Item $deviceId).Length -gt 0) { $ok = $true; break }
    Start-Sleep -Seconds 1
  }
  if (-not $ok) {
    $log = Join-Path $StateDir 'agent.log'
    if (Test-Path $log) { Get-Content $log -Tail 40 }
    throw 'the agent did not enroll within 30 seconds; see the log above'
  }
  Info 'Agent installed, enrolled and running.'
  Write-Host "Check the DefendSec console Devices page for $env:COMPUTERNAME."
  Write-Host "Log: $(Join-Path $StateDir 'agent.log')"
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
