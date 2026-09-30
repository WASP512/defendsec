<#
.SYNOPSIS
  Uninstall the DefendSec agent from Windows.

.DESCRIPTION
  Stops and removes the DefendSecAgent service and the installed binary.
  Agent state (its certificate and key) is kept unless -PurgeData is given,
  so a reinstall can reuse the enrollment. Installed from the MSI? Remove it
  from Settings > Apps, or: msiexec /x defendsec-agent-windows-amd64.msi /qn
  — this script also works, and removes the MSI registration if present.

    .\uninstall-agent.ps1 [-PurgeData]
#>
[CmdletBinding()]
param(
  [switch]$PurgeData,
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

# An MSI install is removed through Windows Installer so its registration
# does not linger in Apps & features.
$msi = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -eq 'DefendSec Agent' -and $_.PSChildName -match '^\{' } | Select-Object -First 1
if ($msi) {
  Info 'Removing the DefendSec Agent MSI'
  $p = Start-Process msiexec.exe -ArgumentList '/x', $msi.PSChildName, '/qn', '/norestart' -Wait -PassThru
  if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "msiexec /x failed with $($p.ExitCode)" }
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
  Info 'Stopping and removing the DefendSecAgent service'
  Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
  & sc.exe delete $ServiceName | Out-Null
}

$exe = Join-Path $InstallDir 'defendsec-agentd.exe'
if (Test-Path $exe) { Remove-Item -Force $exe }
$self = Join-Path $InstallDir 'uninstall-agent.ps1'
if ((Test-Path $InstallDir) -and -not (Get-ChildItem $InstallDir | Where-Object FullName -ne $self)) {
  Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
}

if ($PurgeData) {
  Info "Removing $StateDir"
  Remove-Item -Recurse -Force $StateDir -ErrorAction SilentlyContinue
  $parent = Split-Path $StateDir -Parent
  if ((Test-Path $parent) -and -not (Get-ChildItem $parent)) { Remove-Item -Force $parent }
} else {
  Info "Left agent state in $StateDir (pass -PurgeData to remove it)"
}
Info 'Agent uninstall complete. Remove the host in the console to stop it being listed as offline.'
