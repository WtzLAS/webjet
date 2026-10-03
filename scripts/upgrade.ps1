<#
.SYNOPSIS
  Install or upgrade Webjet on Windows (§19.8). Run as Administrator from a
  checkout of the release tag.

.EXAMPLE
  .\scripts\upgrade.ps1 v2.4.0
  .\scripts\upgrade.ps1 v2.4.0 -Source C:\builds\webjet-v2.4.0
  .\scripts\upgrade.ps1 -Uninstall

.DESCRIPTION
  Fetches the release archive for this platform (or takes the binaries from
  -Source), stops the service, replaces the programs in
  %ProgramFiles%\Webjet together with wintun.dll, and starts the service
  again. A first install registers the LocalSystem service (webjetd install).
  The data directory %ProgramData%\Webjet\state is restricted to SYSTEM and
  Administrators. -Uninstall removes the service, the agent's system
  settings (routes, NRPT rules) and the programs; it keeps the state unless
  -Purge is given.
#>
param(
  [Parameter(Position = 0)] [string] $Version,
  [string] $Source,
  [string] $ReleaseUrl = $env:WEBJET_RELEASE_URL,
  [switch] $Uninstall,
  [switch] $Purge
)
$ErrorActionPreference = 'Stop'
$Install = Join-Path $env:ProgramFiles 'Webjet'
$Data = Join-Path $env:ProgramData 'Webjet'
$Exe = Join-Path $Install 'webjetd.exe'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this script as Administrator.'
}

function Restrict($path) {
  # SYSTEM and Administrators only, inherited (§19.1).
  icacls $path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
}

if ($Uninstall) {
  if (Test-Path $Exe) { & $Exe uninstall }
  Remove-Item -Recurse -Force $Install -ErrorAction SilentlyContinue
  if ($Purge) { Remove-Item -Recurse -Force $Data -ErrorAction SilentlyContinue }
  $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  [Environment]::SetEnvironmentVariable('Path', (($path -split ';') | Where-Object { $_ -ne $Install }) -join ';', 'Machine')
  Write-Host 'Webjet removed.'
  return
}

if (-not $Version -and -not $Source) { throw 'Give a release tag (for example v2.4.0) or -Source.' }

$tmp = Join-Path $env:TEMP "webjet-$([guid]::NewGuid())"
New-Item -ItemType Directory $tmp | Out-Null
try {
  if (-not $Source) {
    if (-not $ReleaseUrl) { throw 'Set -ReleaseUrl or WEBJET_RELEASE_URL to where releases are published.' }
    $zip = Join-Path $tmp 'webjet.zip'
    $url = "$ReleaseUrl/$Version/webjet-$Version-x86_64-pc-windows-msvc.zip"
    Write-Host "Fetching $url"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
    $sumUrl = "$url.sha256"
    $want = ((Invoke-WebRequest -UseBasicParsing -Uri $sumUrl).Content -split '\s+')[0].ToLower()
    $have = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
    if ($want -ne $have) { throw "checksum mismatch for $url" }
    Expand-Archive $zip -DestinationPath $tmp
    $Source = $tmp
  }
  foreach ($f in 'webjetd.exe', 'webjetctl.exe', 'wintun.dll') {
    if (-not (Test-Path (Join-Path $Source $f))) { throw "$f missing in $Source" }
  }

  $svc = Get-Service webjetd -ErrorAction SilentlyContinue
  if ($svc -and $svc.Status -ne 'Stopped') {
    Write-Host 'Stopping webjetd'
    Stop-Service webjetd
    $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60))
  }

  New-Item -ItemType Directory -Force $Install | Out-Null
  New-Item -ItemType Directory -Force (Join-Path $Data 'state') | Out-Null
  Restrict $Data
  Copy-Item -Force (Join-Path $Source '*.exe') $Install
  Copy-Item -Force (Join-Path $Source 'wintun.dll') $Install

  $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  if (($path -split ';') -notcontains $Install) {
    [Environment]::SetEnvironmentVariable('Path', "$path;$Install", 'Machine')
  }

  $cfg = Join-Path $Data 'webjetd.toml'
  if ($svc) {
    Start-Service webjetd
    Write-Host "Webjet upgraded to $(& $Exe --version)"
  } else {
    if (-not (Test-Path $cfg)) { Set-Content -Path $cfg -Value "# webjetd configuration (see the operations guide)`n" -Encoding UTF8 }
    & $Exe --config $cfg install
    Write-Host "Webjet $(& $Exe --version) installed. Enroll with: webjetd enroll <enrollment string>, then Restart-Service webjetd"
  }
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
