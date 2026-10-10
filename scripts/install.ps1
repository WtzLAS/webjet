# Install Webjet on Windows: downloads webjetup (the installation manager)
# for this machine, checks it and runs `webjetup install`. The Windows
# counterpart of install.sh. Run it in an elevated PowerShell (Run as
# Administrator):
#
#   irm https://forgejo.wolf109909.top/webj8/webjet/releases/download/v0.12.0/install.ps1 | iex
#
# With arguments for `webjetup install` (install and enroll, a specific
# version, …):
#
#   & ([scriptblock]::Create((irm …/install.ps1))) --enroll 'wj1:…'
#   & ([scriptblock]::Create((irm …/install.ps1))) v0.12.0
#
# or save it and run `.\install.ps1 --enroll 'wj1:…'`. Environment:
#   WEBJET_REPO     repository to install from (default below)
#   WEBJET_VERSION  release to take webjetup from (default: latest)
#
# Errors are thrown, never `exit`: under `iex` that would close the window.

$ErrorActionPreference = 'Stop'
# Invoke-WebRequest's progress bar slows downloads down a lot in Windows
# PowerShell 5.1.
$ProgressPreference = 'SilentlyContinue'

function Fail([string]$msg) { throw "install.ps1: $msg" }

$repo = if ($env:WEBJET_REPO) { $env:WEBJET_REPO } else { 'https://forgejo.wolf109909.top/webj8/webjet' }
$repo = $repo.TrimEnd('/')

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'run in an elevated PowerShell (right-click, Run as Administrator)'
}

# The architecture of Windows, also from a 32-bit PowerShell.
$arch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
if ($arch -ne 'AMD64') {
    Fail "unsupported architecture ${arch}: Webjet for Windows is built for x86_64 (AMD64)"
}
$target = 'x86_64-pc-windows-msvc'

# Windows PowerShell 5.1 may not offer TLS 1.2 by default.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

if ($env:WEBJET_VERSION) {
    $tag = $env:WEBJET_VERSION
    if (-not $tag.StartsWith('v')) { $tag = "v$tag" }
} else {
    # owner/repo from the repository URL, then the latest release's tag.
    $uri = [Uri]$repo
    $path = $uri.AbsolutePath.Trim('/')
    $api = "$($uri.Scheme)://$($uri.Authority)/api/v1/repos/$path/releases/latest"
    try {
        $tag = (Invoke-RestMethod -UseBasicParsing -Uri $api).tag_name
    } catch {
        Fail "could not find the latest release at ${repo}: $($_.Exception.Message)"
    }
    if (-not $tag) { Fail "could not find the latest release at $repo" }
}

$file = "webjetup-$tag-$target.exe"
$url = "$repo/releases/download/$tag/$file"
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('webjet-install-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $exe = Join-Path $tmp 'webjetup.exe'
    $sum = Join-Path $tmp 'webjetup.exe.sha256'
    Write-Host "Downloading webjetup $tag for $target"
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $exe
        Invoke-WebRequest -UseBasicParsing -Uri "$url.sha256" -OutFile $sum
    } catch {
        Fail "download failed: $url ($($_.Exception.Message))"
    }
    $want = ((Get-Content -Raw -Path $sum).Trim() -split '\s+')[0].ToLowerInvariant()
    $have = (Get-FileHash -Algorithm SHA256 -Path $exe).Hash.ToLowerInvariant()
    if (-not $want -or $want -ne $have) { Fail "checksum mismatch for $file" }

    # webjetup installs itself next to the programs, so it stays available.
    & $exe --repo $repo install @args
    if ($LASTEXITCODE -ne 0) { Fail "webjetup install failed (exit code $LASTEXITCODE)" }
} finally {
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}
