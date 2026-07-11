param(
    [string]$Repo = $(if ($env:CARGO_SCANNER_REPO) { $env:CARGO_SCANNER_REPO } else { "opencomputinggarage/cargo-scanner" }),
    [string]$Version = $(if ($env:CARGO_SCANNER_VERSION) { $env:CARGO_SCANNER_VERSION } else { "latest" }),
    [string]$InstallDir = $(if ($env:CARGO_SCANNER_INSTALL_DIR) { $env:CARGO_SCANNER_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\cargo-scanner" })
)

$ErrorActionPreference = "Stop"

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "AMD64" { "amd64" }
    "ARM64" { "arm64" }
    default { throw "unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
}

if ($Version -eq "latest") {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ Accept = "application/vnd.github+json" }
    $Version = $release.tag_name
}

$archive = "cargo-scanner_$($Version.TrimStart('v'))_windows_$arch.zip"
$base = "https://github.com/$Repo/releases/download/$Version"
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("cargo-scanner-" + [System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    $archivePath = Join-Path $tmp $archive
    $checksumsPath = Join-Path $tmp "checksums.txt"
    Invoke-WebRequest -Uri "$base/$archive" -OutFile $archivePath
    Invoke-WebRequest -Uri "$base/checksums.txt" -OutFile $checksumsPath

    $line = Get-Content $checksumsPath | Where-Object { $_ -match "\s$([regex]::Escape($archive))$" } | Select-Object -First 1
    if (-not $line) {
        throw "checksum for $archive not found"
    }
    $expected = ($line -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 $archivePath).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "checksum mismatch for $archive"
    }

    Expand-Archive -Path $archivePath -DestinationPath $tmp -Force
    $exe = Get-ChildItem -Path $tmp -Filter "cargo-scanner.exe" -Recurse | Select-Object -First 1
    if (-not $exe) {
        throw "cargo-scanner.exe not found in $archive"
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $dst = Join-Path $InstallDir "cargo-scanner.exe"
    Copy-Item -Path $exe.FullName -Destination $dst -Force

    $installedVersion = & $dst version
    Write-Output "installed $installedVersion to $dst"
    Write-Output "next: add $InstallDir to PATH if needed, then run: cargo-scanner doctor --fix"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
