# CI installer. The committed digest pins OpenBao's complete checksum manifest.
param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$pin = Get-Content "$PSScriptRoot/../openbao.json" -Raw | ConvertFrom-Json
$platform = (go env GOHOSTOS GOHOSTARCH) -join '_'
if ($LASTEXITCODE -ne 0) { throw 'Could not determine the Go host platform' }
$extension = if ($IsWindows) { 'zip' } else { 'tar.gz' }
$executable = if ($IsWindows) { 'bao.exe' } else { 'bao' }
$archiveName = "openbao_$($pin.version.TrimStart('v'))_$platform.$extension"
$baseUrl = "https://github.com/openbao/openbao/releases/download/$($pin.version)"
$work = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $checksums = Join-Path $work 'checksums.txt'
    Invoke-WebRequest "$baseUrl/checksums.txt" -OutFile $checksums -TimeoutSec 180
    if ((Get-FileHash $checksums -Algorithm SHA256).Hash -ne $pin.sha256) {
        throw 'OpenBao checksum manifest does not match the committed digest'
    }
    $pattern = '^([a-f0-9]{64})\s+\*?' + [regex]::Escape($archiveName) + '$'
    $entry = @(Get-Content $checksums | Select-String -Pattern $pattern)
    if ($entry.Count -ne 1) { throw "Expected one checksum for $archiveName" }
    $archive = Join-Path $work $archiveName
    Invoke-WebRequest "$baseUrl/$archiveName" -OutFile $archive -TimeoutSec 180
    if ((Get-FileHash $archive -Algorithm SHA256).Hash -ne $entry[0].Matches[0].Groups[1].Value) {
        throw 'OpenBao archive does not match the verified checksum manifest'
    }
    $unpacked = New-Item -ItemType Directory -Path (Join-Path $work 'unpacked')
    if ($IsWindows) {
        Expand-Archive -LiteralPath $archive -DestinationPath $unpacked.FullName
    } else {
        tar -xzf $archive -C $unpacked.FullName $executable
        if ($LASTEXITCODE -ne 0) { throw 'Could not extract OpenBao' }
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Copy-Item (Join-Path $unpacked.FullName $executable) -Destination $Destination
    Write-Host "Installed OpenBao $($pin.version) for $platform in $Destination"
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force
}
