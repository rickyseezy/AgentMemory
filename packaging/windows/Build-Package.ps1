[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StageDirectory,
    [Parameter(Mandatory = $true)][string]$OutputPackage,
    [Parameter(Mandatory = $true)][ValidateSet('amd64', 'arm64')][string]$Architecture,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+$')][string]$Version,
    [Parameter(Mandatory = $true)][string]$Wix,
    [Parameter(Mandatory = $true)][string]$SignTool,
    [Parameter(Mandatory = $true)][string]$CertificateSha1,
    [Parameter(Mandatory = $true)][string]$CertificateSha256,
    [Parameter(Mandatory = $true)][uri]$TimestampUrl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-AbsoluteLocalPath([string]$Path, [string]$Name) {
    if (-not [IO.Path]::IsPathFullyQualified($Path) -or $Path.IndexOfAny("`0`r`n".ToCharArray()) -ge 0) {
        throw "$Name must be an absolute local path"
    }
}

function Assert-ExactCertificate([string]$Path, [string]$ExpectedSha256) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) {
        throw "Authenticode verification failed for $Path"
    }
    $actual = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($signature.SignerCertificate.RawData))
    if ($actual -cne $ExpectedSha256) {
        throw "Authenticode signer certificate changed for $Path"
    }
}

foreach ($entry in @{
    StageDirectory = $StageDirectory; OutputPackage = $OutputPackage; Wix = $Wix; SignTool = $SignTool
}.GetEnumerator()) {
    Assert-AbsoluteLocalPath $entry.Value $entry.Key
}
if ($Version -eq '0.0.0' -or $CertificateSha1 -cnotmatch '^[0-9A-F]{40}$' -or
    $CertificateSha256 -cnotmatch '^[0-9A-F]{64}$' -or $TimestampUrl.Scheme -cne 'https') {
    throw 'Version, certificate, or timestamp authority is invalid'
}
if (-not (Test-Path -LiteralPath $StageDirectory -PathType Container) -or
    -not (Test-Path -LiteralPath $Wix -PathType Leaf) -or
    -not (Test-Path -LiteralPath $SignTool -PathType Leaf) -or
    (Test-Path -LiteralPath $OutputPackage)) {
    throw 'Package input, tool, or new output boundary is invalid'
}

$payload = Join-Path $StageDirectory 'payload'
$launcher = Join-Path $payload 'agentmemory.exe'
$helper = Join-Path $payload 'bin\agentmemory-runtime-helper.exe'
$bundle = Join-Path $payload 'resources\bundle'
foreach ($path in @($launcher, $helper)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing package executable: $path" }
    & $SignTool verify /pa /all /v $path
    if ($LASTEXITCODE -ne 0) { throw "SignTool verify failed for $path" }
    Assert-ExactCertificate $path $CertificateSha256
}
if (-not (Test-Path -LiteralPath $bundle -PathType Container) -or
    (Get-ChildItem -LiteralPath $payload -Recurse -Force -Attributes ReparsePoint | Select-Object -First 1)) {
    throw 'Package payload is missing or contains a reparse point'
}

$wixVersion = (& $Wix --version | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $wixVersion -notmatch '^7\.0\.0(?:\+.*)?$') {
    throw "WiX 7.0.0 is required, found $wixVersion"
}
$wixArchitecture = if ($Architecture -eq 'amd64') { 'x64' } else { 'arm64' }
$parent = Split-Path -Parent $OutputPackage
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'Output parent does not exist' }
$temporary = Join-Path $parent ('.agentmemory-package-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
$committed = $false
try {
    $package = Join-Path $temporary 'agentmemory.msi'
    $intermediate = Join-Path $temporary 'intermediate'
    & $Wix build packaging/windows/Package.wxs -arch $wixArchitecture `
        -bindpath "Payload=$payload" -define "AgentMemoryVersion=$Version" `
        -intermediateFolder $intermediate -pdbtype none -out $package
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $package -PathType Leaf)) {
        throw 'WiX package build failed'
    }
    & $Wix msi validate $package
    if ($LASTEXITCODE -ne 0) { throw 'Windows Installer validation failed' }
    & $SignTool sign /sha1 $CertificateSha1 /fd SHA256 /tr $TimestampUrl.AbsoluteUri /td SHA256 /v $package
    if ($LASTEXITCODE -ne 0) { throw 'SignTool package signing failed' }
    & $SignTool verify /pa /all /v $package
    if ($LASTEXITCODE -ne 0) { throw 'SignTool package verification failed' }
    Assert-ExactCertificate $package $CertificateSha256
    [IO.File]::Move($package, $OutputPackage)
    $committed = $true
}
finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}
