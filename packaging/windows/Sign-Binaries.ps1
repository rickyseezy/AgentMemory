[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$InputDirectory,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$SignTool,
    [Parameter(Mandatory = $true)][string]$CertificateSha1,
    [Parameter(Mandatory = $true)][string]$CertificateSha256,
    [Parameter(Mandatory = $true)][uri]$TimestampUrl
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Assert-AbsoluteLocalPath([string]$Path, [string]$Name) {
    if (-not [System.IO.Path]::IsPathFullyQualified($Path) -or $Path.IndexOfAny("`0`r`n".ToCharArray()) -ge 0) {
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

Assert-AbsoluteLocalPath $InputDirectory 'InputDirectory'
Assert-AbsoluteLocalPath $OutputDirectory 'OutputDirectory'
Assert-AbsoluteLocalPath $SignTool 'SignTool'
if ($CertificateSha1 -cnotmatch '^[0-9A-F]{40}$' -or $CertificateSha256 -cnotmatch '^[0-9A-F]{64}$') {
    throw 'Certificate digests must be uppercase canonical hexadecimal'
}
if ($TimestampUrl.Scheme -cne 'https' -or -not $TimestampUrl.IsAbsoluteUri) {
    throw 'TimestampUrl must be absolute HTTPS'
}
if (-not (Test-Path -LiteralPath $InputDirectory -PathType Container) -or
    -not (Test-Path -LiteralPath $SignTool -PathType Leaf) -or
    (Test-Path -LiteralPath $OutputDirectory)) {
    throw 'Signing input, tool, or new output boundary is invalid'
}

$launcher = Join-Path $InputDirectory 'agentmemory.exe'
$helper = Join-Path $InputDirectory 'agentmemory-runtime-helper.exe'
foreach ($path in @($launcher, $helper)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path -Force).Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw "Unsigned native input is unsafe: $path"
    }
}

$parent = Split-Path -Parent $OutputDirectory
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw 'Output parent does not exist'
}
$temporary = Join-Path $parent ('.agentmemory-sign-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
$committed = $false
try {
    foreach ($source in @($launcher, $helper)) {
        $target = Join-Path $temporary (Split-Path -Leaf $source)
        Copy-Item -LiteralPath $source -Destination $target
        & $SignTool sign /sha1 $CertificateSha1 /fd SHA256 /tr $TimestampUrl.AbsoluteUri /td SHA256 /v $target
        if ($LASTEXITCODE -ne 0) { throw "SignTool sign failed for $target" }
        & $SignTool verify /pa /all /v $target
        if ($LASTEXITCODE -ne 0) { throw "SignTool verify failed for $target" }
        Assert-ExactCertificate $target $CertificateSha256
    }
    [IO.Directory]::Move($temporary, $OutputDirectory)
    $committed = $true
}
finally {
    if (-not $committed -and (Test-Path -LiteralPath $temporary)) {
        Remove-Item -LiteralPath $temporary -Recurse -Force
    }
}
