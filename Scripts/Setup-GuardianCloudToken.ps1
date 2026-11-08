$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Security

$secureToken = Read-Host "Paste Guardian Cloud access token" -AsSecureString
$pointer = [IntPtr]::Zero
$plainToken = $null
$clearBytes = $null
$protectedBytes = $null

try {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
    $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)

    if ([string]::IsNullOrWhiteSpace($plainToken)) {
        throw "The access token cannot be empty."
    }

    $clearBytes = [Text.Encoding]::UTF8.GetBytes($plainToken)
    $entropy = [Text.Encoding]::UTF8.GetBytes("Guardian.Cloud.AccessToken.v1")

    $protectedBytes = [System.Security.Cryptography.ProtectedData]::Protect(
        $clearBytes,
        $entropy,
        [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    )

    $directory = Join-Path $env:LOCALAPPDATA "Guardian"
    New-Item -ItemType Directory -Path $directory -Force | Out-Null

    $destination = Join-Path $directory "cloud-access-token.bin"
    [IO.File]::WriteAllBytes($destination, $protectedBytes)

    Write-Host "Guardian Cloud token saved encrypted for the current Windows user." -ForegroundColor Green
    Write-Host "File: $destination"
}
finally {
    if ($pointer -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }

    if ($clearBytes) {
        [Array]::Clear($clearBytes, 0, $clearBytes.Length)
    }

    if ($secureToken) {
        $secureToken.Dispose()
    }

    $plainToken = $null
    $clearBytes = $null
    $protectedBytes = $null
}
