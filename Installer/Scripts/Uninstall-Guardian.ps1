$ErrorActionPreference = 'Stop'
$PackageIdentityName = '2fdd8c0d-4f9d-4038-909f-5dc994b95ba1'

$logDirectory = Join-Path $env:LOCALAPPDATA 'Guardian\Installer'
$logPath = Join-Path $logDirectory 'uninstall.log'
New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null

function Write-UninstallLog([string]$Message) {
    Add-Content -LiteralPath $logPath -Value ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message) -Encoding UTF8
}

try {
    Get-Process -Name 'Guardian.Desktop' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    $packages = @(Get-AppxPackage -Name $PackageIdentityName -ErrorAction SilentlyContinue)

    foreach ($package in $packages) {
        Remove-AppxPackage -Package $package.PackageFullName -ErrorAction Stop
        Write-UninstallLog "Removed package registration: $($package.PackageFullName)"
    }

    $ownershipPath = 'HKCU:\Software\Guardian\Installer'

    if (Test-Path $ownershipPath) {
        $ownership = Get-ItemProperty -Path $ownershipPath

        if ($ownership.AddedDevelopmentCertificate -eq 1 -and
            $ownership.DevelopmentCertificateThumbprint) {

            $thumbprint = [string]$ownership.DevelopmentCertificateThumbprint

            $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
                [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
                [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
            )

            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

            try {
                $matching = @($store.Certificates | Where-Object {
                    $_.Thumbprint -eq $thumbprint
                })

                foreach ($certificate in $matching) {
                    $store.Remove($certificate)
                    Write-UninstallLog "Removed Guardian-added development certificate: $thumbprint"
                }
            }
            finally {
                $store.Close()
            }
        }

        Remove-Item -LiteralPath $ownershipPath -Recurse -Force
    }

    Write-UninstallLog 'Guardian application identity and installer-owned development certificate cleanup completed.'
}
catch {
    Write-UninstallLog "ERROR: $($_.Exception.Message)"
    Write-UninstallLog $_.ScriptStackTrace
    exit 1
}