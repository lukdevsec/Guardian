[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$AppDirectory,
    [Parameter(Mandatory = $true)] [string]$IdentityPackagePath,
    [Parameter(Mandatory = $true)] [string]$CertificatePath,
    [Parameter(Mandatory = $true)] [string]$RuntimeInstallerPath,
    [Parameter(Mandatory = $true)] [string]$VcRedistPath
)

$ErrorActionPreference = 'Stop'
$PackageIdentityName = '2fdd8c0d-4f9d-4038-909f-5dc994b95ba1'
$ExpectedPublisher = 'CN=Golden Retriever'
$LogDirectory = Join-Path $env:LOCALAPPDATA 'Guardian\Installer'
$LogPath = Join-Path $LogDirectory 'install.log'
New-Item -ItemType Directory -Path $LogDirectory -Force | Out-Null

function Write-InstallLog([string]$Message) {
    Add-Content -LiteralPath $LogPath -Value ('{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message) -Encoding UTF8
}

try {
    $AppDirectory = (Resolve-Path -LiteralPath $AppDirectory).Path
    $IdentityPackagePath = (Resolve-Path -LiteralPath $IdentityPackagePath).Path
    $CertificatePath = (Resolve-Path -LiteralPath $CertificatePath).Path
    $RuntimeInstallerPath = (Resolve-Path -LiteralPath $RuntimeInstallerPath).Path
    $VcRedistPath = (Resolve-Path -LiteralPath $VcRedistPath).Path

    if (-not (Test-Path (Join-Path $AppDirectory 'Guardian.Desktop.exe'))) {
        throw 'Guardian.Desktop.exe is missing from the installation directory.'
    }
    if (-not (Test-Path (Join-Path $AppDirectory 'models\v5\ch_PP-OCRv5_mobile_det.onnx'))) {
        throw 'RapidOCR model files are missing from the installation directory.'
    }

    Write-InstallLog "Installing Guardian external-location app into $AppDirectory."

    Get-Process -Name 'Guardian.Desktop' -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue

    Write-InstallLog 'Installing Microsoft Visual C++ Redistributable x64.'
    $vcProcess = Start-Process -FilePath $VcRedistPath -ArgumentList '/install /quiet /norestart' -Wait -PassThru
    if ($vcProcess.ExitCode -notin @(0, 1638, 3010)) {
        throw "Visual C++ Redistributable installer failed with exit code $($vcProcess.ExitCode)."
    }
    if ($vcProcess.ExitCode -eq 3010) {
        Write-InstallLog 'Visual C++ Redistributable requested a reboot; setup will continue and Windows can restart later.'
    }

    Write-InstallLog 'Installing Windows App SDK Runtime 2.6.5 x64 (Framework, Main, Singleton and DDLM).'
    $runtimeProcess = Start-Process -FilePath $RuntimeInstallerPath -ArgumentList '--quiet' -Wait -PassThru
    if ($runtimeProcess.ExitCode -ne 0) {
        throw "Windows App SDK Runtime installer failed with exit code $($runtimeProcess.ExitCode). See Windows App SDK deployment logs."
    }

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertificatePath)
    if ($certificate.Subject -ne $ExpectedPublisher) {
        throw "Publisher mismatch. Expected '$ExpectedPublisher', found '$($certificate.Subject)'."
    }

    if ($certificate.Thumbprint -ne '4E726676EA77737CF874F7732E17F32B1F2D5A5D') {
        throw 'The development signing certificate thumbprint does not match the expected certificate.'
    }
    if ($certificate.NotAfter -lt (Get-Date)) {
        throw 'Guardian signing certificate has expired.'
    }

    # Development certificate trust for this user. Public releases must use a CA-trusted signing certificate.
    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        $trusted = $store.Certificates | Where-Object { $_.Thumbprint -eq $certificate.Thumbprint }
        if (-not $trusted) {
            [void]$store.Add($certificate)

            $ownershipPath = 'HKCU:\Software\Guardian\Installer'
            New-Item -Path $ownershipPath -Force | Out-Null
            Set-ItemProperty -Path $ownershipPath -Name 'AddedDevelopmentCertificate' -Value 1
            Set-ItemProperty -Path $ownershipPath -Name 'DevelopmentCertificateThumbprint' -Value $certificate.Thumbprint

            Write-InstallLog 'Added development certificate to CurrentUser TrustedPeople and recorded ownership.'
        }
    }
    finally { $store.Close() }

    # Remove an older full-MSIX registration before switching this identity to external-location mode.
    $existingPackages = @(Get-AppxPackage -Name $PackageIdentityName -ErrorAction SilentlyContinue)
    foreach ($existing in $existingPackages) {
        Write-InstallLog "Removing previous package registration $($existing.PackageFullName)."
        Remove-AppxPackage -Package $existing.PackageFullName -ErrorAction Stop
    }

    Write-InstallLog 'Registering sparse identity package with the Program Files application directory.'
    Add-AppxPackage -Path $IdentityPackagePath -ExternalLocation $AppDirectory -ErrorAction Stop

    $registered = Get-AppxPackage -Name $PackageIdentityName -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $registered) {
        throw 'Windows did not register the Guardian external-location identity package.'
    }

    Write-InstallLog "Guardian identity registered. PackageFamilyName=$($registered.PackageFamilyName)"
    Write-InstallLog 'Installation completed successfully.'
    exit 0
}
catch {
    Write-InstallLog "ERROR: $($_.Exception.Message)"
    Write-InstallLog $_.ScriptStackTrace
    Write-Host $_ -ForegroundColor Red
    exit 1
}
