[CmdletBinding()]
param(
    [string]$PfxPath
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$InstallerRoot = Split-Path -Parent $PSScriptRoot
$RepoRoot = Split-Path -Parent $InstallerRoot
$ProjectPath = Join-Path $RepoRoot 'Guardian.Desktop\Guardian.Desktop.csproj'
$PublishProfile = Join-Path $RepoRoot 'Guardian.Desktop\Properties\PublishProfiles\win-x64-external.pubxml'
$ExternalManifest = Join-Path $RepoRoot 'Guardian.Desktop\app.external.manifest'
$IdentitySource = Join-Path $InstallerRoot 'IdentityPackage'
$PayloadIdentity = Join-Path $InstallerRoot 'Payload\Identity'
$PayloadApp = Join-Path $InstallerRoot 'Payload\App'
$PayloadPrerequisites = Join-Path $InstallerRoot 'Payload\Prerequisites'
$WindowsAppRuntimeInstaller = Join-Path $PayloadPrerequisites 'WindowsAppRuntimeInstall-x64.exe'
$VcRedistInstaller = Join-Path $PayloadPrerequisites 'vc_redist.x64.exe'
$WindowsAppRuntimeUrl = 'https://aka.ms/windowsappsdk/2.6/2.6.5/windowsappruntimeinstall-x64.exe'
$VcRedistUrl = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
$IdentityMsix = Join-Path $PayloadIdentity 'Guardian.identity.msix'
$CertificateCer = Join-Path $PayloadIdentity 'Guardian.cer'


function Find-WindowsSdkTool {
    param([string]$Name)

    $roots = @()

    # Discover Windows SDK installation through registry.
    $registryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows Kits\Installed Roots'
    )

    foreach ($registryPath in $registryPaths) {
        $registeredRoot = (
            Get-ItemProperty `
                -Path $registryPath `
                -Name KitsRoot10 `
                -ErrorAction SilentlyContinue
        ).KitsRoot10

        if ($registeredRoot) {
            $roots += $registeredRoot
        }
    }

    # Additional fallback locations.
    $roots += @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'),
        (Join-Path $env:ProgramW6432 'Windows Kits\10'),
        'C:\Program Files (x86)\Windows Kits\10',
        'D:\Program Files (x86)\Windows Kits\10'
    )

    $roots = $roots |
        Where-Object { $_ -and (Test-Path $_) } |
        Select-Object -Unique

    foreach ($root in $roots) {
        $binPath = Join-Path $root 'bin'

        if (-not (Test-Path $binPath)) {
            continue
        }

        $matches = Get-ChildItem `
            -Path $binPath `
            -Recurse `
            -Filter $Name `
            -File `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.FullName -match '[\\/]x64[\\/]'
            }

        if ($matches) {
            $selected = $matches |
                Sort-Object FullName -Descending |
                Select-Object -First 1

            Write-Host "Found SDK tool: $($selected.FullName)" `
                -ForegroundColor Green

            return $selected.FullName
        }
    }

    throw "$Name not found. Windows SDK installation could not be located."
}

try {
    if (-not (Test-Path $ProjectPath)) { throw "Guardian project not found: $ProjectPath" }
    if (-not (Test-Path $PublishProfile)) { throw "External publish profile not found: $PublishProfile" }
    if (-not (Test-Path $ExternalManifest)) { throw "External application manifest not found: $ExternalManifest" }

    if ([string]::IsNullOrWhiteSpace($PfxPath)) {
        $PfxPath = Read-Host 'Full path to your Guardian signing certificate (.pfx)'
    }
    $PfxPath = (Resolve-Path -LiteralPath $PfxPath).Path
    if ([IO.Path]::GetExtension($PfxPath) -ne '.pfx') { throw 'The signing certificate must be a .pfx file.' }

    $makeAppx = Find-WindowsSdkTool 'MakeAppx.exe'
    $signTool = Find-WindowsSdkTool 'SignTool.exe'

    New-Item -ItemType Directory -Path $PayloadIdentity -Force | Out-Null
    New-Item -ItemType Directory -Path $PayloadApp -Force | Out-Null
    New-Item -ItemType Directory -Path $PayloadPrerequisites -Force | Out-Null
    Get-ChildItem -LiteralPath $PayloadApp -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
    Remove-Item -LiteralPath $IdentityMsix, $CertificateCer -Force -ErrorAction SilentlyContinue

    Write-Host 'Publishing Guardian as a .NET self-contained, Windows App SDK framework-dependent external-location app...' -ForegroundColor Cyan

$publishArgs = @(
    'publish',
    $ProjectPath,
    '-c',
    'Release',
    '-r',
    'win-x64',
    '--self-contained',
    'true',

    ('-p:PublishProfile="{0}"' -f $PublishProfile),

    '-p:WindowsPackageType=None',
    '-p:WindowsAppSDKSelfContained=false',
    '-p:SelfContained=true',
    '-p:PublishTrimmed=false',
    '-p:PublishSingleFile=false',
    '-p:DebugType=None',
    '-p:DebugSymbols=false',

    ('-p:PublishDir="{0}"' -f $PayloadApp),

    ('-p:ApplicationManifest="{0}"' -f $ExternalManifest)
)

& dotnet @publishArgs

if ($LASTEXITCODE -ne 0) {
    throw "dotnet publish failed with exit code $LASTEXITCODE."
}



    Write-Host 'Downloading Microsoft Windows App Runtime 2.6.5 (x64)...' -ForegroundColor Cyan
    Invoke-WebRequest -Uri $WindowsAppRuntimeUrl -OutFile $WindowsAppRuntimeInstaller -UseBasicParsing
    Write-Host 'Downloading Microsoft Visual C++ Redistributable (x64)...' -ForegroundColor Cyan
    Invoke-WebRequest -Uri $VcRedistUrl -OutFile $VcRedistInstaller -UseBasicParsing

    foreach ($installer in @($WindowsAppRuntimeInstaller, $VcRedistInstaller)) {
        $signature = Get-AuthenticodeSignature -FilePath $installer
        if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
            $signature.SignerCertificate.Subject -notmatch 'Microsoft') {
            throw "Microsoft Authenticode signature verification failed for: $installer"
        }
    }

    $exe = Join-Path $PayloadApp 'Guardian.Desktop.exe'
    if (-not (Test-Path $exe)) { throw "Published executable not found: $exe" }
    foreach ($required in @(
        'Assets\GuardianIcon.ico',
        'Assets\StoreLogo.png',
        'Assets\Square150x150Logo.png',
        'Assets\Square44x44Logo.png',
        'models\v5\ch_PP-OCRv5_mobile_det.onnx',
        'models\v5\ch_PP-LCNet_x0_25_textline_ori_cls_mobile.onnx',
        'models\v5\latin_PP-OCRv5_rec_mobile_infer.onnx',
        'models\v5\ppocrv5_latin_dict.txt'
    )) {
        if (-not (Test-Path (Join-Path $PayloadApp $required))) {
            throw "Required publish asset is missing: $required"
        }
    }

    Write-Host 'Importing the signing certificate into CurrentUser\My...' -ForegroundColor Cyan
    $pfxPassword = Read-Host 'PFX password' -AsSecureString
    $certificates = Import-PfxCertificate -FilePath $PfxPath `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -Password $pfxPassword
    $certificate = $certificates | Where-Object { $_.Subject -eq 'CN=Golden Retriever' } | Select-Object -First 1
    if (-not $certificate) { throw 'The PFX does not contain a certificate with subject CN=Golden Retriever.' }
    if ($certificate.NotAfter -lt (Get-Date)) { throw 'The signing certificate has expired.' }

    Export-Certificate -Cert $certificate -FilePath $CertificateCer -Force | Out-Null

    # Sparse identity packages must contain the StoreLogo referenced by the manifest.
    $IdentityAssets = Join-Path $IdentitySource 'Assets'
    New-Item -ItemType Directory -Path $IdentityAssets -Force | Out-Null

    $StoreLogoSource = Join-Path $RepoRoot 'Guardian.Desktop\Assets\StoreLogo.png'
    $StoreLogoTarget = Join-Path $IdentityAssets 'StoreLogo.png'

    if (-not (Test-Path $StoreLogoSource)) {
        throw "StoreLogo source asset is missing: $StoreLogoSource"
    }

    Copy-Item -LiteralPath $StoreLogoSource -Destination $StoreLogoTarget -Force
    Write-Host 'Packing sparse identity MSIX...' -ForegroundColor Cyan
    & $makeAppx pack /o /d $IdentitySource /nv /p $IdentityMsix
    if ($LASTEXITCODE -ne 0) { throw "MakeAppx failed with exit code $LASTEXITCODE." }

    Write-Host 'Signing sparse identity MSIX...' -ForegroundColor Cyan
    & $signTool sign /fd SHA256 /s My /sha1 $certificate.Thumbprint /v $IdentityMsix
    if ($LASTEXITCODE -ne 0) { throw "SignTool failed with exit code $LASTEXITCODE." }
    & $signTool verify /pa /v $IdentityMsix
    if ($LASTEXITCODE -ne 0) {
        throw "MSIX signature verification failed with exit code $LASTEXITCODE."
    }


    Write-Host ''
    Write-Host 'Guardian release payload is ready.' -ForegroundColor Green
    Write-Host "Application folder: $PayloadApp"
    Write-Host "Identity package:   $IdentityMsix"
    Write-Host "Public certificate: $CertificateCer"
    Write-Host "Windows App Runtime: $WindowsAppRuntimeInstaller"
    Write-Host "VC++ Redistributable: $VcRedistInstaller"
    Write-Host 'Next: open Installer\GuardianSetup.iss in Inno Setup Compiler and press Ctrl+F9.' -ForegroundColor Green
}
catch {
    Write-Error $_
    exit 1
}
