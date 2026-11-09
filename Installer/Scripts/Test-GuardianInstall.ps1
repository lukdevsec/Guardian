$ErrorActionPreference = 'Stop'
$AppDirectory = Join-Path $env:ProgramFiles 'Guardian'
$PackageName = '2fdd8c0d-4f9d-4038-909f-5dc994b95ba1'

$checks = @()
$checks += [pscustomobject]@{
    Check = 'Guardian executable in Program Files'
    Passed = Test-Path (Join-Path $AppDirectory 'Guardian.Desktop.exe')
    Detail = Join-Path $AppDirectory 'Guardian.Desktop.exe'
}
$checks += [pscustomobject]@{
    Check = 'Guardian icon'
    Passed = Test-Path (Join-Path $AppDirectory 'Assets\GuardianIcon.ico')
    Detail = Join-Path $AppDirectory 'Assets\GuardianIcon.ico'
}
$requiredModels = @(
    'models\v5\ch_PP-OCRv5_mobile_det.onnx',
    'models\v5\ch_PP-LCNet_x0_25_textline_ori_cls_mobile.onnx',
    'models\v5\latin_PP-OCRv5_rec_mobile_infer.onnx',
    'models\v5\ppocrv5_latin_dict.txt'
)

foreach ($model in $requiredModels) {
    $modelPath = Join-Path $AppDirectory $model

    $checks += [pscustomobject]@{
        Check = "OCR asset: $model"
        Passed = Test-Path $modelPath
        Detail = $modelPath
    }
}
$package = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue | Select-Object -First 1
$checks += [pscustomobject]@{
    Check = 'Guardian sparse package identity'
    Passed = ($null -ne $package)
    Detail = if ($package) { $package.PackageFamilyName } else { 'Not registered for current user' }
}
$runtime = Get-AppxPackage -Name 'Microsoft.WindowsAppRuntime.2' -ErrorAction SilentlyContinue | Select-Object -First 1
$checks += [pscustomobject]@{
    Check = 'Windows App SDK 2.x runtime'
    Passed = ($null -ne $runtime)
    Detail = if ($runtime) { $runtime.Version.ToString() } else { 'Not registered for current user (check runtime installer log)' }
}

$checks | Format-Table -AutoSize
if ($checks.Where({ -not $_.Passed }).Count -gt 0) {
    Write-Host 'One or more Guardian installation checks failed.' -ForegroundColor Yellow
    exit 1
}
Write-Host 'Guardian installation checks passed.' -ForegroundColor Green
