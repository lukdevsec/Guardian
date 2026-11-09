#define MyAppName "Guardian"
#define MyAppVersion "1.0.0"
#define MyPublisher "Golden Retriever"
#define MyAppExeName "Guardian.Desktop.exe"

[Setup]
AppId={{B8B79F2D-9A6A-4E43-9E5C-7C6A9E6C1B42}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyPublisher}
AppPublisherURL=https://github.com/lukdevsec
DefaultDirName={autopf}\Guardian
DefaultGroupName=Guardian
UninstallDisplayIcon={app}\Assets\GuardianIcon.ico
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19041
WizardStyle=modern
WizardSizePercent=110
SetupIconFile=Assets\GuardianIcon.ico
OutputDir=Output
OutputBaseFilename=GuardianSetup-{#MyAppVersion}-x64
Compression=lzma2/ultra64
SolidCompression=yes
CloseApplications=yes
CloseApplicationsFilter=Guardian.Desktop.exe
RestartApplications=no
SetupLogging=yes
Uninstallable=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional options:"; Flags: checkedonce
Name: "launchafterinstall"; Description: "Launch Guardian after installation"; GroupDescription: "Additional options:"; Flags: unchecked

[Files]
Source: "Payload\App\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "Payload\Identity\Guardian.identity.msix"; DestDir: "{tmp}\GuardianIdentity"; Flags: deleteafterinstall
Source: "Payload\Identity\Guardian.cer"; DestDir: "{tmp}\GuardianIdentity"; Flags: deleteafterinstall
Source: "Payload\Prerequisites\WindowsAppRuntimeInstall-x64.exe"; DestDir: "{tmp}\GuardianPrerequisites"; Flags: deleteafterinstall
Source: "Payload\Prerequisites\vc_redist.x64.exe"; DestDir: "{tmp}\GuardianPrerequisites"; Flags: deleteafterinstall
Source: "Scripts\Install-Guardian.ps1"; DestDir: "{tmp}\GuardianInstaller"; Flags: deleteafterinstall
Source: "Scripts\Uninstall-Guardian.ps1"; DestDir: "{app}\Support"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Guardian"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\Assets\GuardianIcon.ico"
Name: "{autodesktop}\Guardian"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; IconFilename: "{app}\Assets\GuardianIcon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch Guardian"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent; Tasks: launchafterinstall

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\Support\Uninstall-Guardian.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "GuardianUninstallCleanup"

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  // Stop Guardian before replacing files in Program Files.
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/F /IM Guardian.Desktop.exe', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

function RunGuardianIdentityRegistration(): Boolean;
var
  ResultCode: Integer;
  Params: String;
  ScriptPath: String;
  IdentityPath: String;
  CertificatePath: String;
  RuntimeInstallerPath: String;
  VcRedistPath: String;
  AppPath: String;
begin
  ScriptPath := ExpandConstant('{tmp}\GuardianInstaller\Install-Guardian.ps1');
  IdentityPath := ExpandConstant('{tmp}\GuardianIdentity\Guardian.identity.msix');
  CertificatePath := ExpandConstant('{tmp}\GuardianIdentity\Guardian.cer');
  RuntimeInstallerPath := ExpandConstant('{tmp}\GuardianPrerequisites\WindowsAppRuntimeInstall-x64.exe');
  VcRedistPath := ExpandConstant('{tmp}\GuardianPrerequisites\vc_redist.x64.exe');
  AppPath := ExpandConstant('{app}');

  Params := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
    ScriptPath + '" -AppDirectory "' + AppPath +
    '" -IdentityPackagePath "' + IdentityPath +
    '" -CertificatePath "' + CertificatePath +
    '" -RuntimeInstallerPath "' + RuntimeInstallerPath +
    '" -VcRedistPath "' + VcRedistPath + '"';

  if not Exec(
    ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    Params,
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode) then
  begin
    MsgBox('Guardian setup could not start Windows PowerShell.', mbError, MB_OK);
    Result := False;
    exit;
  end;

  if ResultCode <> 0 then
  begin
    MsgBox(
      'Guardian files were copied, but Windows package identity registration failed.' + #13#10 + #13#10 +
      'Review this log:' + #13#10 +
      ExpandConstant('{localappdata}\Guardian\Installer\install.log'),
      mbError,
      MB_OK);
    Result := False;
    exit;
  end;

  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not RunGuardianIdentityRegistration() then
      Abort;
  end;
end;
