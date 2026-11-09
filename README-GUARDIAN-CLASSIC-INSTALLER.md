# Guardian — classic Windows installation

Guardian can now be distributed with a traditional `GuardianSetup.exe` while keeping the Windows package identity required by Windows App Notifications.

## User experience

- Application binaries and OCR models are installed under `C:\Program Files\Guardian`.
- A Start Menu shortcut is created automatically.
- The installer offers an optional Desktop shortcut (selected by default).
- The installer can optionally launch Guardian when setup completes.
- Uninstall is available from Windows Installed apps / Apps & features.

## Developer build

See [`Installer/README.md`](Installer/README.md). The setup bundles the Microsoft Visual C++ Redistributable and Windows App SDK Runtime 2.6.5 prerequisites, so the end user does not need to install them manually. The app itself includes the .NET runtime. In short:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Installer\Scripts\Build-GuardianRelease.ps1
```

Then compile `Installer\GuardianSetup.iss` in Inno Setup Compiler (`Ctrl+F9`).

This uses .NET self-contained deployment and installs the matching Windows App SDK Runtime as a prerequisite. The output is a normal application folder, not a single-file EXE; this is intentional because Guardian includes OCR models, assets and native dependencies.

## Why sparse package identity?

Guardian uses Windows App Notifications. A completely unpackaged WinUI 3 process would require additional notification activation work and would lose package-identity-gated Windows features. The small sparse identity package is registered with an external location, so Windows sees the app identity while the files remain in the normal Program Files folder.

## Current limitations

- x64 installer only.
- Windows 10 build 19041 or newer.
- The included self-signed certificate workflow is for your private testing machine. Public releases require trusted code signing.
- Guardian Cloud credentials are not embedded in the EXE or installer.
