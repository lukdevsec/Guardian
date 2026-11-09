# Guardian classic installer (Inno Setup + sparse package identity)

This installer places the actual application files in `C:\Program Files\Guardian` and registers a small signed MSIX identity package against that external folder. This is Microsoft's **packaging with external location** model (also called sparse packaging).

It is intentionally used instead of a completely unpackaged WinUI 3 app: Guardian keeps package identity for Windows App Notifications while the EXE, DLLs, assets and OCR models remain in a normal, inspectable Program Files directory.

## Requirements

- Windows 10 version 2004 / build 19041 or newer (Windows 11 is supported).
- Visual Studio 2026 with .NET 10 SDK, Windows App SDK tooling and Windows 10/11 SDK installed.
- Inno Setup 6 or newer.
- Internet access on the developer machine while building the release payload (to download Microsoft prerequisites).
- The existing Guardian signing certificate `.pfx` whose subject is `CN=Golden Retriever`.
- The PFX password. The PFX and its password are never copied into the installer payload or repository.

## Build the release payload

From the Guardian repository root, open PowerShell and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Installer\Scripts\Build-GuardianRelease.ps1
```

The script:

1. Publishes `Guardian.Desktop` as .NET self-contained `win-x64` with `WindowsPackageType=None`. The Windows App SDK runtime remains framework-dependent and is installed by the setup program.
2. Copies all application files, assets and RapidOCR models to `Installer\Payload\App`.
3. Downloads the official Microsoft Windows App SDK Runtime 2.6.5 x64 installer and the current Microsoft Visual C++ Redistributable x64 installer. It verifies both Authenticode signatures before including them in the setup payload.
4. Builds a sparse identity MSIX from `Installer\IdentityPackage\AppxManifest.xml`.
5. Imports the existing PFX into the current user's certificate store for signing, signs `Guardian.identity.msix`, and exports only the public `.cer` certificate.

When prompted, provide the path to your existing `.pfx` file and its password. Do not put the PFX in Git or send it to anyone.

## Compile GuardianSetup.exe

1. Install/open Inno Setup Compiler.
2. Open `Installer\GuardianSetup.iss`.
3. Press `Ctrl+F9`.
4. The installer is created at `Installer\Output\GuardianSetup-0.9.5.1-x64.exe`.

The wizard creates a Start Menu shortcut, offers a desktop shortcut checkbox (selected by default), and offers optional launch after installation.

After installing, you can verify the files, OCR model and package identity with:

```powershell
.\Installer\Scripts\Test-GuardianInstall.ps1
```

## What installation does

- Copies the app and .NET runtime to `C:\Program Files\Guardian`.
- Installs the Microsoft Visual C++ Redistributable x64 and Windows App SDK Runtime 2.6.5 (Framework, Main, Singleton and DDLM) silently as prerequisites. This preserves the Windows App SDK APIs used by WinUI 3 and Windows notifications without asking the user to install runtimes manually.
- Adds the public development certificate to the current user's `TrustedPeople` store if it is not already trusted.
- Removes an older full-MSIX registration for the same Guardian package identity, if present.
- Registers `Guardian.identity.msix` with `Add-AppxPackage -ExternalLocation C:\Program Files\Guardian`.
- Creates Start Menu and optional Desktop shortcuts pointing directly to `Guardian.Desktop.exe` and `Assets\GuardianIcon.ico`.

The sparse identity package is not the app binary. It grants package identity to the normal EXE folder so Windows App Notifications and the existing COM activation registration can continue to work.

## Uninstall

The Inno uninstaller removes the sparse package identity registration before deleting `C:\Program Files\Guardian`. It deliberately does not delete `%LOCALAPPDATA%\Guardian`, so per-user settings, the DPAPI-protected Guardian Cloud token and local history are retained. Users can remove those data separately if desired.

## Important signing note

The included workflow is for private development/testing with your self-signed certificate. The installer trusts the public `.cer` for the current Windows user. **Do not publish this self-signed certificate as a production trust solution.** For public distribution, sign the identity MSIX and `GuardianSetup.exe` with a certificate chaining to a trusted public CA (or distribute through Microsoft Store / an appropriate enterprise trust channel). A self-signed certificate may trigger Windows security warnings on other PCs. The bundled Microsoft runtime installers are downloaded from official Microsoft URLs and their Authenticode signatures are checked during the build.

The package identity is registered for the Windows user who runs the installer. A true all-users enterprise deployment needs a separate provisioning workflow and should be tested independently.

## Cloud credentials

No Anthropic API key or Guardian Cloud access token is included in the installer. The existing per-user DPAPI token store under `%LOCALAPPDATA%\Guardian` remains in use. The Cloudflare Worker and its secrets do not need to change for this packaging migration.
