# Installation and Development Setup

## Requirements

- Windows 10 version 2004 (build 19041) or newer.
- Windows 11 supported.
- Visual Studio with Windows desktop development support.
- .NET 10 SDK.
- Windows SDK and Windows App SDK tooling.
- Git.
- Internet access for NuGet restoration.

## Clone

```powershell
git clone https://github.com/lukdevsec/Guardian.git
cd Guardian
```

## Restore dependencies

```powershell
dotnet restore .\Guardian.slnx
```

## Open the solution

Open `Guardian.slnx` in Visual Studio.

Set `Guardian.Desktop` as the startup project.

Select the appropriate Windows x64 configuration.

Build the solution and run it from Visual Studio.

## Cloud configuration

Cloud analysis requires a separately configured Cloudflare Worker.

The Worker expects these server-side secrets:

- `ANTHROPIC_API_KEY`
- `GUARDIAN_ACCESS_TOKEN`

Do not commit these values or place them in desktop source code.

The developer token provisioning script is:

```text
Scripts/Setup-GuardianCloudToken.ps1
```

It stores the supplied token using Windows DPAPI for the current user.

The shared bearer-token configuration is for private development only.
It must not be distributed to public users as a shared credential.

## Building the Windows installer

The installer workflow is documented separately:

[Installer README](../Installer/README.md)

The release build requires a developer signing certificate and
a configured Windows SDK environment.

The current self-signed certificate workflow is intended for
development and testing, not trusted public distribution.

## Troubleshooting

### NuGet restore errors

Check network connectivity and installed .NET SDK versions.

### Windows App SDK errors

Verify that the required Windows App SDK and Windows SDK components
are installed.

### Cloud analysis unavailable

Verify Worker deployment, server-side secret configuration and
the private development token setup.

Never paste credentials into logs, issue reports or public discussions.