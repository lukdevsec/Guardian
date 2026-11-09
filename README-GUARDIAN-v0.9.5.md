# Guardian v0.9.5 — Premium Dashboard Refresh

This update refines the desktop experience to more closely match the approved premium Guardian dashboard reference.

## UI changes
- Expanded fixed sidebar and corrected brand header: Guardian (title case), full logo, readable subtitle and version badge.
- Dark navy title bar and deeper blue/cyan visual system.
- Larger dashboard heading and typography.
- Four left-icon KPI cards for process events, TCP events, alerts and Cloud AI configuration.
- Endpoint Engine and Recent Activity side-by-side layout.
- Full-width Project Mission panel.
- Compact Author navigation entry remains separate and opens the existing Author page.
- Vision, Settings, Module and Author pages use a consistent premium palette.

## Functional changes
- TelemetryState now keeps the most recent 10 process, TCP and alert events in memory.
- Dashboard Recent Activity displays the latest five actual endpoint events.
- Engine status and application-session uptime are displayed in the Endpoint Engine card.
- Existing Vision, Claude Cloud, notification, tray, Endpoint, Domain, Alerts, History and Author navigation handlers are retained.

## Cloudflare
No Worker change is required for v0.9.5. Keep the existing private-beta Worker and its two Secrets unchanged.

## Validation
XAML/XML structure and event-handler references were checked. A Windows SDK/.NET SDK build must still be performed in Visual Studio on Windows.

## Update an existing local checkout

1. Close Guardian and Visual Studio.
2. Commit or back up the current project folder.
3. Extract this archive to a temporary directory.
4. Copy the contents of the archive's `Guardian` folder into the existing repository folder and merge/replace files.
5. Keep the existing `.git` directory; do not replace or delete it.
6. Open `Guardian.slnx`, set `Guardian.Desktop` as the startup project, select `Debug | x64`, restore NuGet packages and rebuild.

No Cloudflare Worker update is required for this UI release. Keep the existing `ANTHROPIC_API_KEY` and `GUARDIAN_ACCESS_TOKEN` secrets unchanged.
