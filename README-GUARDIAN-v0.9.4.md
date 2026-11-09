# Guardian v0.9.4 — Premium shell and Author page

## UI changes
- Added a branded NavigationView pane header with Guardian icon and version.
- Added a compact Author footer navigation item with the `lukdevsec` handle.
- Added a dedicated Author page with GitHub and LinkedIn links, project background, mission, principles and current project-status disclaimer.
- Redesigned dashboard KPI cards so icon badges sit to the left of their labels and values.
- Added a live Cloud AI readiness indicator based on the existing `GuardianCloudClient.IsConfigured` state.
- Added a dashboard mission panel and simplified the dashboard around endpoint telemetry.

## Files changed
- `Guardian.Desktop/MainWindow.xaml`
- `Guardian.Desktop/MainWindow.xaml.cs`
- `Guardian.Desktop/Guardian.Desktop.csproj`
- `Guardian.Desktop/Pages/AuthorPage.xaml` (new)
- `Guardian.Desktop/Pages/AuthorPage.xaml.cs` (new)

## Notes
- No Cloudflare Worker changes are required.
- Existing endpoint, Vision, Cloud AI, notifications and ModulePage handlers are retained.
- Author links open in the system browser.
- The mission text describes a long-term ambition, not a guarantee of phishing elimination.
- Build and runtime validation must be performed in Visual Studio on Windows with the Windows App SDK installed.
