
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace Guardian.Desktop.Pages;

public sealed partial class ModulePage : Page
{
    public ModulePage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(
        NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);

        string section = e.Parameter?.ToString() ?? "Dashboard";

        switch (section)
        {
            case "Endpoint":

                ModuleTitleText.Text = "Endpoint Monitoring";

                ModuleDescriptionText.Text =
                    "Real-time process and network activity monitoring.";

                ModuleStatusText.Text =
                    "Endpoint monitoring engine is active.";

                ModuleDetailsText.Text =
                    "This section will contain:\n\n" +
                    "• Running process explorer\n" +
                    "• Process metadata and activity\n" +
                    "• TCP connection monitoring\n" +
                    "• Detection events and investigation details\n" +
                    "• Endpoint security statistics\n\n" +
                    "The existing Guardian.Service and Guardian.Monitoring " +
                    "components remain responsible for collecting telemetry.";

                break;

            case "Vision":

                ModuleTitleText.Text = "Guardian Vision";

                ModuleDescriptionText.Text =
                    "Browser intelligence and phishing detection.";

                ModuleStatusText.Text =
                    "Local OCR and heuristic analysis available.";

                ModuleDetailsText.Text =
                    "This section will contain:\n\n" +
                    "• Browser window selection\n" +
                    "• Continuous screen capture\n" +
                    "• Local OCR recognition\n" +
                    "• Browser address verification\n" +
                    "• Phishing risk assessment\n" +
                    "• Future AI context analysis\n\n" +
                    "Current capture mode analyzes a selected window. " +
                    "Full-monitor analysis is not implemented yet.";

                break;

            case "Alerts":

                ModuleTitleText.Text = "Security Alerts";

                ModuleDescriptionText.Text =
                    "Centralized security findings and incident investigation.";

                ModuleStatusText.Text =
                    "Windows notifications are integrated.";

                ModuleDetailsText.Text =
                    "This section will contain:\n\n" +
                    "• HIGH and CRITICAL Vision findings\n" +
                    "• Risk scores and detection reasons\n" +
                    "• Alert timestamps and domains\n" +
                    "• Notification status\n" +
                    "• Incident investigation\n\n" +
                    "Endpoint events are not yet fully integrated " +
                    "into the Vision notification pipeline.";

                break;

            case "History":

                ModuleTitleText.Text = "Security History";

                ModuleDescriptionText.Text =
                    "Review previous analyses and security events.";

                ModuleStatusText.Text =
                    "History interface is being developed.";

                ModuleDetailsText.Text =
                    "Planned functionality:\n\n" +
                    "• Previous website analyses\n" +
                    "• Endpoint activity timeline\n" +
                    "• Historical alerts\n" +
                    "• Search and filtering\n" +
                    "• Exportable security reports\n\n" +
                    "Current analysis reports are retained in memory " +
                    "during the application session. Persistent history " +
                    "has not been implemented yet.";

                break;

            case "Settings":

                ModuleTitleText.Text = "Settings";

                ModuleDescriptionText.Text =
                    "Configure Guardian monitoring and privacy.";

                ModuleStatusText.Text =
                    "Settings interface is being developed.";

                ModuleDetailsText.Text =
                    "Planned configuration:\n\n" +
                    "• Endpoint monitoring preferences\n" +
                    "• Screen capture modes\n" +
                    "• Notification preferences\n" +
                    "• Application exclusions\n" +
                    "• Privacy and data retention\n" +
                    "• Startup and system tray behavior";

                break;

            default:

                ModuleTitleText.Text = "Guardian";

                ModuleDescriptionText.Text =
                    "Endpoint Security Intelligence.";

                ModuleStatusText.Text =
                    "Select a module from the navigation sidebar.";

                ModuleDetailsText.Text =
                    "Guardian security modules.";

                break;
        }
    }
}
