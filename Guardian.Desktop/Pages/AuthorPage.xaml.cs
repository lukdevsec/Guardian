using System;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.System;

namespace Guardian.Desktop.Pages;

public sealed partial class AuthorPage : Page
{
    private const string GitHubUrl = "https://github.com/lukdevsec";
    private const string LinkedInUrl = "https://www.linkedin.com/in/%C5%82ukasz-izdebski-a56932448/";

    public AuthorPage()
    {
        InitializeComponent();
    }

    private async void GitHubButton_Click(object sender, RoutedEventArgs e)
    {
        await Launcher.LaunchUriAsync(new Uri(GitHubUrl));
    }

    private async void LinkedInButton_Click(object sender, RoutedEventArgs e)
    {
        await Launcher.LaunchUriAsync(new Uri(LinkedInUrl));
    }
}
