using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Guardian.Desktop.Cloud;

/// <summary>
/// Stores the private beta access token encrypted for the current Windows user.
/// The token is never written to source code or a plain-text settings file.
/// </summary>
public static class GuardianCloudTokenStore
{
    private static readonly byte[] Entropy =
        Encoding.UTF8.GetBytes("Guardian.Cloud.AccessToken.v1");

    public static string TokenPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Guardian",
        "cloud-access-token.bin");

    public static bool IsConfigured => File.Exists(TokenPath);

    public static string? Load()
    {
        if (!File.Exists(TokenPath))
            return null;

        try
        {
            byte[] protectedBytes = File.ReadAllBytes(TokenPath);
            byte[] clearBytes = ProtectedData.Unprotect(
                protectedBytes,
                Entropy,
                DataProtectionScope.CurrentUser);

            try
            {
                string token = Encoding.UTF8.GetString(clearBytes).Trim();
                return string.IsNullOrWhiteSpace(token) ? null : token;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clearBytes);
            }
        }
        catch (CryptographicException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }
}
