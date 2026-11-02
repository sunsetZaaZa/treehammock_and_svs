using System.Text.Json;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class SMTPServiceConfigurationTests
{
    [Fact]
    public void Constructor_uses_fallback_templates_when_configured_files_are_missing()
    {
        var smtpSettings = Options.Create(new SMTPSettings
        {
            SMTPQualifiedDomain = "localhost",
            SMTPPort = 1025,
            SMTPUsername = "test-smtp-user",
            SMTPPassword = "test-smtp-password",
            NoReplyEmailAddress = "noreply@localhost.test"
        });

        var templateSettings = Options.Create(new EmailTemplateSettings
        {
            AccountVerify = "missing/AccountVerify.html",
            AccountVerifyResend = "missing/AccountVerifyResend.html",
            AccountEmailChangeVerify = "missing/AccountEmailChangeVerify.html",
            AccountDeleteVerify = "missing/AccountDeleteVerify.html",
            AccountUnlock = "missing/AccountUnlock.html",
            TwoFactorSetup = "missing/TwoFactorSetup.html",
            TwoFactorKeyOutbound = "missing/TwoFactorKeyOutbound.html",
            TwoFactorDelete = "missing/TwoFactorDelete.html"
        });

        var exception = Record.Exception(() => new SMTPService(smtpSettings, templateSettings, NullLogger<SMTPService>.Instance));

        exception.ShouldBeNull();
    }

    [Fact]
    public void SMTPSettings_exposes_only_runtime_smtp_transport_configuration()
    {
        string[] propertyNames = typeof(SMTPSettings)
            .GetProperties()
            .Select(property => property.Name)
            .OrderBy(name => name)
            .ToArray();

        propertyNames.ShouldBe(new[]
        {
            nameof(SMTPSettings.TransportMode),
            nameof(SMTPSettings.AllowIsolatedPlaintext),
            nameof(SMTPSettings.NoReplyEmailAddress),
            nameof(SMTPSettings.SMTPPassword),
            nameof(SMTPSettings.SMTPPort),
            nameof(SMTPSettings.SMTPQualifiedDomain),
            nameof(SMTPSettings.SMTPUsername)
        }.OrderBy(name => name).ToArray());
    }

    [Fact]
    public void Appsettings_do_not_include_removed_smtp_contract_settings()
    {
        foreach (string fileName in new[] { "appsettings.json", "appsettings.Example.json" })
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(ProjectFile(fileName)));
            string[] smtpPropertyNames = document.RootElement
                .GetProperty("SMTPSettings")
                .EnumerateObject()
                .Select(property => property.Name)
                .OrderBy(name => name)
                .ToArray();

            smtpPropertyNames.ShouldBe(new[]
            {
                "TransportMode",
                "AllowIsolatedPlaintext",
                "NoReplyEmailAddress",
                "SMTPPassword",
                "SMTPPort",
                "SMTPQualifiedDomain",
                "SMTPUsername"
            }.OrderBy(name => name).ToArray());
        }
    }

    private static string ProjectRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return directory.FullName;
    }

    private static string ProjectFile(params string[] relativePathParts)
    {
        return Path.Combine(new[] { ProjectRoot() }.Concat(relativePathParts).ToArray());
    }
}
