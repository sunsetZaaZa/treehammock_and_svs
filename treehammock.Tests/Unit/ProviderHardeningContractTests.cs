using Shouldly;

namespace treehammock.Tests.Unit;

public class ProviderHardeningContractTests
{
    [Fact]
    public void Sidewalk_settings_expose_sms_feature_flags()
    {
        string settings = File.ReadAllText(ProjectFile("Rigging", "Config", "SidewalkSettings.cs"));
        string appsettings = File.ReadAllText(ProjectFile("appsettings.Example.json"));

        settings.ShouldContain("public bool SmsEnabled { get; set; }");
        settings.ShouldContain("public bool AwsSnsEnabled { get; set; }");
        settings.ShouldContain("public bool TwilioEnabled { get; set; }");
        appsettings.ShouldContain("\"SmsEnabled\": false");
        appsettings.ShouldContain("\"AwsSnsEnabled\": false");
        appsettings.ShouldContain("\"TwilioEnabled\": false");
    }

    [Fact]
    public void Sms_provider_contract_uses_typed_results_instead_of_provider_strings()
    {
        string providerResult = File.ReadAllText(ProjectFile("Rigging", "Sidewalk", "ProviderDeliveryResult.cs"));
        string smsSender = File.ReadAllText(ProjectFile("Services", "SmsSender.cs"));

        providerResult.ShouldContain("enum ProviderDeliveryStatus");
        providerResult.ShouldContain("ConfigurationMissing");
        providerResult.ShouldContain("RateLimited");
        providerResult.ShouldContain("ProviderUnavailable");
        smsSender.ShouldContain("Task<ProviderDeliveryResult> SendSMS");
        smsSender.ShouldContain("ProviderDeliveryResult.Disabled");
        smsSender.ShouldNotContain("StartsWith(\"SM\"");
        smsSender.ShouldNotContain("StartsWith(\"aws:\"");
        smsSender.ShouldNotContain("StartsWith(\"twilio:\"");
        smsSender.ShouldNotContain("TwilioClient.Init");
        smsSender.ShouldNotContain("MessageResource.CreateAsync");
    }

    [Fact]
    public void Sms_provider_configuration_uses_normalized_fail_fast_routing_contract()
    {
        string providerNames = File.ReadAllText(ProjectFile("Rigging", "Config", "SmsProviderNames.cs"));
        string validation = File.ReadAllText(ProjectFile("Rigging", "Config", "ConfigurationValidation.cs"));
        providerNames.ShouldContain("public const string AwsSns = \"aws-sns\"");
        providerNames.ShouldContain("public const string Twilio = \"twilio\"");
        providerNames.ShouldContain("\"aws\" or \"sns\" or AwsSns => AwsSns");
        validation.ShouldContain("SMS provider chain cannot contain duplicate providers after alias normalization");
        validation.ShouldContain("configured but its feature flag is disabled");
        validation.ShouldContain("is not supported. Supported providers are aws-sns and twilio");
    }

    private static string ProjectFile(params string[] relativePath)
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "treehammock.sln")))
        {
            directory = directory.Parent;
        }

        directory.ShouldNotBeNull("The test could not locate the project root containing treehammock.sln.");
        return Path.Combine(new[] { directory.FullName }.Concat(relativePath).ToArray());
    }
}
