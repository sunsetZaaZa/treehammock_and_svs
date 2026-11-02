using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class SmsProviderServiceTests
{
    [Fact]
    public async Task AwsService_returns_disabled_when_feature_flag_is_off()
    {
        var client = Substitute.For<IAwsSnsSmsClient>();
        var service = new AWSService(client, Options.Create(new SidewalkSettings
        {
            SmsEnabled = true,
            AwsSnsEnabled = false,
            PaymentProcessorPrimary = "disabled-test"
        }), NullLogger<AWSService>.Instance);

        ProviderDeliveryResult result = await service.SendSMS("+15555550101", "123456");

        result.Status.ShouldBe(ProviderDeliveryStatus.Disabled);
        await client.DidNotReceiveWithAnyArgs().PublishSms(default!, default!);
    }

    [Fact]
    public async Task AwsService_returns_sent_when_provider_returns_message_id()
    {
        var client = Substitute.For<IAwsSnsSmsClient>();
        client.PublishSms("+15555550101", Arg.Any<string>()).Returns(Task.FromResult<string?>("01234567-89ab-cdef-0123-456789abcdef"));
        var service = new AWSService(client, Options.Create(EnabledAwsSettings()), NullLogger<AWSService>.Instance);

        ProviderDeliveryResult result = await service.SendSMS("+15555550101", "123456");

        result.Succeeded.ShouldBeTrue();
        result.Provider.ShouldBe("aws-sns");
        result.ProviderMessageId.ShouldBe("01234567-89ab-cdef-0123-456789abcdef");
    }

    [Fact]
    public async Task TwilioSmsService_returns_configuration_missing_before_provider_call()
    {
        var client = Substitute.For<ITwilioMessageClient>();
        var settings = EnabledTwilioSettings();
        settings.TwilioAuthToken = null;
        var service = new TwilioSmsService(client, Options.Create(settings), NullLogger<TwilioSmsService>.Instance);

        ProviderDeliveryResult result = await service.SendSMS("+15555550101", "123456");

        result.Status.ShouldBe(ProviderDeliveryStatus.ConfigurationMissing);
        result.FailureCode!.ShouldContain(nameof(SidewalkSettings.TwilioAuthToken));
        await client.DidNotReceiveWithAnyArgs().SendMessage(default!, default!, default!, default!, default!);
    }

    [Fact]
    public async Task TwilioSmsService_returns_sent_when_provider_returns_sid()
    {
        var client = Substitute.For<ITwilioMessageClient>();
        client.SendMessage(
                "AC0123456789abcdef0123456789abcdef",
                "token",
                "+15555550199",
                "+15555550101",
                Arg.Any<string>())
            .Returns(Task.FromResult(ProviderDeliveryResult.Sent("twilio", "SM123")));
        var service = new TwilioSmsService(client, Options.Create(EnabledTwilioSettings()), NullLogger<TwilioSmsService>.Instance);

        ProviderDeliveryResult result = await service.SendSMS("+15555550101", "123456");

        result.Succeeded.ShouldBeTrue();
        result.Provider.ShouldBe("twilio");
        result.ProviderMessageId.ShouldBe("SM123");
    }

    private static SidewalkSettings EnabledAwsSettings() => new()
    {
        SmsEnabled = true,
        AwsSnsEnabled = true,
        PaymentProcessorPrimary = "disabled-test"
    };

    private static SidewalkSettings EnabledTwilioSettings() => new()
    {
        SmsEnabled = true,
        TwilioEnabled = true,
        TwilioAccountSid = "AC0123456789abcdef0123456789abcdef",
        TwilioAuthToken = "token",
        TwilioFromPhoneNumber = "+15555550199",
        PaymentProcessorPrimary = "disabled-test"
    };
}
