using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Shouldly;

using treehammock.Rigging.Config;
using treehammock.Rigging.Sidewalk;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class SmsSenderTests
{
    [Fact]
    public async Task SendCode_uses_aws_primary_provider_before_twilio()
    {
        var aws = Substitute.For<IAWSService>();
        var twilio = Substitute.For<ITwilioSmsService>();
        aws.SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(ProviderDeliveryResult.Sent("aws-sns", "message-id")));
        var sender = new SmsSender(aws, twilio, Options.Create(EnabledSmsSettings()), NullLogger<SmsSender>.Instance);

        bool sent = await sender.SendCode("+15555550101", "123456");

        sent.ShouldBeTrue();
        await aws.Received(1).SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>());
        await twilio.DidNotReceiveWithAnyArgs().SendSMS(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SendCode_falls_back_to_twilio_only_when_aws_explicitly_rejects()
    {
        var aws = Substitute.For<IAWSService>();
        var twilio = Substitute.For<ITwilioSmsService>();
        aws.SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(ProviderDeliveryResult.Rejected("aws-sns")));
        twilio.SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(ProviderDeliveryResult.Sent("twilio", "message-id")));
        var sender = new SmsSender(aws, twilio, Options.Create(EnabledSmsSettings()), NullLogger<SmsSender>.Instance);

        bool sent = await sender.SendCode("+15555550101", "123456");

        sent.ShouldBeTrue();
        await aws.Received(1).SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>());
        await twilio.Received(1).SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SendCode_fails_closed_when_sms_is_disabled()
    {
        var aws = Substitute.For<IAWSService>();
        var twilio = Substitute.For<ITwilioSmsService>();
        var settings = EnabledSmsSettings();
        settings.SmsEnabled = false;
        var sender = new SmsSender(aws, twilio, Options.Create(settings), NullLogger<SmsSender>.Instance);

        bool sent = await sender.SendCode("+15555550101", "123456");

        sent.ShouldBeFalse();
        await aws.DidNotReceiveWithAnyArgs().SendSMS(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        await twilio.DidNotReceiveWithAnyArgs().SendSMS(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SendCode_skips_provider_when_specific_feature_flag_is_disabled()
    {
        var aws = Substitute.For<IAWSService>();
        var twilio = Substitute.For<ITwilioSmsService>();
        twilio.SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(ProviderDeliveryResult.Sent("twilio", "message-id")));
        var settings = EnabledSmsSettings();
        settings.AwsSnsEnabled = false;
        var sender = new SmsSender(aws, twilio, Options.Create(settings), NullLogger<SmsSender>.Instance);

        bool sent = await sender.SendCode("+15555550101", "123456");

        sent.ShouldBeTrue();
        await aws.DidNotReceiveWithAnyArgs().SendSMS(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        await twilio.Received(1).SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SendCode_rejects_unknown_provider_without_calling_known_providers()
    {
        var aws = Substitute.For<IAWSService>();
        var twilio = Substitute.For<ITwilioSmsService>();
        var settings = EnabledSmsSettings();
        settings.SmsProviderPrimary = "carrier-pigeon";
        settings.SmsProviderSecondary = null;
        var sender = new SmsSender(aws, twilio, Options.Create(settings), NullLogger<SmsSender>.Instance);

        bool sent = await sender.SendCode("+15555550101", "123456");

        sent.ShouldBeFalse();
        await aws.DidNotReceiveWithAnyArgs().SendSMS(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        await twilio.DidNotReceiveWithAnyArgs().SendSMS(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }


    [Theory]
    [InlineData("aws")]
    [InlineData("sns")]
    [InlineData("aws-sns")]
    public async Task SendCode_normalizes_aws_sns_provider_aliases(string providerName)
    {
        var aws = Substitute.For<IAWSService>();
        var twilio = Substitute.For<ITwilioSmsService>();
        aws.SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(ProviderDeliveryResult.Sent("aws-sns", "message-id")));
        var settings = EnabledSmsSettings();
        settings.SmsProviderPrimary = providerName;
        settings.SmsProviderSecondary = null;
        var sender = new SmsSender(aws, twilio, Options.Create(settings), NullLogger<SmsSender>.Instance);

        bool sent = await sender.SendCode("+15555550101", "123456");

        sent.ShouldBeTrue();
        await aws.Received(1).SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>());
        await twilio.DidNotReceiveWithAnyArgs().SendSMS(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task SendCode_deduplicates_provider_aliases_before_fallback()
    {
        var aws = Substitute.For<IAWSService>();
        var twilio = Substitute.For<ITwilioSmsService>();
        aws.SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(ProviderDeliveryResult.Rejected("aws-sns")));
        var settings = EnabledSmsSettings();
        settings.SmsProviderPrimary = "aws";
        settings.SmsProviderSecondary = "sns";
        var sender = new SmsSender(aws, twilio, Options.Create(settings), NullLogger<SmsSender>.Instance);

        bool sent = await sender.SendCode("+15555550101", "123456");

        sent.ShouldBeFalse();
        await aws.Received(1).SendSMS("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>());
        await twilio.DidNotReceiveWithAnyArgs().SendSMS(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task SendMessage_uses_raw_provider_message_for_templated_sms_delivery()
    {
        var aws = Substitute.For<IAWSService>();
        var twilio = Substitute.For<ITwilioSmsService>();
        aws.SendMessage("+15555550101", "templated reset message", cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(ProviderDeliveryResult.Sent("aws-sns", "message-id")));
        var sender = new SmsSender(aws, twilio, Options.Create(EnabledSmsSettings()), NullLogger<SmsSender>.Instance);

        bool sent = await sender.SendMessage("+15555550101", "templated reset message");

        sent.ShouldBeTrue();
        await aws.Received(1).SendMessage("+15555550101", "templated reset message", cancellationToken: Arg.Any<CancellationToken>());
        await aws.DidNotReceiveWithAnyArgs().SendSMS(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
        await twilio.DidNotReceiveWithAnyArgs().SendMessage(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    private static SidewalkSettings EnabledSmsSettings() => new()
    {
        SmsEnabled = true,
        AwsSnsEnabled = true,
        TwilioEnabled = true,
        PaymentProcessorPrimary = "disabled-test",
        SmsProviderPrimary = "aws",
        SmsProviderSecondary = "twilio"
    };
}
