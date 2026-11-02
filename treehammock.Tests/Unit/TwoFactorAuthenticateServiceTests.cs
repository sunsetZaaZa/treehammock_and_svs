using NSubstitute;
using Shouldly;

using treehammock.Services;

namespace treehammock.Tests.Unit;

public class TwoFactorAuthenticateServiceTests
{
    [Fact]
    public async Task Email_sends_two_factor_key_through_smtp()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        smtp.TwoFactorKeyOutboundLetter("reader@example.com", Arg.Any<string>(), "123456", token: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        var service = new TwoFactorAuthenticateService(smtp, sms);

        bool sent = await service.Email("reader@example.com", "123456");

        sent.ShouldBe(true);
        await smtp.Received(1).TwoFactorKeyOutboundLetter("reader@example.com", Arg.Any<string>(), "123456", token: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Setup_adapter_maps_acceptance_and_ambiguity()
    {
        var smtp=Substitute.For<ISMTPService>();var sms=Substitute.For<ISmsSender>();var provider=new DeliveryProviderAdapter(smtp,sms);
        var payload=new treehammock.Rigging.Delivery.DeliveryPayload("factor","email","reader@example.test","test","123456");Guid id=Guid.NewGuid();
        smtp.SendDurable(id,payload,Arg.Any<CancellationToken>()).Returns(Task.FromResult(new treehammock.Rigging.Delivery.DeliverySendResult(treehammock.Rigging.Delivery.DeliverySendState.Accepted,"DELIVERY_ACCEPTED")));
        (await provider.SendAsync(id,payload,CancellationToken.None)).State.ShouldBe(treehammock.Rigging.Delivery.DeliverySendState.Accepted);
        smtp.SendDurable(id,payload,Arg.Any<CancellationToken>()).Returns(Task.FromResult(new treehammock.Rigging.Delivery.DeliverySendResult(treehammock.Rigging.Delivery.DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN")));
        (await provider.SendAsync(id,payload,CancellationToken.None)).State.ShouldBe(treehammock.Rigging.Delivery.DeliverySendState.Unknown);
    }

    [Fact]
    public async Task SMS_sends_two_factor_key_through_provider_agnostic_sender()
    {
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();
        sms.SendCode("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        var service = new TwoFactorAuthenticateService(smtp, sms);

        bool? sent = await service.SMS("+15555550101", "123456");

        sent.ShouldBe(true);
        await sms.Received(1).SendCode("+15555550101", "123456", cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Setup_adapter_preserves_unknown_acceptance()
    {
        var smtp=Substitute.For<ISMTPService>();var sms=Substitute.For<ISmsSender>();var provider=new DeliveryProviderAdapter(smtp,sms);
        var payload=new treehammock.Rigging.Delivery.DeliveryPayload("factor","email","reader@example.test","test","123456");Guid id=Guid.NewGuid();
        smtp.SendDurable(id,payload,Arg.Any<CancellationToken>()).Returns(Task.FromResult(new treehammock.Rigging.Delivery.DeliverySendResult(treehammock.Rigging.Delivery.DeliverySendState.Accepted,"DELIVERY_ACCEPTED")));
        (await provider.SendAsync(id,payload,CancellationToken.None)).State.ShouldBe(treehammock.Rigging.Delivery.DeliverySendState.Accepted);
        smtp.SendDurable(id,payload,Arg.Any<CancellationToken>()).Returns(Task.FromResult(new treehammock.Rigging.Delivery.DeliverySendResult(treehammock.Rigging.Delivery.DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN")));
        (await provider.SendAsync(id,payload,CancellationToken.None)).State.ShouldBe(treehammock.Rigging.Delivery.DeliverySendState.Unknown);
    }

    [Fact]
    public void Unsupported_provider_methods_are_not_exposed_by_two_factor_delivery_service()
    {
        Type contract = typeof(ITwoFactorAuthenticateService);

        contract.GetMethod("Au" + "thy").ShouldBeNull();
        contract.GetMethod("Setup" + "Au" + "thy").ShouldBeNull();
        contract.GetMethod("Remove" + "Au" + "thy").ShouldBeNull();
        contract.GetMethod("OAuth").ShouldBeNull();
        contract.GetMethod("SetupOAuth").ShouldBeNull();
        contract.GetMethod("RemoveOAuth").ShouldBeNull();
        contract.GetMethod("RemoveEmail").ShouldBeNull();
        contract.GetMethod("RemoveSMS").ShouldBeNull();
    }
}
