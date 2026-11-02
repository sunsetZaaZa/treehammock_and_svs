using Microsoft.Extensions.Options;
using NodaTime;
using Shouldly;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Tests.Infrastructure;
using treehammock.Services;

namespace treehammock.Tests.Unit;
public class PasswordResetDeliveryServiceTests
{
    [Theory][InlineData("email")][InlineData("sms")]
    public async Task Reset_stages_hashed_metadata_and_raw_payload_for_the_same_request(string channel)
    {
        var durable=new CapturingDurableDelivery();var service=new PasswordResetDeliveryService(durable,Options.Create(new EmailSubjectSettings {PasswordResetCode="Reset"}));
        Guid id=Guid.NewGuid(),account=Guid.NewGuid(),stamp=Guid.NewGuid();Instant expires=SystemClock.Instance.GetCurrentInstant().Plus(Duration.FromMinutes(2));
        var command=new CreatePasswordResetRequestDbCommand(id,account,channel,channel,"hash",1,"fingerprint","masked",true,false,expires,5,null,null,stamp);
        await service.StageAsync(command,new(id,account,channel,channel,"masked","destination","49382710",expires),CancellationToken.None);
        var candidate=durable.Intents.Single();candidate.AccountId.ShouldBe(account);candidate.AccountStamp.ShouldBe(stamp);candidate.ProofHash.ShouldBe("hash");candidate.Payload.Value.ShouldBe("49382710");candidate.Payload.Channel.ShouldBe(channel);
        durable.Protect(candidate).Id.ShouldBe(id);
    }
    [Fact]
    public async Task Reset_admission_uses_account_and_does_not_stage_when_denied()
    {
        var durable=new CapturingDurableDelivery {Allowed=false};var service=new PasswordResetDeliveryService(durable,Options.Create(new EmailSubjectSettings()));Guid account=Guid.NewGuid();
        (await service.AdmitAsync(account,"sms","+15555550101",CancellationToken.None)).ShouldBeFalse();durable.Admissions.Single().Account.ShouldBe(account);durable.Intents.ShouldBeEmpty();
    }
    [Fact]
    public async Task Pending_queries_distinguish_bootstrap_from_second_factor()
    {
        var durable=new CapturingDurableDelivery {Pending=true};var service=new PasswordResetDeliveryService(durable,Options.Create(new EmailSubjectSettings()));
        (await service.IsPendingAsync("hash",CancellationToken.None)).ShouldBeTrue();(await service.IsFactorPendingAsync("hash",CancellationToken.None)).ShouldBeTrue();
    }
}
