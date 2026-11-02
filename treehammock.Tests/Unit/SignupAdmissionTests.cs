using Microsoft.Extensions.Options;
using NSubstitute;
using NodaTime;
using Shouldly;
using treehammock.Entities;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class Cor07SignupAdmissionTests
{
    [Theory]
    [InlineData(false)] [InlineData(true)]
    public async Task Counter_outage_is_unavailable_even_when_authority_fallback_is_allowed(bool fallbackAllowed)
    {
        var store = Substitute.For<IAbuseCounterStore>();
        store.IncrementAsync(Arg.Any<AbuseCounterKey>(), Arg.Any<AbuseCounterLimit>(), Arg.Any<CancellationToken>())
            .Returns(new CounterDecision(fallbackAllowed, 0, 3, TimeSpan.FromMinutes(15), null, AbuseReasonCodes.CounterStoreUnavailable));
        var policy = new SignupAdmissionPolicy(store, Options.Create(new AbuseControlSettings()), Options.Create(new LoginSettings { TwoFactorChallengePepper = "shared-unit-test-pepper" }));
        (await policy.CheckAsync("reader@example.invalid", "reader", "203.0.113.42")).ShouldBe(HttpMessage.ACCOUNT_CREATION_ADMISSION_UNAVAILABLE);
    }
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task Admission_denial_or_existing_duplicate_invokes_neither_hasher_nor_mutation(bool denied)
    {
        var repo = Substitute.For<IAccountRepo>(); var work = Substitute.For<IPasswordWorkService>();
        var admission = Substitute.For<ISignupAdmissionPolicy>();
        admission.CheckAsync(Arg.Any<string>(), Arg.Any<string?>(), Arg.Any<string?>(), Arg.Any<CancellationToken>())
            .Returns(denied ? HttpMessage.ACCOUNT_CREATION_RATE_LIMITED : (HttpMessage?)null);
        repo.CheckSignupAvailability(Arg.Any<string>(), Arg.Any<string?>(), Arg.Any<CancellationToken>()).Returns(HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL);
        var service = new AccountService(new treehammock.Tests.Infrastructure.CapturingDurableDelivery(),repo, Options.Create(new LoginSettings()),
            Options.Create(new RegistrationSettings { PublicOrigin = "http://localhost.test" }), Options.Create(new EmailSubjectSettings()), Substitute.For<IUserSecretHasher>(),
            passwordWork: work, signupAdmission: admission);
        var result = await service.SetupUserAccount("reader@example.invalid", null, "password", Country.USA, SystemClock.Instance.GetCurrentInstant(), AccountSetupAction.EMAIL);
        result.ShouldBe(denied ? HttpMessage.ACCOUNT_CREATION_RATE_LIMITED : HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL);
        await work.DidNotReceiveWithAnyArgs().HashBytesAsync(default!);
        await repo.DidNotReceiveWithAnyArgs().SetupAccount(default!, default!, default!, default, Arg.Any<treehammock.Rigging.Delivery.DeliveryIntent>());
    }
}
