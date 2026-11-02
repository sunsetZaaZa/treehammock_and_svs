using Microsoft.Extensions.Options;
using NodaTime;
using NSubstitute;
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

public class Cor11SignupServiceTests
{
    [Theory]
    [InlineData(HttpMessage.DUPLICATE_USER_GUID, 2)]
    [InlineData(HttpMessage.DUPLICATE_USER_WEBKEY, 2)]
    [InlineData(HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL, 1)]
    [InlineData(HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME, 1)]
    [InlineData(HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME_EMAIL, 1)]
    [InlineData(HttpMessage.ACCOUNT_CREATION_FAILED, 1)]
    public async Task Only_intended_metadata_collisions_retry_with_a_bounded_single_password_hash(HttpMessage conflict, int calls)
    {
        var repo = Substitute.For<IAccountRepo>(); var work = Substitute.For<IPasswordWorkService>();
        var smtp = Substitute.For<ISMTPService>(); var admission = Substitute.For<ISignupAdmissionPolicy>();
        admission.CheckAsync(Arg.Any<string>(), Arg.Any<string?>(), Arg.Any<string?>(), Arg.Any<CancellationToken>()).Returns((HttpMessage?)null);
        repo.CheckSignupAvailability(Arg.Any<string>(), Arg.Any<string?>(), Arg.Any<CancellationToken>()).Returns((HttpMessage?)null);
        byte[] hash = new byte[AccountCryptoSizes.PasswordHashBytes];
        work.HashBytesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(hash);
        var candidates = new List<Account>();
        repo.SetupAccount(Arg.Do<Account>(candidates.Add), Arg.Any<string>(), Arg.Any<Period>(), AccountSetupAction.BOTH, Arg.Any<treehammock.Rigging.Delivery.DeliveryIntent>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<(long?, HttpMessage, string?)>((null, conflict, null)));
        var service = new AccountService(new treehammock.Tests.Infrastructure.CapturingDurableDelivery(),repo, Options.Create(new LoginSettings()),
            Options.Create(new RegistrationSettings { PublicOrigin = "http://localhost.test", AccountMetaDataRetries = 2 }), Options.Create(new EmailSubjectSettings()),
            Substitute.For<IUserSecretHasher>(), passwordWork: work, signupAdmission: admission);
        var outcome = await service.SetupUserAccount("reader@example.invalid", "reader", "password", Country.USA,
            SystemClock.Instance.GetCurrentInstant(), AccountSetupAction.BOTH);
        outcome.ShouldBe(calls == 2 ? HttpMessage.ACCOUNT_CREATION_FAILED : conflict);
        candidates.Count.ShouldBe(calls); candidates.Select(a => a.accountId).Distinct().Count().ShouldBe(calls);
        candidates.Select(a => a.webKey).Distinct().Count().ShouldBe(calls);
        candidates.All(a => ReferenceEquals(a.hashedPassword, hash)).ShouldBeTrue();
        await work.Received(1).HashBytesAsync("password", Arg.Any<CancellationToken>());
        await repo.DidNotReceiveWithAnyArgs().StartAccountVerification(default, default);
        await smtp.DidNotReceiveWithAnyArgs().VerificationLetter(default!, default!, default!, token: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Alternating_metadata_collisions_have_a_total_bound()
    {
        var repo = Substitute.For<IAccountRepo>(); var work = Substitute.For<IPasswordWorkService>();
        var admission = Substitute.For<ISignupAdmissionPolicy>();
        work.HashBytesAsync(Arg.Any<string>(), Arg.Any<CancellationToken>()).Returns(new byte[AccountCryptoSizes.PasswordHashBytes]);
        int calls = 0;
        repo.SetupAccount(Arg.Any<Account>(), Arg.Any<string>(), Arg.Any<Period>(), AccountSetupAction.EMAIL, Arg.Any<treehammock.Rigging.Delivery.DeliveryIntent>(), Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromResult<(long?, HttpMessage, string?)>((null,
                ++calls % 2 == 1 ? HttpMessage.DUPLICATE_USER_GUID : HttpMessage.DUPLICATE_USER_WEBKEY, null)));
        var service = new AccountService(new treehammock.Tests.Infrastructure.CapturingDurableDelivery(),repo, Options.Create(new LoginSettings()),
            Options.Create(new RegistrationSettings { PublicOrigin = "http://localhost.test", AccountMetaDataRetries = 2 }), Options.Create(new EmailSubjectSettings()),
            Substitute.For<IUserSecretHasher>(), passwordWork: work, signupAdmission: admission);
        (await service.SetupUserAccount("reader@example.invalid", null, "password", Country.USA,
            SystemClock.Instance.GetCurrentInstant(), AccountSetupAction.EMAIL)).ShouldBe(HttpMessage.ACCOUNT_CREATION_FAILED);
        calls.ShouldBe(3); await work.Received(1).HashBytesAsync("password", Arg.Any<CancellationToken>());
    }
}
