using Microsoft.Extensions.Options;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.Entities;
using treehammock.Models.Account;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class AccountServiceSetupTests
{
    [Fact]
    public async Task SetupUserAccount_successful_creation_stages_initial_delivery_in_repository_transaction()
    {
        var harness=CreateServiceHarness();
        treehammock.Rigging.Delivery.DeliveryIntent? intent=null;
        harness.AccountRepo.SetupAccount(Arg.Any<Account>(),Arg.Any<string>(),Arg.Any<Period>(),AccountSetupAction.EMAIL,Arg.Do<treehammock.Rigging.Delivery.DeliveryIntent>(d=>intent=d),Arg.Any<CancellationToken>()).Returns((7L,HttpMessage.ACCOUNT_CREATION_SUCCESSED,(string?)null));
        var result=await harness.Service.SetupUserAccount("reader@example.com",null,"ValidPassword1!",Country.USA,SystemClock.Instance.GetCurrentInstant(),AccountSetupAction.EMAIL);
        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);intent.ShouldNotBeNull();intent.Purpose.ShouldBe("verify");intent.Payload.Value.ShouldStartWith("http://localhost.test/account/verifyaccount?payload=");
        harness.Delivery.Admissions.Single().Account.ShouldBe(intent.AccountId);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().StartAccountVerification(default,default);
        await harness.SmtpService.DidNotReceiveWithAnyArgs().VerificationLetter(default!,default!,default!);
    }

    [Theory]
    [InlineData(HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL)]
    [InlineData(HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME)]
    [InlineData(HttpMessage.ACCOUNT_CREATION_DUPLICATE_USERNAME_EMAIL)]
    public async Task SetupUserAccount_returns_duplicate_result_without_sending_verification(HttpMessage duplicateResult)
    {
        var harness = CreateServiceHarness();
        harness.AccountRepo.SetupAccount(Arg.Any<Account>(), Arg.Any<string>(), Arg.Any<Period>(), AccountSetupAction.BOTH, Arg.Any<treehammock.Rigging.Delivery.DeliveryIntent>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<(long?, HttpMessage, string?)>((null, duplicateResult, null)));

        HttpMessage result = await harness.Service.SetupUserAccount(
            "reader@example.com",
            "reader",
            "ValidPassword1!",
            Country.USA,
            SystemClock.Instance.GetCurrentInstant(),
            AccountSetupAction.BOTH);

        result.ShouldBe(duplicateResult);
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().StartAccountVerification(default, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.SmtpService.DidNotReceiveWithAnyArgs().VerificationLetter(default!, default!, default!);
    }



    [Fact]
    public async Task ResendAccountVerification_stages_new_url_with_resolved_account()
    {
        var harness=CreateServiceHarness();harness.Delivery.Allowed=true;
        var owner=new treehammock.Rigging.Delivery.DeliveryAccount(Guid.NewGuid(),Guid.NewGuid(),"reader@example.com",2);harness.Delivery.Account=owner;
        var result=await harness.Service.ResendAccountVerification(owner.Email);
        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);harness.Delivery.Admissions.Single().Account.ShouldBe(owner.AccountId);
        harness.Delivery.Intents.Count.ShouldBe(1);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().ResendAccountVerification(default!,default!,default!);
        await harness.SmtpService.DidNotReceiveWithAnyArgs().ResendVerifyLetter(default!,default!,default!);
    }

    [Fact]
    public async Task ResendAccountVerification_denied_admission_preserves_working_proof()
    {
        var harness=CreateServiceHarness();harness.Delivery.Allowed=false;
        var owner=new treehammock.Rigging.Delivery.DeliveryAccount(Guid.NewGuid(),Guid.NewGuid(),"reader@example.com",2);harness.Delivery.Account=owner;
        var result=await harness.Service.ResendAccountVerification(owner.Email);
        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);harness.Delivery.Admissions.Single().Account.ShouldBe(owner.AccountId);
        harness.Delivery.Intents.Count.ShouldBe(0);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().ResendAccountVerification(default!,default!,default!);
        await harness.SmtpService.DidNotReceiveWithAnyArgs().ResendVerifyLetter(default!,default!,default!);
    }

    [Fact]
    public async Task RequestEmailChange_stages_hash_and_destination()
    {
        var harness=CreateServiceHarness();harness.Delivery.Allowed=true;harness.Delivery.Result=new(true,"DELIVERY_PENDING");
        Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();var result=await harness.Service.RequestEmailChange(account,stamp,"new@example.com",grant:new("session","token-hash","target-hash",SensitiveActionTargets.EmailChange("new@example.com")));
        result.ShouldNotBeNull();harness.Delivery.Admissions.First().Account.ShouldBe(account);harness.Delivery.Intents.Count.ShouldBe(1);
        var d=harness.Delivery.Intents.Single();d.AccountStamp.ShouldBe(stamp);d.Purpose.ShouldBe("email");d.Payload.Destination.ShouldBe("new@example.com");d.ProofHash.ShouldNotBe(d.Payload.Value);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().RequestEmailChange(default,default,default!,default!,default);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().CancelEmailChangeRequest(default,default,default!);
    }

    [Fact]
    public async Task RequestEmailChange_denial_does_not_replace_or_cancel_proof()
    {
        var harness=CreateServiceHarness();harness.Delivery.Allowed=false;harness.Delivery.Result=new(true,"DELIVERY_PENDING");
        Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();var result=await harness.Service.RequestEmailChange(account,stamp,"new@example.com",grant:new("session","token-hash","target-hash",SensitiveActionTargets.EmailChange("new@example.com")));
        result.ShouldNotBeNull();harness.Delivery.Admissions.First().Account.ShouldBe(account);harness.Delivery.Intents.Count.ShouldBe(0);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().RequestEmailChange(default,default,default!,default!,default);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().CancelEmailChangeRequest(default,default,default!);
    }


    [Fact]
    public async Task RequestEmailChange_stage_conflict_preserves_current_request()
    {
        var harness=CreateServiceHarness();harness.Delivery.Allowed=true;harness.Delivery.Result=new(false,"DELIVERY_CANDIDATE_CONFLICT");
        Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();var result=await harness.Service.RequestEmailChange(account,stamp,"new@example.com",grant:new("session","token-hash","target-hash",SensitiveActionTargets.EmailChange("new@example.com")));
        result.ShouldNotBeNull();result.Result.ShouldBeFalse();result.Code.ShouldBe("DELIVERY_CANDIDATE_CONFLICT");harness.Delivery.Admissions.First().Account.ShouldBe(account);harness.Delivery.Intents.Count.ShouldBe(1);
        var d=harness.Delivery.Intents.Single();d.AccountStamp.ShouldBe(stamp);d.Purpose.ShouldBe("email");d.Payload.Destination.ShouldBe("new@example.com");d.ProofHash.ShouldNotBe(d.Payload.Value);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().RequestEmailChange(default,default,default!,default!,default);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().CancelEmailChangeRequest(default,default,default!);
    }

    [Fact]
    public async Task CompleteEmailChange_hashes_raw_token_before_repository_call()
    {
        var harness = CreateServiceHarness();
        string? capturedHash = null;
        harness.AccountRepo.CompleteEmailChange(Arg.Do<string>(hash => capturedHash = hash), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountAdjustResult?>(new AccountAdjustResult(true, "ACCOUNT_ADJUST_SUCCEEDED", Guid.NewGuid())));

        AccountAdjustResult? result = await harness.Service.CompleteEmailChange("raw-token");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        capturedHash.ShouldBe(SecretHashUtility.HashToken("raw-token"));
        capturedHash.ShouldNotBe("raw-token");
    }


    [Fact]
    public async Task CompleteEmailChange_oversized_token_returns_mismatch_without_repository_call()
    {
        var harness = CreateServiceHarness();
        string verifyToken = new('x', AccountEmailChangeVerifyRequest.MaxEmailChangeTokenLength + 1);

        AccountAdjustResult? result = await harness.Service.CompleteEmailChange(verifyToken);

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe("ACCOUNT_ADJUST_TOKEN_MISMATCH");
        await harness.AccountRepo.DidNotReceive().CompleteEmailChange(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task RequestAccountDelete_stages_hashed_lookup_and_encrypted_raw_token()
    {
        var harness=CreateServiceHarness();harness.Delivery.Allowed=true;Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();
        harness.AccountRepo.AdmitAccountDelete(account,stamp,Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Instant>(),Arg.Any<Period>(),Arg.Any<Period>(),Arg.Any<short>(),Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>(),Arg.Any<CancellationToken>()).Returns(new AccountDeleteCommandResult(true,"ACCOUNT_DELETE_PENDING",EmailAddress:"reader@example.com"));
        var result=await harness.Service.RequestAccountDelete(account,stamp,"deletion passphrase",grant:new("session","grant","target",SensitiveActionTargets.AccountDelete("deletion passphrase")));result.ShouldNotBeNull();harness.Delivery.Admissions.First().Account.ShouldBe(account);harness.Delivery.Intents.Count.ShouldBe(1);
        var d=harness.Delivery.Intents.Single();d.Purpose.ShouldBe("delete");d.Payload.Secondary.ShouldNotBeNullOrWhiteSpace();d.ProofHash.ShouldBe(SecretHashUtility.HashLookupToken(d.Payload.Secondary!));
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().CancelAccountDeleteRequest(default,default,default!);
    }

    [Fact]
    public async Task RequestAccountDelete_without_passphrase_stages_one_time_token()
    {
        var harness=CreateServiceHarness();harness.Delivery.Allowed=true;Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();
        harness.AccountRepo.AdmitAccountDelete(account,stamp,Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Instant>(),Arg.Any<Period>(),Arg.Any<Period>(),Arg.Any<short>(),Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>(),Arg.Any<CancellationToken>()).Returns(new AccountDeleteCommandResult(true,"ACCOUNT_DELETE_PENDING",EmailAddress:"reader@example.com"));
        var result=await harness.Service.RequestAccountDelete(account,stamp,null,grant:new("session","grant","target",SensitiveActionTargets.AccountDelete(null)));result.ShouldNotBeNull();harness.Delivery.Admissions.First().Account.ShouldBe(account);harness.Delivery.Intents.Count.ShouldBe(1);
        var d=harness.Delivery.Intents.Single();d.Purpose.ShouldBe("delete");d.Payload.Secondary.ShouldNotBeNullOrWhiteSpace();d.ProofHash.ShouldBe(SecretHashUtility.HashLookupToken(d.Payload.Secondary!));
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().CancelAccountDeleteRequest(default,default,default!);
    }

    [Fact]
    public async Task RequestAccountDelete_denial_does_not_cancel_current_request()
    {
        var harness=CreateServiceHarness();harness.Delivery.Allowed=false;Guid account=Guid.NewGuid(),stamp=Guid.NewGuid();
        harness.AccountRepo.AdmitAccountDelete(account,stamp,Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Instant>(),Arg.Any<Period>(),Arg.Any<Period>(),Arg.Any<short>(),Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>(),Arg.Any<CancellationToken>()).Returns(new AccountDeleteCommandResult(true,"ACCOUNT_DELETE_PENDING",EmailAddress:"reader@example.com"));
        var result=await harness.Service.RequestAccountDelete(account,stamp,"deletion passphrase",grant:new("session","grant","target",SensitiveActionTargets.AccountDelete("deletion passphrase")));result.ShouldNotBeNull();harness.Delivery.Admissions.First().Account.ShouldBe(account);harness.Delivery.Intents.Count.ShouldBe(0);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().CancelAccountDeleteRequest(default,default,default!);
    }




    [Fact]
    public async Task VerifyAccountDeleteToken_hashes_raw_token_before_repository_call()
    {
        var harness = CreateServiceHarness();
        string? capturedDeleteTokenHash = null;
        harness.AccountRepo.VerifyDeleteAccountToken(Arg.Do<string>(hash => capturedDeleteTokenHash = hash), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_VERIFIED", DeletionWorkflow.ONETIME)));

        AccountDeleteCommandResult? result = await harness.Service.VerifyAccountDeleteToken("raw-delete-token");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        result.Code.ShouldBe("ACCOUNT_DELETE_VERIFIED");
        capturedDeleteTokenHash.ShouldNotBeNullOrWhiteSpace();
        capturedDeleteTokenHash.ShouldBe(SecretHashUtility.HashToken("raw-delete-token"));
        capturedDeleteTokenHash.ShouldNotBe("raw-delete-token");
    }

    [Fact]
    public async Task VerifyAccountDeleteToken_blank_token_returns_mismatch_without_repository_call()
    {
        var harness = CreateServiceHarness();

        AccountDeleteCommandResult? result = await harness.Service.VerifyAccountDeleteToken("   ");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeFalse();
        result.Code.ShouldBe("ACCOUNT_DELETE_TOKEN_MISMATCH");
        await harness.AccountRepo.DidNotReceive().VerifyDeleteAccountToken(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task FinalizeAccountDelete_hashes_token_but_passes_raw_passphrase_to_repository_for_argon2id_verification()
    {
        var harness = CreateServiceHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string? capturedDeleteTokenHash = null;
        string? capturedPassPhrase = null;
        short? capturedMaxFailedFinalizeAttempts = null;
        Period? capturedFinalizeLockout = null;
        harness.AccountRepo.FinalizeAccountDelete(
                accountId,
                accountSecurityStamp,
                Arg.Do<string>(hash => capturedDeleteTokenHash = hash),
                Arg.Do<string?>(rawSecret => capturedPassPhrase = rawSecret),
                Arg.Do<short>(max => capturedMaxFailedFinalizeAttempts = max),
                Arg.Do<Period>(period => capturedFinalizeLockout = period), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_SUCCEEDED", DeletionWorkflow.NONE, null, accountId)));

        AccountDeleteCommandResult? result = await harness.Service.FinalizeAccountDelete(accountId, accountSecurityStamp, "raw-delete-token", "secret");

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        result.Code.ShouldBe("ACCOUNT_DELETE_SUCCEEDED");
        capturedDeleteTokenHash.ShouldBe(SecretHashUtility.HashToken("raw-delete-token"));
        capturedPassPhrase.ShouldBe("secret");
        capturedMaxFailedFinalizeAttempts.ShouldBe((short)5);
        capturedFinalizeLockout.ShouldBe(Period.FromMinutes(30));
    }

    [Fact]
    public async Task FinalizeAccountDelete_without_passphrase_passes_null_secret()
    {
        var harness = CreateServiceHarness();
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        harness.AccountRepo.FinalizeAccountDelete(
                accountId,
                accountSecurityStamp,
                Arg.Any<string>(),
                Arg.Is<string?>(value => value == null),
                Arg.Any<short>(),
                Arg.Any<Period>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_SUCCEEDED", DeletionWorkflow.NONE, null, accountId)));

        AccountDeleteCommandResult? result = await harness.Service.FinalizeAccountDelete(accountId, accountSecurityStamp, "raw-delete-token", null);

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        await harness.AccountRepo.Received(1).FinalizeAccountDelete(accountId, accountSecurityStamp, Arg.Any<string>(), Arg.Is<string?>(value => value == null), Arg.Any<short>(), Arg.Any<Period>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task PurgeExpiredDeleteStandby_passes_current_moment_to_repository()
    {
        var harness = CreateServiceHarness();
        Instant? capturedMoment = null;
        harness.AccountRepo.PurgeExpiredDeleteStandby(Arg.Do<Instant>(moment => capturedMoment = moment), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountDeletePurgeResult?>(new AccountDeletePurgeResult(true, "ACCOUNT_DELETE_PURGE_SUCCEEDED", 2)));

        AccountDeletePurgeResult? result = await harness.Service.PurgeExpiredDeleteStandby();

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        result.Code.ShouldBe("ACCOUNT_DELETE_PURGE_SUCCEEDED");
        result.DeletedCount.ShouldBe(2);
        capturedMoment.ShouldNotBeNull();
    }

    [Fact]
    public async Task PurgeExpiredAccountEmailChangeRequests_passes_current_moment_to_repository()
    {
        var harness = CreateServiceHarness();
        Instant? capturedMoment = null;
        harness.AccountRepo.PurgeExpiredAccountEmailChangeRequests(Arg.Do<Instant>(moment => capturedMoment = moment), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountEmailChangePurgeResult?>(new AccountEmailChangePurgeResult(true, "ACCOUNT_ADJUST_PURGE_SUCCEEDED", 3)));

        AccountEmailChangePurgeResult? result = await harness.Service.PurgeExpiredAccountEmailChangeRequests();

        result.ShouldNotBeNull();
        result!.Result.ShouldBeTrue();
        result.Code.ShouldBe("ACCOUNT_ADJUST_PURGE_SUCCEEDED");
        result.DeletedCount.ShouldBe(3);
        capturedMoment.ShouldNotBeNull();
    }



    [Fact]
    public async Task ResendAccountVerification_denied_admission_stages_nothing()
    {
        var harness=CreateServiceHarness();harness.Delivery.Allowed=false;
        var owner=new treehammock.Rigging.Delivery.DeliveryAccount(Guid.NewGuid(),Guid.NewGuid(),"reader@example.com",2);harness.Delivery.Account=owner;
        var result=await harness.Service.ResendAccountVerification(owner.Email);
        result.ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING);harness.Delivery.Admissions.Single().Account.ShouldBe(owner.AccountId);
        harness.Delivery.Intents.Count.ShouldBe(0);
        await harness.AccountRepo.DidNotReceiveWithAnyArgs().ResendAccountVerification(default!,default!,default!);
        await harness.SmtpService.DidNotReceiveWithAnyArgs().ResendVerifyLetter(default!,default!,default!);
    }


    [Theory,InlineData("no-grant"),InlineData("wrong-target"),InlineData("budget"),InlineData("delivery")]
    public async Task Cor18_admission_and_provider_denial_do_not_hash_or_cancel_existing_proof(string denial)
    {
        var repo=Substitute.For<IAccountRepo>();var hasher=Substitute.For<IUserSecretHasher>();var delivery=new treehammock.Tests.Infrastructure.CapturingDurableDelivery{Allowed=denial!="delivery"};
        repo.AdmitAccountDelete(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Instant>(),Arg.Any<Period>(),Arg.Any<Period>(),Arg.Any<short>(),Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>(),Arg.Any<CancellationToken>()).Returns(new AccountDeleteCommandResult(denial!="budget",denial=="budget"?"ACCOUNT_DELETE_RATE_LIMITED":"ACCOUNT_DELETE_PENDING",EmailAddress:"owner@example.test"));
        var service=new AccountService(delivery,repo,Options.Create(new LoginSettings()),Options.Create(new RegistrationSettings { PublicOrigin = "http://localhost.test" }),Options.Create(new EmailSubjectSettings()),hasher,signupAdmission:AllowSignup());
        treehammock.DataLayer.Security.SensitiveActionGrant? grant=denial=="no-grant"?null:new("session","grant","target",denial=="wrong-target"?"delete:one-time":SensitiveActionTargets.AccountDelete("chosen phrase"));
        (await service.RequestAccountDelete(Guid.NewGuid(),Guid.NewGuid(),"chosen phrase",grant:grant)).ShouldNotBeNull().Result.ShouldBeFalse();
        await hasher.DidNotReceiveWithAnyArgs().HashUserSecretAsync(default!,default);await repo.DidNotReceiveWithAnyArgs().CancelAccountDeleteRequest(default,default,default!,default);delivery.Intents.ShouldBeEmpty();
        if(denial is "no-grant" or "wrong-target"){repo.ReceivedCalls().ShouldBeEmpty();delivery.Admissions.ShouldBeEmpty();}
        if(denial=="delivery")await repo.ReceivedWithAnyArgs(1).AdmitAccountDelete(default,default,default,default!,default,default!,default!,default,default!,default);
    }

    private static AccountServiceHarness CreateServiceHarness()
    {
        var accountRepo = Substitute.For<IAccountRepo>();
        accountRepo.ViewAccount(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<CancellationToken>()).Returns(new AccountViewResult(true,"ACCOUNT_VIEW_FOUND",new AccountProfile {emailAddress="old@example.com",createdOn=SystemClock.Instance.GetCurrentInstant(),verifyStatus=VerificationStatus.SUCCESSFUL,country=Country.NONE,features=FeatureSet.basic,twoFactorEnabled=false}));
        var sessionRepo = Substitute.For<ISessionRepo>();
        var activeUserCache = Substitute.For<IActiveUserCacheService>();
        var jwtUtility = Substitute.For<IJsonWebTokenUtility>();
        var twoFactorService = Substitute.For<ITwoFactorAuthenticateService>();
        var smtpService = Substitute.For<ISMTPService>();
        var loginSettings = new LoginSettings
        {
            PasswordRetryLimit = 3,
            TwoAuthRetryLimit = 3,
            Argon2Iterations = 3,
            Argon2MemoryBytes = 67108864
        };
        var registrationSettings = new RegistrationSettings
        {
            MinUsernameLength = 3,
            MaxUsernameLength = 30,
            MinPasswordLength = 8,
            MaxPasswordLength = 128,
            MaxEmailAddressLength = 255,
            AccountMetaDataRetries = 3,
            VerifyAccountPeriodWeeks = 0,
            VerifyAccountPeriodDays = 1,
            VerifyAccountPeriodHours = 0,
            EmailChangeVerifyPeriodWeeks = 0,
            EmailChangeVerifyPeriodDays = 1,
            EmailChangeVerifyPeriodHours = 0,
            AccountDeleteTokenPeriodWeeks = 0,
            AccountDeleteTokenPeriodDays = 1,
            AccountDeleteTokenPeriodHours = 0,
            PublicOrigin = "http://localhost.test",
            DeleteRequestCooldownMinutes = 15,
            DeleteRequestWindowHours = 24,
            DeleteMaxRequestsPerWindow = 8,
            DeleteMaxFinalizeFailures = 5,
            DeleteFinalizeLockoutMinutes = 30
        };
        var userSecretHasher = new Argon2idUserSecretHasher(Options.Create(loginSettings));

        var emailSubjectSettings = new EmailSubjectSettings
        {
            AccountVerify = "Verify your account",
            AccountVerifyResend = "Resend verification",
            AccountEmailChangeVerify = "Verify new email",
            AccountDeleteVerify = "Verify deletion",
            TwoFactorSetup = "Setup 2FA",
            TwoFactorKeyOutbound = "2FA code",
            TwoFactorDelete = "Delete 2FA"
        };

        var delivery = new treehammock.Tests.Infrastructure.CapturingDurableDelivery();
        var service = new AccountService(delivery,
            accountRepo,
            Options.Create(loginSettings),
            Options.Create(registrationSettings),
            Options.Create(emailSubjectSettings),
            userSecretHasher, signupAdmission: AllowSignup());

        return new AccountServiceHarness(delivery, service, accountRepo, smtpService, emailSubjectSettings, userSecretHasher);
    }

    private static treehammock.Rigging.Abuse.ISignupAdmissionPolicy AllowSignup()
    {
        var policy = Substitute.For<treehammock.Rigging.Abuse.ISignupAdmissionPolicy>();
        policy.CheckAsync(Arg.Any<string>(), Arg.Any<string?>(), Arg.Any<string?>(), Arg.Any<CancellationToken>()).Returns((HttpMessage?)null);
        return policy; // Existing service-flow tests substitute admission; COR07 covers the real policy separately.
    }

    private sealed record AccountServiceHarness(
        treehammock.Tests.Infrastructure.CapturingDurableDelivery Delivery,
        AccountService Service,
        IAccountRepo AccountRepo,
        ISMTPService SmtpService,
        EmailSubjectSettings EmailSubjectSettings,
        IUserSecretHasher UserSecretHasher);
}
