using Microsoft.AspNetCore.Http;
using NSubstitute;
using NodaTime;
using Shouldly;

using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Models.Api;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Unit;

public class AccountControllerSafeRepoWrapperTests
{
    [Fact]
    public async Task Authenticate_returns_persistence_failure_when_credential_lookup_throws()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<CredentialLookupResult>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("LOGIN_ATTEMPT_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_returns_db_persistence_failure_when_session_insert_throws()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns("active-access-token");
        harness.SessionRepo.SetSession(Arg.Any<string>(), Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<IntraMessage?>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("ACTIVE_SESSION_DB_PERSISTENCE_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceive().SuccessfulLogin(account.accountId, account.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_clear_dependency_failure_propagates_before_session_publication()
    {
        var harness = new AccountControllerHarness(); var payload = harness.LoginPayload();
        var account = harness.Account(refreshToken: null, hasTwoFactorAuth: false);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>()).Returns(CredentialLookupResult.Found(account));
        harness.AccountRepo.ClearLoginAttempts(account.accountId,account.accountSecurityStamp,Arg.Any<Guid>(),Arg.Any<short>(),Arg.Any<Instant?>(),false,Arg.Any<CancellationToken>())
            .Returns(Task.FromException<treehammock.DataLayer.Security.LoginAttemptTransition>(treehammock.Rigging.Dependencies.DependencyUnavailableException.InvalidResponse("login_attempts")));
        var controller = harness.CreateLoginController();
        await Should.ThrowAsync<treehammock.Rigging.Dependencies.DependencyUnavailableException>(()=>controller.Authenticate(payload));
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!,default!,Arg.Any<CancellationToken>());
        _ = harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!,default!,default,cancellationToken:Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_already_logged_in_returns_500_when_db_rotation_throws_without_touching_cache()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        const string rotatedToken = "rotated-access-token";
        string oldHash = AccessTokenHashUtility.Hash("old-access-token");
        string rotatedHash = AccessTokenHashUtility.Hash(rotatedToken);
        var account = harness.Account(
            refreshToken: Enumerable.Repeat((byte)7, harness.JwtSettings.RefreshTokenBytes).ToArray(),
            hasTwoFactorAuth: false,
            activeAccessTokenHash: oldHash);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(CredentialLookupResult.Found(account)));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), account.webKey).Returns(rotatedToken);
        harness.SessionRepo.RotateActiveSession(account.accountId, oldHash, rotatedHash, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<SessionRotationResult?>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        await harness.ActiveUserCacheService.DidNotReceive().RevokeSession(oldHash, cancellationToken: Arg.Any<CancellationToken>());
        await harness.ActiveUserCacheService.DidNotReceive().SetSession(rotatedHash, Arg.Any<ActiveSession>(), Arg.Any<TimeSpan>(), cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_returns_two_factor_lookup_failure_when_details_lookup_throws()
    {
        var harness = new AccountControllerHarness();
        var payload = harness.LoginPayload();
        var account = harness.Account(hasTwoFactorAuth: true, twoFactorAuthMethod: TwoFactorAuthMethod.EMAIL);
        harness.AccountRepo.GetCredentials(payload, AccountLoginAction.EMAIL, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(_ => Task.FromException<TwoFactorDetailsLookupResult>(new InvalidOperationException("repo boom")));
        var controller = harness.CreateLoginController();

        var actionResult = await controller.Authenticate(payload);

        ApiResponse<AuthenticateResponse> envelope = AccountControllerHarness.ExtractEnvelope(actionResult, StatusCodes.Status500InternalServerError);
        envelope.success.ShouldBeFalse();
        envelope.code.ShouldBe("TWO_FACTOR_DETAILS_LOOKUP_FAILED");
        envelope.data.ShouldNotBeNull();
        envelope.data!.result.ShouldBe(HttpMessage.AUTHENTICATION_FAILED);
        _ = harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!, default!, default, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authenticate_pending_SQL_dependency_failure_propagates_without_cache_mutation()
    {
        var harness = new AccountControllerHarness();var payload=harness.LoginPayload();
        var account=harness.Account(hasTwoFactorAuth:true,twoFactorAuthMethod:TwoFactorAuthMethod.EMAIL);
        harness.AccountRepo.GetCredentials(payload,AccountLoginAction.EMAIL,cancellationToken:Arg.Any<CancellationToken>()).Returns(Task.FromResult(CredentialLookupResult.Found(account)));
        harness.AccountRepo.GetTwoFactorDetails(account.accountId,cancellationToken:Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(new TwoFactorDetails([TwoFactorAuthMethod.EMAIL],null,null,null,["reader@example.com"]))));
        harness.JwtUtility.GenerateAccessToken(Arg.Any<byte[]>(),account.webKey,JsonWebTokenPurpose.PreAuthTwoFactor).Returns("pending-token");
        harness.LoginProofs.BeginAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<CancellationToken>()).Returns(Task.FromException<LoginProofTransition>(new InvalidOperationException("repository boundary")));
        var controller=harness.CreateLoginController();
        await Should.ThrowAsync<InvalidOperationException>(()=>controller.Authenticate(payload));
        _=harness.TwoFactorSessionService.DidNotReceiveWithAnyArgs().SetSession(default!,default!,default,cancellationToken:Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task TwoFactorAuthenticate_propagates_repository_failure_when_pending_db_validation_throws()
    {
        var(harness,_,_)=TwoFactorAuthenticationPromotionTests.Prepare(prior:null);
        harness.LoginProofs.LoadAsync(Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(Task.FromException<TwoFactorSession?>(new InvalidOperationException("repository boundary")));
        var controller=harness.CreateTwoFactorController();harness.HttpContext.Request.Headers["AccessToken"]="pending-token";
        await Should.ThrowAsync<InvalidOperationException>(()=>controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456",TwoFactorAuthMethod.EMAIL)));
        _=harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!,default!,default,cancellationToken:Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task TwoFactorAuthenticate_propagates_repository_failure_when_new_login_promotion_throws()
    {
        var(harness,_,_)=TwoFactorAuthenticationPromotionTests.Prepare(prior:null);
        harness.LoginProofs.PromoteAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<string>(),Arg.Any<ActiveSession>(),Arg.Any<CancellationToken>()).Returns(Task.FromException<LoginProofTransition>(new InvalidOperationException("repository boundary")));
        var controller=harness.CreateTwoFactorController();harness.HttpContext.Request.Headers["AccessToken"]="pending-token";
        await Should.ThrowAsync<InvalidOperationException>(()=>controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456",TwoFactorAuthMethod.EMAIL)));
        _=harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().SetSession(default!,default!,default,cancellationToken:Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task TwoFactorAuthenticate_rotation_repository_failure_does_not_publish_or_revoke_active_cache()
    {
        var(harness,_,_)=TwoFactorAuthenticationPromotionTests.Prepare(prior:"prior-active-hash");
        harness.LoginProofs.PromoteAsync(Arg.Any<string>(),Arg.Any<TwoFactorSession>(),Arg.Any<string>(),Arg.Any<ActiveSession>(),Arg.Any<CancellationToken>()).Returns(Task.FromException<LoginProofTransition>(new InvalidOperationException("repository boundary")));
        var controller=harness.CreateTwoFactorController();harness.HttpContext.Request.Headers["AccessToken"]="pending-token";
        await Should.ThrowAsync<InvalidOperationException>(()=>controller.TwoFactorAuthenticate(new LayeredAuthenticateRequest("123456",TwoFactorAuthMethod.EMAIL)));
        _=harness.ActiveUserCacheService.DidNotReceiveWithAnyArgs().RevokeSession(default!,cancellationToken:Arg.Any<CancellationToken>());
    }


}
