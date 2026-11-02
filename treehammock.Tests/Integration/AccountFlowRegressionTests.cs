using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NodaTime;
using NSubstitute;
using Shouldly;
using StackExchange.Redis;

using treehammock.DataLayer;
using treehammock.DataLayer.Account;
using treehammock.DataLayer.Cache;
using treehammock.Entities;
using treehammock.Models.Api;
using treehammock.Models.PasswordReset;
using treehammock.Repos;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Replay;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Tests.Infrastructure;

namespace treehammock.Tests.Integration;

public partial class AccountFlowRegressionTests
{
    private const string Password = "CorrectHorseBatteryStaple1!";
    private const string AuthenticatedAccessToken = "regression-active-token";
    private const string WebKey = "regression-web-key";

    [Fact]
    public async Task Account_creation_endpoint_flows_through_validation_and_account_service()
    {
        var accountService = Substitute.For<IAccountService>();
        accountService
            .SetupUserAccount(
                "reader@example.com",
                "reader",
                Password,
                Country.USA,
                Arg.Any<Instant>(),
                AccountSetupAction.BOTH)
            .Returns(Task.FromResult(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING));

        using var factory = FlowFactory(services => Replace(services, accountService));
        using HttpClient client = CreateHttpsClient(factory);

        using HttpResponseMessage response = await client.PostAsync(
            "/account/setupaccount",
            JsonContent("""
            {
              "emailAddress": "reader@example.com",
              "username": "reader",
              "password": "CorrectHorseBatteryStaple1!",
              "country": "USA"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        using JsonDocument document = await ReadJson(response);
        AssertSuccessEnvelope(document, StatusCodes.Status202Accepted, HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING.ToString());
        document.RootElement.GetProperty("data").GetProperty("status").GetString().ShouldBe(HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING.ToString());

        await accountService.Received(1).SetupUserAccount(
            "reader@example.com",
            "reader",
            Password,
            Country.USA,
            Arg.Any<Instant>(),
            AccountSetupAction.BOTH, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Password_login_endpoint_can_be_replayed_and_each_success_writes_a_new_active_session()
    {
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        var activeUsers = new InMemoryActiveUserCacheService();
        var twoFactorSessions = new InMemoryTwoFactorSessionService();
        var loginProofs = new LoginProofTestDouble();
        var accountRepo = Substitute.For<IAccountRepo>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        var jwtUtility = Substitute.For<IJsonWebTokenUtility>();

        accountRepo
            .GetCredentials(Arg.Any<treehammock.Models.Authentication.AuthenticateLogin>(), AccountLoginAction.EMAIL)
            .Returns(_ => Task.FromResult(CredentialLookupResult.Found(BuildAccount(accountId, accountSecurityStamp))));
        accountRepo.SuccessfulLogin(accountId, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        sessionRepo.SetSession(Arg.Any<string?>()!, Arg.Any<Session>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL));
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(null));
        jwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), WebKey, Arg.Any<string>()).Returns("active-token-one", "active-token-two");

        using var factory = FlowFactory(services =>
        {
            Replace<IActiveUserCacheService>(services, activeUsers);
            Replace<ITwoFactorSessionService>(services, twoFactorSessions);
            Replace<ILoginProofRepo>(services, loginProofs.Repo);
            Replace(services, accountRepo);
            Replace(services, sessionRepo);
            Replace(services, jwtUtility);
        });
        using HttpClient client = CreateHttpsClient(factory);

        using HttpResponseMessage first = await client.PostAsync("/account/requestaccess", LoginJson());
        using HttpResponseMessage second = await client.PostAsync("/account/requestaccess", LoginJson());

        first.StatusCode.ShouldBe(HttpStatusCode.OK);
        second.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument firstJson = await ReadJson(first);
        using JsonDocument secondJson = await ReadJson(second);
        AssertSuccessEnvelope(firstJson, StatusCodes.Status200OK, HttpMessage.AUTHENTICATION_PASSED.ToString());
        AssertSuccessEnvelope(secondJson, StatusCodes.Status200OK, HttpMessage.AUTHENTICATION_PASSED.ToString());
        firstJson.RootElement.GetProperty("data").GetProperty("accessToken").GetString().ShouldBe("active-token-one");
        secondJson.RootElement.GetProperty("data").GetProperty("accessToken").GetString().ShouldBe("active-token-two");

        string firstHash = AccessTokenHashUtility.Hash("active-token-one");
        string secondHash = AccessTokenHashUtility.Hash("active-token-two");
        firstHash.ShouldNotBe(secondHash);
        activeUsers.StoredSessions.ShouldContainKey(firstHash);
        activeUsers.StoredSessions.ShouldContainKey(secondHash);
        activeUsers.StoredSessions[firstHash].accountId.ShouldBe(accountId);
        activeUsers.StoredSessions[secondHash].accountId.ShouldBe(accountId);
        await sessionRepo.Received(1).SetSession(firstHash, Arg.Is<Session>(session => session.accountId == accountId), cancellationToken: Arg.Any<CancellationToken>());
        await sessionRepo.Received(1).SetSession(secondHash, Arg.Is<Session>(session => session.accountId == accountId), cancellationToken: Arg.Any<CancellationToken>());
        await accountRepo.Received(2).SuccessfulLogin(accountId, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData(false,"access")]
    [InlineData(false,"hard")]
    [InlineData(false,"cutoff")]
    [InlineData(false,"live")]
    [InlineData(false,"cache-miss")]
    [InlineData(true,"access")]
    [InlineData(true,"hard")]
    [InlineData(true,"cutoff")]
    [InlineData(true,"live")]
    [InlineData(true,"cache-miss")]
    public async Task Password_login_final_output_withholds_expired_credentials_after_cache_await(bool replacement,string boundary)
    {
        Guid accountId=Guid.NewGuid(),stamp=Guid.NewGuid();int committed=0;
        var account=BuildAccount(accountId,stamp);
        if(replacement){account.refreshToken=RandomBytes(64);account.activeAccessTokenHash=AccessTokenHashUtility.Hash("prior-access");}
        var cache=new InMemoryActiveUserCacheService {BeforeStore=async session=>
        {
            await Task.Yield();var now=SystemClock.Instance.GetCurrentInstant();
            if(boundary=="access")session.accessExpiration=now;
            if(boundary=="hard")session.sessionExpiration=now;
            if(boundary=="cutoff")session.cutOff=now;
            return boundary!="cache-miss";
        }};
        var repo=Substitute.For<IAccountRepo>();var sessions=Substitute.For<ISessionRepo>();var jwt=Substitute.For<IJsonWebTokenUtility>();var proofs=new LoginProofTestDouble();
        repo.GetCredentials(Arg.Any<treehammock.Models.Authentication.AuthenticateLogin>(),AccountLoginAction.EMAIL).Returns(Task.FromResult(CredentialLookupResult.Found(account)));
        repo.SuccessfulLogin(accountId,stamp,Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        sessions.SetSession(Arg.Any<string>(),Arg.Any<Session>(),Arg.Any<CancellationToken>()).Returns(_=>{committed++;return Task.FromResult<IntraMessage?>(IntraMessage.SUCCESSFUL);});
        sessions.RotateActiveSession(Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<Session>(),Arg.Any<CancellationToken>()).Returns(_=>{committed++;return Task.FromResult<treehammock.RiggingSupport.Status.SessionRotationResult?>(new(treehammock.RiggingSupport.Status.SessionRotationStatus.Succeeded));});
        jwt.GenerateAccessToken(Arg.Any<byte[]>(),WebKey,Arg.Any<string>()).Returns("late-login-access");
        using var lateLoginFactory = FlowFactory(services=>{Replace<IActiveUserCacheService>(services,cache);Replace<ITwoFactorSessionService>(services,new InMemoryTwoFactorSessionService());Replace<ILoginProofRepo>(services,proofs.Repo);Replace(services,repo);Replace(services,sessions);Replace(services,jwt);});
        using var client=CreateHttpsClient(lateLoginFactory);using var response=await client.PostAsync("/account/requestaccess",LoginJson(),TestContext.Current.CancellationToken);
        committed.ShouldBe(1);using var json=await ReadJson(response);
        if(boundary is "live" or "cache-miss")
        {
            response.StatusCode.ShouldBe(HttpStatusCode.OK);json.RootElement.GetProperty("data").GetProperty("accessToken").GetString().ShouldBe("late-login-access");
        }
        else
        {
            response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);json.RootElement.GetProperty("code").GetString().ShouldBe(HttpMessage.AUTHENTICATION_EXPIRED.ToString());
            json.RootElement.GetRawText().ShouldNotContain("late-login-access");
            if(json.RootElement.TryGetProperty("data",out var data)&&data.ValueKind==JsonValueKind.Object&&data.TryGetProperty("session",out var credential))credential.ValueKind.ShouldBe(JsonValueKind.Null);
            response.Headers.Contains(SessionProtocol.FamilyHeader).ShouldBeFalse();response.Headers.Contains("AccessToken").ShouldBeFalse();
        }
    }

    [Fact]
    public async Task Email_two_factor_login_endpoint_flow_issues_challenge_promotes_session_and_revokes_pending_session()
    {
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string? deliveredCode = null;
        var activeUsers = new InMemoryActiveUserCacheService();
        var twoFactorSessions = new InMemoryTwoFactorSessionService();
        var loginProofs = new LoginProofTestDouble();
        var accountRepo = Substitute.For<IAccountRepo>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        var jwtUtility = Substitute.For<IJsonWebTokenUtility>();
        var twoFactorService = Substitute.For<ITwoFactorAuthenticateService>();

        accountRepo
            .GetCredentials(Arg.Any<treehammock.Models.Authentication.AuthenticateLogin>(), AccountLoginAction.EMAIL)
            .Returns(_ => Task.FromResult(CredentialLookupResult.Found(BuildAccount(
                accountId,
                accountSecurityStamp,
                hasTwoFactorAuth: true,
                twoFactorAuthMethod: TwoFactorAuthMethod.EMAIL))));
        accountRepo.GetTwoFactorDetails(accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult(TwoFactorDetailsLookupResult.Found(
            new TwoFactorDetails(
                new List<TwoFactorAuthMethod> { TwoFactorAuthMethod.EMAIL },
                userAuthIds: null,
                phoneNumbers: null,
                phoneCountryCode: null,
                emailAddresses: new List<string> { "reader@example.com" }))));




        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(null));
        jwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), WebKey, Arg.Any<string>()).Returns("preauth-token", "final-active-token");
        jwtUtility.ValidateAccessToken(
                Arg.Is<string>(value => value == "preauth-token"),
                Arg.Any<byte[]>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                Arg.Is<string>(value => value == JsonWebTokenPurpose.PreAuthTwoFactor),
                Arg.Any<Duration?>())
            .Returns(Task.FromResult<(IntraMessage, string?)>((IntraMessage.TOKEN_PASSED_VALIDATION, WebKey)));
        twoFactorService.Email("reader@example.com", Arg.Do<string>(code => deliveredCode = code), token: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));

        using var factory = FlowFactory(services =>
        {
            Replace<IActiveUserCacheService>(services, activeUsers);
            Replace<ITwoFactorSessionService>(services, twoFactorSessions);
            Replace<ILoginProofRepo>(services, loginProofs.Repo);
            Replace(services, accountRepo);
            Replace(services, sessionRepo);
            Replace(services, jwtUtility);
            Replace(services, twoFactorService);
        });
        using HttpClient client = CreateHttpsClient(factory);

        using HttpResponseMessage login = await client.PostAsync("/account/requestaccess", LoginJson());
        login.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument loginJson = await ReadJson(login);
        AssertSuccessEnvelope(loginJson, StatusCodes.Status200OK, HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED.ToString());
        loginJson.RootElement.GetProperty("data").TryGetProperty("accessToken", out _).ShouldBeFalse();
        loginJson.RootElement.GetProperty("data").GetProperty("twoFactorAccessToken").GetString().ShouldBe("preauth-token");
        loginJson.RootElement.GetProperty("data").GetProperty("availableTwoFactorAuthConfigurations").EnumerateArray().Select(value => value.GetString()).ShouldContain("EMAIL");

        client.DefaultRequestHeaders.Remove("AccessToken");

        using HttpResponseMessage challenge = await client.PostAsync(
            "/account/twofactor/select",
            JsonContent("""
            {
              "configuration": "EMAIL",
              "destination": 0,
              "twoFactorAccessToken": "preauth-token"
            }
            """));

        challenge.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument challengeJson = await ReadJson(challenge);
        AssertSuccessEnvelope(challengeJson, StatusCodes.Status200OK, HttpMessage.TWOFACTOR_WAITING_INTRA_EMAIL.ToString());
        deliveredCode.ShouldNotBeNullOrWhiteSpace();

        client.DefaultRequestHeaders.Add("AccessToken", "preauth-token");

        using HttpResponseMessage final = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent($$"""
            {
              "method": "EMAIL",
              "codeKey": "{{deliveredCode}}"
            }
            """));

        final.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument finalJson = await ReadJson(final);
        AssertSuccessEnvelope(finalJson, StatusCodes.Status200OK, TwoFactorAuthOutcome.SUCCESS.ToString());
        finalJson.RootElement.GetProperty("data").GetProperty("accessToken").GetString().ShouldBe("final-active-token");

        string pendingHash = AccessTokenHashUtility.Hash("preauth-token");
        string finalHash = AccessTokenHashUtility.Hash("final-active-token");
        twoFactorSessions.StoredSessions.ShouldNotContainKey(pendingHash);
        activeUsers.StoredSessions.ShouldContainKey(finalHash);
        await loginProofs.Repo.Received(1).PromoteAsync(pendingHash, Arg.Any<TwoFactorSession>(), finalHash, Arg.Any<ActiveSession>(), Arg.Any<CancellationToken>());
    }


    [Fact]
    public async Task Login_twofactor_legacy_method_endpoint_is_not_public()
    {
        using var factory = FlowFactory(_ => { });
        using HttpClient client = CreateHttpsClient(factory);

        using HttpResponseMessage response = await client.PostAsync(
            "/account/twofactormethod",
            JsonContent("""
            {
              "method": "EMAIL",
              "destination": 0
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task Password_reset_request_rejects_legacy_method_payload_for_greenfield_contract()
    {
        var service = Substitute.For<IPasswordResetService>();
        service
            .RequestReset(Arg.Any<RequestPasswordResetCommand>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new PasswordResetRequestResult(PasswordResetService.RequestAcceptedCode, Guid.NewGuid())));

        using var factory = FlowFactory(services => Replace<IPasswordResetService>(services, service));
        using HttpClient client = CreateHttpsClient(factory);

        using HttpResponseMessage response = await client.PostAsync(
            "/account/password-reset/request",
            JsonContent("""
            {
              "identifier": "reader@example.com",
              "method": "email_code_totp"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        document.RootElement.GetProperty("errors")[0].GetProperty("field").GetString().ShouldBe("deliveryChannel");
        await service.DidNotReceive().RequestReset(Arg.Any<RequestPasswordResetCommand>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Password_reset_request_rejects_authenticator_as_public_delivery_channel()
    {
        var service = Substitute.For<IPasswordResetService>();
        service
            .RequestReset(Arg.Any<RequestPasswordResetCommand>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new PasswordResetRequestResult(PasswordResetService.RequestAcceptedCode, Guid.NewGuid())));

        using var factory = FlowFactory(services => Replace<IPasswordResetService>(services, service));
        using HttpClient client = CreateHttpsClient(factory);

        using HttpResponseMessage response = await client.PostAsync(
            "/account/password-reset/request",
            JsonContent("""
            {
              "identifier": "reader@example.com",
              "deliveryChannel": "authenticator"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument document = await ReadJson(response);
        AssertFailureEnvelope(document, StatusCodes.Status400BadRequest, ApiResponses.ValidationFailedCode);
        document.RootElement.GetProperty("errors")[0].GetProperty("field").GetString().ShouldBe("deliveryChannel");
        await service.DidNotReceive().RequestReset(Arg.Any<RequestPasswordResetCommand>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Password_reset_request_accepts_delivery_channel_shape_only_for_greenfield_contract()
    {
        var service = Substitute.For<IPasswordResetService>();
        var resetId = Guid.Parse("018f7f7e-8da0-7d7c-a512-f5c7f72c2123");
        service
            .RequestReset(Arg.Any<RequestPasswordResetCommand>(), Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(new PasswordResetRequestResult(PasswordResetService.RequestAcceptedCode, resetId)));

        using var factory = FlowFactory(services => Replace<IPasswordResetService>(services, service));
        using HttpClient client = CreateHttpsClient(factory);

        using HttpResponseMessage response = await client.PostAsync(
            "/account/password-reset/request",
            JsonContent("""
            {
              "identifier": "reader@example.com",
              "deliveryChannel": "email"
            }
            """));

        response.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        using JsonDocument document = await ReadJson(response);
        AssertSuccessEnvelope(document, StatusCodes.Status202Accepted, PasswordResetService.RequestAcceptedCode);
        document.RootElement.GetProperty("data").GetProperty("resetId").GetGuid().ShouldBe(resetId);
        await service.Received(1).RequestReset(
            Arg.Is<RequestPasswordResetCommand>(command =>
                command.Identifier == "reader@example.com" &&
                command.DeliveryChannel == PasswordResetDeliveryChannels.Email),
            Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Login_twofactor_rejects_proof_before_configuration_selection()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.EMAIL]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        LoginSelection login = await LoginAndAssertSelectionRequired(client, expectedConfiguration: "EMAIL");
        login.Token.ShouldBe(harness.PreAuthToken);

        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage proof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent("""
            {
              "method": "EMAIL",
              "codeKey": "123456"
            }
            """));

        proof.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument proofJson = await ReadJson(proof);
        AssertFailureEnvelope(proofJson, StatusCodes.Status400BadRequest, "TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED");
        harness.ActiveUsers.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.FinalAccessToken));
    }

    [Fact]
    public async Task Login_authenticator_app_selection_sends_no_delivery_and_promotes_after_totp()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "AUTHENTICATOR_APP");

        using HttpResponseMessage selected = await client.PostAsync(
            "/account/twofactor/select",
            JsonContent($$"""
            {
              "configuration": "AUTHENTICATOR_APP",
              "twoFactorAccessToken": "{{harness.PreAuthToken}}"
            }
            """));

        selected.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument selectedJson = await ReadJson(selected);
        AssertSuccessEnvelope(selectedJson, StatusCodes.Status200OK, HttpMessage.TWOFACTOR_WAITING_AUTHENTICATOR_APP.ToString());
        selectedJson.RootElement.GetProperty("data").GetProperty("currentRequiredMethod").GetString().ShouldBe("AUTHENTICATOR_APP");
        harness.DeliveredEmailCode.ShouldBeNull();
        harness.DeliveredSmsCode.ShouldBeNull();

        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage final = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent("""
            {
              "method": "AUTHENTICATOR_APP",
              "codeKey": "123456"
            }
            """));

        final.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument finalJson = await ReadJson(final);
        AssertSuccessEnvelope(finalJson, StatusCodes.Status200OK, TwoFactorAuthOutcome.SUCCESS.ToString());
        finalJson.RootElement.GetProperty("data").GetProperty("accessToken").GetString().ShouldBe(harness.FinalAccessToken);
        harness.ActiveUsers.StoredSessions.ShouldContainKey(AccessTokenHashUtility.Hash(harness.FinalAccessToken));
    }

    [Fact]
    public async Task Login_twofactor_login_response_does_not_send_delivery_until_select()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.EMAIL]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "SMS");

        harness.DeliveredSmsCodes.ShouldBeEmpty();
        harness.DeliveredEmailCodes.ShouldBeEmpty();

        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "SMS");

        harness.DeliveredSmsCodes.Count.ShouldBe(1);
        harness.DeliveredEmailCodes.ShouldBeEmpty();
    }

    [Fact]
    public async Task Login_twofactor_select_sms_sends_exactly_one_sms_challenge()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.SMS_KEY]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "SMS");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "SMS");

        harness.DeliveredSmsCodes.Count.ShouldBe(1);
        harness.DeliveredSmsCode.ShouldNotBeNullOrWhiteSpace();
        harness.DeliveredEmailCodes.ShouldBeEmpty();
    }

    [Fact]
    public async Task Login_twofactor_select_email_sends_exactly_one_email_challenge()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.EMAIL]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "EMAIL");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "EMAIL");

        harness.DeliveredEmailCodes.Count.ShouldBe(1);
        harness.DeliveredEmailCode.ShouldNotBeNullOrWhiteSpace();
        harness.DeliveredSmsCodes.ShouldBeEmpty();
    }

    [Fact]
    public async Task Login_twofactor_select_sms_and_authenticator_sends_first_sms_challenge_only()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "SMS_AND_AUTHENTICATOR_APP");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "SMS_AND_AUTHENTICATOR_APP");

        harness.DeliveredSmsCodes.Count.ShouldBe(1);
        harness.DeliveredEmailCodes.ShouldBeEmpty();

        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage smsProof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent($$"""
            {
              "method": "SMS_KEY",
              "codeKey": "{{harness.DeliveredSmsCode}}"
            }
            """));

        smsProof.StatusCode.ShouldBe(HttpStatusCode.OK);
        harness.DeliveredSmsCodes.Count.ShouldBe(1);
        harness.DeliveredEmailCodes.ShouldBeEmpty();

        using HttpResponseMessage authenticatorProof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent("""
            {
              "method": "AUTHENTICATOR_APP",
              "codeKey": "123456"
            }
            """));

        authenticatorProof.StatusCode.ShouldBe(HttpStatusCode.OK);
        harness.DeliveredSmsCodes.Count.ShouldBe(1);
        harness.DeliveredEmailCodes.ShouldBeEmpty();
    }

    [Fact]
    public async Task Login_twofactor_select_email_and_authenticator_sends_first_email_challenge_only()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "EMAIL_AND_AUTHENTICATOR_APP");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "EMAIL_AND_AUTHENTICATOR_APP");

        harness.DeliveredEmailCodes.Count.ShouldBe(1);
        harness.DeliveredSmsCodes.ShouldBeEmpty();

        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage emailProof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent($$"""
            {
              "method": "EMAIL",
              "codeKey": "{{harness.DeliveredEmailCode}}"
            }
            """));

        emailProof.StatusCode.ShouldBe(HttpStatusCode.OK);
        harness.DeliveredEmailCodes.Count.ShouldBe(1);
        harness.DeliveredSmsCodes.ShouldBeEmpty();

        using HttpResponseMessage authenticatorProof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent("""
            {
              "method": "AUTHENTICATOR_APP",
              "codeKey": "123456"
            }
            """));

        authenticatorProof.StatusCode.ShouldBe(HttpStatusCode.OK);
        harness.DeliveredEmailCodes.Count.ShouldBe(1);
        harness.DeliveredSmsCodes.ShouldBeEmpty();
    }

    [Fact]
    public async Task Login_twofactor_session_expires_before_proof_verification()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.SMS_KEY]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "SMS");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "SMS");
        harness.DeliveredSmsCode.ShouldNotBeNullOrWhiteSpace();

        string hashedPreAuthToken = AccessTokenHashUtility.Hash(harness.PreAuthToken);
        TwoFactorSession session = harness.ProofState.Stored[hashedPreAuthToken];
        session.expiration = SystemClock.Instance.GetCurrentInstant().Minus(Duration.FromSeconds(1));

        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage proof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent($$"""
            {
              "method": "SMS_KEY",
              "codeKey": "{{harness.DeliveredSmsCode}}"
            }
            """));

        proof.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using JsonDocument proofJson = await ReadJson(proof);
        AssertFailureEnvelope(proofJson, StatusCodes.Status401Unauthorized, HttpMessage.AUTHENTICATION_TWO_FACTOR_FAILED.ToString());
        harness.ActiveUsers.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.FinalAccessToken));
        harness.ActiveUsers.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.FinalAccessToken));
    }

    [Fact]
    public async Task Sms_challenge_code_expires_independently_from_login_twofactor_session()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.SMS_KEY]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "SMS");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "SMS");
        harness.DeliveredSmsCode.ShouldNotBeNullOrWhiteSpace();

        string hashedPreAuthToken = AccessTokenHashUtility.Hash(harness.PreAuthToken);
        TwoFactorSession session = harness.ProofState.Stored[hashedPreAuthToken];
        Instant now = SystemClock.Instance.GetCurrentInstant();
        session.expiration = now.Plus(Duration.FromMinutes(10));
        session.challengeExpiration = now.Minus(Duration.FromSeconds(1));

        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage proof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent($$"""
            {
              "method": "SMS_KEY",
              "codeKey": "{{harness.DeliveredSmsCode}}"
            }
            """));

        proof.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using JsonDocument proofJson = await ReadJson(proof);
        AssertFailureEnvelope(proofJson, StatusCodes.Status401Unauthorized, "PENDING_TWO_FACTOR_EXPIRED");
        harness.ProofState.Stored[hashedPreAuthToken].completedMethods.ShouldBeEmpty();
        harness.ActiveUsers.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.FinalAccessToken));
    }

    [Fact]
    public async Task Login_sms_and_authenticator_rejects_out_of_order_authenticator_proof()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "SMS_AND_AUTHENTICATOR_APP");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "SMS_AND_AUTHENTICATOR_APP");
        harness.DeliveredSmsCode.ShouldNotBeNullOrWhiteSpace();

        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage proof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent("""
            {
              "method": "AUTHENTICATOR_APP",
              "codeKey": "123456"
            }
            """));

        proof.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
        using JsonDocument proofJson = await ReadJson(proof);
        AssertFailureEnvelope(proofJson, StatusCodes.Status400BadRequest, "TWO_FACTOR_METHOD_NOT_CURRENTLY_REQUIRED");
        harness.ActiveUsers.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.FinalAccessToken));
    }

    [Fact]
    public async Task Login_sms_and_authenticator_promotes_only_after_both_proofs()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "SMS_AND_AUTHENTICATOR_APP");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "SMS_AND_AUTHENTICATOR_APP");
        harness.DeliveredSmsCode.ShouldNotBeNullOrWhiteSpace();

        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage smsProof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent($$"""
            {
              "method": "SMS_KEY",
              "codeKey": "{{harness.DeliveredSmsCode}}"
            }
            """));

        smsProof.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument smsProofJson = await ReadJson(smsProof);
        AssertSuccessEnvelope(smsProofJson, StatusCodes.Status200OK, HttpMessage.AUTHENTICATION_TWO_FACTOR_PROOF_ACCEPTED_NEXT_PROOF_REQUIRED.ToString());
        JsonElement smsProofData = smsProofJson.RootElement.GetProperty("data");
        smsProofData.GetProperty("currentRequiredMethod").GetString().ShouldBe("AUTHENTICATOR_APP");
        smsProofData.TryGetProperty("accessToken", out JsonElement intermediateToken).ShouldBeFalse();
        intermediateToken.ValueKind.ShouldBe(JsonValueKind.Undefined);
        harness.ActiveUsers.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.FinalAccessToken));

        using HttpResponseMessage final = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent("""
            {
              "method": "AUTHENTICATOR_APP",
              "codeKey": "123456"
            }
            """));

        final.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument finalJson = await ReadJson(final);
        AssertSuccessEnvelope(finalJson, StatusCodes.Status200OK, TwoFactorAuthOutcome.SUCCESS.ToString());
        finalJson.RootElement.GetProperty("data").GetProperty("accessToken").GetString().ShouldBe(harness.FinalAccessToken);
        harness.ActiveUsers.StoredSessions.ShouldContainKey(AccessTokenHashUtility.Hash(harness.FinalAccessToken));
    }

    [Fact]
    public async Task Removing_authenticator_revokes_pending_login_session_and_future_login_keeps_sms_email_only()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([
            TwoFactorAuthMethod.SMS_KEY,
            TwoFactorAuthMethod.EMAIL,
            TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "SMS_AND_AUTHENTICATOR_APP");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "SMS_AND_AUTHENTICATOR_APP");
        harness.TwoFactorSessions.StoredSessions.ShouldContainKey(AccessTokenHashUtility.Hash(harness.PreAuthToken));

        harness.ConfigureSuccessfulMethodRemoval(
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            [TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.EMAIL],
            [TwoFactorAuthConfiguration.SMS, TwoFactorAuthConfiguration.EMAIL]);

        using HttpResponseMessage removed = await PostAuthenticatedRemoveTwoFactorMethod(
            client,
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            "remove-authenticator-cross-flow-0001");

        removed.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument removedJson = await ReadJson(removed);
        AssertSuccessEnvelope(removedJson, StatusCodes.Status200OK, "TWO_FACTOR_METHOD_REMOVED");
        JsonElement removalData = removedJson.RootElement.GetProperty("data");
        removalData.GetProperty("removedMethod").GetString().ShouldBe("AUTHENTICATOR_APP");
        removalData.GetProperty("availableTwoFactorAuthConfigurations").EnumerateArray().Select(value => value.GetString()).ShouldBe(["SMS", "EMAIL"]);
        removalData.GetProperty("availableTwoFactorAuthConfigurations").EnumerateArray().Select(value => value.GetString()).ShouldNotContain("AUTHENTICATOR_APP");
        removalData.GetProperty("availableTwoFactorAuthConfigurations").EnumerateArray().Select(value => value.GetString()).ShouldNotContain("SMS_AND_AUTHENTICATOR_APP");
        removalData.GetProperty("availableTwoFactorAuthConfigurations").EnumerateArray().Select(value => value.GetString()).ShouldNotContain("EMAIL_AND_AUTHENTICATOR_APP");

        client.DefaultRequestHeaders.Remove("AccessToken");
        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage staleProof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent($$"""
            {
              "method": "SMS_KEY",
              "codeKey": "{{harness.DeliveredSmsCode}}"
            }
            """));

        staleProof.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using JsonDocument staleProofJson = await ReadJson(staleProof);
        AssertFailureEnvelope(staleProofJson, StatusCodes.Status401Unauthorized, "TWO_FACTOR_PENDING_SESSION_MISMATCH");
        harness.TwoFactorSessions.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.PreAuthToken));
        harness.ActiveUsers.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.FinalAccessToken));

        using HttpClient futureClient = CreateHttpsClient(harness.Factory);
        LoginSelection futureLogin = await LoginAndAssertSelectionRequired(futureClient, expectedConfiguration: "SMS");
        string[] futureConfigurations = futureLogin.Configurations;

        futureConfigurations.ShouldBe(["SMS", "EMAIL"]);
        futureConfigurations.ShouldNotContain("AUTHENTICATOR_APP");
        futureConfigurations.ShouldNotContain("SMS_AND_AUTHENTICATOR_APP");
        futureConfigurations.ShouldNotContain("EMAIL_AND_AUTHENTICATOR_APP");
    }

    [Fact]
    public async Task Removing_sms_revokes_pending_login_session_and_future_login_keeps_authenticator_available()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "SMS_AND_AUTHENTICATOR_APP");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "SMS_AND_AUTHENTICATOR_APP");

        harness.ConfigureSuccessfulMethodRemoval(
            TwoFactorAuthMethod.SMS_KEY,
            [TwoFactorAuthMethod.AUTHENTICATOR_APP],
            [TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);

        using HttpResponseMessage removed = await PostAuthenticatedRemoveTwoFactorMethod(
            client,
            TwoFactorAuthMethod.SMS_KEY,
            "remove-sms-cross-flow-0001");

        removed.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument removedJson = await ReadJson(removed);
        AssertSuccessEnvelope(removedJson, StatusCodes.Status200OK, "TWO_FACTOR_METHOD_REMOVED");
        removedJson.RootElement.GetProperty("data").GetProperty("availableTwoFactorAuthConfigurations")
            .EnumerateArray()
            .Select(value => value.GetString())
            .ShouldBe(["AUTHENTICATOR_APP"]);

        client.DefaultRequestHeaders.Remove("AccessToken");
        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage staleProof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent($$"""
            {
              "method": "SMS_KEY",
              "codeKey": "{{harness.DeliveredSmsCode}}"
            }
            """));

        staleProof.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using JsonDocument staleProofJson = await ReadJson(staleProof);
        AssertFailureEnvelope(staleProofJson, StatusCodes.Status401Unauthorized, "TWO_FACTOR_PENDING_SESSION_MISMATCH");
        harness.TwoFactorSessions.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.PreAuthToken));

        using HttpClient futureClient = CreateHttpsClient(harness.Factory);
        LoginSelection futureLogin = await LoginAndAssertSelectionRequired(futureClient, expectedConfiguration: "AUTHENTICATOR_APP");
        futureLogin.Configurations
            .ShouldBe(["AUTHENTICATOR_APP"]);
    }

    [Fact]
    public async Task Removing_email_revokes_pending_login_session_and_future_login_keeps_authenticator_available()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.EMAIL, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "EMAIL_AND_AUTHENTICATOR_APP");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "EMAIL_AND_AUTHENTICATOR_APP");
        harness.DeliveredEmailCode.ShouldNotBeNullOrWhiteSpace();

        harness.ConfigureSuccessfulMethodRemoval(
            TwoFactorAuthMethod.EMAIL,
            [TwoFactorAuthMethod.AUTHENTICATOR_APP],
            [TwoFactorAuthConfiguration.AUTHENTICATOR_APP]);

        using HttpResponseMessage removed = await PostAuthenticatedRemoveTwoFactorMethod(
            client,
            TwoFactorAuthMethod.EMAIL,
            "remove-email-cross-flow-0001");

        removed.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument removedJson = await ReadJson(removed);
        AssertSuccessEnvelope(removedJson, StatusCodes.Status200OK, "TWO_FACTOR_METHOD_REMOVED");
        removedJson.RootElement.GetProperty("data").GetProperty("availableTwoFactorAuthConfigurations")
            .EnumerateArray()
            .Select(value => value.GetString())
            .ShouldBe(["AUTHENTICATOR_APP"]);

        client.DefaultRequestHeaders.Remove("AccessToken");
        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage staleProof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent($$"""
            {
              "method": "EMAIL",
              "codeKey": "{{harness.DeliveredEmailCode}}"
            }
            """));

        staleProof.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using JsonDocument staleProofJson = await ReadJson(staleProof);
        AssertFailureEnvelope(staleProofJson, StatusCodes.Status401Unauthorized, "TWO_FACTOR_PENDING_SESSION_MISMATCH");
        harness.TwoFactorSessions.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.PreAuthToken));

        using HttpClient futureClient = CreateHttpsClient(harness.Factory);
        LoginSelection futureLogin = await LoginAndAssertSelectionRequired(futureClient, expectedConfiguration: "AUTHENTICATOR_APP");
        futureLogin.Configurations
            .ShouldBe(["AUTHENTICATOR_APP"]);
    }

    [Fact]
    public async Task Concurrent_method_removal_is_deterministic_and_stale_login_session_stays_unpromoted()
    {
        await using LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness([TwoFactorAuthMethod.SMS_KEY, TwoFactorAuthMethod.AUTHENTICATOR_APP]);
        using HttpClient client = CreateHttpsClient(harness.Factory);

        await LoginAndAssertSelectionRequired(client, expectedConfiguration: "SMS_AND_AUTHENTICATOR_APP");
        await SelectLoginTwoFactorConfiguration(client, harness.PreAuthToken, "SMS_AND_AUTHENTICATOR_APP");
        harness.TwoFactorSessions.StoredSessions.ShouldContainKey(AccessTokenHashUtility.Hash(harness.PreAuthToken));

        harness.ConfigureIdempotentMethodRemovalRace(
            TwoFactorAuthMethod.AUTHENTICATOR_APP,
            [TwoFactorAuthMethod.SMS_KEY],
            [TwoFactorAuthConfiguration.SMS]);

        using HttpClient firstClient = CreateHttpsClient(harness.Factory);
        using HttpClient secondClient = CreateHttpsClient(harness.Factory);
        Task<HttpResponseMessage>[] requests = [
            PostAuthenticatedRemoveTwoFactorMethod(firstClient, TwoFactorAuthMethod.AUTHENTICATOR_APP, "remove-authenticator-race-0001"),
            PostAuthenticatedRemoveTwoFactorMethod(secondClient, TwoFactorAuthMethod.AUTHENTICATOR_APP, "remove-authenticator-race-0002")];

        try
        {
            HttpResponseMessage[] responses = await Task.WhenAll(requests);
            responses.Select(response => response.StatusCode).OrderBy(status => (int)status).ToArray().ShouldBe([HttpStatusCode.OK, HttpStatusCode.NotFound]);

            using JsonDocument firstJson = await ReadJson(responses[0]);
            using JsonDocument secondJson = await ReadJson(responses[1]);
            new[]
            {
                firstJson.RootElement.GetProperty("code").GetString(),
                secondJson.RootElement.GetProperty("code").GetString()
            }.OrderBy(code => code).ToArray().ShouldBe(["TWO_FACTOR_METHOD_NOT_CONFIGURED", "TWO_FACTOR_METHOD_REMOVED"]);
        }
        finally
        {
            foreach (Task<HttpResponseMessage> request in requests)
            {
                if (request.IsCompletedSuccessfully) request.Result.Dispose();
            }
        }

        client.DefaultRequestHeaders.Add("AccessToken", harness.PreAuthToken);
        using HttpResponseMessage staleProof = await client.PostAsync(
            "/account/twofactorauth",
            JsonContent($$"""
            {
              "method": "SMS_KEY",
              "codeKey": "{{harness.DeliveredSmsCode}}"
            }
            """));

        staleProof.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
        using JsonDocument staleProofJson = await ReadJson(staleProof);
        AssertFailureEnvelope(staleProofJson, StatusCodes.Status401Unauthorized, "TWO_FACTOR_PENDING_SESSION_MISMATCH");
        harness.TwoFactorSessions.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.PreAuthToken));
        harness.ActiveUsers.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(harness.FinalAccessToken));
    }

    [Fact]
    public async Task Authenticated_activation_endpoint_flow_uses_trusted_target_and_durable_delivery()
    {
        Guid accountId=Guid.NewGuid(),stamp=Guid.NewGuid(),grant=Guid.NewGuid(),request=Guid.NewGuid();string? code=null;
        var activeUsers=AuthenticatedActiveCache(accountId,stamp);var repo=Substitute.For<IActivationRepo>();
        var delivery=Substitute.For<treehammock.Rigging.Delivery.IDurableDeliveryService>();
        delivery.AdmitWithReasonAsync(Arg.Any<AbuseFeature>(),Arg.Any<string>(),accountId,Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(AbuseDecision.Allow());
        repo.AdmitCreationAsync(Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<Guid>(),Arg.Any<long>(),Arg.Any<string>(),Arg.Any<string>(),Arg.Any<short>(),Arg.Any<short>(),Arg.Any<short>(),Arg.Any<string>(),Arg.Any<treehammock.Rigging.Config.ActivationAbusePolicySettings>(),Arg.Any<CancellationToken>()).Returns(new ActivationCreationAdmission(true,"ACTIVATION_CREATION_ADMITTED",Guid.NewGuid()));
        delivery.EnqueueAsync(Arg.Do<treehammock.Rigging.Delivery.DeliveryIntent>(x=>code=x.Payload.Value),Arg.Any<CancellationToken>()).Returns(new treehammock.Rigging.Delivery.DeliveryStageResult(true,"DELIVERY_PENDING",request));
        repo.TransitionAsync(accountId,stamp,Arg.Any<string>(),activeUsers.AuthenticatedSession.familyId,grant,1,request,Arg.Any<string?>(),"verify",Arg.Any<CancellationToken>()).Returns(new treehammock.Models.Activation.ActivationLifecycleResult(true,ActivationService.VerifiedCode));
        using var factory=FlowFactory(services=>{Replace<IActiveUserCacheService>(services,activeUsers);Replace(services,AuthenticatedSessionRepo(activeUsers.AuthenticatedSession,CachedSessionTrustStatus.Valid));Replace(services,AuthenticatedJwtUtility());Replace(services,repo);Replace(services,delivery);});
        using var client=CreateAuthenticatedHttpsClient(factory);
        using var placed=await PostJsonWithIdempotency(client,"/activations/place",$$"""{"version":2,"grantId":"{{grant}}","grantVersion":1,"emailAddress":"invitee@example.com","featureSet":1,"term":"WEEKLY","recycle":"NONE"}""","activation-place-flow-0001");
        placed.StatusCode.ShouldBe(HttpStatusCode.Accepted);code.ShouldNotBeNullOrWhiteSpace();
        using var verified=await PostJsonWithIdempotency(client,"/activations/verify",$$"""{"version":2,"grantId":"{{grant}}","grantVersion":1,"requestId":"{{request}}","emailAddress":"invitee@example.com","code":"{{code}}"}""","activation-verify-flow-0001");
        verified.StatusCode.ShouldBe(HttpStatusCode.OK);using var json=await ReadJson(verified);AssertSuccessEnvelope(json,200,ActivationService.VerifiedCode);
        json.RootElement.GetProperty("data").GetProperty("lifecycle").GetString().ShouldBe("active");
        json.RootElement.GetProperty("data").GetProperty("rightsEnabled").GetBoolean().ShouldBeFalse();
    }

    [Fact]
    public async Task Account_unlock_endpoint_flow_starts_email_unlock_then_verifies_captured_token()
    {
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        Instant now = SystemClock.Instance.GetCurrentInstant();
        Instant unlockWhen = now.Plus(Duration.FromMinutes(30));
        string? unlockToken = null;
        var repo = Substitute.For<IAccountRecoveryRepo>();
        var smtp = Substitute.For<ISMTPService>();
        var sms = Substitute.For<ISmsSender>();

        repo.LookupLockedAccount("reader@example.com", Arg.Any<Instant>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountRecoveryLookupResult?>(new AccountRecoveryLookupResult(
                true,
                "ACCOUNT_UNLOCK_ACCOUNT_FOUND",
                accountId,
                "reader@example.com",
                null,
                null,
                accountSecurityStamp,
                unlockWhen, Guid.Empty)));
        repo.BeginUnlock(
                accountId,
                Arg.Do<string>(token => unlockToken = token),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                AccountRecovery_Status.STANDBY,
                AccountUnlockDeliveryMethod.EMAIL,
                accountSecurityStamp,
                unlockWhen, Arg.Any<Guid>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountRecovery_Status?>(AccountRecovery_Status.STANDBY));
        smtp.AccountUnlockLetter("reader@example.com", Arg.Any<string?>()!, Arg.Any<string>(), token: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<bool?>(true));
        repo.VerifyUnlock(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>())
            .Returns(callInfo => Task.FromResult<AccountRecovery_Status?>(
                string.Equals(callInfo.Arg<string>(), unlockToken, StringComparison.Ordinal)
                    ? AccountRecovery_Status.COMPLETE
                    : AccountRecovery_Status.BAD_TOKEN));

        var delivery=Substitute.For<treehammock.Rigging.Delivery.IDurableDeliveryService>();
        delivery.AdmitAsync(Arg.Any<AbuseFeature>(),Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(true);
        delivery.EnqueueAsync(Arg.Do<treehammock.Rigging.Delivery.DeliveryIntent>(d=>unlockToken=d.Payload.Value),Arg.Any<CancellationToken>()).Returns(new treehammock.Rigging.Delivery.DeliveryStageResult(true,"DELIVERY_PENDING"));
        using var factory = FlowFactory(services =>
        {
            Replace(services,delivery);
            Replace(services, repo);
            Replace(services, smtp);
            Replace(services, sms);
        });
        using HttpClient client = CreateHttpsClient(factory);

        using HttpResponseMessage start = await client.PostAsync(
            "/account/unlock/start",
            JsonContent("""
            {
              "identifier": "reader@example.com"
            }
            """));

        start.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        using JsonDocument startJson = await ReadJson(start);
        AssertSuccessEnvelope(startJson, StatusCodes.Status202Accepted, AccountRecoveryService.PendingCode);
        unlockToken.ShouldNotBeNullOrWhiteSpace();

        using HttpResponseMessage verify = await client.PostAsync(
            "/account/unlock/verify",
            JsonContent($$"""
            {
              "token": "{{unlockToken}}"
            }
            """));

        verify.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument verifyJson = await ReadJson(verify);
        AssertSuccessEnvelope(verifyJson, StatusCodes.Status200OK, AccountRecoveryService.VerifiedCode);
        verifyJson.RootElement.GetProperty("data").GetProperty("result").GetString().ShouldBe(HttpMessage.ACCOUNT_UNLOCK_VERIFIED.ToString());
    }

    [Fact]
    public async Task Account_delete_endpoint_flow_requests_verifies_and_finalizes_delete_with_session_revoke()
    {
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        const string deleteToken = "delete-token-123";
        var activeUsers = AuthenticatedActiveCache(accountId, accountSecurityStamp);
        var sessionRepo = AuthenticatedSessionRepo(activeUsers.AuthenticatedSession, CachedSessionTrustStatus.Valid);
        var jwtUtility = AuthenticatedJwtUtility();
        var accountService = Substitute.For<IAccountService>();

        accountService.RequestAccountDelete(accountId, accountSecurityStamp, null, cancellationToken: Arg.Any<CancellationToken>(),grant:Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_PENDING", DeletionWorkflow.ONETIME, "reader@example.com", accountId)));
        accountService.VerifyAccountDeleteToken(deleteToken, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_VERIFIED", DeletionWorkflow.ONETIME, AccountId: accountId)));
        accountService.FinalizeAccountDelete(accountId, accountSecurityStamp, deleteToken, null, cancellationToken: Arg.Any<CancellationToken>(),sessionHash:Arg.Any<string>())
            .Returns(Task.FromResult<AccountDeleteCommandResult?>(new AccountDeleteCommandResult(true, "ACCOUNT_DELETE_SUCCEEDED", DeletionWorkflow.ONETIME, AccountId: accountId)));

        var sensitive=Substitute.For<IAccountSensitiveActionService>();
        sensitive.ValidateAsync(Arg.Any<SensitiveActionValidationCommand>(),Arg.Any<CancellationToken>()).Returns(call=>new SensitiveActionValidationResult(true,HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATED,"SENSITIVE_ACTION_TOKEN_VALIDATED",Grant:new(call.ArgAt<SensitiveActionValidationCommand>(0).SessionBindingHash,"grant","target",SensitiveActionTargets.AccountDelete(null))));
        using var factory = FlowFactory(services =>
        {
            Replace<IActiveUserCacheService>(services, activeUsers);
            Replace(services, sessionRepo);
            Replace(services, jwtUtility);
            Replace(services, accountService);
            Replace(services,sensitive);
        });
        using HttpClient client = CreateAuthenticatedHttpsClient(factory);
        client.DefaultRequestHeaders.Add(SensitiveActionTokenConstants.HeaderName,"fresh-proof");

        using HttpResponseMessage request = await PostJsonWithIdempotency(client, "/account/wipeout", "{}", "delete-request-flow-0001");
        request.StatusCode.ShouldBe(HttpStatusCode.Accepted);
        using JsonDocument requestJson = await ReadJson(request);
        AssertSuccessEnvelope(requestJson, StatusCodes.Status202Accepted, "ACCOUNT_DELETE_PENDING");

        using var confirmation = new FormUrlEncodedContent(new Dictionary<string,string> {
            ["deleteToken"] = deleteToken,
            ["operationKey"] = treehammock.DataLayer.Operations.SecurityOperationKey.Create(),
            ["operationRecovery"] = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)) });
        using HttpResponseMessage verify = await client.PostAsync("/account/wipeout/verify", confirmation);
        verify.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument verifyJson = await ReadJson(verify);
        AssertSuccessEnvelope(verifyJson, StatusCodes.Status200OK, "ACCOUNT_DELETE_VERIFIED");

        using HttpResponseMessage finalize = await PostJsonWithIdempotency(
            client,
            "/account/wipeout/finalize",
            $$"""
            {
              "deleteToken": "{{deleteToken}}"
            }
            """,
            "delete-finalize-flow-0001");

        finalize.StatusCode.ShouldBe(HttpStatusCode.OK);
        finalize.Headers.TryGetValues("AppStatus", out IEnumerable<string>? appStatuses).ShouldBeTrue();
        appStatuses.ShouldContain(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        using JsonDocument finalizeJson = await ReadJson(finalize);
        AssertSuccessEnvelope(finalizeJson, StatusCodes.Status200OK, "ACCOUNT_DELETE_SUCCEEDED");
        activeUsers.StoredSessions.ShouldNotContainKey(AccessTokenHashUtility.Hash(AuthenticatedAccessToken));
    }

    [Fact]
    public async Task Required_authenticated_mutation_without_idempotency_key_returns_precondition_required()
    {
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        var activeUsers = AuthenticatedActiveCache(accountId, accountSecurityStamp);
        var sessionRepo = AuthenticatedSessionRepo(activeUsers.AuthenticatedSession, CachedSessionTrustStatus.Valid);

        using var factory = FlowFactory(services =>
        {
            Replace<IActiveUserCacheService>(services, activeUsers);
            Replace(services, sessionRepo);
            Replace(services, AuthenticatedJwtUtility());
            Replace(services, Substitute.For<IAccountService>());
        });
        using HttpClient client = CreateAuthenticatedHttpsClient(factory);

        using HttpResponseMessage response = await client.PostAsync("/account/wipeout", JsonContent("{}"));

        response.StatusCode.ShouldBe(HttpStatusCode.PreconditionRequired);
        using JsonDocument responseJson = await ReadJson(response);
        AssertFailureEnvelope(responseJson, StatusCodes.Status428PreconditionRequired, AuthenticatedMutationIdempotencyConstants.MissingRequiredKeyCode);
    }

    [Fact]
    public async Task Current_session_logout_remains_optional_without_idempotency_key()
    {
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        var activeUsers = AuthenticatedActiveCache(accountId, accountSecurityStamp);
        var sessionRepo = AuthenticatedSessionRepo(activeUsers.AuthenticatedSession, CachedSessionTrustStatus.Valid);
        sessionRepo.LogoutCurrentSession(accountId, Arg.Any<string?>()!, accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<DbCommandResult?>(new DbCommandResult(true, "AUTHENTICATION_LOGOFF_SUCCEEDED")));

        using var factory = FlowFactory(services =>
        {
            Replace<IActiveUserCacheService>(services, activeUsers);
            Replace(services, sessionRepo);
            Replace(services, AuthenticatedJwtUtility());
        });
        using HttpClient client = CreateAuthenticatedHttpsClient(factory);

        using HttpResponseMessage response = await client.PostAsync("/account/logoff", JsonContent("{}"));

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        response.Headers.TryGetValues("AppStatus", out IEnumerable<string>? appStatuses).ShouldBeTrue();
        appStatuses.ShouldContain(AppStatus.CLIENT_CLEAR_ACCESS_TOKEN.ToString());
        using JsonDocument responseJson = await ReadJson(response);
        AssertSuccessEnvelope(responseJson, StatusCodes.Status200OK, "LOGOFF_SUCCEEDED");
    }

    private static LoginTwoFactorHarness BuildLoginTwoFactorHarness(IReadOnlyCollection<TwoFactorAuthMethod> methods, Action<IServiceCollection>? configureFactory = null)
    {
        Guid accountId = Guid.NewGuid();
        Guid accountSecurityStamp = Guid.NewGuid();
        string preAuthToken = $"preauth-{Guid.NewGuid():N}";
        string finalAccessToken = $"final-{Guid.NewGuid():N}";
        var activeUsers = AuthenticatedActiveCache(accountId, accountSecurityStamp);
        var twoFactorSessions = new InMemoryTwoFactorSessionService();
        var loginProofs = new LoginProofTestDouble();
        var accountRepo = Substitute.For<IAccountRepo>();
        var sessionRepo = Substitute.For<ISessionRepo>();
        var jwtUtility = Substitute.For<IJsonWebTokenUtility>();
        var twoFactorService = Substitute.For<ITwoFactorAuthenticateService>();
        var authenticatorVerifier = Substitute.For<IAuthenticatorAppLoginVerifier>();
        var sensitiveActionService = Substitute.For<IAccountSensitiveActionService>();
        var harness = new LoginTwoFactorHarness(
            accountId,
            accountSecurityStamp,
            preAuthToken,
            finalAccessToken,
            activeUsers,
            twoFactorSessions,
            accountRepo,
            sessionRepo,
            jwtUtility,
            twoFactorService,
            authenticatorVerifier,
            sensitiveActionService);

        accountRepo
            .GetCredentials(Arg.Any<treehammock.Models.Authentication.AuthenticateLogin>(), AccountLoginAction.EMAIL)
            .Returns(_ => Task.FromResult(CredentialLookupResult.Found(BuildAccount(
                accountId,
                accountSecurityStamp,
                hasTwoFactorAuth: true,
                twoFactorAuthMethod: methods.FirstOrDefault(TwoFactorAuthMethod.NONE)))));

        harness.ProofState = loginProofs;
        loginProofs.AuthorityCurrent = () => harness.PendingTwoFactorSessionCurrent;
        harness.VerifiedMethods = methods.ToList();
        accountRepo.GetTwoFactorDetails(accountId, cancellationToken: Arg.Any<CancellationToken>()).Returns(_ => Task.FromResult(TwoFactorDetailsLookupResult.Found(
            new TwoFactorDetails(
                harness.VerifiedMethods.ToList(),
                userAuthIds: null,
                phoneNumbers: harness.VerifiedMethods.Contains(TwoFactorAuthMethod.SMS_KEY) ? new List<string> { "5551234567" } : null,
                phoneCountryCode: harness.VerifiedMethods.Contains(TwoFactorAuthMethod.SMS_KEY) ? new List<string> { "1" } : null,
                emailAddresses: harness.VerifiedMethods.Contains(TwoFactorAuthMethod.EMAIL) ? new List<string> { "reader@example.com" } : null))));









        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(null));
        sessionRepo.ValidateCachedSessionTrust(
                Arg.Any<string?>()!,
                accountId,
                activeUsers.AuthenticatedSession.securityStamp,
                accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<CachedSessionTrustResult?>(new CachedSessionTrustResult(
                CachedSessionTrustStatus.Valid,
                AccessExpiration: activeUsers.AuthenticatedSession.accessExpiration,
                SessionExpiration: activeUsers.AuthenticatedSession.sessionExpiration,
                CutOff: activeUsers.AuthenticatedSession.cutOff,
                SecurityStamp: activeUsers.AuthenticatedSession.securityStamp,
                AccountSecurityStamp: accountSecurityStamp, Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(activeUsers.AuthenticatedSession.accountId))));
        sessionRepo.ExpireSession(Arg.Any<string?>()!, Arg.Any<Instant?>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        jwtUtility.GenerateAccessToken(Arg.Any<byte[]>(), WebKey, Arg.Any<string>()).Returns(preAuthToken, finalAccessToken);
        jwtUtility.ValidateAccessToken(
                Arg.Is<string>(value => value == preAuthToken),
                Arg.Any<byte[]>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                Arg.Is<string>(value => value == JsonWebTokenPurpose.PreAuthTwoFactor),
                Arg.Any<Duration?>())
            .Returns(Task.FromResult<(IntraMessage, string?)>((IntraMessage.TOKEN_PASSED_VALIDATION, WebKey)));
        jwtUtility.ValidateAccessToken(
                AuthenticatedAccessToken,
                Arg.Any<byte[]>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                JsonWebTokenPurpose.Active,
                Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)WebKey)));

        sensitiveActionService.ValidateAsync(Arg.Any<SensitiveActionValidationCommand>(), Arg.Any<CancellationToken>())
            .Returns(call => Task.FromResult(new SensitiveActionValidationResult(
                true,
                HttpMessage.SENSITIVE_ACTION_TOKEN_VALIDATED,
                AccountSensitiveActionService.TokenValidatedCode,
                call.ArgAt<SensitiveActionValidationCommand>(0).Purpose,
                Grant: new(call.ArgAt<SensitiveActionValidationCommand>(0).SessionBindingHash,"test-token","test-target",call.ArgAt<SensitiveActionValidationCommand>(0).Target ?? SensitiveActionTargets.DefaultSetup))));

        twoFactorService.Email(Arg.Any<string>(), Arg.Do<string>(code =>
        {
            harness.DeliveredEmailCode = code;
            harness.DeliveredEmailCodes.Add(code);
        }), token: Arg.Any<CancellationToken>()).Returns(Task.FromResult(true));
        twoFactorService.SMS(Arg.Any<string>(), Arg.Do<string>(code =>
        {
            harness.DeliveredSmsCode = code;
            harness.DeliveredSmsCodes.Add(code);
        }), token: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        authenticatorVerifier.VerifyForLoginAsync(
                accountId,
                Arg.Any<string>(),
                Arg.Any<Instant>(),
                Arg.Any<CancellationToken>())
            .Returns(Task.FromResult(AuthenticatorAppLoginVerificationResult.Success()));

        harness.Factory = FlowFactory(services =>
        {
            Replace<IActiveUserCacheService>(services, activeUsers);
            Replace<ITwoFactorSessionService>(services, twoFactorSessions);
            Replace<ILoginProofRepo>(services, loginProofs.Repo);
            Replace(services, accountRepo);
            Replace(services, sessionRepo);
            Replace(services, jwtUtility);
            Replace(services, twoFactorService);
            Replace<IAuthenticatorAppLoginVerifier>(services, authenticatorVerifier);
            Replace<IAccountSensitiveActionService>(services, sensitiveActionService);
            configureFactory?.Invoke(services);
        });

        return harness;
    }

    private static async Task<LoginSelection> LoginAndAssertSelectionRequired(HttpClient client, string expectedConfiguration)
    {
        using HttpResponseMessage login = await client.PostAsync("/account/requestaccess", LoginJson());
        login.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument loginJson = await ReadJson(login);
        AssertSuccessEnvelope(loginJson, StatusCodes.Status200OK, HttpMessage.AUTHENTICATION_TWO_FACTOR_SELECTION_REQUIRED.ToString());
        loginJson.RootElement.GetProperty("data").TryGetProperty("accessToken", out _).ShouldBeFalse();
        loginJson.RootElement.GetProperty("data").GetProperty("availableTwoFactorAuthConfigurations").EnumerateArray().Select(value => value.GetString()).ShouldContain(expectedConfiguration);
        return new LoginSelection(
            loginJson.RootElement.GetProperty("data").GetProperty("twoFactorAccessToken").GetString(),
            loginJson.RootElement.GetProperty("data").GetProperty("availableTwoFactorAuthConfigurations").EnumerateArray()
                .Select(value => value.GetString()!).ToArray());
    }

    private static async Task SelectLoginTwoFactorConfiguration(HttpClient client, string twoFactorAccessToken, string configuration)
    {
        using HttpResponseMessage selected = await client.PostAsync(
            "/account/twofactor/select",
            JsonContent($$"""
            {
              "configuration": "{{configuration}}",
              "destination": 0,
              "twoFactorAccessToken": "{{twoFactorAccessToken}}"
            }
            """));

        selected.StatusCode.ShouldBe(HttpStatusCode.OK);
        using JsonDocument selectedJson = await ReadJson(selected);
        AssertSuccessEnvelope(selectedJson, StatusCodes.Status200OK, configuration.Contains("SMS", StringComparison.Ordinal)
            ? HttpMessage.TWOFACTOR_WAITING_SMS_KEY.ToString()
            : HttpMessage.TWOFACTOR_WAITING_INTRA_EMAIL.ToString());
        selectedJson.RootElement.GetProperty("data").GetProperty("selectedConfiguration").GetString().ShouldBe(configuration);

    }

    private static TreehammockWebApplicationFactory FlowFactory(Action<IServiceCollection> configureTestServices)
    {
        return new TreehammockWebApplicationFactory(TestConfiguration.ValidSettings(), services =>
        {
            Replace<IAbuseCounterStore>(services, new AllowingAbuseCounterStore());
            Replace<IAuthenticatedMutationIdempotencyService>(services, new AllowingAuthenticatedMutationIdempotencyService());
            configureTestServices(services);
        });
    }

    private static HttpClient CreateHttpsClient(TreehammockWebApplicationFactory factory)
    {
        return factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
    }

    private static HttpClient CreateAuthenticatedHttpsClient(TreehammockWebApplicationFactory factory)
    {
        HttpClient client = CreateHttpsClient(factory);
        client.DefaultRequestHeaders.Add("AccessToken", AuthenticatedAccessToken);
        return client;
    }

    private static async Task<HttpResponseMessage> PostJsonWithIdempotency(
        HttpClient client,
        string route,
        string json,
        string key)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, route)
        {
            Content = JsonContent(json)
        };

        request.Headers.Add(AuthenticatedMutationIdempotencyConstants.HeaderName, key);
        return await client.SendAsync(request);
    }

    private static async Task<HttpResponseMessage> PostAuthenticatedRemoveTwoFactorMethod(
        HttpClient client,
        TwoFactorAuthMethod method,
        string idempotencyKey)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/account/twofactor/method/remove")
        {
            Content = JsonContent($$"""
            {
              "method": "{{method}}"
            }
            """)
        };

        request.Headers.Add("AccessToken", AuthenticatedAccessToken);
        request.Headers.Add(SensitiveActionTokenConstants.HeaderName, "sensitive-remove-token");
        request.Headers.Add(AuthenticatedMutationIdempotencyConstants.HeaderName, idempotencyKey);
        return await client.SendAsync(request);
    }

    private static StringContent LoginJson()
    {
        return JsonContent("""
        {
          "emailAddress": "reader@example.com",
          "password": "CorrectHorseBatteryStaple1!"
        }
        """);
    }

    private static StringContent JsonContent(string json)
    {
        return new StringContent(json, Encoding.UTF8, "application/json");
    }

    private static async Task<JsonDocument> ReadJson(HttpResponseMessage response)
    {
        string body = await response.Content.ReadAsStringAsync();
        return JsonDocument.Parse(body);
    }

    private static void AssertSuccessEnvelope(JsonDocument document, int statusCode, string code)
    {
        document.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        document.RootElement.GetProperty("statusCode").GetInt32().ShouldBe(statusCode);
        document.RootElement.GetProperty("code").GetString().ShouldBe(code);
        if (document.RootElement.TryGetProperty("errors", out JsonElement errors))
        {
            errors.ValueKind.ShouldBe(JsonValueKind.Null);
        }

        document.RootElement.GetProperty("data").ValueKind.ShouldNotBe(JsonValueKind.Null);
    }

    private static void AssertFailureEnvelope(JsonDocument document, int statusCode, string code)
    {
        document.RootElement.GetProperty("success").GetBoolean().ShouldBeFalse();
        document.RootElement.GetProperty("statusCode").GetInt32().ShouldBe(statusCode);
        document.RootElement.GetProperty("code").GetString().ShouldBe(code);
    }

    private static void Replace<TService>(IServiceCollection services, TService implementation)
        where TService : class
    {
        if (implementation is IAccountRepo repo)
            repo.ClearLoginAttempts(Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<short>(), Arg.Any<Instant?>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
                .Returns(new treehammock.DataLayer.Security.LoginAttemptTransition(true, "CLEARED", 0, null, Guid.NewGuid()));
        services.RemoveAll<TService>();
        services.AddSingleton(implementation);
    }

    private static IntraAccount BuildAccount(
        Guid accountId,
        Guid accountSecurityStamp,
        bool hasTwoFactorAuth = false,
        TwoFactorAuthMethod twoFactorAuthMethod = TwoFactorAuthMethod.NONE)
    {
        return new IntraAccount(
            accountId,
            HashPassword(Password),
            WebKey,
            VerificationStatus.SUCCESSFUL,
            RandomBytes(AccountCryptoSizes.SaltOneBytes),
            RandomBytes(AccountCryptoSizes.SivBytes),
            RandomBytes(AccountCryptoSizes.NonceBytes),
            unlockWhen: null,
            refreshToken: null,
            refreshes: 0,
            limit: 3,
            lifespan: Period.FromHours(1),
            loginFailures: 0,
            twoFactorAccessToken: null,
            authenticatorAppUsage: 0,
            smsKeyUsage: 0,
            smsUsage: 0,
            hasTwoFactorAuth: hasTwoFactorAuth,
            country: Country.USA,
            cutOff: null,
            lockedDown: null,
            features: FeatureSet.basic,
            activeAccessTokenHash: null,
            accountSecurityStamp: accountSecurityStamp)
        {
            twoFactorAuthMethod = twoFactorAuthMethod
        };
    }

    private static byte[] HashPassword(string password)
    {
        return Argon2idPasswordHashCodec.HashToStorageBytes(password, 3, 67108864);
    }

    private static byte[] RandomBytes(int length)
    {
        return RandomNumberGenerator.GetBytes(length);
    }

    private static AuthenticatedActiveUserCacheService AuthenticatedActiveCache(Guid accountId, Guid accountSecurityStamp)
    {
        Instant createdOn = SystemClock.Instance.GetCurrentInstant();
        var session = treehammock.Tests.Support.EntitlementTestData.Attach(new ActiveSession(
            accountId,
            RandomNumberGenerator.GetBytes(64),
            0,
            createdOn,
            Period.FromMinutes(15),
            createdOn.Plus(Duration.FromMinutes(15)),
            createdOn.Plus(Duration.FromHours(1)),
            cutOff: null,
            features: FeatureSet.basic,
            accountSecurityStamp: accountSecurityStamp));

        var cache = new AuthenticatedActiveUserCacheService(session);
        cache.StoredSessions[AccessTokenHashUtility.Hash(AuthenticatedAccessToken)] = session;
        return cache;
    }

    private static ISessionRepo AuthenticatedSessionRepo(ActiveSession session, CachedSessionTrustStatus trustStatus)
    {
        var sessionRepo = Substitute.For<ISessionRepo>();
        sessionRepo.GetSession(Arg.Any<string>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<Session?>(null));
        sessionRepo.ValidateCachedSessionTrust(
                Arg.Any<string?>()!,
                session.accountId,
                session.securityStamp,
                session.accountSecurityStamp, cancellationToken: Arg.Any<CancellationToken>())
            .Returns(Task.FromResult<CachedSessionTrustResult?>(trustStatus == CachedSessionTrustStatus.Valid
                ? new CachedSessionTrustResult(
                    CachedSessionTrustStatus.Valid,
                    AccessExpiration: session.accessExpiration,
                    SessionExpiration: session.sessionExpiration,
                    CutOff: session.cutOff,
                    SecurityStamp: session.securityStamp,
                    AccountSecurityStamp: session.accountSecurityStamp, Entitlements: treehammock.Tests.Support.EntitlementTestData.ForAccount(session.accountId))
                : new CachedSessionTrustResult(trustStatus, Code: trustStatus.ToString())));
        sessionRepo.ExpireSession(Arg.Any<string?>()!, Arg.Any<Instant?>(), cancellationToken: Arg.Any<CancellationToken>()).Returns(Task.FromResult<bool?>(true));
        return sessionRepo;
    }

    private static IJsonWebTokenUtility AuthenticatedJwtUtility()
    {
        var jwtUtility = Substitute.For<IJsonWebTokenUtility>();
        jwtUtility.ValidateAccessToken(
                AuthenticatedAccessToken,
                Arg.Any<byte[]>(),
                Arg.Any<Instant>(),
                Arg.Any<Instant>(),
                JsonWebTokenPurpose.Active,
                Arg.Any<Duration?>())
            .Returns(Task.FromResult((IntraMessage.TOKEN_PASSED_VALIDATION, (string?)WebKey)));
        return jwtUtility;
    }


    private sealed record LoginSelection(string? Token, string[] Configurations);

    private sealed class LoginTwoFactorHarness : IAsyncDisposable
    {
        public LoginTwoFactorHarness(
            Guid accountId,
            Guid accountSecurityStamp,
            string preAuthToken,
            string finalAccessToken,
            InMemoryActiveUserCacheService activeUsers,
            InMemoryTwoFactorSessionService twoFactorSessions,
            IAccountRepo accountRepo,
            ISessionRepo sessionRepo,
            IJsonWebTokenUtility jwtUtility,
            ITwoFactorAuthenticateService twoFactorService,
            IAuthenticatorAppLoginVerifier authenticatorVerifier,
            IAccountSensitiveActionService sensitiveActionService)
        {
            AccountId = accountId;
            AccountSecurityStamp = accountSecurityStamp;
            PreAuthToken = preAuthToken;
            FinalAccessToken = finalAccessToken;
            ActiveUsers = activeUsers;
            TwoFactorSessions = twoFactorSessions;
            AccountRepo = accountRepo;
            SessionRepo = sessionRepo;
            JwtUtility = jwtUtility;
            TwoFactorService = twoFactorService;
            AuthenticatorVerifier = authenticatorVerifier;
            SensitiveActionService = sensitiveActionService;
        }

        public Guid AccountId { get; }

        public Guid AccountSecurityStamp { get; }

        public string PreAuthToken { get; }

        public string FinalAccessToken { get; }

        public InMemoryActiveUserCacheService ActiveUsers { get; }

        public InMemoryTwoFactorSessionService TwoFactorSessions { get; }

        public IAccountRepo AccountRepo { get; }

        public ISessionRepo SessionRepo { get; }

        public IJsonWebTokenUtility JwtUtility { get; }

        public ITwoFactorAuthenticateService TwoFactorService { get; }

        public IAuthenticatorAppLoginVerifier AuthenticatorVerifier { get; }

        public IAccountSensitiveActionService SensitiveActionService { get; }

        public List<TwoFactorAuthMethod> VerifiedMethods { get; set; } = [];

        public LoginProofTestDouble ProofState { get; set; } = null!;
        public bool PendingTwoFactorSessionCurrent { get; set; } = true;

        private readonly object _disposalGate = new();
        private Task? _disposeTask;
        private TreehammockWebApplicationFactory? _factory;

        public TreehammockWebApplicationFactory Factory
        {
            get
            {
                lock (_disposalGate)
                {
                    if (_disposeTask is not null) throw new ObjectDisposedException(nameof(LoginTwoFactorHarness));
                    return _factory ?? throw new InvalidOperationException("The flow factory has not been assigned.");
                }
            }
            set => _factory = value;
        }

        public ValueTask DisposeAsync()
        {
            lock (_disposalGate)
            {
                return new ValueTask(_disposeTask ??= DisposeFactoryAsync());
            }
        }

        private async Task DisposeFactoryAsync()
        {
            if (_factory is not null) await _factory.DisposeAsync();
        }

        public string? DeliveredEmailCode { get; set; }

        public List<string> DeliveredEmailCodes { get; } = [];

        public string? DeliveredSmsCode { get; set; }

        public List<string> DeliveredSmsCodes { get; } = [];

        public void ConfigureSuccessfulMethodRemoval(
            TwoFactorAuthMethod removedMethod,
            IReadOnlyList<TwoFactorAuthMethod> remainingMethods,
            IReadOnlyList<TwoFactorAuthConfiguration> remainingConfigurations)
        {
            AccountRepo.RemoveTwoFactorMethod(
                    AccountId,
                    AccountSecurityStamp,
                    removedMethod,
                    Arg.Any<Instant>(), cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant?>())
                .Returns(_ =>
                {
                    VerifiedMethods = remainingMethods.ToList();
                    PendingTwoFactorSessionCurrent = false;
                    return Task.FromResult<TwoFactorMethodRemovalCommandResult?>(new TwoFactorMethodRemovalCommandResult(
                        true,
                        "TWO_FACTOR_METHOD_REMOVED",
                        removedMethod,
                        remainingMethods,
                        remainingConfigurations));
                });
        }

        public void ConfigureIdempotentMethodRemovalRace(
            TwoFactorAuthMethod removedMethod,
            IReadOnlyList<TwoFactorAuthMethod> remainingMethods,
            IReadOnlyList<TwoFactorAuthConfiguration> remainingConfigurations)
        {
            int removalAttempts = 0;
            AccountRepo.RemoveTwoFactorMethod(
                    AccountId,
                    AccountSecurityStamp,
                    removedMethod,
                    Arg.Any<Instant>(), cancellationToken: Arg.Any<CancellationToken>(), grant: Arg.Any<treehammock.DataLayer.Security.SensitiveActionGrant?>())
                .Returns(_ =>
                {
                    int attempt = Interlocked.Increment(ref removalAttempts);
                    if (attempt == 1)
                    {
                        VerifiedMethods = remainingMethods.ToList();
                        PendingTwoFactorSessionCurrent = false;
                        return Task.FromResult<TwoFactorMethodRemovalCommandResult?>(new TwoFactorMethodRemovalCommandResult(
                            true,
                            "TWO_FACTOR_METHOD_REMOVED",
                            removedMethod,
                            remainingMethods,
                            remainingConfigurations));
                    }

                    return Task.FromResult<TwoFactorMethodRemovalCommandResult?>(new TwoFactorMethodRemovalCommandResult(
                        false,
                        "TWO_FACTOR_METHOD_NOT_CONFIGURED",
                        removedMethod,
                        remainingMethods,
                        remainingConfigurations));
                });
        }
    }


    private sealed class AllowingAbuseCounterStore : IAbuseCounterStore
    {
        public Task<CounterDecision> IncrementAsync(
            AbuseCounterKey key,
            AbuseCounterLimit limit,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new CounterDecision(
                Allowed: true,
                CurrentCount: 1,
                Limit: limit.MaxAttempts,
                Window: limit.Window,
                RetryAfter: null,
                ReasonCode: null));
        }

        public Task ResetAsync(
            AbuseCounterKey key,
            CancellationToken cancellationToken = default)
        {
            return Task.CompletedTask;
        }

        public Task<CooldownDecision> GetCooldownAsync(
            AbuseCounterKey key,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(new CooldownDecision(false, null, null));
        }
    }

    private class InMemoryActiveUserCacheService : IActiveUserCacheService
    {
        public ConcurrentDictionary<string, ActiveSession> StoredSessions { get; } = new(StringComparer.Ordinal);
        public Func<ActiveSession,Task<bool>>? BeforeStore { get; init; }

        public Task<ActiveSession?> GetSession(string hashedAccessToken, CancellationToken cancellationToken = default)
        {
            StoredSessions.TryGetValue(hashedAccessToken, out ActiveSession? session);
            return Task.FromResult(session);
        }

        public async Task<bool> SetSession(string newHashedAccessToken, ActiveSession session, TimeSpan expire, CommandFlags flags = CommandFlags.PreferMaster, CancellationToken cancellationToken = default)
        {
            if(BeforeStore is not null&&!await BeforeStore(session))return false;
            StoredSessions[newHashedAccessToken] = session;
            return true;
        }

        public Task<bool> WarmSession(string hashedAccessToken, ActiveSession session, TimeSpan expire, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(expire > TimeSpan.Zero && StoredSessions.TryAdd(hashedAccessToken, session));
        }

        public Task<bool> RevokeSession(string hashedAccessToken, CancellationToken cancellationToken = default)
        {
            StoredSessions.TryRemove(hashedAccessToken, out _);
            return Task.FromResult(true);
        }

        public Task<bool> AdjustExpiration(string newHashedAccessToken, TimeSpan expire, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(StoredSessions.ContainsKey(newHashedAccessToken));
        }
    }

    private sealed class AuthenticatedActiveUserCacheService : InMemoryActiveUserCacheService
    {
        public AuthenticatedActiveUserCacheService(ActiveSession authenticatedSession)
        {
            AuthenticatedSession = authenticatedSession;
        }

        public ActiveSession AuthenticatedSession { get; }
    }

    private sealed class InMemoryTwoFactorSessionService : ITwoFactorSessionService
    {
        public ConcurrentDictionary<string, TwoFactorSession> StoredSessions { get; } = new(StringComparer.Ordinal);

        public Task<TwoFactorSession?> GetSession(string hashedAccessToken, CancellationToken cancellationToken = default)
        {
            StoredSessions.TryGetValue(hashedAccessToken, out TwoFactorSession? session);
            return Task.FromResult(session);
        }

        public Task<bool?> SetSession(string hashedAccessToken, TwoFactorSession session, TimeSpan expire, CommandFlags flags = CommandFlags.PreferMaster, CancellationToken cancellationToken = default)
        {
            StoredSessions[hashedAccessToken] = LoginProofTestDouble.Clone(session);
            return Task.FromResult<bool?>(true);
        }

        public Task<bool> RevokeSession(string hashedAccessToken, CancellationToken cancellationToken = default)
        {
            StoredSessions.TryRemove(hashedAccessToken, out _);
            return Task.FromResult(true);
        }

        public Task<bool> AdjustExpiration(string newHashedAccessToken, TimeSpan expire, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(StoredSessions.ContainsKey(newHashedAccessToken));
        }
    }
}
