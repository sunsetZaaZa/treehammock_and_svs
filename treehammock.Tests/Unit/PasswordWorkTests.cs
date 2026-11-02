using System.Text;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Options;
using Shouldly;
using NSubstitute;
using Microsoft.Extensions.DependencyInjection;
using treehammock.Rigging.Config;
using treehammock.Rigging.Security;
using treehammock.Services;

namespace treehammock.Tests.Unit;

public class Cor07PasswordWorkTests
{
    [Theory]
    [InlineData(true)] [InlineData(false)]
    public async Task Login_busy_or_lost_rehash_CAS_neither_charges_incorrect_proof_nor_issues_session(bool busy)
    {
        // Direct action boundary: repository/cache/proof results are explicit doubles.
        var harness = new treehammock.Tests.Infrastructure.AccountControllerHarness();
        var payload = harness.LoginPayload(); var account = harness.Account();
        harness.AccountRepo.GetCredentials(payload, treehammock.RiggingSupport.Actions.Account.AccountLoginAction.EMAIL, Arg.Any<CancellationToken>())
            .Returns(treehammock.Repos.CredentialLookupResult.Found(account));
        var work = Substitute.For<IPasswordWorkService>();
        work.VerifyAndUpgradeAsync(Arg.Any<byte[]>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
            .Returns(busy ? Task.FromException<PasswordVerification>(new PasswordWorkBusyException())
                : Task.FromResult(new PasswordVerification(true, new byte[128])));
        harness.AccountRepo.UpgradePasswordHash(Arg.Any<Guid>(), Arg.Any<Guid>(), Arg.Any<byte[]>(), Arg.Any<byte[]>(), Arg.Any<CancellationToken>())
            .Returns(false);
        var controller = harness.CreateLoginController();
        using var provider = new ServiceCollection().AddSingleton(work).BuildServiceProvider();
        harness.HttpContext.RequestServices = provider;
        if (busy) await Should.ThrowAsync<PasswordWorkBusyException>(() => controller.Authenticate(payload));
        else treehammock.Tests.Infrastructure.AccountControllerHarness.ExtractEnvelope(await controller.Authenticate(payload), 409)
            .code.ShouldBe("PASSWORD_CREDENTIAL_CHANGED");
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SetLoginFailures(default, default, Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SetLockOut(default, default, Arg.Any<CancellationToken>());
        _ = harness.AccountRepo.DidNotReceiveWithAnyArgs().SuccessfulLogin(default, default, Arg.Any<CancellationToken>());
        _ = harness.SessionRepo.DidNotReceiveWithAnyArgs().SetSession(default!, default!, Arg.Any<CancellationToken>());
    }
    [Fact]
    public async Task Busy_password_work_returns_retryable_503_without_clearing_credentials()
    {
        var context = new Microsoft.AspNetCore.Http.DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        var middleware = new treehammock.Rigging.Dependencies.DependencyExceptionMiddleware(
            _ => throw new PasswordWorkBusyException(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<treehammock.Rigging.Dependencies.DependencyExceptionMiddleware>.Instance);
        await middleware.InvokeAsync(context);
        context.Response.StatusCode.ShouldBe(503);
        context.Response.Headers.RetryAfter.ToString().ShouldBe("1");
        context.Response.Headers.CacheControl.ToString().ShouldBe("no-store");
        context.Response.Headers.ContainsKey("CLIENT_CLEAR_ACCESS_TOKEN").ShouldBeFalse();
        context.Response.Body.Position = 0;
        (await new StreamReader(context.Response.Body).ReadToEndAsync()).ShouldContain(PasswordWorkBusyException.Code);
    }
    private static (PasswordWorkService Work, PasswordWorkLimiter Limiter) Work(LoginSettings? settings = null)
    {
        var options = Options.Create(settings ?? new()); var limiter = new PasswordWorkLimiter(options);
        return (new(options, limiter), limiter);
    }
    [Fact]
    public async Task Native_signup_and_reset_hashes_encode_65536_KiB_three_iterations_and_one_lane()
    {
        var (work, limiter) = Work();
        byte[] signup = await work.HashBytesAsync("pāssword e\u0301");
        var reset = await new PasswordResetPasswordMaterialFactory(Options.Create(new LoginSettings()), work)
            .CreatePasswordMaterialAsync("pāssword e\u0301");
        foreach (byte[] hash in new[] { signup, reset.HashedPassword })
        {
            hash.Length.ShouldBe(AccountCryptoSizes.PasswordHashBytes);
            string phc = Encoding.UTF8.GetString(hash).TrimEnd('\0');
            phc.ShouldStartWith("$argon2id$v=19$m=65536,t=3,p=1$");
            (await work.VerifyBytesAsync(hash, "pāssword e\u0301")).ShouldBeTrue();
            (await work.VerifyBytesAsync(hash, "pāssword é")).ShouldBeFalse(); // Preserve existing UTF-8 semantics.
        }
        limiter.Snapshot.Active.ShouldBe(0); limiter.Snapshot.ReservedMemoryBytes.ShouldBe(0);
    }
    [Fact]
    public async Task Legacy_cost_upgrades_only_after_correct_password_and_stronger_cost_is_not_downgraded()
    {
        var (work, _) = Work();
        byte[] legacy = Argon2idPasswordHashCodec.HashToStorageBytes("correct password", 3, 65536);
        var rejected = await work.VerifyAndUpgradeAsync(legacy, "incorrect password");
        rejected.Verified.ShouldBeFalse(); rejected.UpgradedHash.ShouldBeNull();
        var accepted = await work.VerifyAndUpgradeAsync(legacy, "correct password");
        accepted.Verified.ShouldBeTrue(); accepted.UpgradedHash.ShouldNotBeNull();
        Encoding.UTF8.GetString(accepted.UpgradedHash!).ShouldStartWith("$argon2id$v=19$m=65536,t=3,p=1$");
        byte[] stronger = Argon2idPasswordHashCodec.HashToStorageBytes("correct password", 4, 67108864);
        (await work.VerifyAndUpgradeAsync(stronger, "correct password")).UpgradedHash.ShouldBeNull();
    }
    [Theory]
    [InlineData("not-phc")]
    [InlineData("$argon2id$v=19$m=999999999,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=65536,t=11,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("$argon2id$v=19$m=65536,t=3,p=5$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    public async Task Invalid_or_oversized_encoded_costs_never_enter_native_work(string hash)
    {
        var (work, limiter) = Work();
        (await work.VerifyStringAsync(hash, "password")).ShouldBeFalse();
        limiter.Snapshot.Started.ShouldBe(0);
    }
    [Fact]
    public void Ambiguous_legacy_config_and_under_budget_generation_fail_validation()
    {
        var settings = new LoginSettings { Argon2MemoryUsePer = 65536 };
        Should.Throw<ValidationException>(() => Work(settings));
        settings = new() { Argon2MemoryBytes = 65536 };
        Should.Throw<ValidationException>(() => Work(settings));
        settings = new() { PasswordWork = new() { MemoryBudgetBytes = 67108864, MaxEncodedMemoryBytes = 134217728 } };
        Should.Throw<ValidationException>(() => Work(settings));
    }
    [Fact]
    public async Task Cancelled_running_native_work_keeps_lease_until_worker_finishes_and_queue_is_bounded()
    {
        var options = Options.Create(new LoginSettings { PasswordWork = new() { MaxActiveOperations = 1, MaxQueuedOperations = 1, QueueTimeoutMilliseconds = 5000 } });
        var limiter = new PasswordWorkLimiter(options); using var release = new ManualResetEventSlim();
        using var caller = new CancellationTokenSource(); var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<int> running = limiter.RunAsync(() => { entered.SetResult(); if (!release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException(); return 1; }, 67108864, cancellationToken: caller.Token);
        Task<int>? queued = null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(3)); caller.Cancel();
            limiter.Snapshot.Active.ShouldBe(1); running.IsCompleted.ShouldBeFalse();
            queued = limiter.RunAsync(() => 2, 67108864);
            limiter.Snapshot.Queued.ShouldBe(1);
            await Should.ThrowAsync<PasswordWorkBusyException>(() => limiter.RunAsync(() => 3, 67108864));
        }
        finally { release.Set(); }
        await Should.ThrowAsync<OperationCanceledException>(() => running);
        (await queued!).ShouldBe(2);
        limiter.Snapshot.Active.ShouldBe(0); limiter.Snapshot.Queued.ShouldBe(0); limiter.Snapshot.ReservedMemoryBytes.ShouldBe(0);
    }
    [Fact]
    public async Task Weighted_memory_and_queue_deadline_reject_without_dispatch_and_release_capacity()
    {
        var options = Options.Create(new LoginSettings { PasswordWork = new() { MaxActiveOperations = 2, MaxQueuedOperations = 1, QueueTimeoutMilliseconds = 30 } });
        var limiter = new PasswordWorkLimiter(options); using var release = new ManualResetEventSlim();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<int> running = limiter.RunAsync(() => { entered.SetResult(); if (!release.Wait(TimeSpan.FromSeconds(5))) throw new TimeoutException(); return 1; }, 134217728);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(3));
            await Should.ThrowAsync<PasswordWorkBusyException>(() => limiter.RunAsync<int>(() => throw new InvalidOperationException("Must not dispatch"), 67108864));
            limiter.Snapshot.Started.ShouldBe(1); limiter.Snapshot.Active.ShouldBe(1); limiter.Snapshot.Queued.ShouldBe(0);
        }
        finally { release.Set(); }
        await running;
        (await limiter.RunAsync(() => 2, 67108864)).ShouldBe(2);
    }
}
