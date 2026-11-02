using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.AspNetCore.Http;
using Npgsql;
using NSubstitute;
using NodaTime;
using Shouldly;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Operations;
using treehammock.Rigging.Security;
using treehammock.RiggingSupport.Actions.Account;
using treehammock.RiggingSupport.Enum;
using treehammock.RiggingSupport.Status;
using treehammock.Services;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

[Trait("Suite", "SqlContracts")]
public class Cor07PasswordCostTests(ITestOutputHelper output)
{
    private static SecurityOperationSettings Settings() => new()
    { HmacKeys = new() { [1] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) } };

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public Task Delayed_cost_upgrade_cannot_overwrite_password_reset_or_another_hash(bool resetStamp)
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            await using var storage = new FixtureStorage(fixture, Settings());
            var repo = Repo(storage); var admin = await fixture.OpenConnectionAsync();
            Guid id = Guid.NewGuid(), stamp = Guid.NewGuid();
            byte[] oldHash = Argon2idPasswordHashCodec.HashToStorageBytes("old password", 3, 65536);
            var login = Options.Create(new LoginSettings()); var work = new PasswordWorkService(login, new PasswordWorkLimiter(login));
            var verified = await work.VerifyAndUpgradeAsync(oldHash, "old password", token); verified.UpgradedHash.ShouldNotBeNull();
            byte[] resetHash = await work.HashBytesAsync("reset password", token);
            await Seed(admin, id, stamp, oldHash, token);
            var reset = await fixture.OpenConnectionAsync(); await using var transaction = await reset.BeginTransactionAsync(token);
            await using (var update = new NpgsqlCommand("update accounts set hashed_password=@hash,security_stamp=@stamp where account_id=@id", reset, transaction))
            {
                update.Parameters.AddWithValue("hash", resetHash); update.Parameters.AddWithValue("stamp", resetStamp ? Guid.NewGuid() : stamp);
                update.Parameters.AddWithValue("id", id); await update.ExecuteNonQueryAsync(token);
            }
            var context = SecurityOperationRequestContext.Isolated("test.cost-upgrade");
            using (SecurityOperationRequestContext.Push(context))
            {
                Task<bool> delayed = fixture.Observe(repo.UpgradePasswordHash(id, stamp, oldHash, verified.UpgradedHash!, token));
                await ObserveBlocker(admin, reset.ProcessID, token);
                await transaction.CommitAsync(token);
                (await delayed).ShouldBeFalse();
                await storage.SecurityOperations.FinishAsync(context, 409, false);
            }
            (await ReadHash(admin, id, token)).ShouldBe(resetHash);
        }, TestContext.Current.CancellationToken);

    [Fact]
    public Task Cost_upgrade_winning_account_lock_is_followed_by_reset_without_restoring_old_credential()
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            await using var storage = new FixtureStorage(fixture, Settings()); var admin = await fixture.OpenConnectionAsync();
            Guid id = Guid.NewGuid(), stamp = Guid.NewGuid(); byte[] oldHash = new byte[128], upgraded = Enumerable.Repeat((byte)1,128).ToArray(), resetHash = Enumerable.Repeat((byte)2,128).ToArray();
            await Seed(admin,id,stamp,oldHash,token);
            var context = SecurityOperationRequestContext.Isolated("test.upgrade-first");
            using (SecurityOperationRequestContext.Push(context))
            {
                await using var operation = await storage.SecurityOperations.BeginAsync("test.upgrade",new {id},id,stamp,null,token);
                await using var change = new NpgsqlCommand("select upgrade_account_password_hash(@id,@stamp,@old,@new)",operation.Connection,operation.Transaction);
                change.Parameters.AddWithValue("id",id);change.Parameters.AddWithValue("stamp",stamp);change.Parameters.AddWithValue("old",oldHash);change.Parameters.AddWithValue("new",upgraded);
                ((bool)(await change.ExecuteScalarAsync(token))!).ShouldBeTrue();
                var reset = await fixture.OpenConnectionAsync();
                var task = fixture.Observe(Task.Run(async () =>
                {
                    await using var command = new NpgsqlCommand("update accounts set hashed_password=@hash,security_stamp=gen_random_uuid() where account_id=@id",reset);
                    command.Parameters.AddWithValue("hash",resetHash);command.Parameters.AddWithValue("id",id);await command.ExecuteNonQueryAsync(token);
                },token));
                await ObserveBlocker(admin,operation.Connection.ProcessID,token);
                await operation.CommitAsync(true); await task;
            }
            (await ReadHash(admin,id,token)).ShouldBe(resetHash);
        }, TestContext.Current.CancellationToken);

    [Theory]
    [InlineData(false)] [InlineData(true)]
    public Task Real_cache_signup_flood_with_denied_delivery_bounds_hashes_queue_memory_and_account_rows(bool duplicate)
        => SqlContractFixture.RunAsync(async (fixture, token) =>
        {
            await using var storage = new FixtureStorage(fixture, Settings()); var repo = Repo(storage);
            using var cache = await Cor06ReplayLeaseTests.Connect();
            using var store = new DragonflyAbuseCounterStore(Options.Create(new AbuseCounterCacheSettings { database=0 }), Options.Create(new AbuseControlSettings { DragonflyTimeoutMilliseconds=60 }),cache);
            var login = Options.Create(new LoginSettings { TwoFactorChallengePepper=Convert.ToHexString(RandomNumberGenerator.GetBytes(32)), PasswordWork=new() {MaxQueuedOperations=2,QueueTimeoutMilliseconds=2000} });
            var limiter = new PasswordWorkLimiter(login); var work = new PasswordWorkService(login,limiter);
            var abuse = Options.Create(new AbuseControlSettings { Signup=new() {MaxAttemptsPerIp=3,MaxAttemptsPerIdentifier=3} });
            var accessor = new HttpContextAccessor {HttpContext=new DefaultHttpContext()}; accessor.HttpContext.Connection.RemoteIpAddress=System.Net.IPAddress.Parse("203.0.113.47");
            var smtp = Substitute.For<ISMTPService>(); // Delivery staged; this test does not run a provider.
            smtp.VerificationLetter(Arg.Any<string>(),Arg.Any<string>(),Arg.Any<string>(), token: Arg.Any<CancellationToken>()).Returns((bool?)false);
            var delivery=Substitute.For<treehammock.Rigging.Delivery.IDurableDeliveryService>();
            delivery.AdmitAsync(Arg.Any<AbuseFeature>(),Arg.Any<string>(),Arg.Any<Guid>(),Arg.Any<string>(),Arg.Any<CancellationToken>()).Returns(true);
            var service = new AccountService(delivery,repo,login,Options.Create(new RegistrationSettings { PublicOrigin = "http://localhost.test",AccountMetaDataRetries=2,VerifyAccountPeriodDays=1}),Options.Create(new EmailSubjectSettings()),new Argon2idUserSecretHasher(login,work),
                abuseCounterStore:store,abuseControlSettings:abuse,httpContextAccessor:accessor,passwordWork:work,signupAdmission:new SignupAdmissionPolicy(store,abuse,login));
            var admin=await fixture.OpenConnectionAsync();
            if (duplicate) await Seed(admin,Guid.NewGuid(),Guid.NewGuid(),new byte[128],token);
            var process=Process.GetCurrentProcess(); long before=process.WorkingSet64;
            Task<HttpMessage>[] tasks=Enumerable.Range(0,30).Select(index=>Task.Run(async()=>
            {
                var context=SecurityOperationRequestContext.Isolated("test.signup:"+index);
                using(SecurityOperationRequestContext.Push(context))
                {
                    try { return await service.SetupUserAccount(duplicate ? "cor07@example.invalid" : $"cor07-{index}@example.invalid",null,"native password",Country.USA,SystemClock.Instance.GetCurrentInstant(),AccountSetupAction.EMAIL,token); }
                    catch(PasswordWorkBusyException) { return HttpMessage.ACCOUNT_CREATION_ADMISSION_UNAVAILABLE; }
                    finally { await storage.SecurityOperations.FinishAsync(context,200,false); }
                }
            },token)).ToArray();
            foreach(var task in tasks)fixture.Observe(task);
            var results=await Task.WhenAll(tasks); var sample=limiter.Snapshot;process.Refresh();
            long rows=await Scalar<long>(admin,"select count(*) from accounts",token);
            sample.Started.ShouldBeLessThanOrEqualTo(3L);sample.PeakActive.ShouldBeLessThanOrEqualTo(2);sample.PeakQueued.ShouldBeLessThanOrEqualTo(2);
            sample.PeakReservedMemoryBytes.ShouldBeLessThanOrEqualTo(134217728L);sample.Active.ShouldBe(0);sample.Queued.ShouldBe(0);
            rows.ShouldBeLessThanOrEqualTo(3L);rows.ShouldBe((duplicate ? 1L : 0L) + results.Count(result=>result==HttpMessage.ACCOUNT_CREATION_VERIFICATION_PENDING));
            if (duplicate) { sample.Started.ShouldBe(0L); results.Count(result=>result==HttpMessage.ACCOUNT_CREATION_DUPLICATE_EMAIL).ShouldBe(3); }
            results.Count(result=>result==HttpMessage.ACCOUNT_CREATION_RATE_LIMITED).ShouldBeGreaterThanOrEqualTo(27);
            ThreadPool.GetAvailableThreads(out int worker,out int io);
            output.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { profile="COR07-owned-signup",duplicate,requests=30,results=results.GroupBy(x=>x).ToDictionary(x=>x.Key.ToString(),x=>x.Count()),passwordWork=sample,accountRows=rows,workingSetBefore=before,workingSetAfter=process.WorkingSet64,peakWorkingSet=process.PeakWorkingSet64,threadCount=process.Threads.Count,availableWorkers=worker,availableIo=io }));
        }, TestContext.Current.CancellationToken);

    private static AccountRepo Repo(StorageContext storage) => new(new treehammock.Rigging.Delivery.DeliveryPayloadProtector(Options.Create(new DeliveryOutboxSettings {EncryptionKeys=new() {{1,Convert.ToBase64String(new byte[32])}}})),storage,Options.Create(new JWTSettings()),NullLogger<AccountRepo>.Instance,Substitute.For<IUserSecretHasher>());
    private static async Task Seed(NpgsqlConnection connection,Guid id,Guid stamp,byte[] hash,CancellationToken token)
    {
        await using var command=new NpgsqlCommand("insert into accounts(account_id,email_address,verify_status,security_stamp,hashed_password) values(@id,'cor07@example.invalid',1,@stamp,@hash)",connection);
        command.Parameters.AddWithValue("id",id);command.Parameters.AddWithValue("stamp",stamp);command.Parameters.AddWithValue("hash",hash);await command.ExecuteNonQueryAsync(token);
    }
    private static async Task<byte[]> ReadHash(NpgsqlConnection connection,Guid id,CancellationToken token)
    {await using var command=new NpgsqlCommand("select hashed_password from accounts where account_id=@id",connection);command.Parameters.AddWithValue("id",id);return (byte[])(await command.ExecuteScalarAsync(token))!;}
    private static async Task<T> Scalar<T>(NpgsqlConnection connection,string sql,CancellationToken token)
    {await using var command=new NpgsqlCommand(sql,connection);return (T)(await command.ExecuteScalarAsync(token))!;}
    private static async Task ObserveBlocker(NpgsqlConnection admin,int blocker,CancellationToken token)
    {
        for(int attempt=0;attempt<100;attempt++)
        {if(await Scalar<bool>(admin,$"select exists(select 1 from pg_stat_activity where {blocker}=any(pg_blocking_pids(pid)))",token))return;await Task.Delay(10,token);}
        throw new InvalidOperationException("Exact backend contention was not observed.");
    }
    private sealed class FixtureStorage : StorageContext
    {
        private readonly SqlContractFixture _fixture;
        public FixtureStorage(SqlContractFixture fixture,SecurityOperationSettings settings):base(Options.Create(Database()),Options.Create(settings))=>_fixture=fixture;
        private static DatabaseSettings Database()
        {var p=new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);return new(){servers=p.Host,port=p.Port,database=p.Database,userId=p.Username!,password=p.Password!,maximumPoolSize=4};}
        public override async Task<NpgsqlConnection> CreateConnection(CancellationToken token=default)
        {
            var connection=await base.CreateConnection(token);
            try{await using var command=new NpgsqlCommand($"set search_path to {_fixture.Schema},public",connection);await command.ExecuteNonQueryAsync(token);return connection;}
            catch{await connection.DisposeAsync();throw;}
        }
    }
}
