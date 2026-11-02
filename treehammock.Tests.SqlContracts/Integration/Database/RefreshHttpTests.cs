using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NodaTime;
using NodaTime.Serialization.JsonNet;
using Npgsql;
using NSubstitute;
using Shouldly;
using treehammock.Controllers;
using treehammock.DataLayer.Operations;
using treehammock.Models.Authentication;
using treehammock.Repos;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Authorization;
using treehammock.Rigging.Cache;
using treehammock.Rigging.Config;
using treehammock.Rigging.Database;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Operations;
using treehammock.Rigging.Hosting;
using treehammock.Services;
using treehammock.Tests.SqlContracts.Support;

namespace treehammock.Tests.Integration.Database;

// Production refresh controller, token validator, operation middleware, service
// and repositories with real PostgreSQL. Cache misses/writes and unused account
// controller dependencies are explicit substitutes. No password/factor proof,
// actual Redis, proxy/TLS or production capacity qualification is claimed.
[Trait("Suite", "SqlContracts")]
public class Cor09RefreshHttpTests
{
    private static TaskCompletionSource<bool> Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private sealed class ValidationBarrier(ISessionRefreshRepo inner,CancellationToken token) : ISessionRefreshRepo
    {
        private int _arrived;
        public readonly TaskCompletionSource<bool> Both=Signal(), Release=Signal();
        public async Task<RefreshSessionSnapshot?> FindAsync(string hash,Guid family,long generation,CancellationToken cancellation)
        {
            var result=await inner.FindAsync(hash,family,generation,cancellation);
            if(Interlocked.Increment(ref _arrived)==2) Both.TrySetResult(true);
            await Release.Task.WaitAsync(token); return result;
        }
        public Task<RefreshSessionResult> RotateAsync(RefreshSessionSnapshot snapshot,string refresh,string hash,byte[] key,
            Guid identity,int seconds,int interval,CancellationToken cancellation)
            => inner.RotateAsync(snapshot,refresh,hash,key,identity,seconds,interval,cancellation);
    }
    private sealed class ResponseBarrier(CancellationToken token)
    {
        private int _arrived;
        public readonly TaskCompletionSource<bool> Both=Signal(), Winner=Signal(), Loser=Signal();
        public async Task Starting(HttpContext context)
        {
            if(Interlocked.Increment(ref _arrived)==2) Both.TrySetResult(true);
            await(context.Response.StatusCode==200?Winner:Loser).Task.WaitAsync(token);
        }
    }
    internal sealed class FixtureStorage : StorageContext
    {
        private readonly SqlContractFixture _fixture;
        public FixtureStorage(SqlContractFixture fixture,SecurityOperationSettings settings,int? port=null)
            :base(Options.Create(Database(port)),Options.Create(settings))=>_fixture=fixture;
        private static DatabaseSettings Database(int? port)
        {
            var parsed=new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            return new(){servers=port.HasValue?"127.0.0.1":parsed.Host,port=port??parsed.Port,database=parsed.Database,
                userId=parsed.Username!,password=parsed.Password!,maximumPoolSize=8};
        }
        public override async Task<NpgsqlConnection> CreateConnection(CancellationToken token=default)
        {
            var connection=await base.CreateConnection(token);
            try { await using var command=new NpgsqlCommand($"set search_path to {_fixture.Schema},public",connection);
                await command.ExecuteNonQueryAsync(token);return connection; }
            catch { await connection.DisposeAsync();throw; }
        }
    }
    private static SecurityOperationSettings Operations() => new() { HmacKeys=new(){[1]=Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))} };
    private static (string Key,string Recovery) Identity() => (SecurityOperationKey.Create(),Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
    private static HttpRequestMessage Refresh(Cor09SessionFamilyTests.SeededSession seed,(string Key,string Recovery) operation) => new(HttpMethod.Post,SessionProtocol.RefreshPath)
    {
        Content=JsonContent.Create(new RefreshSessionRequest {protocolVersion=2,sessionId=seed.Family,generation=1,refreshToken=seed.Refresh}),
        Headers={ {SecurityOperationMiddleware.KeyHeader,operation.Key},{SecurityOperationMiddleware.RecoveryHeader,operation.Recovery} }
    };
    private static HttpRequestMessage Probe(string access) => new(HttpMethod.Get,"/cor09/probe") {Headers={{"AccessToken",access}}};
    private static TestServer Host(FixtureStorage storage,SecurityOperationSettings operations,ISessionRefreshRepo refresh,ResponseBarrier? responses=null)
        => new(new WebHostBuilder().ConfigureServices(services=>
        {
            var jwt=Options.Create(Cor09SessionFamilyTests.Settings());
            services.AddLogging();services.AddRouting();
            services.AddSingleton<IOptions<RequestBodySettings>>(Options.Create(new RequestBodySettings()));
            services.AddSingleton<RequestBodyPolicy>();
            services.AddControllers().AddApplicationPart(typeof(AccountSessionController).Assembly)
                .AddNewtonsoftJson(options=>options.SerializerSettings.ConfigureForNodaTime(DateTimeZoneProviders.Tzdb));
            services.AddSingleton<IOptions<JWTSettings>>(jwt);
            services.AddSingleton<IOptions<SessionCacheFallbackSettings>>(Options.Create(new SessionCacheFallbackSettings()));
            services.AddSingleton<IOptions<SecurityOperationSettings>>(Options.Create(operations));
            services.AddSingleton<IOptions<RegistrationSettings>>(Options.Create(new RegistrationSettings { PublicOrigin = "http://localhost.test" }));
            services.AddSingleton<IOptions<LoginSettings>>(Options.Create(new LoginSettings()));
            services.AddSingleton<IOptions<AbuseControlSettings>>(Options.Create(new AbuseControlSettings()));
            services.AddSingleton<SecurityOperationService>(storage.SecurityOperations);
            services.AddSingleton<ISessionRepo>(new SessionRepo(storage,jwt,NullLogger<SessionRepo>.Instance));
            services.AddSingleton<IJsonWebTokenUtility>(new JsonWebTokenUtility(NullLogger<JsonWebTokenUtility>.Instance,jwt));
            services.AddSingleton<ISessionRefreshRepo>(refresh);services.AddSingleton<SessionRefreshService>();
            services.AddSingleton(Substitute.For<IActiveUserCacheService>());
            services.AddSingleton(Substitute.For<IAccountRepo>());services.AddSingleton(Substitute.For<ITwoFactorSessionService>());
            services.AddSingleton(Substitute.For<ITwoFactorAuthenticateService>());services.AddSingleton(Substitute.For<IAccountService>());
            services.AddSingleton(Substitute.For<IAbuseCounterStore>());services.AddSingleton(Substitute.For<ILoginAbuseCounterKeyFactory>());
        }).Configure(app=>
        {
            app.UseMiddleware<SecurityResponseCacheMiddleware>();
            app.UseMiddleware<HttpExceptionFallbackMiddleware>();
            app.UseRouting();
            app.UseMiddleware<RequestBodyMiddleware>();
            if(responses is not null) app.Use(async(context,next)=>
            { if(context.Request.Path==SessionProtocol.RefreshPath) context.Response.OnStarting(()=>responses.Starting(context));await next(); });
            app.UseMiddleware<SecurityOperationMiddleware>();app.UseMiddleware<DependencyExceptionMiddleware>();app.UseMiddleware<JsonWebTokenMiddleware>();
            app.UseEndpoints(endpoints=>
            {
                endpoints.MapControllers();
                endpoints.MapGet("/cor09/probe",context=>
                {context.Response.StatusCode=context.Items[AuthContextItems.WebKey] is string?200:401;return Task.CompletedTask;});
            });
        }));

    [Theory]
    [InlineData(true)] [InlineData(false)]
    public Task Concurrent_routed_refresh_after_two_validations_has_one_winner_in_both_response_orders(bool winnerFirst)
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var admin=await fixture.OpenConnectionAsync();var seed=await Cor09SessionFamilyTests.Seed(fixture,admin,token);
            var operations=Operations();await using var storage=new FixtureStorage(fixture,operations);
            var validation=new ValidationBarrier(new SessionRefreshRepo(storage),token);var responses=new ResponseBarrier(token);
            using var server=Host(storage,operations,validation,responses);using var client=server.CreateClient();
            using var one=Refresh(seed,Identity());using var two=Refresh(seed,Identity());
            var first=fixture.Observe(client.SendAsync(one,token));var second=fixture.Observe(client.SendAsync(two,token));
            await validation.Both.Task.WaitAsync(token);validation.Release.TrySetResult(true);
            await responses.Both.Task.WaitAsync(token);
            (winnerFirst?responses.Winner:responses.Loser).TrySetResult(true);
            var ready=await Task.WhenAny(first,second).WaitAsync(token);
            var early=await ready;
            early.StatusCode.ShouldBe(winnerFirst?HttpStatusCode.OK:HttpStatusCode.Conflict);
            (winnerFirst?responses.Loser:responses.Winner).TrySetResult(true);
            var results=await Task.WhenAll(first,second);var winner=results.Single(result=>result.StatusCode==HttpStatusCode.OK);
            var loser=results.Single(result=>result.StatusCode==HttpStatusCode.Conflict);
            foreach(var response in results) { response.Headers.CacheControl!.NoStore.ShouldBeTrue();
                response.Headers.Pragma.ShouldContain(value=>value.Name=="no-cache"); }
            loser.Headers.Contains("AppStatus").ShouldBeFalse();loser.Headers.Contains("AccessToken").ShouldBeFalse();
            using var json=JsonDocument.Parse(await winner.Content.ReadAsStringAsync(token));
            var data=json.RootElement.GetProperty("data");string access=data.GetProperty("accessToken").GetString()!;
            data.GetProperty("session").GetProperty("sessionId").GetGuid().ShouldBe(seed.Family);
            data.GetProperty("session").GetProperty("generation").GetInt64().ShouldBe(2);
            using var stale=await client.SendAsync(Probe(seed.Access),token);stale.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);stale.Headers.CacheControl!.NoStore.ShouldBeTrue();
            stale.Headers.GetValues(SessionProtocol.ClearTokenHashHeader).Single().ShouldBe(seed.Hash);
            using var current=await client.SendAsync(Probe(access),token);current.StatusCode.ShouldBe(HttpStatusCode.OK);current.Headers.CacheControl!.NoStore.ShouldBeTrue();
            await fixture.ExecuteAsync(admin,$"select * from revoke_session_for_account('{seed.Account}','{seed.Family}','{seed.Stamp}','{AccessTokenHashUtility.Hash(access)}')",cancellation:token);
            using var revoked=await client.SendAsync(Probe(access),token);revoked.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
            foreach(var result in results) result.Dispose();
        },TestContext.Current.CancellationToken);

    [Fact]
    public Task Refresh_commit_ack_loss_is_reconciled_on_another_instance_then_logout_fences_credentials()
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var admin=await fixture.OpenConnectionAsync();var seed=await Cor09SessionFamilyTests.Seed(fixture,admin,token);
            var parsed=new NpgsqlConnectionStringBuilder(DeferredSqlProcedureContractSettings.ConnectionString!);
            await using var proxy=new Cor04CommitAckLossProxy(parsed.Host,parsed.Port);
            var operations=Operations();await using var first=new FixtureStorage(fixture,operations,proxy.Port);
            await using var second=new FixtureStorage(fixture,operations);var repository=new SessionRefreshRepo(first);
            var snapshot=await repository.FindAsync(AccessTokenHashUtility.Hash(seed.Refresh),seed.Family,1,token);snapshot.ShouldNotBeNull();
            var identity=Identity();var context=new SecurityOperationRequestContext {ClientKey=identity.Key,RecoveryKey=identity.Recovery,
                Purpose="POST:/account/refresh",CanonicalBody=[]};
            using(SecurityOperationRequestContext.Push(context))
            {
                // Admit before arming so the proxy drops the rotation COMMIT,
                // not the operation-root reservation COMMIT.
                await using(var scope=await first.SecurityOperations.BeginAsync("test.admission",new {admission=true},seed.Account,seed.Stamp,null,token))
                { await scope.CommitAsync(new {Result=true,Code="ADMITTED"}); }
                proxy.Arm();
                await Should.ThrowAsync<SecurityOperationException>(()=>repository.RotateAsync(snapshot!,AccessTokenHashUtility.Hash(seed.Refresh),
                    AccessTokenHashUtility.Hash("unknown-output"),RandomNumberGenerator.GetBytes(64),Guid.NewGuid(),900,1,token));
            }
            await proxy.Dropped.WaitAsync(TimeSpan.FromSeconds(5),token);
            var status=await second.SecurityOperations.ReconcileAuthorizedAsync(identity.Key,identity.Recovery,token);
            status.Steps.Single(step=>step.Code=="SESSION_REFRESHED").Succeeded.ShouldBe(true);
            using var anotherHost=Host(second,operations,new SessionRefreshRepo(second));
            using var anotherClient=anotherHost.CreateClient();
            using var recoveryRequest=new HttpRequestMessage(HttpMethod.Get,SecurityOperationMiddleware.StatusPath)
                {Headers={{SecurityOperationMiddleware.KeyHeader,identity.Key},{SecurityOperationMiddleware.RecoveryHeader,identity.Recovery}}};
            using var recovered=await anotherClient.SendAsync(recoveryRequest,token);
            recovered.StatusCode.ShouldBe(HttpStatusCode.OK);
            string recoveryBody=await recovered.Content.ReadAsStringAsync(token);
            recoveryBody.ShouldContain("SESSION_REFRESHED");recoveryBody.ShouldNotContain(seed.Refresh);recoveryBody.ShouldNotContain(seed.Access);
            using var retryRequest=Refresh(seed,identity);
            using var retry=await anotherClient.SendAsync(retryRequest,token);
            retry.StatusCode.ShouldBe(HttpStatusCode.Conflict);retry.Headers.Contains("AccessToken").ShouldBeFalse();
            (await Cor09SessionFamilyTests.Scalar<long>(admin,"select count(*) from sessions where generation=2",token)).ShouldBe(1);
            await fixture.ExecuteAsync(admin,$"select * from logout_current_session('{seed.Account}','{seed.Hash}','{seed.Stamp}')",cancellation:token);
            (await Cor09SessionFamilyTests.Scalar<long>(admin,"select count(*) from sessions where session_expiration>clock_timestamp()",token)).ShouldBe(0);
            JsonSerializer.Serialize(status).ShouldNotContain(seed.Refresh);JsonSerializer.Serialize(status).ShouldNotContain(seed.Access);
        },TestContext.Current.CancellationToken);
    private static byte[] Cor23FEncode(byte[] input,string encoding)
    {
        using var output=new MemoryStream();
        using(Stream compressor=encoding switch {
            "gzip"=>new System.IO.Compression.GZipStream(output,System.IO.Compression.CompressionLevel.Fastest,true),
            "deflate"=>new System.IO.Compression.ZLibStream(output,System.IO.Compression.CompressionLevel.Fastest,true),
            "br"=>new System.IO.Compression.BrotliStream(output,System.IO.Compression.CompressionLevel.Fastest,true),
            _=>throw new ArgumentException("Unknown encoding.") }) compressor.Write(input);
        return output.ToArray();
    }
    private static Task<string> Cor23FSnapshot(NpgsqlConnection connection,CancellationToken token)
        => Cor09SessionFamilyTests.Scalar<string>(connection,"""
            select jsonb_build_object(
              'sessions',(select jsonb_agg(to_jsonb(s) order by to_jsonb(s)::text) from sessions s),
              'operations',(select jsonb_agg(to_jsonb(o) order by to_jsonb(o)::text) from security_operations o))::text
            """,token);
    [Theory]
    [InlineData("gzip","truncated",400,"REQUEST_COMPRESSED_BODY_INVALID")]
    [InlineData("deflate","truncated",400,"REQUEST_COMPRESSED_BODY_INVALID")]
    [InlineData("br","truncated",400,"REQUEST_COMPRESSED_BODY_INVALID")]
    [InlineData("gzip","malformed",400,"REQUEST_COMPRESSED_BODY_INVALID")]
    [InlineData("deflate","malformed",400,"REQUEST_COMPRESSED_BODY_INVALID")]
    [InlineData("br","malformed",400,"REQUEST_COMPRESSED_BODY_INVALID")]
    [InlineData("gzip","expanded",413,"REQUEST_DECODED_BODY_TOO_LARGE")]
    [InlineData("gzip","wire",413,"REQUEST_ENCODED_BODY_TOO_LARGE")]
    public Task Cor23F_rejected_refresh_bodies_create_no_operation_or_session_write(string encoding,string damage,int status,string code)
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var admin=await fixture.OpenConnectionAsync();var seed=await Cor09SessionFamilyTests.Seed(fixture,admin,token);
            var operations=Operations();await using var storage=new FixtureStorage(fixture,operations);
            using var server=Host(storage,operations,new SessionRefreshRepo(storage));using var client=server.CreateClient();
            using var request=Refresh(seed,Identity());byte[] plain=await request.Content!.ReadAsByteArrayAsync(token);
            byte[] complete=Cor23FEncode(plain,encoding);
            byte[] invalid=damage switch {
                "truncated"=>complete[..^1],"malformed"=>new byte[]{0xff,0xff,0xff},
                "expanded"=>Cor23FEncode(new byte[RequestBodySettings.DefaultDecodedBytes+1],encoding),
                "wire"=>new byte[262145],_=>throw new ArgumentException("Unknown damage.") };
            request.Content.Dispose();request.Content=new ByteArrayContent(invalid);
            request.Content.Headers.ContentType=new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            request.Content.Headers.ContentEncoding.Add(encoding);
            string before=await Cor23FSnapshot(admin,token);
            using var response=await client.SendAsync(request,token);((int)response.StatusCode).ShouldBe(status);
            response.Headers.CacheControl!.NoStore.ShouldBeTrue();
            using var body=JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));
            body.RootElement.GetProperty("success").GetBoolean().ShouldBeFalse();
            body.RootElement.GetProperty("statusCode").GetInt32().ShouldBe(status);body.RootElement.GetProperty("code").GetString().ShouldBe(code);
            (await Cor23FSnapshot(admin,token)).ShouldBe(before);
            (await Cor09SessionFamilyTests.Scalar<long>(admin,"select max(generation) from sessions",token)).ShouldBe(1);
        },TestContext.Current.CancellationToken);
    [Theory]
    [InlineData("gzip")] [InlineData("deflate")] [InlineData("br")]
    public Task Cor23F_valid_compressed_refresh_preserves_operation_admission_and_rotates_once(string encoding)
        => SqlContractFixture.RunAsync(async(fixture,token)=>
        {
            var admin=await fixture.OpenConnectionAsync();var seed=await Cor09SessionFamilyTests.Seed(fixture,admin,token);
            var operations=Operations();await using var storage=new FixtureStorage(fixture,operations);
            using var server=Host(storage,operations,new SessionRefreshRepo(storage));using var client=server.CreateClient();
            using var request=Refresh(seed,Identity());byte[] plain=await request.Content!.ReadAsByteArrayAsync(token);
            request.Content.Dispose();request.Content=new ByteArrayContent(Cor23FEncode(plain,encoding));
            request.Content.Headers.ContentType=new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");request.Content.Headers.ContentEncoding.Add(encoding);
            using var response=await client.SendAsync(request,token);response.StatusCode.ShouldBe(HttpStatusCode.OK);response.Headers.CacheControl!.NoStore.ShouldBeTrue();
            (await Cor09SessionFamilyTests.Scalar<long>(admin,"select count(*) from sessions where generation=2",token)).ShouldBe(1);
            using var body=JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));body.RootElement.GetProperty("success").GetBoolean().ShouldBeTrue();
        },TestContext.Current.CancellationToken);

}
