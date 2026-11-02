using System.Text;
using System.Text.RegularExpressions;
using StackExchange.Redis;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.DragonflyTests;

// Separate native runner. Missing owned target/config fails; no implicit skip or local execution.
public sealed class NativeCachePrivilegesTests
{
    private static string Required(string key)=>Environment.GetEnvironmentVariable(key)??throw new InvalidOperationException("Missing native fixture configuration: "+key);
    private static async Task<ConnectionMultiplexer> Connect(string name)
    {
        if(Required("SVS06_DISPOSABLE_DRAGONFLY")!="true")throw new InvalidOperationException("Owned disposable Dragonfly acknowledgment required.");
        var options=ConfigurationOptions.Parse(Required(name));
        if(options.EndPoints.Count!=1||string.IsNullOrWhiteSpace(options.User)||!options.Ssl)throw new InvalidOperationException("Dedicated user, verified TLS and one explicit endpoint required.");
        options.AbortOnConnectFail=true;options.ConnectRetry=0;options.ConnectTimeout=2000;options.SyncTimeout=2000;options.AsyncTimeout=2000;
        return await ConnectionMultiplexer.ConnectAsync(options);
    }
    private static string Prefix()
    {
        var prefix=Required("SVS06_OWNED_NAMESPACE");
        if(!Regex.IsMatch(prefix,@"^svs:authority:v1:[a-z0-9.-]{1,32}:[a-f0-9]{32}$",RegexOptions.CultureInvariant))throw new InvalidOperationException("Exact owned v1 namespace required.");return prefix;
    }
    [Fact] public async Task Actual_dragonfly_reader_gets_only_its_owned_fixture()
    {
        using var owner=await Connect("SVS06_OWNER_CONNECTION");using var reader=await Connect("SVS06_READER_CONNECTION");
        var db=owner.GetDatabase();string key=Prefix()+":native:"+Guid.NewGuid().ToString("N");
        var info=await db.ExecuteAsync("INFO","server");Assert.Contains("dragonfly_version:",info.ToString(),StringComparison.Ordinal);
        try
        {
            Assert.True(await db.StringSetAsync(key,"synthetic-fixture",TimeSpan.FromMinutes(1)));
            using var get=new DragonflyGetStore(reader,new SessionCacheAdmission());
            var bytes=await get.GetAsync(key,TestContext.Current.CancellationToken);Assert.Equal("synthetic-fixture",Encoding.UTF8.GetString(bytes!));
        }
        finally{await db.KeyDeleteAsync(key);}
    }
    [Theory][InlineData("SET")][InlineData("DEL")][InlineData("EXPIRE")][InlineData("EVAL")][InlineData("outside-GET")]
    public async Task Actual_reader_acl_denies_mutation_scripts_and_other_namespaces(string operation)
    {
        using var owner=await Connect("SVS06_OWNER_CONNECTION");using var reader=await Connect("SVS06_READER_CONNECTION");
        var fixture=owner.GetDatabase();var db=reader.GetDatabase();string key=Prefix()+":native:"+Guid.NewGuid().ToString("N");
        var info=await fixture.ExecuteAsync("INFO","server");Assert.Contains("dragonfly_version:",info.ToString(),StringComparison.Ordinal);
        try
        {
            await fixture.StringSetAsync(key,"fixture",TimeSpan.FromMinutes(1));
            var ex=await Assert.ThrowsAsync<RedisServerException>(async()=>
            {
                switch(operation)
                {
                    case "SET":await db.StringSetAsync(key,"forbidden");break;
                    case "DEL":await db.KeyDeleteAsync(key);break;
                    case "EXPIRE":await db.KeyExpireAsync(key,TimeSpan.FromSeconds(1));break;
                    case "EVAL":await db.ExecuteAsync("EVAL","return redis.call('SET',KEYS[1],'forbidden')",1,key);break;
                    default:await db.StringGetAsync("svs06-outside:"+Guid.NewGuid().ToString("N"));break;
                }
            });
            Assert.StartsWith("NOPERM",ex.Message,StringComparison.Ordinal);
            Assert.Equal("fixture",(string?)await fixture.StringGetAsync(key));
        }
        finally{await fixture.KeyDeleteAsync(key);}
    }
}
