using NodaTime;
using Npgsql;
using Treehammock.SessionValidation.Storage;
using Xunit;
namespace Treehammock.SessionValidation.YsqlTests;

// Deliberately separate from local tests. No automatic skip/pass when native prerequisites are absent.
public sealed class NativeAuthorityTests
{
    [Theory]
    [InlineData("eligible")][InlineData("unverified")][InlineData("locked")][InlineData("cutoff")]
    [InlineData("session-cutoff")][InlineData("access-expired")][InlineData("hard-expired")]
    [InlineData("stamp-changed")][InlineData("logout")][InlineData("account-deleted")]
    public async Task Actual_target_snapshot_is_nonmutating_and_denies_ineligible_identity(string scenario)
    {
        var ct=TestContext.Current.CancellationToken;
        if(Environment.GetEnvironmentVariable("SVS04_DISPOSABLE_DATABASE")!="true") throw new InvalidOperationException("Disposable Yugabyte database acknowledgment required");
        await using var writer=YsqlAuthorityDataSource.Create(Required("SVS04_WRITER_CONNECTION"));
        await using var reader=YsqlAuthorityDataSource.CreateValidator(Required("SVS04_READER_CONNECTION"));
        Assert.Equal(DatabaseIdentityAuditStatus.Verified,(await reader.RefreshIdentityAsync(ct)).Status);
        await using var connection=await writer.OpenConnectionAsync(ct);
        await using(var check=new NpgsqlCommand("select version()",connection))
            Assert.Contains("YB",(string)(await check.ExecuteScalarAsync(ct))!,StringComparison.OrdinalIgnoreCase);
        var account=Guid.NewGuid();var stamp=Guid.NewGuid();var family=Guid.NewGuid();
        string hash=Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(account.ToByteArray()));
        try
        {
            await using(var seed=new NpgsqlCommand("insert into public.accounts(account_id,email_address,verify_status,security_stamp) values(@a,@email,1,@stamp); "+
                "insert into public.sessions(access_token_hash,account_id,session_id,security_stamp,account_security_stamp,access_expiration,session_expiration) "+
                "values(@hash,@a,@family,@sessionstamp,@stamp,clock_timestamp()+interval '5 minutes',clock_timestamp()+interval '1 hour')",connection))
            {
                seed.Parameters.AddWithValue("a",account);seed.Parameters.AddWithValue("email",account+"@svs04.invalid");seed.Parameters.AddWithValue("stamp",stamp);
                seed.Parameters.AddWithValue("hash",hash);seed.Parameters.AddWithValue("family",family);seed.Parameters.AddWithValue("sessionstamp",Guid.NewGuid());await seed.ExecuteNonQueryAsync(ct);
            }
            var authority=new YsqlSessionAuthority(reader,TimeSpan.FromSeconds(3));
            // These probes use the real reader connection, distinct from the writer.
            using(var baseline=await authority.ReadAsync(hash,SystemClock.Instance.GetCurrentInstant()+Duration.FromSeconds(5),ct))
            { Assert.Equal(AuthorityReadStatus.Found,baseline.Status);Assert.Equal(account,baseline.Projection!.Identity.AccountId); }
            string? mutation=scenario switch {
                "unverified"=>"update public.accounts set verify_status=0 where account_id=@a",
                "locked"=>"update public.accounts set unlock_when=clock_timestamp()+interval '1 hour' where account_id=@a",
                "cutoff"=>"update public.accounts set cut_off=clock_timestamp() where account_id=@a",
                "session-cutoff"=>"update public.sessions set cut_off=clock_timestamp() where account_id=@a",
                "access-expired"=>"update public.sessions set access_expiration=clock_timestamp() where account_id=@a",
                "hard-expired"=>"update public.sessions set access_expiration=clock_timestamp(),session_expiration=clock_timestamp() where account_id=@a",
                "stamp-changed"=>"update public.accounts set security_stamp=gen_random_uuid() where account_id=@a",
                "logout"=>"delete from public.sessions where account_id=@a",
                "account-deleted"=>"delete from public.accounts where account_id=@a",_=>null };
            if(mutation is not null) { await using var command=new NpgsqlCommand(mutation,connection);command.Parameters.AddWithValue("a",account);await command.ExecuteNonQueryAsync(ct); }
            var before=await Mirror(connection,account,ct);
            using(var current=await authority.ReadAsync(hash,SystemClock.Instance.GetCurrentInstant()+Duration.FromSeconds(5),ct))
            {
                if(scenario=="eligible") Assert.Equal(AuthorityReadStatus.Found,current.Status);
                else { Assert.Contains(current.Status,new[]{AuthorityReadStatus.Unauthenticated,AuthorityReadStatus.NotFound});Assert.Null(current.Projection); }
            }
            Assert.Equal(before,await Mirror(connection,account,ct));
        }
        finally
        {
            using var cleanup=new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await using var delete=new NpgsqlCommand("delete from public.accounts where account_id=@a",connection);
            delete.Parameters.AddWithValue("a",account);await delete.ExecuteNonQueryAsync(cleanup.Token);
        }
    }
    private static string Required(string key)=>Environment.GetEnvironmentVariable(key)??throw new InvalidOperationException("Native configuration missing: "+key);
    private static async Task<string> Mirror(NpgsqlConnection c,Guid account,CancellationToken ct)
    {
        await using var command=new NpgsqlCommand("select coalesce((select jsonb_build_array(a.features,a.entitlement_version,a.entitlement_fingerprint)::text from public.accounts a where a.account_id=@a),'absent') || ':' || "+
            "coalesce((select jsonb_agg(jsonb_build_array(s.session_id,s.generation,s.features,s.entitlement_version) order by s.session_id)::text from public.sessions s where s.account_id=@a),'absent')",c);
        command.Parameters.AddWithValue("a",account);return (string)(await command.ExecuteScalarAsync(ct))!;
    }
}
