using Npgsql;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
using treehammock.Repos;
namespace treehammock.Tests.SqlContracts.Support;

internal static class Cor21CreationSql
{
    public static string Admit(Guid account,Guid stamp,string session,Guid family,Guid grant,string hash,string email,int tier=2,int term=1,int cadence=0) =>
        $"(select admission_id from cor21_admit_creation('{account}','{stamp}','{session}','{family}','{grant}',1,'{hash}','{email}',{tier}::smallint,{term}::smallint,{cadence}::smallint,'{new string('a',32)}'))";
    public static async Task<Guid> AdmitPayload(NpgsqlConnection c,ProtectedDelivery d,CancellationToken ct)
    {
        using var m=System.Text.Json.JsonDocument.Parse(d.MetadataJson);var j=m.RootElement;
        await using var command=new NpgsqlCommand("select admission_id from cor21_admit_creation(@account,@stamp,@session,@family,@grant,@version,@hash,@email,@tier,@term,@cadence,@ip)",c);
        command.Parameters.AddWithValue("account",d.AccountId);command.Parameters.AddWithValue("stamp",d.AccountStamp);
        command.Parameters.AddWithValue("session",j.GetProperty("sessionHash").GetString()!);command.Parameters.AddWithValue("family",j.GetProperty("familyId").GetGuid());
        command.Parameters.AddWithValue("grant",j.GetProperty("grantId").GetGuid());command.Parameters.AddWithValue("version",j.GetProperty("grantVersion").GetInt64());
        command.Parameters.AddWithValue("hash",d.ProofHash);command.Parameters.AddWithValue("email",j.GetProperty("emailAddress").GetString()!);
        command.Parameters.AddWithValue("tier",(short)j.GetProperty("tier").GetInt32());command.Parameters.AddWithValue("term",(short)j.GetProperty("term").GetInt32());
        command.Parameters.AddWithValue("cadence",(short)j.GetProperty("cadence").GetInt32());command.Parameters.AddWithValue("ip",new string('a',32));
        return (Guid)(await command.ExecuteScalarAsync(ct))!;
    }
}
