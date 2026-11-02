using Npgsql;
using Shouldly;
using treehammock.Tests.SqlContracts.Support;
namespace treehammock.Tests.Integration.Database;
[Trait("Suite","SqlContracts")]
public class ActivationProcedureContractTests
{
    [Fact]
    public async Task Client_selected_activation_producer_is_rejected_without_persisting_a_code()
    {
        await SqlContractFixture.RunAsync(async(f,ct)=>{var c=await f.OpenConnectionAsync();
            await using var cmd=new NpgsqlCommand("select result,code from place_activation(gen_random_uuid(),gen_random_uuid(),'client@example.test','plaintext',clock_timestamp(),1::smallint,0::smallint,clock_timestamp()+interval '1 day',2::smallint,1::smallint,'client',3::smallint,null)",c);
            await using var dr=await cmd.ExecuteReaderAsync(ct);(await dr.ReadAsync(ct)).ShouldBeTrue();dr.GetBoolean(0).ShouldBeFalse();dr.GetString(1).ShouldBe("ACTIVATION_TRUSTED_GRANT_REQUIRED");await dr.DisposeAsync();
            await using var count=new NpgsqlCommand("select count(*) from activations",c);((long)(await count.ExecuteScalarAsync(ct))!).ShouldBe(0);
        });
    }
}
