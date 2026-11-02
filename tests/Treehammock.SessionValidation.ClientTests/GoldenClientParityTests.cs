using Google.Protobuf;
using Svs12.Golden;
using Treehammock.SessionValidation.Client;
using Treehammock.SessionValidation.Contracts.V1;
using Xunit;
namespace Treehammock.SessionValidation.ClientTests;
public sealed class GoldenClientParityTests
{
    public static IEnumerable<object[]> Cases()=>TreehammockParityFixtures.Cases();
    [Theory][MemberData(nameof(Cases))]
    public async Task SDK_preserves_each_server_decision_and_exposes_subject_only_for_active(string id)
    {
        var c=TreehammockParityFixtures.Case(id);using var fixture=new ClientFixture();string credential=TreehammockParityFixtures.Credential(c);
        await using var server=fixture.ServerApp(async context=>
        {
            var request=await ClientFixture.Read(context);Assert.Equal(credential,request.AccessCredential.ToStringUtf8());Assert.Equal("backup.read",request.RequestedAction);
            var reply=ClientFixture.Reply(request);reply.Decision=Enum.Parse<Decision>(c.ExpectedCoordinator);if(reply.Decision==Decision.Active)reply.Generation=c.Generation;
            if(reply.Decision!=Decision.Active){reply.AccountIdUuid=ByteString.Empty;reply.SessionFamilyUuid=ByteString.Empty;reply.Generation=0;reply.SessionProtocolVersion=0;reply.ValidUntilUnixMs=0;}
            await ClientFixture.Write(context,reply.ToByteArray());
        });
        await server.StartAsync(TestContext.Current.CancellationToken);await using var sdk=new SessionValidatorClient(fixture.Options());
        var actual=await sdk.ValidateAsync(credential,"backup.read",DateTimeOffset.UtcNow.AddSeconds(2),TestContext.Current.CancellationToken);
        int status=c.ExpectedCoordinator switch{"Active"=>200,"Unauthenticated"=>401,"Forbidden"=>403,_=>503};Assert.Equal(status,actual.HttpStatusCode);Assert.Equal(status==200,actual.Subject is not null);if(actual.Subject is {} subject)Assert.Equal(c.Generation,subject.Generation);
        TreehammockParityFixtures.Report("sdk-"+id,new{Id=id,Status=actual.HttpStatusCode,Subject=actual.Subject is not null});
    }
}
