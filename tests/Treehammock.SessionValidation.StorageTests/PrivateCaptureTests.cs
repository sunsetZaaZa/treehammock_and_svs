using System.Text.Json;
using Svs12.Golden;
using Svs12.Harness;
using Xunit;
namespace Treehammock.SessionValidation.StorageTests;
public sealed class Svs21PrivateCaptureTests
{
    public static IEnumerable<object[]> Cases()=>TreehammockParityFixtures.Cases();
    [Theory][MemberData(nameof(Cases))]
    public async Task Independent_decision_provider_captures_private_pair(string id)
    {
        using var h=new ParityHarness(id,true);long start=System.Diagnostics.Stopwatch.GetTimestamp();
        var decision=await h.Validate(TestContext.Current.CancellationToken);
        Assert.Equal(h.Case.ExpectedCoordinator,decision.Decision.ToString());
        if(Environment.GetEnvironmentVariable("SVS21_PRIVATE_CAPTURE") is not {} directory)return;
        Directory.CreateDirectory(directory);if(!OperatingSystem.IsWindows())File.SetUnixFileMode(directory,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        object? identity=decision.Subject is {} s?new{account=s.AccountId.ToString("N"),family=s.FamilyId.ToString("N"),generation=s.Generation,protocol=s.ProtocolVersion}:null;
        var row=new{token=h.Credential,decision=decision.Decision.ToString(),identity,sql=h.Database.Calls,cache_hit=h.Store.Gets==2 && h.Database.Calls==0,duration_us=(int)Math.Min(100000000,System.Diagnostics.Stopwatch.GetElapsedTime(start).TotalMicroseconds)};
        var path=Path.Combine(directory,"svs-"+id+".json");File.WriteAllText(path,JsonSerializer.Serialize(row));if(!OperatingSystem.IsWindows())File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);
    }
}
