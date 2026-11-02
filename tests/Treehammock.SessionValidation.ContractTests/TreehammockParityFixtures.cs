using System.Text.Json;
namespace Svs12.Golden;

// Shared data only. Expected decisions are reviewed JSON literals, not calculated
// by the implementation under test. Keys/tokens are public synthetic fixtures.
public sealed class ParityCase
{
    public string Id {get;set;}="";
    public string Token {get;set;}="issued";
    public string ExpectedCore {get;set;}="Active";
    public string ExpectedCoordinator {get;set;}="Active";
    public string? ExpectedTreehammock {get;set;}
    public string ExpectedToken {get;set;}="Passed";
    public string AccountState {get;set;}="Eligible";
    public string Authority {get;set;}="current";
    public long Generation {get;set;}=7;
    public int Protocol {get;set;}=2;
    public bool EmptyFamily {get;set;}
    public bool BadBinding {get;set;}
    public bool ShortKey {get;set;}
    public long AccessTicks {get;set;}=3000000000;
    public long HardTicks {get;set;}=36000000000;
    public long? CutoffTicks {get;set;}
    public long? UnlockTicks {get;set;}
    public long EvaluatedTicks {get;set;}
    public long? BoundaryTicks {get;set;}=6000000000;
    public long? EligibilityTicks {get;set;}
    public long EntitlementVersion {get;set;}=1;
    public int FeatureTier {get;set;}=1;
    public string[] Capabilities {get;set;}=["account.read","account.manage"];
    public string RequiredCapability {get;set;}="account.read";
    public override string ToString()=>Id;
}
public sealed class ParityCorpus
{
    public string Format {get;set;}="";
    public bool SyntheticOnly {get;set;}
    public bool NativeQualification {get;set;}
    public string Now {get;set;}="";
    public string Issuer {get;set;}="";
    public string TestKeyHex {get;set;}="";
    public ParityCase[] Cases {get;set;}=[];
}
public static class TreehammockParityFixtures
{
    public static readonly JsonSerializerOptions Json=new(){PropertyNamingPolicy=JsonNamingPolicy.CamelCase,UnmappedMemberHandling=System.Text.Json.Serialization.JsonUnmappedMemberHandling.Disallow};
    public static string Folder=>Path.Combine(AppContext.BaseDirectory,"Fixtures/GoldenSessions");
    public static ParityCorpus Corpus {get;}=JsonSerializer.Deserialize<ParityCorpus>(File.ReadAllText(Path.Combine(Folder,"session-cases.json")),Json)??throw new InvalidOperationException("Missing corpus.");
    public static IEnumerable<object[]> Cases()=>Corpus.Cases.Select(c=>new object[]{c.Id});
    public static ParityCase Case(string id)=>Corpus.Cases.Single(c=>c.Id==id);
    public static byte[] Key()=>Convert.FromHexString(Corpus.TestKeyHex);
    public static string Credential(ParityCase c)
    {
        string path=Environment.GetEnvironmentVariable("SVS12_ISSUED_TOKENS_PATH")??Path.Combine(Folder,"tokens.json");
        using var d=JsonDocument.Parse(File.ReadAllText(path));
        if(d.RootElement.GetProperty("format").GetString()!="SVS12Tokens.v1"||!d.RootElement.GetProperty("syntheticOnly").GetBoolean())throw new InvalidOperationException("Explicit synthetic fixture required.");
        return d.RootElement.GetProperty("tokens").GetProperty(c.Token).GetString()!;
    }
    public static void Report(string component,object values)
    {
        if(Environment.GetEnvironmentVariable("SVS12_EVIDENCE_DIRECTORY") is not {} folder)return;
        Directory.CreateDirectory(folder);string framework=System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription.Replace(' ','_');
        File.WriteAllText(Path.Combine(folder,component+"-"+framework+".json"),JsonSerializer.Serialize(values,Json));
    }
}
