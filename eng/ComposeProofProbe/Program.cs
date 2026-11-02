using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
try
{
    if (args.Length == 2 && args[0] == "--ready")
    {
        int total = int.Parse(Environment.GetEnvironmentVariable("TREEHAMMOCK_COMPOSE_READY_TIMEOUT_MS") ?? "60000");
        int attempt = int.Parse(Environment.GetEnvironmentVariable("TREEHAMMOCK_COMPOSE_ATTEMPT_TIMEOUT_MS") ?? "2000");
        if (total is < 1 or > 120000 || attempt < 1 || attempt > total) return 2;
        using CancellationTokenSource deadline = new(TimeSpan.FromMilliseconds(total));
        using HttpClientHandler handler = new() { AllowAutoRedirect = false };
        using HttpClient client = new(handler) { Timeout = TimeSpan.FromMilliseconds(attempt), MaxResponseContentBufferSize = 65536 };
        Stopwatch elapsed = Stopwatch.StartNew();
        while (!deadline.IsCancellationRequested)
        {
            try
            {
                using HttpResponseMessage response = await client.GetAsync(args[1].TrimEnd('/') + "/health/ready", deadline.Token);
                if ((int)response.StatusCode == 200 && elapsed.ElapsedMilliseconds < total) return 0;
            }
            catch (HttpRequestException) { }
            catch (OperationCanceledException) when (!deadline.IsCancellationRequested) { }
            await Task.Delay(250, deadline.Token);
        }
        return 2;
    }
    if (args.Length != 4 || args[0] != "--trx") return 2;
    string result = args[1], inventory = args[2], runId = args[3];
    if (!Guid.TryParse(runId, out _) || (File.GetAttributes(result) & FileAttributes.ReparsePoint) != 0) return 2;
    using JsonDocument index = JsonDocument.Parse(File.ReadAllText(inventory));
    // The System project also compiles the shared BuildIdentityProbe Fact via Compile Include.
    // Keep this current compiled surface aligned with host-system-proof.expected_tests.
    // The other current linked source (RegistrationVerificationAssertions.cs) has no attributed tests.
    var cases = index.RootElement.GetProperty("attributed_test_methods").EnumerateArray()
        .Where(x => x.GetProperty("path").GetString()!.StartsWith("treehammock.Tests.System/", StringComparison.Ordinal)
            || x.GetProperty("path").GetString() == "treehammock.Tests/Infrastructure/BuildIdentity.cs").ToArray();
    if (cases.Length == 0 || cases.Any(x => x.GetProperty("attribute").GetString() != "Fact")) return 2;
    HashSet<string> expected = cases.Select(x => x.GetProperty("method").GetString()!).ToHashSet(StringComparer.Ordinal);
    if (expected.Count != cases.Length) return 2;
    using XmlReader reader = XmlReader.Create(result, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 4000000 });
    XDocument document = XDocument.Load(reader); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
    XElement counters = document.Descendants(ns + "Counters").Single();
    foreach (string name in new[] { "total", "executed", "passed" }) if ((int?)counters.Attribute(name) != expected.Count) return 2;
    foreach (string name in new[] { "failed", "notExecuted" }) if ((int?)counters.Attribute(name) != 0) return 2;
    XElement[] results = document.Descendants(ns + "UnitTestResult").ToArray();
    if (results.Length != expected.Count || results.Any(x => (string?)x.Attribute("outcome") != "Passed"
        || string.IsNullOrWhiteSpace((string?)x.Attribute("executionId")))
        || results.Select(x => (string?)x.Attribute("executionId")).Distinct().Count() != results.Length) return 2;
    HashSet<string> observed = results.Select(x => ((string)x.Attribute("testName")!).Split('(')[0].Split('.').Last()).ToHashSet(StringComparer.Ordinal);
    if (!observed.SetEquals(expected)) return 2;
    Console.WriteLine(JsonSerializer.Serialize(new { schema_version = 1, run_id = runId, status = "Passed", executed_tests = results.Length, result_sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(result))).ToLowerInvariant() }));
    return 0;
}
catch
{
    Console.Error.WriteLine("Compose readiness or fresh result validation failed.");return 2;
}
