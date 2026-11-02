using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text.Json;

try
{
    if (args.Length == 2 && args[0] == "--http")
    {
        using CancellationTokenSource deadline = new(TimeSpan.FromSeconds(120));
        using HttpClient client = new() { Timeout = TimeSpan.FromSeconds(3) };
        int live = 0, ready = 0;
        while (!deadline.IsCancellationRequested)
        {
            try
            {
                using HttpResponseMessage l = await client.GetAsync(args[1] + "/health/live", deadline.Token);
                using HttpResponseMessage r = await client.GetAsync(args[1] + "/health/ready", deadline.Token);
                live = (int)l.StatusCode; ready = (int)r.StatusCode;
                if (live == 200 && ready == 200)
                {
                    Console.WriteLine(JsonSerializer.Serialize(new { live, ready }));
                    return 0;
                }
            }
            catch (HttpRequestException) { }
            catch (OperationCanceledException) when (!deadline.IsCancellationRequested) { }
            await Task.Delay(1000, deadline.Token);
        }
        return 2;
    }
    if (args.Length != 7) return 2;
    string path = args[0], tag = args[1], version = args[2], assemblyVersion = args[3], sha = args[4], run = args[5], informational = args[6];
    using FileStream file = File.OpenRead(path);
    using PEReader pe = new(file);
    MetadataReader reader = pe.GetMetadataReader();
    AssemblyDefinition assembly = reader.GetAssemblyDefinition();
    if (reader.GetString(assembly.Name) != "treehammock" || assembly.Version.ToString() != assemblyVersion) return 2;
    Dictionary<string, string> metadata = new(StringComparer.Ordinal);
    string? fileVersion = null, info = null, configuration = null;
    foreach (CustomAttributeHandle handle in assembly.GetCustomAttributes())
    {
        CustomAttribute attribute = reader.GetCustomAttribute(handle);
        if (attribute.Constructor.Kind != HandleKind.MemberReference) continue;
        MemberReference constructor = reader.GetMemberReference((MemberReferenceHandle)attribute.Constructor);
        if (constructor.Parent.Kind != HandleKind.TypeReference) continue;
        TypeReference type = reader.GetTypeReference((TypeReferenceHandle)constructor.Parent);
        if (reader.GetString(type.Namespace) != "System.Reflection") continue;
        string name = reader.GetString(type.Name);
        if (name is not ("AssemblyMetadataAttribute" or "AssemblyFileVersionAttribute" or "AssemblyInformationalVersionAttribute" or "AssemblyConfigurationAttribute")) continue;
        BlobReader blob = reader.GetBlobReader(attribute.Value);
        if (blob.ReadUInt16() != 1) return 2;
        string? value = blob.ReadSerializedString();
        if (name == "AssemblyMetadataAttribute") metadata.Add(value!, blob.ReadSerializedString()!);
        else if (name == "AssemblyFileVersionAttribute") fileVersion = value;
        else if (name == "AssemblyInformationalVersionAttribute") info = value;
        else configuration = value;
    }
    if (fileVersion != assemblyVersion || FileVersionInfo.GetVersionInfo(path).FileVersion != assemblyVersion || info != informational || configuration != "Release") return 2;
    if (metadata["TreehammockReleaseTag"] != tag || metadata["TreehammockReleaseVersion"] != version || metadata["TreehammockReleasePackageVersion"] != version || metadata["TreehammockReleaseSourceSha"] != sha || metadata["TreehammockProofRunId"] != run) return 2;
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        tag, version, source_sha = sha, build_run_id = run,
        assembly_version = assembly.Version.ToString(), file_version = fileVersion,
        informational_version = info, configuration,
        mvid = reader.GetGuid(reader.GetModuleDefinition().Mvid).ToString(),
        sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant()
    }));
    return 0;
}
catch
{
    Console.Error.WriteLine("Release artifact inspection or runtime probe failed.");
    return 2;
}
