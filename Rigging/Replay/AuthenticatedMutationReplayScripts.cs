namespace treehammock.Rigging.Replay;

public static class AuthenticatedMutationReplayScripts
{
    public static readonly string Reserve = Read("reserve-v2.lua");
    public static readonly string Complete = Read("complete-v2.lua");
    public static readonly string Renew = Read("renew-v2.lua");
    private static string Read(string name)
    {
        using var stream = typeof(AuthenticatedMutationReplayScripts).Assembly.GetManifestResourceStream("treehammock.ReplayScripts." + name)
            ?? throw new InvalidOperationException("Missing replay script: " + name);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
