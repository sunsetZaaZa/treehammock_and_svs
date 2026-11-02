namespace treehammock.Rigging.Abuse;

/// <summary>Bounded scripts; keys must be supplied explicitly. Existing standalone namespace is retained.</summary>
public static class AbuseCounterScripts
{
    public static readonly string CaptchaConsume = Read("captcha-consume-v1.lua");
    public static readonly string Increment = Read("increment-v1.lua");
    public static readonly string Cooldown = Read("cooldown-v1.lua");

    public static readonly string ProviderHealthAcquire = Read("provider-health-acquire-v1.lua");
    public static readonly string ProviderHealthComplete = Read("provider-health-complete-v1.lua");

    private static string Read(string name)
    {
        using var stream = typeof(AbuseCounterScripts).Assembly.GetManifestResourceStream("treehammock.AbuseScripts." + name)
            ?? throw new InvalidOperationException("Missing embedded abuse script: " + name);
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd();
    }
}
