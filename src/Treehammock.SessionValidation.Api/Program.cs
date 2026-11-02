namespace Treehammock.SessionValidation.Api;
public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is not ["--config", var path]) throw new ArgumentException();
            await using var app = SvsHost.Build(HostSettings.Load(path)); await app.RunAsync(); return 0;
        }
        catch { Console.Error.WriteLine("SVS host startup or shutdown rejected."); return 1; }
    }
}
