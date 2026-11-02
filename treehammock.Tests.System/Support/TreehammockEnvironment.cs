namespace treehammock.Tests.System.Support;

internal static class TreehammockEnvironment
{
    public static string GetValue(string name, string defaultValue)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        return defaultValue;
    }
}
