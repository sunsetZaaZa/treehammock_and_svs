namespace treehammock.Rigging.Config;

public sealed class SystemTestSettings
{
    public bool Enabled { get; set; }
    public bool EnableTestInspectionEndpoints { get; set; }
    public string TestKey { get; set; } = string.Empty;
}
