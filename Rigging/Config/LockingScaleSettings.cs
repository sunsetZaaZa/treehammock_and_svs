using NodaTime;

namespace treehammock.Rigging.Config;

public class LockingScaleSettings
{
    public int loginLow { get; set; } = 4;
    public Period loginLowTime { get; set; } = Period.Zero;


}
