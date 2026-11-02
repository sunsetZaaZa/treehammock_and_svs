using treehammock.Rigging.Health;

namespace treehammock.Models.Api;

public sealed class HealthStatusResponse
{
    public HealthStatusResponse(string status)
        : this(status, Array.Empty<HealthDependencyResult>())
    {
    }

    public HealthStatusResponse(string status, IReadOnlyList<HealthDependencyResult> dependencies)
    {
        this.status = status;
        this.dependencies = dependencies;
    }

    public string status { get; }

    public IReadOnlyList<HealthDependencyResult> dependencies { get; }

    public DateTimeOffset? sampledAtUtc { get; }
    public long? sampleAgeMilliseconds { get; }
    public long? sampleDurationMilliseconds { get; }
    public int? freshnessLimitMilliseconds { get; }
    public bool? cached { get; }

    private HealthStatusResponse(HealthDependencyReport report) : this(report.Status, report.dependencies)
    {
        sampledAtUtc = report.sampledAtUtc; sampleAgeMilliseconds = report.sampleAgeMilliseconds;
        sampleDurationMilliseconds = report.sampleDurationMilliseconds;
        freshnessLimitMilliseconds = report.freshnessLimitMilliseconds; cached = report.cached;
    }
    public static HealthStatusResponse FromReport(HealthDependencyReport report)
    {
        return new HealthStatusResponse(report);
    }
}
