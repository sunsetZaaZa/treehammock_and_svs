using System.Diagnostics.CodeAnalysis;

using NodaTime;

using treehammock.RiggingSupport.Enum;

namespace treehammock.DataLayer;

public class ActivationQuery
{
    [SetsRequiredMembers]
    public ActivationQuery(FeatureSet featureSet, Instant expiration, DayDuration duration, DurationRepeat repeated)
    {
        (this.featureSet, this.expiration, this.duration, this.repeated) = 
        (featureSet, expiration, duration, repeated);
    }

    public required FeatureSet featureSet { get; set; }
    public required Instant expiration { get; set; }
    public required DayDuration duration { get; set; }
    public required DurationRepeat repeated { get; set; }
}
