using System.ComponentModel.DataAnnotations;
namespace treehammock.Rigging.Config;

public sealed class HealthProbeSettings : IValidatableObject
{
    [Range(50, 5000)] public int TotalTimeoutMilliseconds { get; set; } = 2000;
    [Range(10, 5000)] public int DependencyTimeoutMilliseconds { get; set; } = 500;
    [Range(10, 1000)] public int SampleMaxAgeMilliseconds { get; set; } = 250;
    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (DependencyTimeoutMilliseconds > TotalTimeoutMilliseconds)
            yield return new("Dependency timeout cannot exceed the total readiness timeout.", [nameof(DependencyTimeoutMilliseconds)]);
    }
}
