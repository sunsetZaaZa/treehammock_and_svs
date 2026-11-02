using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using treehammock.Rigging.Observability;
namespace treehammock.Tests.Infrastructure;

// Tests using this process-wide meter run serially; metric values, not source strings, are the oracle.
internal sealed class Cor23PMetricCapture : IDisposable
{
    internal sealed record Measurement(string Name, long Value, IReadOnlyDictionary<string, string> Tags);
    internal readonly ConcurrentQueue<Measurement> Values = new();
    private readonly MeterListener _listener = new();
    internal Cor23PMetricCapture()
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == AbuseOperationalTelemetry.MeterName) listener.EnableMeasurementEvents(instrument);
        };
        _listener.SetMeasurementEventCallback<long>((instrument, value, tags, state) =>
            Values.Enqueue(new(instrument.Name, value, tags.ToArray().ToDictionary(t => t.Key, t => t.Value?.ToString() ?? "null"))));
        _listener.Start();
    }
    internal long Sum(string name, string? outcome = null, string? dependency = null) => Values
        .Where(m => m.Name == name && (outcome is null || m.Tags.GetValueOrDefault("outcome") == outcome)
            && (dependency is null || m.Tags.GetValueOrDefault("dependency") == dependency)).Sum(m => m.Value);
    public void Dispose() => _listener.Dispose();
}
