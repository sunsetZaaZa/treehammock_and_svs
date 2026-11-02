using System.Diagnostics;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.Options;
using Npgsql;
using treehammock.Repos;
using treehammock.Rigging.Config;
namespace treehammock.Services;

public sealed class RetentionWorker(RetentionRepo repo, IOptions<RetentionSettings> options,
    ILogger<RetentionWorker> logger) : BackgroundService
{
    private static readonly Meter Meter = new("Treehammock.Retention", "1.0");
    private static readonly Counter<long> Batches = Meter.CreateCounter<long>("retention.batches");
    private static readonly Counter<long> Failures = Meter.CreateCounter<long>("retention.failures");
    private static readonly Histogram<double> Duration = Meter.CreateHistogram<double>("retention.duration", "ms");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = options.Value;
        if (!settings.Enabled) return;
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(settings.PollSeconds));
        do
        {
            RetentionClaim? claim = null;
            var start = Stopwatch.GetTimestamp();
            try
            {
                using var budget = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                budget.CancelAfter(TimeSpan.FromSeconds(15));
                claim = await repo.ClaimAsync(budget.Token);
                if (claim is null) continue;
                var outcome = await repo.RunAsync(claim, settings, budget.Token);
                Batches.Add(1, new KeyValuePair<string, object?>("job", claim.Job), new("dry_run", settings.DryRun));
                Duration.Record(Stopwatch.GetElapsedTime(start).TotalMilliseconds, new KeyValuePair<string, object?>("job", claim.Job));
                logger.LogInformation("Retention {Job}: dry_run={DryRun}, eligible={Eligible}, affected={Affected}, wrapped={Wrapped}",
                    claim.Job, settings.DryRun, outcome.Eligible, outcome.Affected, outcome.Wrapped);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                string code = ex is PostgresException pg ? pg.SqlState : ex is OperationCanceledException ? "deadline" : "dependency";
                Failures.Add(1, new KeyValuePair<string, object?>("job", claim?.Job ?? "claim"));
                // No exception text, row identities, SQL parameters or secrets in telemetry.
                logger.LogWarning("Retention {Job} failed: {Code}; lease/cursor remains recoverable", claim?.Job ?? "claim", code);
                if (claim is not null)
                {
                    try
                    {
                        using var recovery = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                        recovery.CancelAfter(TimeSpan.FromSeconds(5));
                        await repo.RecordFailureAsync(claim, code, recovery.Token);
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                    catch { logger.LogWarning("Retention failure recording unavailable; expired lease will recover"); }
                }
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
