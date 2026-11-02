using Microsoft.Extensions.Options;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Observability;
namespace treehammock.Services;

// Independent bounded expiry cleanup; never resets a live admission window/cooldown.
public sealed class PostgreSqlAbuseBudgetCleanupWorker(IPostgreSqlAbuseBudgetStore budgets,
    IOptions<AbuseControlSettings> abuse, IOptions<RetentionSettings> retention, ILogger<PostgreSqlAbuseBudgetCleanupWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings=retention.Value;
        if (!settings.Enabled || abuse.Value.CounterFailureMode!=AbuseCounterFailureMode.RequirePostgreSqlBudgetV1) return;
        using var timer=new PeriodicTimer(TimeSpan.FromSeconds(settings.PollSeconds));
        do
        {
            try
            {
                int rows=await DependencyDeadline.RunAsync(ct=>budgets.PurgeExpiredAsync(settings.BatchSize,settings.DryRun,ct),TimeSpan.FromMilliseconds(abuse.Value.PostgreSqlBudgetTimeoutMilliseconds),stoppingToken);
                logger.LogInformation("Abuse budget expiry batch: dry_run={DryRun}, rows={Rows}",settings.DryRun,rows);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch { AbuseOperationalTelemetry.RecordCounterStoreFailure("budget_cleanup",AbuseReasonCodes.CounterStoreUnavailable,"postgresql"); }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
