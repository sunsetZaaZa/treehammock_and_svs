using treehammock.Repos;
namespace treehammock.Services;

public sealed class EntitlementRenewalWorker(EntitlementRepo repository, ILogger<EntitlementRenewalWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                deadline.CancelAfter(TimeSpan.FromSeconds(10));
                await repository.RenewAsync(deadline.Token);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch { logger.LogWarning("Entitlement cycle recording unavailable; request-time eligibility remains authoritative."); }
        }
    }
}
