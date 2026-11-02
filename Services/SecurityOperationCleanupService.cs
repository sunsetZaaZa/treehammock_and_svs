using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;

namespace treehammock.Services;

public sealed class SecurityOperationCleanupService(SecurityOperationService operations,
    IOptions<SecurityOperationSettings> settings, ILogger<SecurityOperationCleanupService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(settings.Value.CleanupIntervalSeconds));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try { await operations.PurgeAsync(stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch { logger.LogWarning("Security operation cleanup unavailable; retained receipts remain authoritative."); }
        }
    }
}
