using Treehammock.SessionValidation.Storage;
namespace Treehammock.SessionValidation.Api;

internal sealed class HostLifecycle(IHostResources resources, RequestLifetime requests, HostSettings settings) : IHostedService, IDisposable
{
    private readonly CancellationTokenSource _stop = new();
    private Task? _loop;
    private int _disposed;
    internal bool Live { get; private set; }
    internal bool Ready => Live && requests.Open && (resources is not IFleetResources f || f.Gate.Mode is treehammock.Rigging.Fleet.FleetMode.CoherentAdmitted or treehammock.Rigging.Fleet.FleetMode.DBOnlyIsolated) && (resources.DatabaseReady || resources.Admission.CacheReady);
    public async Task StartAsync(CancellationToken token)
    {
        await resources.AuditAsync(token);
        if (resources.LastAudit is DatabaseIdentityAuditStatus.Rejected or DatabaseIdentityAuditStatus.Quarantined) { resources.Admission.Quarantine(); requests.Close(); throw new InvalidOperationException("Database identity rejected."); }
        Live = true; _loop = LoopAsync();
    }
    private async Task LoopAsync()
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(settings.AuditIntervalMilliseconds));
            while (await timer.WaitForNextTickAsync(_stop.Token))
            {
                await resources.AuditAsync(_stop.Token);
                if (resources.LastAudit is DatabaseIdentityAuditStatus.Rejected or DatabaseIdentityAuditStatus.Quarantined) { resources.Admission.Quarantine(); requests.Close(); }
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch { resources.Admission.Quarantine(); requests.Close(); }
    }
    internal async Task StopAuditAsync(CancellationToken token)
    {
        Live=false;requests.Close();resources.Admission.Quarantine();await _stop.CancelAsync();
        if(_loop is not null)await _loop.WaitAsync(token);
        await resources.DrainAuditAsync(token);
    }
    public async Task StopAsync(CancellationToken token)
    {
        await StopAuditAsync(token);
        if(resources is IFleetResources fleet)fleet.Quarantine();
        var refill = resources is IFleetResources coherent ? coherent.DrainAsync(token) : resources.StopRefillAsync();
        await requests.DrainAsync(token);
        if (_loop is not null) await _loop.WaitAsync(token);
        await refill.WaitAsync(token);
    }
    public void Dispose() { if (Interlocked.Exchange(ref _disposed, 1) == 0) _stop.Dispose(); }
}
