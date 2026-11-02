using treehammock.Rigging.Abuse;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using treehammock.Repos;
using treehammock.Rigging.Config;
using treehammock.Rigging.Delivery;
namespace treehammock.Services;

public sealed class DeliveryOutboxWorker(DeliveryOutboxRepo repo,DeliveryPayloadProtector protector,
    IDeliveryProvider provider,IOptions<DeliveryOutboxSettings> options,IDeliveryAbuseThrottleService throttle,ILogger<DeliveryOutboxWorker> logger, DeliveryExecutionPolicy? execution=null) : BackgroundService
{
    private readonly DeliveryOutboxSettings _settings=options.Value;
    private readonly DeliveryExecutionPolicy _execution=execution??new(options);
    private readonly SemaphoreSlim _iteration=new(1,1);
    public async Task<bool> ProcessOnceAsync(CancellationToken stopping)
    {
        await _iteration.WaitAsync(stopping);
        try {return await ProcessCoreAsync(stopping);}finally {_iteration.Release();}
    }
    private async Task<bool> ProcessCoreAsync(CancellationToken stopping)
    {
        using var acquire=CancellationTokenSource.CreateLinkedTokenSource(stopping);
        acquire.CancelAfter(TimeSpan.FromSeconds(5));
        var job=await repo.ClaimAsync(acquire.Token);if(job is null)return false;
        if(job.State is "expired" or "superseded" or "ambiguous")return true;
        if(job.State=="accepted") { await repo.PublishAsync(job.Delivery.Id,acquire.Token);return true; }
        DeliverySendResult result;DeliveryPayload? payload=null;
        try
        {
            payload=protector.Open(job.Delivery);
        }
        catch {result=new(DeliverySendState.NotSubmitted,"DELIVERY_INVALID_ENVELOPE");return await PersistAsync(job,result,null);}
        var sendingPayload=payload;
        result=await _execution.RunAsync(stopping,async budget =>
        {
            if(!await budget.CheckAuthorityAsync())return new DeliverySendResult(DeliverySendState.NotSubmitted,"DELIVERY_NOT_STARTED");
            return (await provider.SendAsync(job.LeaseId!.Value,sendingPayload,budget.Token)).Normalize();
        },()=>new DeliverySendResult(DeliverySendState.NotSubmitted,"DELIVERY_NOT_STARTED",true),
          ()=>new DeliverySendResult(DeliverySendState.Unknown,"DELIVERY_ACCEPTANCE_UNKNOWN"),
          new DateTimeOffset(job.Delivery.ExpiresAt.ToDateTimeUtc()),token=>repo.CanSendAsync(job,token),
          late=>PersistLateAsync(job,late.Normalize()));
        return await PersistAsync(job,result,payload);
    }
    private async Task PersistLateAsync(DeliveryJob job,DeliverySendResult result)
    {
        if(result.State is not (DeliverySendState.Accepted or DeliverySendState.Rejected))return;
        using var persist=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        if(await repo.RecordAsync(job,result,persist.Token) && result.State==DeliverySendState.Accepted)await repo.PublishAsync(job.Delivery.Id,persist.Token);
    }
    private async Task<bool> PersistAsync(DeliveryJob job,DeliverySendResult result,DeliveryPayload? payload)
    {
        /* provider exceptions are ambiguous; envelope rejection happens before sending. */
        // Once sending started, caller shutdown/timeout cannot imply safe rejection.
        // Leave the claim for SQL ambiguity reconciliation if this bounded write fails.
        using var persist=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        if(!await repo.RecordAsync(job,result,persist.Token))return true;
        if(result.State==DeliverySendState.Accepted)await repo.PublishAsync(job.Delivery.Id,persist.Token);
        else if(payload is not null)
        {
            var feature=job.Delivery.Purpose switch {"verify"=>AbuseFeature.Activation,"unlock"=>AbuseFeature.AccountUnlock,"reset" or "reset-factor"=>AbuseFeature.PasswordResetRequest,_=>AbuseFeature.Delivery};
            try { await throttle.RecordProviderFailureAsync(new(feature,payload.Channel,job.Delivery.AccountId,DeliveryAbuseThrottleService.SafeDestination(payload.Channel,payload.Destination)),persist.Token); }
            catch(Exception error) { logger.LogWarning("Delivery failure counter unavailable ({ErrorType})",error.GetType().Name); }
        }
        return true;
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while(!stoppingToken.IsCancellationRequested)
        {
            try { if(await ProcessOnceAsync(stoppingToken))continue; }
            catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested) { break; }
            catch(Exception error) { logger.LogWarning("Delivery worker operation unavailable ({ErrorType})",error.GetType().Name); }
            try { await Task.Delay(TimeSpan.FromSeconds(_settings.PollSeconds),stoppingToken); }
            catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
