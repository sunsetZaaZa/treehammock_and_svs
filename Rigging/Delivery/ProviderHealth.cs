using System.Security.Cryptography;
using System.Text;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using treehammock.Rigging.Abuse;
using treehammock.Rigging.Config;
using treehammock.Rigging.Dependencies;
using treehammock.Rigging.Cache;
namespace treehammock.Rigging.Delivery;
public enum ProviderHealthEvidence { Neutral, Healthy, Outage }
public enum DeliveryRoute { Smtp, Twilio, AwsSns }
public sealed record ProviderHealthPermit(bool Allowed,string Key,string Generation,int Slot,string Id,string Reason);
public interface IProviderHealthService
{
    Task<ProviderHealthPermit> AcquireAsync(DeliveryRoute route,CancellationToken token);
    Task CompleteAsync(ProviderHealthPermit permit,ProviderHealthEvidence evidence,CancellationToken token);
}
public sealed class NullProviderHealthService : IProviderHealthService
{
    public static NullProviderHealthService Instance { get; } = new();
    public Task<ProviderHealthPermit> AcquireAsync(DeliveryRoute route,CancellationToken token)=>Task.FromResult(new ProviderHealthPermit(true,"","",1,"","disabled"));
    public Task CompleteAsync(ProviderHealthPermit permit,ProviderHealthEvidence evidence,CancellationToken token)=>Task.CompletedTask;
}
public sealed class ProviderHealthService : IProviderHealthService
{
    private readonly IDatabase? _database;
    private readonly CacheConnectionSlot? _slot;
    private readonly ProviderHealthSettings _settings;
    private readonly string[] _keys;
    private readonly bool[] _emergency;
    private readonly TimeSpan _timeout;
    private static readonly Meter Meter=new("treehammock.delivery.health","1.0.0");
    private static readonly Counter<long> Events=Meter.CreateCounter<long>("treehammock_delivery_health_total");
    public ProviderHealthService(IOptions<ProviderHealthSettings> settings,IOptions<SMTPSettings> smtp,IOptions<SidewalkSettings> sms,IOptions<AbuseControlSettings> abuse,CacheConnectionSlot slot)
        :this(settings,smtp,sms,abuse,(IDatabase?)null){_slot=slot;}
    // Explicit database constructor is used by real-cache and isolated protocol fixtures.
    public ProviderHealthService(IOptions<ProviderHealthSettings> settings,IOptions<SMTPSettings> smtp,IOptions<SidewalkSettings> sms,IOptions<AbuseControlSettings> abuse,IDatabase? database)
    {
        var s=settings.Value;
        if(!ConfigurationValidation.TryValidate(s,out _))throw new ArgumentException("Invalid provider health settings.");
        _settings=new(){Enabled=s.Enabled,FailureThreshold=s.FailureThreshold,WindowSeconds=s.WindowSeconds,OpenSeconds=s.OpenSeconds,PermitSeconds=s.PermitSeconds,MaxInFlightPerRoute=s.MaxInFlightPerRoute};
        _emergency=[s.EmergencyEmailStop,s.EmergencySmsStop,s.EmergencySmsStop];
        var mail=smtp.Value;var text=sms.Value;
        _keys=[Key("smtp",s.SmtpScope+"|"+mail.SMTPQualifiedDomain.ToLowerInvariant()+"|"+mail.SMTPPort+"|"+mail.SMTPUsername),Key("twilio",s.TwilioScope+"|"+text.TwilioAccountSid),Key("aws-sns",s.AwsSnsScope)];
        _timeout=TimeSpan.FromMilliseconds(Math.Clamp(abuse.Value.DragonflyTimeoutMilliseconds,10,5000));_database=database;
    }
    private static string Key(string provider,string route)=>"delivery:health:v1:"+provider+":"+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(route)),0,16).ToLowerInvariant();
    private IDatabase Database=>_database??_slot!.Database;
    private void Metric(string key,string action)=>Events.Add(1,new KeyValuePair<string,object?>("provider",key.Split(':')[3]),new KeyValuePair<string,object?>("action",action));
    public async Task<ProviderHealthPermit> AcquireAsync(DeliveryRoute route,CancellationToken token)
    {
        token.ThrowIfCancellationRequested();int index=(int)route;if(index is <0 or >2)throw new ArgumentOutOfRangeException(nameof(route));
        string key=_keys[index];
        if(_emergency[index]){Metric(key,"emergency");return new(false,key,"",0,"","emergency");}
        if(!_settings.Enabled)return new(true,"","",1,"","disabled");
        try
        {
            var reply=await DependencyDeadline.RunAsync(_=>Database.ScriptEvaluateAsync(AbuseCounterScripts.ProviderHealthAcquire,[key],[_settings.WindowSeconds*1000,_settings.OpenSeconds*1000,_settings.PermitSeconds*1000,_settings.MaxInFlightPerRoute,Guid.NewGuid().ToString("N")]),_timeout,token);
            var values=(RedisResult[])reply;if(values.Length!=5)throw new InvalidOperationException("Invalid health reply.");
            bool allowed=(long)values[0]==1;int slot=checked((int)(long)values[2]);
            Metric(key,allowed?(slot==0?"probe":"allowed"):"blocked");
            return new(allowed,key,(string)values[1]!,slot,(string)values[3]!,allowed?"allowed":"circuit");
        }
        catch(OperationCanceledException) when(token.IsCancellationRequested){throw;}
        catch(Exception){Metric(key,"cache-unavailable");return new(false,key,"",0,"","cache-unavailable");}
    }
    public async Task CompleteAsync(ProviderHealthPermit permit,ProviderHealthEvidence evidence,CancellationToken token)
    {
        if(!permit.Allowed || permit.Key.Length==0)return;
        // Health reporting cannot replace an actual transport outcome, even after cancellation.
        try
        {
            var reply=await DependencyDeadline.RunAsync(_=>Database.ScriptEvaluateAsync(AbuseCounterScripts.ProviderHealthComplete,[permit.Key],[permit.Generation,permit.Slot,permit.Id,(int)evidence,Guid.NewGuid().ToString("N"),_settings.FailureThreshold,_settings.WindowSeconds*1000,_settings.OpenSeconds*1000,_settings.PermitSeconds*1000,_settings.MaxInFlightPerRoute]),_timeout,token);
            Metric(permit.Key,(long)reply==1?evidence switch {ProviderHealthEvidence.Outage=>"outage",ProviderHealthEvidence.Healthy=>"healthy",_=>"neutral"}:"stale");
        }
        catch(Exception){Metric(permit.Key,"report-unavailable");}
    }
}
