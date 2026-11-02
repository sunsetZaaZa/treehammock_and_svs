using System.Globalization;
using System.Text;
namespace Treehammock.SessionValidation.Api;
// Fixed labels and integer updates only. Exporters never run on the handler path.
internal sealed class Metrics
{
    private readonly long[] _decisions=new long[5],_buckets=new long[9];private long _micros;
    private static readonly string[] Decisions=["active","unauthenticated","forbidden","unavailable","refused"];
    private static readonly double[] Bounds=[.001,.005,.01,.025,.05,.1,.5,5];
    internal void Record(int decision,TimeSpan duration)
    {
        Interlocked.Increment(ref _decisions[decision is >=0 and <5?decision:4]);long micros=(long)Math.Max(0,duration.TotalMicroseconds);Interlocked.Add(ref _micros,micros);int bucket=0;while(bucket<Bounds.Length&&micros>Bounds[bucket]*1_000_000)bucket++;Interlocked.Increment(ref _buckets[bucket]);
    }
    internal string Render(OperationalHealth h)
    {
        var b=new StringBuilder(4096);void G(string n,bool v)=>b.Append(n).Append(' ').Append(v?'1':'0').Append('\n');
        G("svs_live",h.Live);G("svs_ready",h.Ready);G("svs_database_fallback_ready",h.DatabaseFallbackReady);G("svs_cache_ready",h.CacheReady);G("svs_refill_ready",h.RefillReady);G("svs_server_certificate_near_expiry",h.ServerCertificateNearExpiry);G("svs_clock_offset_known",h.ClockOffsetKnown);
        foreach(var s in ServiceConcurrencyLimiter.Totals())foreach(var v in new[]{("accepted_total",s.Accepted),("rejected_total",s.Rejected),("active",s.Active),("queued",0L)})b.Append("svs_capacity_").Append(v.Item1).Append("{stage=\"").Append(s.Name).Append("\"} ").Append(v.Item2.ToString(CultureInfo.InvariantCulture)).Append('\n');
        for(int i=0;i<Decisions.Length;i++)b.Append("svs_validation_handler_decisions_total{decision=\"").Append(Decisions[i]).Append("\"} ").Append(Interlocked.Read(ref _decisions[i]).ToString(CultureInfo.InvariantCulture)).Append('\n');
        long count=0;for(int i=0;i<_buckets.Length;i++){count+=Interlocked.Read(ref _buckets[i]);b.Append("svs_validation_handler_seconds_bucket{le=\"").Append(i<Bounds.Length?Bounds[i].ToString(CultureInfo.InvariantCulture):"+Inf").Append("\"} ").Append(count.ToString(CultureInfo.InvariantCulture)).Append('\n');}
        b.Append("svs_validation_handler_seconds_count ").Append(count.ToString(CultureInfo.InvariantCulture)).Append('\n');b.Append("svs_validation_handler_seconds_sum ").Append((Interlocked.Read(ref _micros)/1_000_000d).ToString(CultureInfo.InvariantCulture)).Append('\n');return b.ToString();
    }
}
