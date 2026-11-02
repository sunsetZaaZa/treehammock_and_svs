using Npgsql;
namespace Treehammock.SessionValidation.Api;

// Per-replica ceilings plus an explicit shared SQL planning envelope. The writer's
// pool is never reconfigured; its declared reserve must match the operator's fleet.
public sealed class CapacitySettings
{
    public int ForegroundSqlOperations { get; init; } = 1;
    public int CacheReadOperations { get; init; } = 32;
    public int RawCacheOperations { get; init; } = 256;
    public int ReplicaCount { get; init; } = 2;
    public int WriterConnectionReserve { get; init; } = 16;
    public int TotalSqlConnectionBudget { get; init; } = 64;
    internal void Validate(HostSettings host)
    {
        if(ForegroundSqlOperations is <1 or >15 || CacheReadOperations is <1 or >1024 || RawCacheOperations is <1 or >2048 ||
           ReplicaCount is <1 or >64 || WriterConnectionReserve is <1 or >4096 || TotalSqlConnectionBudget is <4 or >16384)
            throw new ArgumentException("Explicit bounded service capacity required.");
        var foreground=new NpgsqlConnectionStringBuilder(host.DatabaseConnectionString);
        int refill=host.Refill is null?0:new NpgsqlConnectionStringBuilder(host.Refill.DatabaseConnectionString).MaxPoolSize;
        if(ForegroundSqlOperations+1>foreground.MaxPoolSize || RawCacheOperations<CacheReadOperations+(host.Refill?.Workers??0)+2 ||
           checked(ReplicaCount*(foreground.MaxPoolSize+refill)+WriterConnectionReserve)>TotalSqlConnectionBudget)
            throw new ArgumentException("Capacity must reserve audit, refill, and writer connections within the declared fleet envelope.");
    }
    public override string ToString()=>nameof(CapacitySettings);
}
