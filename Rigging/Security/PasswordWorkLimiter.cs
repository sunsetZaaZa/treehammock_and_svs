using Microsoft.Extensions.Options;
using treehammock.Rigging.Config;

namespace treehammock.Rigging.Security;

public sealed class PasswordWorkBusyException : Exception
{
    public const string Code = "PASSWORD_WORK_UNAVAILABLE";
    public PasswordWorkBusyException() : base(Code) { }
}

public sealed record PasswordWorkSnapshot(int Active, int Queued, long ReservedMemoryBytes, int ReservedCpu,
    int PeakActive, int PeakQueued, long PeakReservedMemoryBytes, long Started, long Rejected);

/// <summary>FIFO bounded admission; native work keeps its lease until it actually finishes.</summary>
public sealed class PasswordWorkLimiter
{
    internal static PasswordWorkLimiter SharedDefault { get; } = new(Options.Create(new LoginSettings()));
    private readonly PasswordWorkSettings _settings;
    private readonly object _gate = new();
    private readonly LinkedList<Waiter> _queue = new();
    private int _active, _cpu, _peakActive, _peakQueued;
    private long _memory, _peakMemory, _started, _rejected;
    private sealed class Waiter(int memory, int cpu)
    {
        public readonly int Memory = memory, Cpu = cpu;
        public readonly TaskCompletionSource<Lease> Completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public LinkedListNode<Waiter>? Node;
    }
    private sealed class Lease(PasswordWorkLimiter owner, int memory, int cpu) : IDisposable
    {
        private int _released;
        public void Dispose() { if (Interlocked.Exchange(ref _released, 1) == 0) owner.Release(memory, cpu); }
    }
    public PasswordWorkLimiter(IOptions<LoginSettings> settings)
    {
        _settings = settings.Value.PasswordWork;
        Validator(_settings);
    }
    private static void Validator(PasswordWorkSettings settings)
        => System.ComponentModel.DataAnnotations.Validator.ValidateObject(settings, new(settings), true);
    public PasswordWorkSnapshot Snapshot
    {
        get { lock (_gate) return new(_active, _queue.Count, _memory, _cpu, _peakActive, _peakQueued, _peakMemory, _started, _rejected); }
    }
    public async Task<T> RunAsync<T>(Func<T> work, int memoryBytes, int parallelism = 1, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var lease = await AcquireAsync(memoryBytes, parallelism, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        // Do not abandon this task or release its memory/CPU on caller timeout. Argon2's
        // native operation has no cancellation API. Only admitted work enters Task.Run.
        T result = await Task.Run(work, CancellationToken.None).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }
    private async Task<Lease> AcquireAsync(int memory, int cpu, CancellationToken caller)
    {
        Waiter waiter;
        lock (_gate)
        {
            if (memory < 1 || cpu < 1 || memory > _settings.MemoryBudgetBytes || cpu > _settings.CpuBudget)
            { _rejected++; throw new PasswordWorkBusyException(); }
            if (_queue.Count == 0 && Fits(memory, cpu)) return Grant(memory, cpu);
            if (_queue.Count >= _settings.MaxQueuedOperations) { _rejected++; throw new PasswordWorkBusyException(); }
            waiter = new(memory, cpu); waiter.Node = _queue.AddLast(waiter);
            _peakQueued = Math.Max(_peakQueued, _queue.Count);
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(caller);
        deadline.CancelAfter(_settings.QueueTimeoutMilliseconds);
        using var registration = deadline.Token.Register(() =>
        {
            lock (_gate)
            {
                if (waiter.Node?.List is null) return;
                _queue.Remove(waiter.Node); waiter.Node = null; _rejected++;
                if (caller.IsCancellationRequested) waiter.Completion.TrySetCanceled(caller);
                else waiter.Completion.TrySetException(new PasswordWorkBusyException());
                Drain();
            }
        });
        return await waiter.Completion.Task.ConfigureAwait(false);
    }
    private bool Fits(int memory, int cpu) => _active < _settings.MaxActiveOperations
        && _memory + memory <= _settings.MemoryBudgetBytes && _cpu + cpu <= _settings.CpuBudget;
    private Lease Grant(int memory, int cpu)
    {
        _active++; _memory += memory; _cpu += cpu; _started++;
        _peakActive = Math.Max(_peakActive, _active); _peakMemory = Math.Max(_peakMemory, _memory);
        return new(this, memory, cpu);
    }
    private void Drain()
    {
        while (_queue.First is { } node && Fits(node.Value.Memory, node.Value.Cpu))
        {
            var waiter = node.Value; _queue.RemoveFirst(); waiter.Node = null;
            waiter.Completion.SetResult(Grant(waiter.Memory, waiter.Cpu));
        }
    }
    private void Release(int memory, int cpu)
    {
        lock (_gate) { _active--; _memory -= memory; _cpu -= cpu; Drain(); }
    }
}
