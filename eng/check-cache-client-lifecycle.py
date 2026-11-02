#!/usr/bin/env python3
"""COR23N supplemental source contracts; never substitutes for native lifecycle qualification."""
import argparse
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
OWNER = 'Rigging/Cache/CacheConnectionOwner.cs'
HEALTH = 'Rigging/Health/HealthDependencyService.cs'
DI = 'Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs'
def require(value, message):
    if not value:
        raise ValueError(message)
def validate(root):
    read = lambda path: (root/path).read_text()
    owner, health, di = read(OWNER), read(HEALTH), read(DI)
    for token in ['_settings = Snapshot(settings)', 'if (!_borrowed && _worker is null)',
                  'if (_disposed) throw new ObjectDisposedException(nameof(CacheConnectionSlot))',
                  'Math.Clamp(settings.reconnectRetryPolicy, 10u, 60000u)', 'Math.Min(60000L,',
                  'configuration.ConnectRetry = 0', 'Task.Delay(TimeSpan.FromMilliseconds(delay), _stop.Token)',
                  'if (_disposed) return;', 'if (disposeCandidate) candidate.Dispose()',
                  'if (!_borrowed) connection?.Dispose()', '_connection = null;',
                  'if (_disposal is not null) return new ValueTask(_disposal)',
                  'drain.WaitAsync(cancellationToken)', 'TaskContinuationOptions.OnlyOnFaulted',
                  'GetDiagnostics()', ':cor23n:{profile}:{instance}']:
        require(token in owner, 'Missing lifecycle boundary: '+token)
    require(owner.index('if (disposeCandidate) candidate.Dispose()') > owner.index('bool disposeCandidate;'), 'Late candidate disposal boundary absent')
    cleanup = owner[owner.index('private async Task DisposeCoreAsync'):]
    require('lock (_gate)' not in cleanup[:cleanup.index('catch (Exception ex)')], 'External cleanup cannot run under lifecycle lock')
    getter = owner[owner.index('public IConnectionMultiplexer Connection'):owner.index('internal int RetryDelayForFailure')]
    require('if (_disposed)' in getter, 'Disposed borrowed/owned slots must reject access')
    require('bool connected = !_disposed && _connection?.IsConnected' in owner and
            'return !_disposed && _connection?.IsConnected' in owner, 'Disposed slots cannot remain ready')
    require('private readonly CacheConnectionOwner _cacheConnections' in health, 'Health must borrow shared owner')
    require('ConnectionMultiplexer.Connect' not in health and 'PublicationOnly' not in health and 'new CacheConnectionSlot' not in health and 'connection.Dispose' not in health and '_cacheConnections.Dispose' not in health, 'Health cannot create/dispose cache clients')
    for role in ['ActiveSessions', 'TwoFactorSessions', 'AbuseCounters']:
        require('_cacheConnections.Get(CacheProfile.'+role+')' in health, 'Health must borrow role '+role)
    require('AddSingleton<CacheConnectionOwner>()' in di and 'AddHostedService(provider => provider.GetRequiredService<CacheConnectionOwner>())' in di, 'Host must own the same singleton')
    for service, role in [('ActiveUserCacheService', 'ActiveSessions'), ('TwoFactorSessionService', 'TwoFactorSessions'), ('DragonflyAbuseCounterStore', 'AbuseCounters'), ('DragonflyAuthenticatedMutationIdempotencyService', 'AbuseCounters')]:
        start = di.index('new '+service+'(')
        require('Get(CacheProfile.'+role+')' in di[start:di.index(';', start)], 'Consumer must borrow role '+service)
    for path in ['Rigging/Cache/ActiveUserCacheService.cs','Rigging/Cache/TwoFactorSessionService.cs','Rigging/Abuse/DragonflyAbuseCounterStore.cs','Rigging/Replay/AuthenticatedMutationIdempotency.cs']:
        require('_ownsSlot ? _slot.DisposeAsync()' in read(path), 'Consumer may dispose only a dedicated slot: '+path)
    require('FullyQualifiedName~Cor23NCacheOwnershipTests' in read('eng/correction-baseline.py'), 'Native real-cache lifecycle qualification must be mandatory')
    require('python3 eng/check-cache-client-lifecycle.py' in read('.github/workflows/treehammock-ci.yml'), 'CI lifecycle guard missing')
    require('cache-product: [redis, dragonfly]' in read('.github/workflows/treehammock-ci.yml') and
            '--cache-product ${{ matrix.cache-product }}' in read('.github/workflows/treehammock-ci.yml'), 'Both native cache products must be collected')
    require("choices=['redis', 'dragonfly']" in read('eng/correction-sql-fixture.py') and
            (root/'docker-compose.corrections.dragonfly.yml').exists(), 'Owned fixture product selection missing')
    for path in ['treehammock.Tests/Unit/CacheLifecycleTests.cs','treehammock.Tests/Integration/CacheHostTests.cs','treehammock.Tests.SqlContracts/Integration/Database/CacheOwnershipTests.cs']:
        require((root/path).is_file(), 'Native regression missing: '+path)
    return dict(status='SourceContractsConsistent', qualification='NotRun', logical_owned_roles=3,
                retry_floor_ms=10, retry_ceiling_ms=60000, health='borrows host-owned clients',
                native_required=['concurrent startup and real health probes', 'failure/backoff and recovery',
                                 'late initialization and canceled host wait', 'repeated hosts and scoped CLIENT LIST leak counts'])
def main():
    p = argparse.ArgumentParser(description=__doc__); p.add_argument('--root', type=Path, default=ROOT); args = p.parse_args()
    try:
        print(json.dumps(validate(args.root), indent=2)); return 0
    except (ValueError, OSError) as error:
        print(str(error)); return 1
if __name__ == '__main__':
    raise SystemExit(main())
