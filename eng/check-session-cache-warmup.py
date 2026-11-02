#!/usr/bin/env python3
"""Supplemental warmup source boundaries; never substitutes for C#/SQL/cache qualification."""
import argparse
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
WORKER = 'Services/SessionCacheWarmupWorker.cs'
REPO = 'Repos/SessionCacheWarmupRepo.cs'
CACHE = 'Rigging/Cache/ActiveUserCacheService.cs'
SETTINGS = 'Rigging/Config/SessionCacheWarmupSettings.cs'
DI = 'Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs'

def validate(root):
    def require(ok, message):
        if not ok: raise ValueError(message)
    read = lambda p: (root/p).read_text()
    worker, repo, cache, settings, di = map(read, [WORKER, REPO, CACHE, SETTINGS, DI])
    warm = cache[cache.index('public async Task<bool> WarmSession'):cache.index('public async Task<bool> RevokeSession')]
    for token in ['When.NotExists', 'CommandFlags.PreferMaster', 'expire <= TimeSpan.Zero', 'AccountSecurityStampGuard.Require', '_slot.ExecuteAsync']:
        require(token in warm, 'Missing insert-only cache boundary: '+token)
    require('AddValidatedOptions<SessionCacheWarmupSettings>(configuration, "SessionCacheWarmupSettings")' in di and
            'AddSingleton<ISessionCacheWarmupRepo, SessionCacheWarmupRepo>()' in di and
            'AddHostedService<SessionCacheWarmupWorker>()' in di, 'Warmup must be validated and host-owned')
    for token in ['if (!_settings.Enabled) return', 'await Task.Yield()', 'lifetime.CancelAfter',
                  'batch.CancelAfter', 'WarmBatchAsync(batch.Token)', 'Task.Delay(TimeSpan.FromSeconds(_settings.IntervalSeconds), lifetime.Token)',
                  'hashes.Count > _settings.BatchSize', 'sessions.GetSession(hash, cancellationToken)',
                  'SessionProtocol.FromSession(stored)', 'cache.WarmSession(hash, session, ttl, cancellationToken)',
                  'session.entitlements?.IsCurrent', 'session.accessExpiration < expiry', 'session.EffectiveSessionExpiration < expiry',
                  'session.entitlements.NextBoundary', 'now + configured < expiry', 'Duration.FromSeconds(ttlSeconds)',
                  'hashes.Count < _settings.BatchSize', '_afterHash = hash']:
        require(token in worker, 'Missing worker boundary: '+token)
    require(worker.index('_afterHash = hash') > worker.index('await cache.WarmSession'), 'Cursor cannot abandon interrupted entries')
    for token in ['limit @limit', 'order by s.access_token_hash', 's.access_token_hash > @afterHash',
                  's.account_security_stamp = a.security_stamp', 'a.verify_status = 1', 'a.unlock_when',
                  's.access_expiration > clock_timestamp()', 's.session_expiration > clock_timestamp()',
                  's.cut_off', 'a.cut_off', 's.session_lifespan is not null', 's.protocol_version = 2',
                  'await using var connection', 'ExecuteReaderAsync(cancellationToken)', 'ReadAsync(cancellationToken)']:
        require(token in repo, 'Missing database candidate boundary: '+token)
    for token in ['[Range(1, 1000)]', '[Range(1, 3600)]', '[Range(0, 86400)]', '[Range(1, 86400)]', '[Range(100, 30000)]']:
        require(token in settings, 'Warmup settings bounds missing: '+token)
    for code in [worker, repo]:
        require('ConnectionMultiplexer.Connect' not in code and 'new StorageContext' not in code and 'Task.WhenAll' not in code,
                'Warmup cannot create clients or unbounded concurrency')
    middleware = read('Rigging/Authentication/JsonWebTokenMiddleware.cs')
    require('else if (!await ValidateCachedSessionTrust(' in middleware, 'Cache warmup must retain request-time authority')
    for p in root.glob('appsettings*.json'):
        require(json.loads(p.read_text())['SessionCacheWarmupSettings']['Enabled'] is False, 'Warmup must remain opt-in: '+p.name)
    require('FullyQualifiedName~SessionCacheWarmupSqlTests' in read('eng/correction-baseline.py'), 'Real SQL/cache cases must be collected')
    require('python3 eng/check-session-cache-warmup.py' in read('.github/workflows/treehammock-ci.yml'), 'CI warmup guard missing')
    for key in ['Enabled', 'BatchSize', 'IntervalSeconds', 'DurationSeconds', 'CacheTtlSeconds', 'BatchTimeoutMilliseconds']:
        require('SessionCacheWarmupSettings__'+key in read('deploy/session-cache-warmup.env.example') and
                'SessionCacheWarmupSettings__'+key in read('docker-compose.integration.yml'), 'Deployment knob missing: '+key)
    require((root/'treehammock.Tests/Unit/SessionCacheWarmupTests.cs').is_file() and
            (root/'treehammock.Tests.SqlContracts/Integration/Database/SessionCacheWarmupSqlTests.cs').is_file(), 'Native regressions missing')
    return dict(status='SourceContractsConsistent', qualification='NotRun', native_cases_executed=0,
                scope='Supplemental source checks only', schema_changes=False)

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
    try: print(json.dumps(validate(args.root),indent=2));return 0
    except (ValueError,OSError,KeyError) as error: print(str(error));return 1
if __name__=='__main__': raise SystemExit(main())
