#!/usr/bin/env python3
"""COR23O source contracts only; native timing, adapters, callbacks and recovery remain qualification obligations."""
import argparse,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
HEALTH='Rigging/Health/HealthDependencyService.cs'
def require(value,message):
 if not value:raise ValueError(message)
def validate(root):
 read=lambda path:(root/path).read_text()
 health=read(HEALTH);settings=read('Rigging/Config/HealthProbeSettings.cs')
 for token in ['[Range(50, 5000)]','[Range(10, 5000)]','[Range(10, 1000)]','DependencyTimeoutMilliseconds > TotalTimeoutMilliseconds']:
  require(token in settings,'Invalid/unbounded readiness configuration: '+token)
 for token in ['_settings = new()','cancellationToken.ThrowIfCancellationRequested();','if (_flight is null || _flight.IsCompleted)',
  'slot.Work is { IsCompleted: false }','work = slot.Work = Task.Run','DependencyDeadline.Observe(work)',
  'flight.WaitAsync(TimeSpan.FromMilliseconds(_settings.TotalTimeoutMilliseconds), _clock, cancellationToken)',
  'work.WaitAsync(TimeSpan.FromMilliseconds(budget), _clock)','Task.WhenAll(probes)',
  'remaining <= 0','Elapsed(admitted) >= budget','budget - Elapsed(queued)','Age(_sample) < _settings.SampleMaxAgeMilliseconds',
  'Age(sample) >= _settings.SampleMaxAgeMilliseconds','duration >= _settings.TotalTimeoutMilliseconds',
  '"probe_in_progress"','"stale_sample"','"readiness_deadline"','Array.AsReadOnly(results)',
  'await cancellation.ConfigureAwait(false)','await operation.CancelAsync().ConfigureAwait(false)',
  'finished.Token, _shutdown.Token','sampledAtUtc','GetDiagnostics()']:
  require(token in health,'Missing readiness ownership/deadline boundary: '+token)
 owned=health[health.index('private async Task<bool> ProbeOwnedAsync'):health.index('private async Task CancelProbeAsync')]
 require('await cancellation.ConfigureAwait(false)' in owned,'Probe cannot retire before cancellation callbacks finish')
 check=health[health.index('public async Task<HealthDependencyReport> CheckAsync'):health.index('private async Task<Sample> RunSampleAsync')]
 require(check.index('cancellationToken.ThrowIfCancellationRequested')<check.index('Task.Run'),'Pre-canceled request must not create a sample')
 require('_client.ProbeAsync(dependency, operation.Token)' in health,'Providers must receive isolated operation cancellation')
 postgres=health[health.index('private async Task<bool> PostgreSql'):health.index('private static async Task<bool> Cache')]
 require('await storage.CreateConnection(cancellationToken)' in postgres and 'command.ExecuteScalarAsync(cancellationToken)' in postgres,'SQL acquisition and command must receive the probe token')
 require(postgres.index('cancellationToken.ThrowIfCancellationRequested(); // A late acquisition')<postgres.index('connection.CreateCommand()'),'Late acquisition cannot start a new command')
 require('await using DbConnection' in postgres and 'await using DbCommand' in postgres,'SQL resources must be disposed through raw task completion')
 require('connection.Database.PingAsync()' in health and 'connection.ExecuteAsync' not in health,'Own RAW Redis PING rather than a shorter wait task')
 require('_cacheConnections.Dispose' not in health and 'connection.DisposeAsync' not in health,'Sampler cannot dispose borrowed cache clients')
 require('new HealthProbeSettings' not in check,'Request cannot reset/read mutable readiness budgets')
 di=read('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs')
 for token in ['AddValidatedOptions<HealthProbeSettings>','sectionName == "HealthProbeSettings"','AddSingleton<HealthDependencyService>()','AddHostedService(provider => provider.GetRequiredService<HealthDependencyService>())']:
  require(token in di,'Validated singleton/host ownership missing: '+token)
 response=read('Models/Api/HealthStatusResponse.cs')
 for token in ['sampledAtUtc','sampleAgeMilliseconds','sampleDurationMilliseconds','freshnessLimitMilliseconds','cached']:
  require(token+' { get; }' in response,'HTTP sample metadata missing: '+token)
 controller=read('Controllers/HealthController.cs');live=controller[controller.index('public ActionResult<HealthStatusResponse> Live'):controller.index('[HttpGet("ready")')]
 require('_healthDependencyService.CheckAsync' not in live,'Liveness must remain dependency free')
 require('ResponseCache(NoStore = true' in controller,'Probe reports cannot be cached by intermediaries')
 for path in root.glob('appsettings*.json'):
  config=json.loads(path.read_text())['HealthProbeSettings'];require(config==dict(TotalTimeoutMilliseconds=2000,DependencyTimeoutMilliseconds=500,SampleMaxAgeMilliseconds=250),'Profile readiness defaults drifted: '+path.name)
 for path in ['deploy/haproxy/haproxy.cfg','deploy/haproxy/haproxy.host-system.cfg']:
  require('timeout check 6s' in read(path),'Readiness requires an explicit deployment check deadline')
 for path in ['treehammock.Tests/Unit/ReadinessTests.cs','treehammock.Tests/Unit/ProbeAdapterTests.cs','treehammock.Tests/Integration/ReadinessHttpTests.cs','treehammock.Tests.SqlContracts/Integration/Database/ReadinessBudgetTests.cs']:
  require((root/path).exists(),'Native regression missing: '+path)
 require('FullyQualifiedName~Cor23OReadinessBudgetTests' in read('eng/correction-baseline.py'),'SQL/cache readiness qualification must be mandatory')
 require('python3 eng/check-readiness-probes.py' in read('.github/workflows/treehammock-ci.yml'),'CI readiness guard missing')
 return dict(status='SourceContractsConsistent',qualification='NotRun',sample_flight_limit=1,raw_operation_limit_per_dependency=1,
  required_dependencies=4,defaults=dict(total_ms=2000,dependency_ms=500,completed_sample_age_ms=250),
  meaning='Connectivity only; PostgreSQL and all three cache roles required; no schema/write permission claim',
  native_required=['hung acquisition/command/PING and blocked cancellation callbacks','parallel phase/total deadline matrix','late cleanup and real one-slot pool recovery','HTTP freshness/no-store and Redis/Dragonfly recovery'])
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
 try:print(json.dumps(validate(a.root),indent=2));return 0
 except(ValueError,OSError,KeyError) as error:print(str(error));return 1
if __name__=='__main__':raise SystemExit(main())
