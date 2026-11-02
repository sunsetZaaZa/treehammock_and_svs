#!/usr/bin/env python3
"""Source guard only; actual host stop/provider disposal requires the compiled probe."""
import argparse,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
FLOW='treehammock.Tests/Integration/AccountFlowRegressionTests.cs'
PROBE='treehammock.Tests/Integration/AccountFlowRegressionTests.Lifecycle.cs'
def require(value,message):
    if not value:raise ValueError(message)
def validate(root=ROOT):
    source=(root/FLOW).read_text();probe=(root/PROBE).read_text()
    allocations=re.findall(r'(?m)^\s*(.*?)LoginTwoFactorHarness harness = BuildLoginTwoFactorHarness\(',source)
    require(len(allocations)==15 and all(prefix=='await using ' for prefix in allocations),'Every original harness must have an async scope')
    require(len(re.findall(r'using var factory\s*=\s*FlowFactory\(',source))==12,'Existing direct factory scopes changed')
    require('using var lateLoginFactory = FlowFactory(' in source,'Added final-output fixture must own its factory')
    for token in ['LoginTwoFactorHarness : IAsyncDisposable','lock (_disposalGate)','_disposeTask ??= DisposeFactoryAsync()','if (_factory is not null) await _factory.DisposeAsync();','using JsonDocument loginJson = await ReadJson(login);','using JsonDocument selectedJson = await ReadJson(selected);','Task<LoginSelection> LoginAndAssertSelectionRequired','async Task SelectLoginTwoFactorConfiguration','new LoginSelection(','if (request.IsCompletedSuccessfully) request.Result.Dispose();']:
        require(token in source,'Flow ownership boundary missing: '+token)
    require('Task<JsonDocument> LoginAndAssertSelectionRequired' not in source and 'Task<JsonDocument> SelectLoginTwoFactorConfiguration' not in source,'Helper still transfers a disposable document')
    require(not re.search(r'(?m)^\s*JsonDocument \w+ = await ReadJson\(',source),'Unscoped helper JSON document')
    require(source.index('using JsonDocument loginJson = await ReadJson(login);',source.index('private static async Task<LoginSelection>'))<source.index('AssertSuccessEnvelope(loginJson',source.index('private static async Task<LoginSelection>')),'JSON must be owned before an assertion can throw')
    for token in ['IHostedService, IDisposable, IAsyncDisposable','services.AddSingleton<IHostedService>(provider =>','lifetime.ApplicationStopping.Register','lifetime.ApplicationStopped.Register','observed.ShouldBeSameAs(original);','first.ShouldBeSameAs(second);','for (int iteration = 0; iteration < 12; iteration++)','probe.Attachments.ShouldBe(0);','Disposals.ShouldBe(1);','Stops.ShouldBe(1);','probes.Count(value => value.Starts != value.Stops || value.Attachments != value.Disposals).ShouldBe(0);']:
        require(token in probe,'Compiled host lifecycle observation missing: '+token)
    return dict(status='SourceContractsConsistent',qualification='NotRun',original_harness_scopes=15,preserved_direct_factory_scopes=12,native='Complete account-flow suite and in-process lifecycle probe required')
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);args=parser.parse_args()
    try:print(json.dumps(validate(args.root)));return 0
    except (OSError,ValueError):print('Account-flow ownership source contract failed.');return 1
if __name__=='__main__':raise SystemExit(main())
