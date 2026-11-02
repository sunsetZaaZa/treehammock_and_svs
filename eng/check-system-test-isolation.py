#!/usr/bin/env python3
"""COR23D supplemental source/config guard. Does not compile or qualify host/HTTP behavior."""
import argparse
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]

def require(condition, message):
    if not condition:
        raise ValueError(message)

def validate(root):
    capability = (root/'Rigging/Hosting/SystemTestCapability.cs').read_text()
    require('private SystemTestCapability(' in capability, 'Capability must be immutable and startup-owned')
    require('settings.Enabled && !string.Equals(environment?.EnvironmentName, EnvironmentName, StringComparison.Ordinal)' in capability
            and 'EnvironmentName = "Testing"' in capability, 'Only exact Testing may enable capabilities')
    require('!settings.Enabled && (settings.EnableTestInspectionEndpoints || !string.IsNullOrEmpty(settings.TestKey))' in capability,
            'Disabled inspection/key combinations must fail closed')
    require('CryptographicOperations.FixedTimeEquals' in capability and 'supplied.Count != 1' in capability,
            'Inspection must reject multiple keys and compare digests')
    composition = (root/'Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs').read_text()
    start = composition.index('if (systemTestCapability.CaptureEnabled)')
    end = composition.index('\n        else', start)
    branch = composition[start:end]
    for interface, provider in [('ISystemTestDeliveryCapture','SystemTestDeliveryCapture'),('ISMTPService','SystemTestSmtpService'),('ISmsSender','SystemTestSmsSender')]:
        registration = f'services.AddSingleton<{interface}, {provider}>();'
        require(composition.count(registration) == 1 and registration in branch, 'Test provider outside validated capability: '+provider)
        require('capability.RequireCapture();' in (root/f'Services/SystemTesting/{provider}.cs').read_text(), 'Missing constructor boundary: '+provider)
    require('new SystemTestControllerFeatureProvider(systemTestCapability)' in composition, 'Composition must install route isolation')
    feature = (root/'Rigging/Hosting/SystemTestControllerFeatureProvider.cs').read_text()
    require('if (capability.InspectionEnabled) return;' in feature and 'feature.Controllers.Remove(type)' in feature,
            'Disabled inspection must remove privileged controllers')
    for controller in ('SystemTestAccountController','SystemTestDeliveryController','SystemTestIdentityController'):
        require(f'typeof({controller})' in feature, 'Controller not removed: '+controller)
        source = (root/f'Controllers/{controller}.cs').read_text()
        require(('if (!_capability.InspectionEnabled) return NotFound();' in source and '_capability.Authorizes(Request)' in source) or ('if (!capability.InspectionEnabled) return NotFound();' in source and 'capability.Authorizes(Request)' in source),
                'Controller must enforce validated capability: '+controller)
        require('IOptions<SystemTestSettings>' not in source, 'Mutable settings cannot grant request access')
    profiles = 0
    for p in root.glob('appsettings*.json'):
        settings = json.loads(p.read_text()).get('SystemTestSettings')
        if settings is not None:
            require(settings == dict(Enabled=False, EnableTestInspectionEndpoints=False, TestKey=''), 'Unsafe/unsupported defaults: '+p.name)
            profiles += 1
    for name in ['docker-compose.testing.yml','eng/docker-host-system-stack-tests.sh','eng/docker-host-system-stack-tests.ps1']:
        text = (root/name).read_text()
        require('SystemTestSettings__DeliveryCaptureConnection' not in text, 'Unsupported capture connection: '+name)
        for prefix in ['ASPNETCORE_ENVIRONMENT','DOTNET_ENVIRONMENT']:
            require(any(prefix in line and 'Testing' in line for line in text.splitlines()), 'Harness requires explicit Testing: '+name)
    integration = (root/'docker-compose.integration.yml').read_text()
    require('SystemTestSettings__Enabled: "false"' in integration and 'SystemTestSettings__EnableTestInspectionEndpoints: "false"' in integration
            and 'SystemTestSettings__TestKey: ""' in integration, 'Base Compose must disable test capabilities')
    for stem in ['docker-http-contracts-direct','docker-http-contracts-proxy','docker-system-stack-tests']:
        for ext in ['sh','ps1']:
            name = f'eng/{stem}.{ext}'
            text = (root/name).read_text()
            testing = "'-f', 'docker-compose.testing.yml'" if ext == 'ps1' else '-f docker-compose.testing.yml'
            proxy = "'-f', 'docker-compose.api-proxy.yml'" if ext == 'ps1' else '-f docker-compose.api-proxy.yml'
            require(testing in text, 'Test runner must select explicit Testing composition: '+name)
            if proxy in text:
                require(text.index(proxy) < text.index(testing), 'Testing selection must follow generic proxy override: '+name)
    require('FullyQualifiedName~Cor23DTestCapabilityHttpTests'  in (root/'eng/correction-baseline.py').read_text(), 'Owned HTTP SQL cases must be mandatory')
    return dict(status='SourceContractsConsistent', qualification='NotRun', checked_default_profiles=profiles,
                native_required=['fast','sql-harness','sql','system'])

def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--root', type=Path, default=ROOT); args = parser.parse_args()
    try: print(json.dumps(validate(args.root), indent=2)); return 0
    except (ValueError, OSError, KeyError) as error: print(str(error)); return 1

if __name__ == '__main__': raise SystemExit(main())
