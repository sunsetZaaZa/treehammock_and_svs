#!/usr/bin/env python3
"""COR23H supplemental SMTP source/configuration checks; native TLS qualification is mandatory."""
import argparse,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def require(value,message):
    if not value:raise ValueError(message)
def validate(root):
    read=lambda p:(root/p).read_text()
    profiles=sorted(root.glob('appsettings*.json'));require(len(profiles)==8,'SMTP profile catalog changed')
    for path in profiles:
        s=json.loads(path.read_text())['SMTPSettings'];require(s['TransportMode']=='RequiredStartTls' and s['AllowIsolatedPlaintext'] is False,'Shipped profiles must require TLS without a plaintext exception: '+path.name)
        if path.name in ('appsettings.json','appsettings.Example.json'):require(s['SMTPPort']==587,'Default required STARTTLS submission port')
    settings=read('Rigging/Config/SMTPSettings.cs')
    for token in ['SmtpTransportMode { RequiredStartTls, ImplicitTls, IsolatedPlaintext }','Enum.IsDefined(TransportMode)','!AllowIsolatedPlaintext','IPAddress.TryParse(SMTPQualifiedDomain','!IPAddress.IsLoopback(address)','else if (AllowIsolatedPlaintext)','SMTPPort == 465','SMTPPort == 587','Uri.CheckHostName(SMTPQualifiedDomain)']:
        require(token in settings,'SMTP configuration validation missing: '+token)
    policy=read('Rigging/Delivery/SmtpTransportPolicy.cs')
    for token in ['environment == "Testing"','ConfigurationValidation.TryValidate(settings','SmtpTransportMode.RequiredStartTls => SecureSocketOptions.StartTls','SmtpTransportMode.ImplicitTls => SecureSocketOptions.SslOnConnect','SmtpTransportMode.IsolatedPlaintext => SecureSocketOptions.None','RequireEncryption = settings.TransportMode != SmtpTransportMode.IsolatedPlaintext','public string Password { get; }']:
        require(token in policy,'SMTP startup/snapshot policy missing: '+token)
    require('StartTlsWhenAvailable' not in policy and 'SecureSocketOptions.Auto' not in policy,'No opportunistic TLS policy')
    service=read('Services/SMTPService.cs')
    tokens=['await smtp.ConnectAsync(_transport.Host, _transport.Port, _transport.SocketOptions,token);','if (_transport.RequireEncryption && (!smtp.IsSecure || smtp.SslProtocol is not (SslProtocols.Tls12 or SslProtocols.Tls13)))','await smtp.AuthenticateAsync(_transport.Username, _transport.Password,token);','await smtp.SendAsync(email,token);']
    indexes=[service.index(t) if t in service else -1 for t in tokens];require(all(x>=0 for x in indexes) and indexes==sorted(indexes),'Connect and verify TLS before AUTH/DATA')
    require('new SmtpClient {' not in service and 'SecureSocketOptions.None' not in service and 'ex.GetType().Name' in service and '_logger.LogWarning(ex' not in service,'Common client boundary/sanitized errors')
    require('new SmtpTransportPolicy(smtpSettings.Value, null)' in service,'Direct constructor must fail closed without an isolated environment')
    factory=read('Rigging/Delivery/SmtpClientFactory.cs');require('SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13' in factory and 'CheckCertificateRevocation = true' in factory,'TLS floor/revocation policy')
    require('ServerCertificateValidationCallback =' not in factory,'Production certificate validation cannot be replaced')
    di=read('Rigging/DependencyInjection/TreehammockServiceCollectionExtensions.cs')
    for token in ['SmtpTransportPolicy.AllowedForEnvironment(settings, environment?.EnvironmentName)','sectionName == "SMTPSettings"','services.AddSingleton<ISmtpClientFactory, SmtpClientFactory>();','new SmtpTransportPolicy(provider.GetRequiredService<IOptions<SMTPSettings>>().Value, environment?.EnvironmentName)']:
        require(token in di,'SMTP DI/startup validation missing: '+token)
    for path,method in [('treehammock.Tests/Integration/SmtpTransportTests.cs','Certificate_chain_expiry_and_hostname_failures'),('treehammock.Tests/Integration/SmtpTransportTests.cs','Every_public_security_mail_method_and_durable_kind'),('treehammock.Tests/Unit/SmtpPolicyTests.cs','Deployable_host_rejects_plaintext_before_any_delivery_worker'),('treehammock.Tests/Unit/SmtpPolicyTests.cs','Explicit_Testing_host_starts_with_real_provider')]:require(method in read(path),'Native SMTP regression absent: '+method)
    require('SMTPSettings__TransportMode=RequiredStartTls' in read('README.md') and 'SMTPSettings__TransportMode=ImplicitTls' in read('README.md') and 'SMTPSettings__AllowIsolatedPlaintext=true' in read('README.md'),'Published transport configuration examples')
    return dict(status='SourceContractsConsistent',qualification='NotRun',profiles=len(profiles),default='RequiredStartTls',isolated_plaintext='explicit Testing and literal loopback only',native_required=['pinned MailKit transport/certificate/startup matrix','published deployment relay trust','COR24 qualification'])
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args()
    try:print(json.dumps(validate(a.root),indent=2));return 0
    except (ValueError,OSError,KeyError) as error:print(str(error));return 1
if __name__=='__main__':raise SystemExit(main())
