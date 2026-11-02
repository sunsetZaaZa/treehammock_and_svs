#!/usr/bin/env python3
"""Render a fresh public deployment directory. Never install, reload or apply it."""
import argparse,ipaddress,json,re,shutil,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];DEPLOY=ROOT/'deploy/session-validation'
class Refused(RuntimeError):pass
def require(value,code):
    if not value:raise Refused(code)
def validate(value):
    fields={'datacenter','tlsName','ingressIp','haproxyIp','replicaIps','replicaUids','controllerIp','writerIps','callerIps','databaseIp','cacheIp','cacheTlsName'};require(isinstance(value,dict) and set(value)==fields,'INVENTORY_FIELDS_REFUSED')
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,31}',value['datacenter']) and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',value['tlsName']) and '.' in value['tlsName'],'DATACENTER_NAME_REFUSED')
    require(all(isinstance(value[k],list) for k in ['replicaIps','replicaUids','writerIps','callerIps']),'ROLE_LIST_REQUIRED')
    require(all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in (value['tlsName']+'.'+value['cacheTlsName']).split('.')),'TLS_NAME_REFUSED')
    require(len(value['replicaIps'])==len(value['replicaUids'])==2 and 1<=len(value['writerIps'])<=8 and 1<=len(value['callerIps'])<=64,'BOUNDED_ROLE_INVENTORY_REQUIRED')
    require(all(type(uid) is int and 1000<=uid<=60000 for uid in value['replicaUids']) and len(set(value['replicaUids']))==2 and not set(value['replicaUids']).intersection({1660,1661}),'DISTINCT_SERVICE_UIDS_REQUIRED')
    addresses=[value[k] for k in ['ingressIp','haproxyIp','controllerIp','databaseIp','cacheIp']]+value['replicaIps']+value['writerIps']+value['callerIps'];require(len(addresses)==len(set(addresses)),'DISTINCT_PRIVATE_BINDINGS_REQUIRED')
    for address in addresses:
        try:ip=ipaddress.IPv4Address(address)
        except (ValueError,TypeError):raise Refused('PRIVATE_IPV4_REQUIRED') from None
        require(str(ip)==address and any(ip in n for n in [ipaddress.ip_network('10.0.0.0/8'),ipaddress.ip_network('172.16.0.0/12'),ipaddress.ip_network('192.168.0.0/16')]),'PRIVATE_IPV4_REQUIRED')
    return value
def firewall(v):
    ips=lambda values:', '.join(values);uids=', '.join(str(x) for x in v['replicaUids']);replicas=ips(v['replicaIps']);sql=ips(v['replicaIps']+v['writerIps']+[v['controllerIp']]);protected=ips([v['ingressIp'],v['haproxyIp'],*v['replicaIps'],v['databaseIp'],v['cacheIp']])
    return f'''# Review/merge on the declared role hosts; never flush an existing ruleset.
table inet svs_private {{
    chain input {{
        type filter hook input priority -10; policy accept;
        ip daddr {{ {protected} }} tcp dport {{ 8443, 8444, 9443, 5433, 6379 }} jump protected_services
    }}
    chain protected_services {{
        ip daddr {v['ingressIp']} ip saddr {{ {ips(v['callerIps'])} }} tcp dport 9443 accept
        ip daddr {v['haproxyIp']} ip saddr {v['ingressIp']} tcp dport 9443 accept
        ip daddr {{ {replicas} }} ip saddr {v['haproxyIp']} tcp dport 8443 accept
        ip daddr {{ {replicas} }} ip saddr {v['controllerIp']} tcp dport 8444 accept
        ip daddr {v['databaseIp']} ip saddr {{ {sql} }} tcp dport 5433 accept
        ip daddr {v['cacheIp']} ip saddr {{ {sql} }} tcp dport 6379 accept
        drop
    }}
    chain output {{
        type filter hook output priority -10; policy accept;
        meta skuid {{ {uids} }} ct direction reply accept
        meta skuid {{ {uids} }} ip daddr {v['databaseIp']} tcp dport 5433 accept
        meta skuid {{ {uids} }} ip daddr {v['cacheIp']} tcp dport 6379 accept
        meta skuid {{ {uids} }} reject
    }}
}}
'''
def render(value,output):
    v=validate(value);output=Path(output);require(not output.exists(),'FRESH_OUTPUT_REQUIRED');output.mkdir(parents=True,mode=0o700)
    for directory in ['systemd','nginx','haproxy','firewall','physical']:(output/directory).mkdir()
    for name in ['svs@.service','svs-proxy@.service','session-validation.sysusers.conf']:shutil.copyfile(DEPLOY/'systemd'/name,output/'systemd'/name)
    mapping={'10.77.0.10':v['ingressIp'],'10.77.1.11':v['haproxyIp'],'10.77.2.21':v['replicaIps'][0],'10.77.2.22':v['replicaIps'][1]}
    replace=lambda text:re.sub(r'10\.77\.(?:0\.10|1\.11|2\.21|2\.22)',lambda m:mapping[m[0]],text)
    text=replace((DEPLOY/'nginx/grpc.conf').read_text());(output/'nginx/grpc.conf').write_text(text);shutil.copyfile(DEPLOY/'nginx/nginx.conf',output/'nginx/nginx.conf')
    text=(DEPLOY/'haproxy/internal.cfg').read_text()
    text=replace(text)
    (output/'haproxy/internal.cfg').write_text(text);(output/'firewall/svs-private.nft').write_text(firewall(v))
    users=(output/'systemd/session-validation.sysusers.conf').read_text().replace('svs-1 1654 ',f"svs-1 {v['replicaUids'][0]} ").replace('svs-2 1655 ',f"svs-2 {v['replicaUids'][1]} ");(output/'systemd/session-validation.sysusers.conf').write_text(users)
    for i,ip in enumerate(v['replicaIps'],1):
        allow=[ip,v['haproxyIp'],v['controllerIp'],v['databaseIp'],v['cacheIp']];(output/f'systemd/svs@{i}.network.conf').write_text('[Service]\n'+''.join('IPAddressAllow='+p+'/32\n' for p in allow))
        host=json.loads((DEPLOY/'host.example.json').read_text());prefix=f'/run/credentials/svs@{i}.service';host.update(bindAddress=ip,port=8443,serverCertificatePath=prefix+'/server.pfx',serverRootCertificatePath=prefix+'/services-ca.pem',clientRootCertificatePath=prefix+'/clients-ca.pem');host['cache'].update(address=v['cacheIp'],tlsName=v['cacheTlsName'],rootCertificatePath=prefix+'/cache-ca.pem')
        host['databaseConnectionString']=host['databaseConnectionString'].replace('db.intranet',v['databaseIp']).replace('/run/svs/db-ca.cer',prefix+'/sql-ca.pem').replace('Host='+v['databaseIp']+';', 'Host='+v['databaseIp']+';Port=5433;')
        refill=host['refill'];refill['databaseConnectionString']=refill['databaseConnectionString'].replace('db.intranet',v['databaseIp']).replace('/run/svs/db-ca.cer',prefix+'/sql-ca.pem').replace('Host='+v['databaseIp']+';', 'Host='+v['databaseIp']+';Port=5433;');refill['publisherCache'].update(address=v['cacheIp'],tlsName=v['cacheTlsName'],rootCertificatePath=prefix+'/cache-ca.pem')
        host['fleet'].update(instanceId=f'svs-{i}',bindAddress=ip,port=8444,checkpointPath=f'/var/lib/svs-{i}/fleet.checkpoint',serverCertificatePath=prefix+'/fleet.pfx',controllerRootCertificatePath=prefix+'/controller-ca.pem');host['capacity']=json.loads((DEPLOY/'capacity.example.json').read_text())['capacity'];(output/f'physical/host-{i}.example.json').write_text(json.dumps(host,indent=2)+'\n')
    for name,command,allow in [('nginx','/usr/sbin/nginx -c /etc/svs/proxy/nginx.conf -g "daemon off;"',[v['ingressIp'],v['haproxyIp'],*v['callerIps']]),('haproxy','/usr/sbin/haproxy -W -db -f /etc/svs/proxy/internal.cfg',[v['haproxyIp'],v['ingressIp'],*v['replicaIps']])]:
        (output/f'systemd/svs-proxy@{name}.override.conf').write_text('[Service]\nExecStart=\nExecStart='+command+'\n'+''.join('IPAddressAllow='+ip+'/32\n' for ip in allow))
    (output/'physical/certificate-plan.json').write_text(json.dumps(dict(server_dns=v['tlsName'],cache_server_dns=v['cacheTlsName'],database_ip_san=v['databaseIp'],replica_ip_sans=v['replicaIps'],client_eku='clientAuth',server_eku='serverAuth',private_ca_location='Offline; never loaded into callers or proxies',pins='Operator supplies reviewed uppercase DER SHA256 leaf pins; no placeholder admits runtime'),indent=2)+'\n')
    caller=json.loads((DEPLOY/'client.example.json').read_text());caller.update(tlsName=v['tlsName'],privateAddress=v['ingressIp'],port=9443,serverRootCertificatePath='/run/credentials/caller/services-ca.pem',clientRootCertificatePath='/run/credentials/caller/clients-ca.pem',clientCertificatePath='/run/credentials/caller/client.pfx',serverLeafSha256=['REPLACE_WITH_REVIEWED_REPLICA1_DER_SHA256','REPLACE_WITH_REVIEWED_REPLICA2_DER_SHA256']);(output/'physical/caller-options.example.json').write_text(json.dumps(caller,indent=2)+'\n')
    (output/'physical/datacenter.json').write_text(json.dumps(v,indent=2)+'\n')
    credentials=json.loads((DEPLOY/'physical/credentials.example.json').read_text())
    for item in credentials['items']:item['owner_uid']=v['replicaUids'][0 if '/svs@1.service/' in item['path'] else 1]
    (output/'physical/credentials.example.json').write_text(json.dumps(credentials,indent=2)+'\n')
    return dict(status='RenderedOnly',files=sum(p.is_file() for p in output.rglob('*')),native_execution='NotRun',grant_rights=False,release_ready=False)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inventory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();require(a.inventory.stat().st_size<=32768,'INVENTORY_BOUND');print(json.dumps(render(json.loads(a.inventory.read_text()),a.output)))
if __name__=='__main__':
    try:main()
    except Exception as e:print(json.dumps(dict(status='Refused',code=str(e) if isinstance(e,Refused) else 'RENDER_FAILED')));sys.exit(1)
