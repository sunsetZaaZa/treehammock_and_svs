#!/usr/bin/env python3
"""Bounded private HTTPS caller load; results are exploratory, never SLO acceptance."""
import argparse,concurrent.futures,http.client,ipaddress,json,math,ssl,sys,threading,time
from pathlib import Path
from urllib.parse import urlsplit
class Refused(RuntimeError):pass
def require(value,code):
    if not value:raise Refused(code)
def validate(target,requests,concurrency,timeout):
    require(1<=requests<=10000 and 1<=concurrency<=64 and .05<=timeout<=10,'LOAD_BOUNDS_REFUSED')
    uri=urlsplit(target);require(uri.scheme=='https' and not uri.username and not uri.password and not uri.query and not uri.fragment and uri.path in ['/health/live','/health/ready','/validate'],'PRIVATE_TARGET_REFUSED')
    try:address=ipaddress.ip_address(uri.hostname)
    except ValueError:raise Refused('PRIVATE_LITERAL_ADDRESS_REQUIRED') from None
    require(address.is_loopback or address in ipaddress.ip_network('10.0.0.0/8') or address in ipaddress.ip_network('172.16.0.0/12') or address in ipaddress.ip_network('192.168.0.0/16') or address in ipaddress.ip_network('fc00::/7'),'PRIVATE_TARGET_REFUSED')
    require(uri.port is not None and 1024<=uri.port<=65535,'EXPLICIT_PRIVATE_PORT_REQUIRED');return uri
def load(target,context,requests=100,concurrency=4,timeout=2,payload=None):
    uri=validate(target,requests,concurrency,timeout);require((uri.path=='/validate')==(payload is not None),'PAYLOAD_SCOPE_REFUSED');require(payload is None or len(payload)<=16384,'PAYLOAD_BOUND')
    lock=threading.Lock();next_request=0;latencies=[];counts={};connections=0
    def worker():
        nonlocal next_request,connections
        connection=None
        try:
            while True:
                with lock:
                    if next_request>=requests:return
                    next_request+=1
                started=time.perf_counter();status=0
                try:
                    if connection is None:
                        connection=http.client.HTTPSConnection(uri.hostname,uri.port,timeout=timeout,context=context)
                        with lock:connections+=1
                    connection.request('POST' if payload is not None else 'GET',uri.path,payload,{'Content-Type':'application/json','Cache-Control':'no-store'});reply=connection.getresponse();body=reply.read(16385);require(len(body)<=16384,'RESPONSE_BOUND');status=reply.status
                except Exception:
                    if connection:connection.close();connection=None
                with lock:
                    latencies.append((time.perf_counter()-started)*1000);counts[str(status)]=counts.get(str(status),0)+1
        finally:
            if connection:connection.close()
    started=time.perf_counter()
    # Exactly N long-lived workers; no future/task is allocated per request.
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures=[executor.submit(worker) for _ in range(concurrency)]
        for future in futures:future.result()
    ordered=sorted(latencies)
    def percentile(p):return round(ordered[max(0,math.ceil(len(ordered)*p)-1)],3)
    return dict(status='Completed',scope='Exploratory private HTTPS driver; no SLO qualification',requests=len(ordered),concurrency=concurrency,connection_attempts=connections,status_counts=counts,p50_ms=percentile(.5),p95_ms=percentile(.95),p99_ms=percentile(.99),seconds=round(time.perf_counter()-started,3),native_acceptance='NotRun',grant_rights=False,release_ready=False)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--target',required=True);p.add_argument('--ca',required=True,type=Path);p.add_argument('--cert',required=True,type=Path);p.add_argument('--key',required=True,type=Path);p.add_argument('--payload',type=Path);p.add_argument('--requests',type=int,default=100);p.add_argument('--concurrency',type=int,default=4);p.add_argument('--timeout',type=float,default=2);a=p.parse_args();validate(a.target,a.requests,a.concurrency,a.timeout)
    require(a.key.is_file() and not a.key.is_symlink() and a.key.stat().st_mode&0o077==0,'PRIVATE_KEY_FILE_REQUIRED');context=ssl.create_default_context(cafile=str(a.ca));context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(a.cert,a.key)
    payload=None
    if a.payload:
        require(a.payload.is_file() and not a.payload.is_symlink() and a.payload.stat().st_mode&0o077==0 and a.payload.stat().st_size<=16384,'PRIVATE_PAYLOAD_REQUIRED');payload=a.payload.read_bytes()
    print(json.dumps(load(a.target,context,a.requests,a.concurrency,a.timeout,payload)))
if __name__=='__main__':
    try:main()
    except Exception as error:print(json.dumps(dict(status='Refused',code=str(error) if isinstance(error,Refused) else 'LOAD_FAILED')));sys.exit(1)
