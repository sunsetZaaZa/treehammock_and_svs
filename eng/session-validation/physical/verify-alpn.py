#!/usr/bin/env python3
"""One explicitly requested private mTLS handshake; checks chain, name, pin, ALPN."""
import argparse,hashlib,ipaddress,json,re,socket,ssl,stat,sys
from pathlib import Path
def verify(address,port,name,ca,cert,key,pins):
    ip=ipaddress.ip_address(address)
    if not (ip.is_loopback or any(ip in net for net in [ipaddress.ip_network('10.0.0.0/8'),ipaddress.ip_network('172.16.0.0/12'),ipaddress.ip_network('192.168.0.0/16'),ipaddress.ip_network('fc00::/7')])) or not 1024<=port<=65535:raise ValueError()
    if not 1<=len(pins)<=4 or any(re.fullmatch('[A-F0-9]{64}',p) is None for p in pins):raise ValueError()
    key_path=Path(key)
    if not key_path.is_file() or any(p.is_symlink() for p in [key_path,*key_path.parents]) or stat.S_IMODE(key_path.stat().st_mode)!=0o600:raise ValueError()
    context=ssl.create_default_context(cafile=str(ca));context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(cert,key);context.set_alpn_protocols(['h2'])
    with socket.create_connection((address,port),timeout=3) as raw:
        with context.wrap_socket(raw,server_hostname=name) as connection:
            if connection.selected_alpn_protocol()!='h2' or hashlib.sha256(connection.getpeercert(binary_form=True)).hexdigest().upper() not in pins:raise ValueError()
    return dict(status='ScopedChainNamePinALPNPassed',client_authentication_enforcement='NotRun',application_authorization='NotRun',firewall_direct_bypass='NotRun',full_physical_qualification='NotRun',grant_rights=False,release_ready=False)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['address','server-name','ca','cert','key','pins']:p.add_argument('--'+name,required=True)
    p.add_argument('--port',type=int,default=9443);a=p.parse_args();print(json.dumps(verify(a.address,a.port,a.server_name,a.ca,a.cert,a.key,a.pins.split(','))))
if __name__=='__main__':
    try:main()
    except Exception:print(json.dumps(dict(status='Refused',code='TLS_CHAIN_NAME_PIN_OR_ALPN_REFUSED')));sys.exit(1)
