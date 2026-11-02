"""Bounded, isolated STARTTLS SMTP fixture for the real delivery outbox/provider.

No inspection endpoints or session/account seed DML are installed in TreeHammock.
Messages stay on the owned private capture mount and are deleted with the stack.
"""
import base64,hmac,json,os,secrets,socketserver,ssl,threading,time
from pathlib import Path
from common import require
LIMIT=8
CAPTURE=Path('/capture')
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True
    def __init__(self,address,handler):self.permits=threading.BoundedSemaphore(LIMIT);super().__init__(address,handler)
    def process_request(self,request,address):
        if not self.permits.acquire(False):request.close();return
        super().process_request(request,address)
    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self.permits.release()
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        sock=self.request;sock.settimeout(10);stream=sock.makefile('rb');tls=False;authenticated=False;recipient=None
        def reply(text):sock.sendall(text.encode()+b'\r\n')
        try:
            reply('220 smtp.fixture ESMTP')
            for _ in range(100):
                line=stream.readline(8193);require(line.endswith(b'\r\n') and len(line)<=8192,'SMTP_LINE_BOUND');line=line[:-2].decode('ascii');command,_,value=line.partition(' ');command=command.upper()
                if command in ['EHLO','HELO']:
                    reply('250-smtp.fixture');reply('250-AUTH PLAIN LOGIN' if tls else '250-STARTTLS');reply('250 SIZE 262144')
                elif command=='STARTTLS' and not tls:
                    reply('220 Ready for TLS');stream.close();sock=CONTEXT.wrap_socket(sock,server_side=True);stream=sock.makefile('rb');tls=True
                elif command=='AUTH' and tls:
                    mode,_,payload=value.partition(' ')
                    if mode.upper()=='PLAIN':
                        if not payload:reply('334 ');payload=stream.readline(8193).strip().decode()
                        fields=base64.b64decode(payload,validate=True).split(b'\x00');require(len(fields)==3,'SMTP_AUTH');user,secret=fields[1:]
                    elif mode.upper()=='LOGIN':
                        if payload:user=base64.b64decode(payload,validate=True)
                        else:reply('334 VXNlcm5hbWU6');user=base64.b64decode(stream.readline(8193).strip(),validate=True)
                        reply('334 UGFzc3dvcmQ6');secret=base64.b64decode(stream.readline(8193).strip(),validate=True)
                    else:reply('504 Unsupported');continue
                    authenticated=hmac.compare_digest(user,b'fixture') and hmac.compare_digest(secret,SECRET.encode());reply('235 Authenticated' if authenticated else '535 Refused')
                elif command=='MAIL' and authenticated:recipient=None;reply('250 OK')
                elif command=='RCPT' and authenticated:
                    require(value.upper().startswith('TO:<') and value.endswith('>'),'SMTP_RECIPIENT');recipient=value[4:-1].lower();require(recipient.endswith('@svs15.test'),'SMTP_RECIPIENT');reply('250 OK')
                elif command=='DATA' and authenticated and recipient:
                    reply('354 End with dot');data=bytearray()
                    while True:
                        block=stream.readline(8193);require(block and len(block)<=8192,'SMTP_DATA_BOUND')
                        if block==b'.\r\n':break
                        data.extend(block[1:] if block.startswith(b'..') else block);require(len(data)<=262144,'SMTP_DATA_BOUND')
                    capture=CAPTURE;require(len(list(capture.glob('*.json')))<32,'SMTP_CAPTURE_BOUND')
                    p=capture/(str(time.time_ns())+'-'+secrets.token_hex(4)+'.json');p.write_text(json.dumps({'recipient':recipient,'message':base64.b64encode(data).decode()}));p.chmod(0o600);reply('250 Stored')
                elif command=='RSET':recipient=None;reply('250 OK')
                elif command=='NOOP':reply('250 OK')
                elif command=='QUIT':reply('221 Bye');break
                else:reply('530 Authentication required')
        except Exception:pass # Never log provider payloads, destinations or credentials.
        finally:stream.close();sock.close()
def main():
    global SECRET,CONTEXT
    SECRET=json.loads(Path('/run/fixture/config.json').read_text())['secret'];CONTEXT=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);CONTEXT.minimum_version=ssl.TLSVersion.TLSv1_2;CONTEXT.load_cert_chain('/run/fixture/server.pem','/run/fixture/server.key')
    with Server(('172.29.94.20',2525),Handler) as server:server.serve_forever()
if __name__=='__main__':main()
