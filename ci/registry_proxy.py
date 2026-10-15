"""Fixed HTTPS CONNECT registry proxy for the isolated build bridge.

Never accepts caller-selected hosts outside the reviewed registry list, private
addresses, arbitrary ports, redirects or DNS rebinding to a second resolution.
"""
import ipaddress
import select
import socket
import socketserver
import threading
import time

HOSTS=frozenset(['pypi.org','files.pythonhosted.org','registry.npmjs.org'])


def destination(authority, resolver=socket.getaddrinfo):
    if authority not in {name+':443' for name in HOSTS}:
        raise ValueError('Registry target denied')
    host=authority[:-4]
    addresses=resolver(host,443,family=socket.AF_INET,type=socket.SOCK_STREAM)
    candidates=[]
    for family,kind,protocol,_,address in addresses:
        ip=ipaddress.ip_address(address[0])
        if not ip.is_global:
            raise ValueError('Non-public registry address denied')
        if family==socket.AF_INET and ip.version==4:
            candidates.append((family,kind,protocol,address))
    if not candidates:
        raise ValueError('No registry address')
    return candidates[0]


class RegistryProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    request_queue_size=8

    def __init__(self,address):
        super().__init__(address,Tunnel)
        self.slots=threading.BoundedSemaphore(24)

    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request,address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self,request,address):
        try:
            super().process_request_thread(request,address)
        finally:
            self.slots.release()

    def handle_error(self,*args):
        pass


class Tunnel(socketserver.BaseRequestHandler):
    def handle(self):
        upstream=None
        try:
            self.request.settimeout(10)
            header=b''
            while b'\r\n\r\n' not in header:
                part=self.request.recv(1)
                if not part or len(header)>8192:
                    raise ValueError()
                header+=part
            lines=header.decode('ascii').split('\r\n')
            verb,authority,version=lines[0].split(' ')
            if verb!='CONNECT' or version not in ['HTTP/1.0','HTTP/1.1']:
                raise ValueError()
            # No proxy authentication, request body, forwarding or extra CONNECTs.
            for line in lines[1:]:
                if line and line.split(':',1)[0].lower() not in ['host','user-agent','proxy-connection','connection']:
                    raise ValueError()
            family,kind,protocol,address=destination(authority)
            upstream=socket.socket(family,kind,protocol)
            upstream.settimeout(10)
            upstream.connect(address)  # Connect the already checked address; no second DNS lookup.
            self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            deadline=time.monotonic()+180
            transferred=0
            while time.monotonic()<deadline:
                ready,_,_=select.select([self.request,upstream],[],[],10)
                if not ready:
                    continue
                for current in ready:
                    data=current.recv(65536)
                    if not data:
                        return
                    transferred+=len(data)
                    if transferred>200*1024*1024:
                        return
                    (upstream if current is self.request else self.request).sendall(data)
        except Exception:
            pass
        finally:
            if upstream is not None:
                upstream.close()


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--bind',required=True);args=parser.parse_args()
    ip=ipaddress.ip_address(args.bind)
    if ip not in ipaddress.ip_network('172.26.0.0/24'):
        raise SystemExit('Only the dedicated local sandbox bridge may host this proxy.')
    RegistryProxy((str(ip),3128)).serve_forever()
