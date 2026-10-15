"""Private verified TLS transport. Importing does not start a server or enable execution."""
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid

from .controller_contract import MAX_BODY, canonical, sign
from .errors import RuleError


def private_ipv4(value):
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or not any(ip in ipaddress.ip_network(network) for network in ['10.0.0.0/8','172.16.0.0/12','192.168.0.0/16']):
        raise ValueError('Reviewed private IPv4 required')
    return ip


def strict_json(content):
    def pairs(values):
        result = {}
        for name, value in values:
            if name in result:
                raise ValueError('duplicate field')
            result[name] = value
        return result
    if len(content) > MAX_BODY:
        raise ValueError('oversize')
    return json.loads(content, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def status_query(release_id, key, now=None):
    value = {'action': 'deployment_receipt', 'release_id': release_id,
             'issued_at': int(time.time()) if now is None else now}
    return {'query': value, 'signature': sign(value, key)}


def validate_query(body, key, now=None):
    if not isinstance(body, dict) or set(body) != {'query', 'signature'}:
        raise ValueError()
    value = body['query']
    if (not isinstance(body['signature'], str) or
        not hmac.compare_digest(sign(value, key), body['signature']) or
        not isinstance(value, dict) or set(value) != {'action', 'release_id', 'issued_at'} or
        value['action'] != 'deployment_receipt' or type(value['issued_at']) is not int):
        raise ValueError()
    current = int(time.time()) if now is None else now
    if abs(current - value['issued_at']) > 60 or str(uuid.UUID(value['release_id'])) != value['release_id']:
        raise ValueError()
    return value['release_id']


def handler(controller):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'
        server_version = 'ReleasePortal'
        sys_version = ''

        def log_message(self, *args):
            pass

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def send_body(self, status, value):
            content = canonical(value)
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(content)

        def do_POST(self):
            body = None
            try:
                lengths = self.headers.get_all('Content-Length', [])
                if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal() or
                    self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type') != 'application/json'):
                    raise ValueError()
                size = int(lengths[0])
                if not 0 < size <= MAX_BODY:
                    raise ValueError()
                content = self.rfile.read(size)
                if len(content) != size:
                    raise ValueError()
                body = strict_json(content)
                if self.path == '/v1/deploy':
                    if not isinstance(body, dict) or set(body) != {'snapshot', 'signature', 'credentials'} or not isinstance(body['credentials'], dict):
                        raise ValueError()
                    value = controller.start(body['snapshot'], body['signature'], body['credentials'])
                    self.send_body(202, value)
                elif self.path == '/v1/receipt':
                    release_id = validate_query(body, controller.key)
                    value = controller.ledger.get(release_id)
                    self.send_body(200 if value else 404, value or {'code': 'receipt_not_found'})
                else:
                    self.send_body(404, {'code': 'route_not_found'})
            except (RuleError, ValueError, TypeError, KeyError, AttributeError):
                self.send_body(409, {'code': 'controller_request_rejected'})
            except (OSError, socket.timeout):
                pass
            except Exception:
                self.send_body(503, {'code': 'controller_outcome_unconfirmed'})
            finally:
                if isinstance(body, dict) and isinstance(body.get('credentials'), dict):
                    body['credentials'].clear()
                body = None

    return Handler


class PrivateServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 4

    def __init__(self, address, controller, certificate, private_key):
        private_ipv4(address[0])
        if address[1] != 9443:
            raise ValueError('A reviewed private interface on 9443 is required')
        super().__init__(address, handler(controller))
        self.slots = threading.BoundedSemaphore(4)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, private_key)
        self.socket = context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            request.settimeout(10)
            request.do_handshake()
            super().process_request_thread(request, address)
        except Exception:
            self.shutdown_request(request)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        # No raw requests or tracebacks in the system journal.
        pass


class PrivateClient:
    def __init__(self, private_ip, certificate):
        ip = private_ipv4(private_ip)
        context = (ssl.create_default_context(cadata=certificate) if str(certificate).startswith('-----BEGIN CERTIFICATE-----')
                   else ssl.create_default_context(cafile=str(certificate)))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # SSL verifies both pinned certificate trust and its private-IP SAN.
        self.url = 'https://' + str(ip) + ':9443'
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context), NoRedirect())

    def post(self, route, value):
        if route not in ['/v1/deploy', '/v1/receipt']:
            raise ValueError('Unsupported controller route')
        request = urllib.request.Request(self.url + route, data=canonical(value), method='POST',
            headers={'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=20) as response:
                if response.status not in [200, 202] or response.geturl() != self.url + route:
                    raise ValueError()
                return strict_json(response.read(MAX_BODY + 1))
        except Exception:
            raise RuleError('controller_outcome_unknown', 'Read the controller receipt before another deployment attempt.') from None

    def ready(self,key):
        """Verified private TLS + signed read, with no AWS request or credential entry."""
        request=urllib.request.Request(self.url+'/v1/receipt',data=canonical(status_query(str(uuid.uuid4()),key)),
            method='POST',headers={'Content-Type':'application/json'})
        try:
            self.opener.open(request,timeout=10).close()
        except urllib.error.HTTPError as error:
            try:
                return error.code==404 and strict_json(error.read(MAX_BODY+1))=={'code':'receipt_not_found'}
            except Exception:
                return False
        except Exception:
            return False
        return False
