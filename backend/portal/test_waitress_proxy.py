import ipaddress
import os
from pathlib import Path
import runpy
from unittest.mock import patch

from django.core.handlers.wsgi import WSGIRequest
from django.http import HttpResponse
from django.test import SimpleTestCase, RequestFactory, override_settings
from waitress.proxy_headers import proxy_headers_middleware

from .middleware import IngressMiddleware


@override_settings(PUBLIC=True, TRUSTED_PROXY_NETWORKS=[ipaddress.ip_network('172.31.32.0/20')],
                   ALLOWED_HOSTS=['portal.example.com'])
class WaitressIngressTests(SimpleTestCase):
    def exercise(self, peer, proto):
        with patch.dict(os.environ, {'PORTAL_BIND_HOST': '127.0.0.1'}), patch('waitress.serve') as serve:
            runpy.run_path(str(Path(__file__).resolve().parents[2] / 'scripts' / 'serve.py'))
        options = serve.call_args.kwargs
        request = RequestFactory().get('/', REMOTE_ADDR=peer, HTTP_HOST='portal.example.com',
            HTTP_X_FORWARDED_PROTO=proto, HTTP_X_FORWARDED_FOR='192.0.2.99',
            HTTP_X_FORWARDED_HOST='untrusted.example.com')
        result = []
        def application(environ, start_response):
            self.assertEqual(environ['REMOTE_ADDR'], peer)
            self.assertNotIn('HTTP_X_FORWARDED_FOR', environ)
            self.assertNotIn('HTTP_X_FORWARDED_HOST', environ)
            response = IngressMiddleware(lambda request: HttpResponse('ok'))(WSGIRequest(environ))
            result.append(response.status_code)
            return []
        proxy_headers_middleware(application, trusted_proxy=options.get('trusted_proxy'),
            trusted_proxy_headers=options.get('trusted_proxy_headers'),
            clear_untrusted=options.get('clear_untrusted_proxy_headers', True))(
                request.environ, lambda *args: None)
        return result[0]

    def test_https_from_approved_proxy_survives_server_header_filtering(self):
        self.assertEqual(self.exercise('172.31.32.10', 'https'), 200)

    def test_http_and_unapproved_peers_remain_blocked(self):
        self.assertEqual(self.exercise('172.31.32.10', 'http'), 400)
        self.assertEqual(self.exercise('192.0.2.10', 'https'), 403)
