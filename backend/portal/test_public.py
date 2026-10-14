import ipaddress
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock
from django.test import TestCase, SimpleTestCase, RequestFactory, override_settings
from django.http import JsonResponse
from .middleware import IngressMiddleware
from .roles import role_for

@override_settings(PUBLIC=True, TRUSTED_PROXY_NETWORKS=[ipaddress.ip_network('10.253.240.0/24')],
                   ALLOWED_HOSTS=['portal.example.invalid'])
class PublicIngressTests(TestCase):
    def setUp(self):
        self.factory=RequestFactory()
        self.next=Mock(return_value=JsonResponse({'handled':True}))
        self.middleware=IngressMiddleware(self.next)
    def request(self, path='/', peer='10.253.240.5', host='portal.example.invalid', proto='https', method='get'):
        return getattr(self.factory,method)(path,REMOTE_ADDR=peer,HTTP_HOST=host,HTTP_X_FORWARDED_PROTO=proto)
    def test_untrusted_peer_cannot_spoof_forwarded_proto(self):
        result=self.middleware(self.request(peer='203.0.113.8'))
        self.assertEqual(result.status_code,403);self.next.assert_not_called()
    def test_health_allows_alb_http_target_host_only_on_health_route(self):
        result=self.middleware(self.request('/healthz',host='10.253.240.50:8055',proto='http'))
        self.assertEqual(result.status_code,200)
        self.assertEqual(json.loads(result.content),{'status':'ok'})
        self.assertEqual(result['Cache-Control'],'no-store');self.next.assert_not_called()
    def test_health_does_not_accept_untrusted_peer_or_post(self):
        self.assertEqual(self.middleware(self.request('/healthz',peer='203.0.113.8')).status_code,403)
        self.assertEqual(self.middleware(self.request('/healthz',method='post')).status_code,405)
    def test_other_routes_require_https_and_exact_host(self):
        for request in [self.request('/api/session',proto='http'),self.request('/auth/callback?code=public-fixture',host='evil.example.invalid')]:
            result=self.middleware(request)
            self.assertEqual(result.status_code,400)
            self.assertNotIn(b'public-fixture',result.content)
        self.next.assert_not_called()
    def test_trusted_https_request_reaches_normal_controls(self):
        self.assertEqual(self.middleware(self.request('/api/session')).status_code,200)
        self.next.assert_called_once()
    @override_settings(AUTH_MODE='github',GITHUB_ALLOWED_USER_IDS={'1','2'},GITHUB_REVIEWER_IDS={'2'})
    def test_removed_public_identity_loses_role(self):
        self.assertIsNone(role_for(Mock(github_id=3,role='developer')))
        self.assertEqual(role_for(Mock(github_id=1,role='developer')),'developer')

class PublicConfigurationTests(SimpleTestCase):
    def test_public_startup_never_fakes_private_boundary_or_enables_deployment(self):
        root=Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as runtime:
            env={k:v for k,v in os.environ.items() if not k.startswith('PORTAL_')}
            env.update(PYTHONPATH=str(root),PORTAL_MODE='pilot',PORTAL_INGRESS_MODE='public',PORTAL_PUBLIC_INGRESS_APPROVED='1',
                PORTAL_TRUST_PROXY='1',PORTAL_TRUSTED_PROXY_CIDRS='10.253.240.0/24',PORTAL_RUNTIME_DIR=runtime,
                PORTAL_HOSTS='portal.example.invalid',PORTAL_SECRET_KEY='public-test-fixture',
                PORTAL_DB_HOST='postgres.example.invalid',PORTAL_DB_PASSWORD='public-test-fixture',
                PORTAL_GITHUB_CLIENT_ID='public-test-fixture',PORTAL_GITHUB_CLIENT_SECRET='public-test-fixture',
                PORTAL_GITHUB_REDIRECT_URI='https://portal.example.invalid/auth/callback',PORTAL_GITHUB_ALLOWED_USER_IDS='1,2',PORTAL_GITHUB_REVIEWER_IDS='2')
            command=[sys.executable,'-c','from config import settings; assert settings.PUBLIC; assert not settings.PRIVATE_INGRESS_CONFIRMED']
            self.assertEqual(subprocess.run(command,env=env,capture_output=True,timeout=30).returncode,0)
            for change in [{'PORTAL_PUBLIC_INGRESS_APPROVED':'0'},{'PORTAL_PRIVATE_INGRESS_CONFIRMED':'1'},
                           {'PORTAL_AWS_DEPLOYMENT_ENABLED':'1'},{'PORTAL_BUILD_RUNTIME':'runsc'},
                           {'PORTAL_HOSTS':'*'},{'PORTAL_TRUSTED_PROXY_CIDRS':'0.0.0.0/0'},
                           {'PORTAL_GITHUB_ALLOWED_USER_IDS':'1'},{'PORTAL_GITHUB_REDIRECT_URI':'https://evil.example.invalid/auth/callback'}]:
                with self.subTest(change=change):
                    self.assertNotEqual(subprocess.run(command,env={**env,**change},capture_output=True,timeout=30).returncode,0)
