import hashlib
import io
import json
import tarfile
import tempfile
import uuid
from pathlib import Path
from unittest.mock import Mock, patch
from django.contrib.auth import get_user_model
from django.test import TestCase, SimpleTestCase, override_settings
from django.utils import timezone
from datetime import timedelta
from .models import Member, Run, Release, Event
from .services import RuleError, attach_evidence, prepare_release, decide, digest
from .github import parse_repository, authorization, exchange
from .memory import MemoryStore
from .source import normalized_archive, directory
from .deployment import Credentials, execute, template_hash
from .direct_worker import command, configured
from .tests import evidence

def archive(members):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w:gz') as result:
        for name,content in members:
            member=tarfile.TarInfo(name)
            member.size=len(content)
            result.addfile(member,io.BytesIO(content))
    return buffer.getvalue()

class SourceTests(SimpleTestCase):
    def test_repository_url_normalization_and_org(self):
        self.assertEqual(parse_repository('https://github.com/macANTONIO213/example.git'),'macANTONIO213/example')
        for bad in ['https://evil.example/macANTONIO213/example','other-org/repo','macANTONIO213/../repo','macANTONIO213/repo?token=value']:
            with self.assertRaises(RuleError): parse_repository(bad)
    def test_snapshot_is_normalized(self):
        data=normalized_archive(archive([('root/app.py',b'pass')]))
        with tarfile.open(fileobj=io.BytesIO(data)) as result:
            self.assertEqual(result.getnames(),['app.py'])
    def test_traversal_and_duplicate_are_rejected(self):
        for contents in [[('root/../../outside',b'x')],[('root/a',b'x'),('root/a',b'y')]]:
            with self.assertRaises(RuleError): normalized_archive(archive(contents))
    def test_secret_file_rejected(self):
        with self.assertRaises(RuleError): normalized_archive(archive([('root/.env',b'fixture')]))
    def test_capability_is_user_bound_and_single_use(self):
        memory=MemoryStore()
        key=memory.put('fixture',1)
        self.assertIsNone(memory.get(key,2))
        self.assertEqual(memory.get(key,1,consume=True),'fixture')
        self.assertIsNone(memory.get(key,1))
    def test_expired_capability_is_not_reused(self):
        memory=MemoryStore()
        key=memory.put('fixture',1,ttl=-1)
        self.assertIsNone(memory.get(key,1))
    def test_aws_values_are_not_in_object_representation(self):
        credentials=Credentials('fixture-id','fixture-secret','fixture-token')
        self.assertNotIn('fixture',repr(credentials))
        credentials.erase()
        self.assertEqual(credentials.session_token,'')
    @override_settings(BUILD_IMAGE='image@sha256:'+'a'*64, BUILD_NETWORK='host', BUILD_RUNTIME='runc',BUILD_EGRESS_CONFIRMED=True)
    @patch('portal.direct_worker.shutil.which',return_value='/usr/bin/docker')
    def test_unsafe_runtime_is_rejected(self,tool):
        self.assertFalse(configured())

@override_settings(AUTH_MODE='github',GITHUB_REVIEWER_IDS={'2'})
class DirectFlowTests(TestCase):
    def setUp(self):
        self.owner=get_user_model().objects.create_user('github-1')
        self.reviewer=get_user_model().objects.create_user('github-2')
        Member.objects.create(user=self.owner,role='developer',github_id=1,github_login='owner')
        Member.objects.create(user=self.reviewer,role='reviewer',github_id=2,github_login='reviewer')
        self.client.force_login(self.owner)
        self.runtime=tempfile.TemporaryDirectory()
        self.override=override_settings(ARTIFACT_ROOT=Path(self.runtime.name))
        self.override.enable()
    def tearDown(self):
        self.override.disable()
        self.runtime.cleanup()
    def post(self,path,payload,secure=False):
        return self.client.post(path,json.dumps(payload),content_type='application/json',secure=secure)
    def ready(self):
        run=Run.objects.create(requester=self.owner,commit='a'*40)
        root=directory(run); root.mkdir()
        content=archive([('app.py',b'pass')])
        (root/'source.tar.gz').write_bytes(content)
        actual=hashlib.sha256(content).hexdigest()
        report=evidence();report['artifact'].update(sha256=actual,bytes=len(content))
        report['scans']['source']={'status':'passed','findings':0}
        run.source_sha256=actual;run.save()
        run=attach_evidence(run.id,report,actual)
        release=decide(prepare_release(run.id,self.owner).id,self.reviewer,True)
        return release,content
    def credentials(self,release):
        return {'access_key_id':'ASIA'+'A'*16,'secret_access_key':'x'*40,'session_token':'t'*100,
            'confirmed':True,'plan_digest':release.plan_digest}
    def test_login_page_configuration_is_honest(self):
        self.client.logout()
        data=self.client.get('/api/session').json()
        self.assertEqual(data['auth_method'],'github')
        self.assertFalse(data['github_configured'])
        self.assertIsNone(data['user'])
    def test_password_login_cannot_bypass_github(self):
        self.assertEqual(self.post('/api/login',{}).status_code,403)
    @patch('portal.direct_views.github.client_for')
    def test_dashboard_filters_repository_access(self,client):
        Run.objects.create(requester=self.owner,commit='a'*40,repository='macANTONIO213/not-authorized')
        client.return_value.repositories.return_value=['macANTONIO213/releaseportal-demo']
        self.assertEqual(self.client.get('/api/dashboard').json()['runs'],[])
    @patch('portal.direct_views.github.client_for')
    def test_artifact_access_is_rechecked(self,client):
        release,_=self.ready()
        client.return_value.repository.side_effect=RuleError('access_denied','Denied',403)
        self.assertEqual(self.client.get('/api/artifacts/'+str(release.run_id)).status_code,403)
    @patch('portal.direct_views.github.client_for')
    def test_credential_entry_requires_https(self,client):
        release,_=self.ready()
        response=self.post(f'/api/releases/{release.id}/deploy',self.credentials(release))
        self.assertEqual(response.status_code,400)
        self.assertEqual(response.json()['code'],'https_required')
    @patch('portal.direct_views.github.client_for')
    def test_disabled_template_does_not_accept_deployment(self,client):
        release,_=self.ready()
        response=self.post(f'/api/releases/{release.id}/deploy',self.credentials(release),True)
        self.assertEqual(response.status_code,503)
        release.refresh_from_db();self.assertEqual(release.status,'approved')
    @override_settings(AWS_DEPLOYMENT_ENABLED=True,DEPLOYMENT_TEMPLATE_APPROVED=True)
    @patch('portal.deployment.threading.Thread')
    @patch('portal.direct_views.github.client_for')
    def test_credentials_not_saved_in_models(self,client,thread):
        release,_=self.ready()
        payload=self.credentials(release)
        response=self.post(f'/api/releases/{release.id}/deploy',payload,True)
        self.assertEqual(response.status_code,202)
        release.refresh_from_db()
        persisted=json.dumps({'plan':release.plan,'result':release.deployment_result,'events':list(Event.objects.values('detail'))})
        for value in [payload['access_key_id'],payload['secret_access_key'],payload['session_token']]:
            self.assertNotIn(value,persisted)
        self.assertEqual(release.status,'deploying')
        thread.return_value.start.assert_called_once()
    @override_settings(AWS_DEPLOYMENT_ENABLED=True,DEPLOYMENT_TEMPLATE_APPROVED=True)
    @patch('portal.direct_views.github.client_for')
    def test_changed_template_blocks_credentials(self,client):
        release,_=self.ready()
        release.plan['template_sha256']='c'*64;release.plan_digest=digest(release.plan);release.save()
        response=self.post(f'/api/releases/{release.id}/deploy',self.credentials(release),True)
        self.assertEqual(response.status_code,409)
    @patch('portal.deployment.requests',create=True)
    def test_aws_failure_has_no_fallback_or_secret_receipt(self,unused):
        release,content=self.ready()
        release.status='deploying';release.operator=self.owner;release.save()
        factory=Mock()
        factory.return_value.client.return_value.put_object.side_effect=RuntimeError('fixture secret must not be logged')
        credentials=Credentials('fixture-id','fixture-secret','fixture-token')
        execute(str(release.id),credentials,content,session_factory=factory,sleep=lambda _:None)
        release.refresh_from_db()
        self.assertEqual(release.status,'reconciliation_required')
        self.assertNotIn('fixture',json.dumps(release.deployment_result))
        self.assertEqual(factory.call_args.kwargs['aws_session_token'],'fixture-token')
        self.assertEqual(credentials.session_token,'')
    @patch('portal.deployment.requests',create=True)
    def test_corrupt_artifact_never_calls_aws(self,unused):
        release,_=self.ready();release.status='deploying';release.operator=self.owner;release.save()
        factory=Mock();credentials=Credentials('fixture-id','fixture-secret','fixture-token')
        execute(str(release.id),credentials,b'wrong artifact',session_factory=factory,sleep=lambda _:None)
        factory.assert_not_called()
    def test_cookie_session_contains_no_github_token(self):
        from .memory import github_tokens
        capability=github_tokens.put('fixture-github-token',self.owner.id)
        session=self.client.session;session['github_capability']=capability;session.save()
        self.assertNotIn('fixture-github-token',json.dumps(dict(self.client.session)))
    @override_settings(GITHUB_CLIENT_ID='fixture',GITHUB_CLIENT_SECRET='fixture',GITHUB_REDIRECT_URI='https://portal.example/auth/callback')
    def test_oauth_uses_state_and_pkce(self):
        self.client.logout()
        response=self.client.get('/auth/login')
        self.assertEqual(response.status_code,302)
        self.assertIn('code_challenge_method=S256',response['Location'])
        self.assertIn('state=',response['Location'])
        self.assertNotIn('client_secret',response['Location'])
    @override_settings(GITHUB_CLIENT_ID='fixture',GITHUB_CLIENT_SECRET='fixture',GITHUB_REDIRECT_URI='https://portal.example/auth/callback')
    @patch('portal.github.requests.post')
    def test_bad_oauth_state_makes_no_token_request(self,post):
        self.client.logout();self.client.get('/auth/login')
        response=self.client.get('/auth/callback?state=wrong&code=fixture')
        self.assertEqual(response.status_code,403);post.assert_not_called()
    @override_settings(BUILD_IMAGE='image@sha256:'+'a'*64,BUILD_RUNTIME='runsc',BUILD_NETWORK='releaseportal-build')
    def test_builder_has_no_credentials_or_docker_socket_mount(self):
        run=Run.objects.create(requester=self.owner,commit='a'*40)
        args=command(run)
        serialized=' '.join(args)
        self.assertNotIn('AWS_SECRET',serialized)
        self.assertNotIn('docker.sock',serialized)
        self.assertIn('--cap-drop=ALL',args)

    @patch('requests.get',return_value=Mock(status_code=200))
    def test_success_uses_only_scoped_s3_and_ssm_then_http(self,http):
        release,content=self.ready();release.status='deploying';release.operator=self.owner;release.save()
        s3,ssm=Mock(),Mock()
        command_id='12345678-1234-1234-1234-123456789abc'
        ssm.send_command.return_value={'Command':{'CommandId':command_id}}
        ssm.get_command_invocation.return_value={'Status':'Success','StandardOutputContent':'must never be retained'}
        factory=Mock()
        factory.return_value.client.side_effect=lambda name,**kwargs:{'s3':s3,'ssm':ssm}[name]
        credentials=Credentials('fixture-id','fixture-secret','fixture-token')
        execute(str(release.id),credentials,content,session_factory=factory,sleep=lambda _:None)
        release.refresh_from_db()
        self.assertEqual(release.status,'deployed')
        self.assertFalse(release.deployment_result['authenticated_login_verified'])
        self.assertNotIn('must never',json.dumps(release.deployment_result))
        self.assertEqual(s3.put_object.call_args.kwargs['ExpectedBucketOwner'],'111122223333')
        self.assertEqual(ssm.send_command.call_args.kwargs['InstanceIds'],['i-00000000000000000'])
        self.assertEqual([c.args[0] for c in factory.return_value.client.call_args_list],['s3','ssm'])
        self.assertEqual(http.call_count,2)

    @override_settings(GITHUB_REVIEWER_IDS=set())
    @patch('portal.direct_views.github.client_for')
    def test_removed_reviewer_cannot_keep_approval_privilege(self,client):
        release,_=self.ready()
        release.status='awaiting_approval';release.save()
        self.client.force_login(self.reviewer)
        self.assertEqual(self.post(f'/api/releases/{release.id}/approve',{'acknowledged':True}).status_code,403)

    @patch('portal.direct_views.github.GitHub')
    @patch('portal.direct_views.github.exchange',return_value=('fixture-github-token',300))
    def test_github_callback_binds_existing_identity_and_memory_token(self,exchange,client):
        client.return_value.identity.return_value={'id':1,'login':'owner'}
        client.return_value.repositories.return_value=['macANTONIO213/releaseportal-demo']
        self.client.logout()
        self.assertEqual(self.client.get('/auth/callback?state=fixture&code=fixture').status_code,302)
        self.assertEqual(self.client.get('/api/session').json()['user']['name'],'owner')
        self.assertNotIn('fixture-github-token',json.dumps(dict(self.client.session)))
