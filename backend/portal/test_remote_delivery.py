import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch
import uuid

from django.contrib.auth import get_user_model
from django.test import TestCase,override_settings

from . import remote_delivery,services
from .ecs_release import fingerprint
from .models import Member,Run,Release,Event
from .remote_jobs import signed_status


@override_settings(GITHUB_REVIEWER_IDS={'202'},GITHUB_ALLOWED_USER_IDS={'101','202'})
class RemoteDeliveryTests(TestCase):
    def setUp(self):
        self.owner=get_user_model().objects.create_user('owner-fixture')
        self.reviewer=get_user_model().objects.create_user('reviewer-fixture')
        Member.objects.create(user=self.owner,role='developer',github_id=101)
        Member.objects.create(user=self.reviewer,role='reviewer',github_id=202)
        Event.objects.create(actor=self.reviewer,action='github_signed_in')
        self.profile={'account':'111122223333','region':'ap-southeast-1',
            'repository':'macANTONIO213/releaseportal-demo','service_arn':'arn:aws:ecs:ap-southeast-1:111122223333:service/portal/portal',
            'image_repository':'111122223333.dkr.ecr.ap-southeast-1.amazonaws.com/portal',
            'allowed_creator_ids':['101'],'allowed_reviewer_ids':['202'],'execution_enabled':True,
            'health_url':'https://portal.example.invalid/healthz'}
        self.image=self.profile['image_repository']+'@sha256:'+'b'*64
        self.cfg={'profile':self.profile,'pipeline_enabled':True,'deployment_enabled':True,
            'controller_private_ip':'172.31.32.123','controller_certificate':'fixture-cert',
            'accepted':{k:True for k in ['linux_isolation','restricted_egress','runner_image','private_storage','queue_integration',
                'controller_tls','reviewer_oauth_guard','update_recovery']},
            'baseline_service':{'serviceArn':self.profile['service_arn'],'activeConfigurations':[{
                'cpu':'512','memory':'1024','primaryContainer':{'image':self.profile['image_repository']+'@sha256:'+'a'*64,
                    'containerPort':8055,'environment':[{'name':'PORTAL_OWNER_SIGNIN_ONLY','value':'0'}]}}]}}
        self.objects={};self.sent=[];self.key=b'k'*32
        class Storage:
            def put(inner,run,name,content):
                self.objects[(run,name)]=content
                return hashlib.sha256(content).hexdigest()
            def get(inner,run,name,digest=None):
                content=self.objects[(run,name)]
                if digest and hashlib.sha256(content).hexdigest()!=digest:
                    raise ValueError()
                return content
        class Queue:
            def send(inner,value):
                self.sent.append(value)
                return {'MessageId':str(uuid.uuid4())}
        self.storage,self.queue=Storage(),Queue()
        for target,replacement in [('config',lambda:self.cfg),('key',lambda:self.key),
                                   ('adapters',lambda:(self.cfg,self.storage,self.queue))]:
            context=patch.object(remote_delivery,target,replacement);context.start();self.addCleanup(context.stop)
        context=patch.object(remote_delivery,'_control_health',{'fingerprint':fingerprint(self.cfg),'until':float('inf'),'ready':True})
        context.start();self.addCleanup(context.stop)
        self.run=Run.objects.create(requester=self.owner,repository=self.profile['repository'],commit='c'*40,status='fetching_source')

    def ready(self):
        remote_delivery.enqueue(self.run,b'fixture source')
        artifact=b'fixture compiled artifact';artifact_sha=hashlib.sha256(artifact).hexdigest()
        report={'schema_version':1,'repository':self.run.repository,'commit':self.run.commit,
            'source_sha256':self.run.source_sha256,'profile_sha256':fingerprint(self.profile),
            'artifact_sha256':artifact_sha,'image':self.image,'error_code':'',
            'image_scan':{'status':'COMPLETE','high':0,'critical':0},
            'tests':{'passed':3,'failed':0,'skipped':0,'total':3},
            'scans':{k:{'status':'passed','findings':0} for k in ['source','dependencies','secrets']},
            'logs':'untrusted raw output must be discarded'}
        raw=json.dumps(report).encode()
        self.storage.put(str(self.run.id),'release-evidence.json',raw)
        self.storage.put(str(self.run.id),'release.tar.gz',artifact)
        status={'run_id':str(self.run.id),'source_sha256':self.run.source_sha256,'profile_sha256':fingerprint(self.profile),
            'status':'ready','code':'','evidence_sha256':hashlib.sha256(raw).hexdigest(),'artifact_sha256':artifact_sha,'image':self.image}
        self.storage.put(str(self.run.id),'status.json',json.dumps(signed_status(status,self.key)).encode())
        remote_delivery.poll();self.run.refresh_from_db()

    def test_end_to_end_contract_keeps_queue_credential_free_and_discards_guest_logs(self):
        self.ready()
        self.assertEqual(self.run.status,'ready')
        self.assertNotIn('logs',self.run.evidence)
        self.assertEqual(self.run.artifact_name,'release.tar.gz')
        self.assertEqual(set(self.sent[0]),{'version','run_id','repository','commit','source_sha256','profile_sha256'})
        release=services.prepare_release(self.run.id,self.owner)
        self.assertEqual(release.plan['execution'],'ecs-service-image-v1')
        with self.assertRaises(services.RuleError):
            services.decide(release.id,self.owner,True)
        release=services.decide(release.id,self.reviewer,True)
        self.assertLessEqual((release.approval_expires_at-release.approved_at).total_seconds(),1801)
        captured=[]
        class Client:
            def __init__(inner,*args):pass
            def post(inner,path,value):
                captured.append(value)
                return {'release_id':str(release.id),'plan_digest':release.plan_digest,'status':'accepted'}
        payload={'confirmed':True,'plan_digest':release.plan_digest,'access_key_id':'ASIA'+'A'*16,
                 'secret_access_key':'s'*40,'session_token':'t'*32}
        with patch.object(remote_delivery,'PrivateClient',Client):
            result=remote_delivery.deploy(SimpleNamespace(is_secure=lambda:True,user=self.owner),release,payload)
        self.assertFalse(result['credentials_persisted'])
        self.assertEqual(captured[0]['credentials'],{})
        release.refresh_from_db();self.assertEqual(release.status,'deploying')
        self.assertNotIn('secret_access_key',json.dumps(release.deployment_result))

    def test_submission_uncertainty_never_requeues_automatically(self):
        with patch.object(self.queue,'send',side_effect=TimeoutError()):
            with self.assertRaises(services.RuleError):
                remote_delivery.enqueue(self.run,b'fixture source')
        self.run.refresh_from_db()
        self.assertEqual(self.run.status,'sync_required')
        self.assertEqual(self.run.error_code,'remote_submission_unknown')

    def test_tampered_status_or_artifact_never_becomes_ready(self):
        self.ready()
        Run.objects.filter(pk=self.run.id).update(status='running',evidence={},artifact_sha256='')
        self.objects[(str(self.run.id),'release.tar.gz')]=b'tampered'
        remote_delivery.poll();self.run.refresh_from_db()
        self.assertEqual(self.run.status,'sync_required')
        self.assertNotEqual(self.run.status,'ready')

    def test_scope_approval_alone_does_not_enable_deployment_or_pipeline(self):
        self.cfg['accepted']['linux_isolation']=False
        self.assertFalse(remote_delivery.configured())
        self.cfg['accepted']['linux_isolation']=True
        Event.objects.filter(action='github_signed_in').delete()
        self.assertTrue(remote_delivery.configured())
        self.assertFalse(remote_delivery.configured(deployment=True))
