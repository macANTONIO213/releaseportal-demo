import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

from .controller_contract import sign
from .controller_http import strict_json, status_query, validate_query, PrivateClient
from .ecs_release import fingerprint
from .remote_jobs import Artifacts, Queue, RoleCLI, job, validate_job, signed_status


class RemoteJobsTests(unittest.TestCase):
    def setUp(self):
        self.id = str(uuid.uuid4())
        self.profile = {'repository': 'example/portal', 'execution_enabled': False}
        self.job = job(self.id, 'example/portal', 'a'*40, 'b'*64, fingerprint(self.profile))
        self.key = b'k'*32

    def test_job_schema_cannot_transport_credentials_or_unreviewed_profile(self):
        self.assertEqual(validate_job(self.job, self.profile), self.job)
        for key, value in [('access_key_id','secret'),('repository','other/repo'),('profile_sha256','f'*64)]:
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    validate_job({**self.job, key:value}, self.profile)

    def test_strict_json_rejects_duplicate_keys_nonfinite_numbers_and_oversize(self):
        for content in [b'{"a":1,"a":2}', b'{"a":NaN}', b' '*65537]:
            with self.assertRaises(ValueError):
                strict_json(content)

    def test_receipt_request_is_signed_expiring_and_action_bound(self):
        request = status_query(self.id, self.key, now=1000)
        self.assertEqual(validate_query(request,self.key,now=1001),self.id)
        for now in [900,1100]:
            with self.assertRaises(ValueError):
                validate_query(request,self.key,now=now)
        request['query']['action']='deploy'
        request['signature']=sign(request['query'],self.key)
        with self.assertRaises(ValueError):
            validate_query(request,self.key,now=1000)

    def test_workload_cli_discards_operator_credentials_and_default_profiles(self):
        calls=[]
        def fake(args,**kwargs):
            calls.append((args,kwargs['env']))
            return SimpleNamespace(returncode=0,stdout='{}',stderr='')
        with patch.dict('os.environ', {'AWS_ACCESS_KEY_ID':'operator-secret','AWS_PROFILE':'other-account',
            'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI':'/v2/credentials/fixture-123'}):
            web=RoleCLI('/usr/local/bin/aws','ap-southeast-1','web',run=fake)
            web.call('sqs','send-message',{'QueueUrl':'fixture','MessageBody':'{}'})
            self.assertNotIn('AWS_ACCESS_KEY_ID',calls[0][1])
            self.assertNotIn('AWS_PROFILE',calls[0][1])
            self.assertEqual(calls[0][1]['AWS_EC2_METADATA_DISABLED'],'true')
            worker=RoleCLI('/usr/local/bin/aws','ap-southeast-1','worker',run=fake)
            self.assertEqual(worker.env['AWS_EC2_METADATA_V1_DISABLED'],'true')
            self.assertNotIn('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI',worker.env)
        with self.assertRaises(ValueError):
            web.call('sts','get-caller-identity',{})

    def test_streaming_object_read_uses_cli_supported_flags_and_cannot_change_owner(self):
        calls=[]
        def fake(args,**kwargs):
            calls.append(args)
            return SimpleNamespace(returncode=0,stdout='{}',stderr='')
        cli=RoleCLI('/usr/local/bin/aws','ap-southeast-1','worker',run=fake)
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        output=str(Path(temporary.name)/'fixture-output')
        cli.call('s3api','get-object',{'Bucket':'fixture-bucket','Key':'runs/fixture/status.json',
            'ExpectedBucketOwner':'111122223333'},output=output)
        command=calls[0]
        self.assertNotIn('--cli-input-json',command)
        self.assertNotIn('--no-cli-pager',command)
        self.assertEqual(command[-1],output)
        self.assertEqual(command[command.index('--expected-bucket-owner')+1],'111122223333')
        with self.assertRaises(ValueError):
            cli.call('s3api','get-object',{'Bucket':'fixture-bucket','Key':'fixture','Endpoint':'other'},output=output)
        self.assertEqual(len(calls),1)

    def test_objects_are_private_prefix_bound_verified_and_use_file_body(self):
        content=b'fixture compiled artifact'
        class CLI:
            def call(inner,service,operation,params,output=None,body=None):
                self.assertEqual(params['ExpectedBucketOwner'],'111122223333')
                self.assertEqual(params['Key'],'runs/'+self.id+'/release.tar.gz')
                self.assertNotIn('ACL',params)
                if operation=='put-object':
                    self.assertEqual(Path(body).read_bytes(),content)
                else:
                    Path(output).write_bytes(content)
                return {}
        storage=Artifacts(CLI(),'portal-artifacts-111122223333','111122223333')
        digest=storage.put(self.id,'release.tar.gz',content)
        self.assertEqual(storage.get(self.id,'release.tar.gz',digest),content)
        with self.assertRaises(Exception):
            storage.get(self.id,'release.tar.gz','0'*64)
        for name in ['../control/key','credentials.json','source/../../key']:
            with self.assertRaises(ValueError):
                storage.key(self.id,name)

    def test_queue_url_and_messages_cannot_switch_account_or_include_secrets(self):
        class CLI:
            region='ap-southeast-1'
            def call(inner,*args):
                return {}
        queue=Queue(CLI(),'https://sqs.ap-southeast-1.amazonaws.com/111122223333/builds','111122223333','builds')
        queue.send(self.job)
        with self.assertRaises(ValueError):
            queue.send({**self.job,'session_token':'secret'})
        with self.assertRaises(ValueError):
            Queue(CLI(),'https://sqs.ap-southeast-1.amazonaws.com/999900001111/builds','111122223333','builds')

    def test_controller_client_refuses_public_or_loopback_addresses(self):
        for ip in ['127.0.0.1','8.8.8.8','::1']:
            with self.assertRaises(ValueError):
                PrivateClient(ip,'unused-cert.pem')

    def test_runner_status_cannot_publish_raw_logs_or_tokens(self):
        status={'run_id':self.id,'source_sha256':'b'*64,'profile_sha256':fingerprint(self.profile),
            'status':'failed','code':'unit_tests_failed','evidence_sha256':'', 'artifact_sha256':'','image':''}
        self.assertIn('signature',signed_status(status,self.key))
        with self.assertRaises(ValueError):
            signed_status({**status,'logs':'raw guest output'},self.key)


if __name__=='__main__':
    unittest.main()
