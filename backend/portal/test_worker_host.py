"""Host orchestration contract tests. No Linux execution, networking or AWS calls."""
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import tempfile
import unittest
import uuid
from unittest.mock import Mock

from .ecs_release import fingerprint
from .remote_jobs import job

root=Path(__file__).resolve().parents[2]
def load(name):
    spec=importlib.util.spec_from_file_location('trusted_'+name,root/'ci'/f'{name}.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
proxy=load('registry_proxy');worker=load('releaseportal_dispatcher')


class WorkerHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.profile={'account':'111122223333','region':'ap-southeast-1','repository':'example/portal',
            'runner_image':'111122223333.dkr.ecr.ap-southeast-1.amazonaws.com/releaseportal/runner@sha256:'+'a'*64}
        self.value=job(str(uuid.uuid4()),'example/portal','b'*40,hashlib.sha256(b'fixture').hexdigest(),fingerprint(self.profile))

    def test_proxy_pins_reviewed_registry_addresses_and_rejects_private_dns(self):
        def resolve(*args,**kwargs):
            return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]
        self.assertEqual(proxy.destination('pypi.org:443',resolve)[-1],('8.8.8.8',443))
        for target in ['github.com:443','pypi.org:80','169.254.169.254:443','pypi.org.evil.invalid:443']:
            with self.assertRaises(ValueError):proxy.destination(target,resolve)
        for ip in ['169.254.169.254','172.31.32.1','127.0.0.1','::1','fd00:ec2::254']:
            with self.subTest(ip=ip):
                with self.assertRaises(ValueError):
                    proxy.destination('pypi.org:443',lambda *a,**k:[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,443))])

    def test_sandbox_has_no_credentials_socket_privilege_or_host_network(self):
        command=worker.sandbox_command(self.value,self.profile,Path(self.tmp.name)/self.value['run_id'])
        text=' '.join(command)
        for forbidden in ['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','GITHUB_TOKEN',
                          'docker.sock','--privileged','--network host']:
            self.assertNotIn(forbidden,text)
        self.assertIn('--runtime runsc',text);self.assertIn('--log-driver=none',text)
        self.assertIn('--read-only',command)
        self.assertIn('--memory=4g',command)
        self.assertIn('HTTPS_PROXY=http://172.26.0.1:3128',command)

    def test_duplicate_and_uncertain_claims_cannot_execute_after_restart(self):
        path=Path(self.tmp.name)/'claims.sqlite3';claims=worker.Claims(path);claims.claim(self.value)
        restarted=worker.Claims(path)
        with self.assertRaises(ValueError):restarted.claim({**self.value,'run_id':str(uuid.uuid4())})
        claims.finish(self.value['run_id'],'ready')
        self.assertFalse(restarted.claim(self.value))

    def test_failed_pipeline_is_reported_without_image_build_or_automatic_rerun(self):
        queue=Mock();queue.receive.return_value=[{'Body':json.dumps(self.value),'ReceiptHandle':'fixture-handle'}]
        storage=Mock();storage.get.return_value=b'fixture';storage.put.side_effect=lambda *args:hashlib.sha256(args[-1]).hexdigest()
        sandbox=Mock();sandbox.execute.return_value=(None,None);assembler=Mock()
        dispatcher=worker.Dispatcher(self.profile,b'k'*32,queue,storage,worker.Claims(Path(self.tmp.name)/'claims.sqlite3'),sandbox,assembler)
        dispatcher.tick()
        assembler.assert_not_called();queue.delete.assert_called_once_with('fixture-handle')
        status=json.loads(storage.put.call_args.args[-1])['status']
        self.assertEqual(status['status'],'failed');self.assertEqual(status['code'],'pipeline_failed')
        dispatcher.tick()
        sandbox.execute.assert_called_once()
        self.assertEqual(queue.delete.call_count,2)

    def test_guest_output_symlink_is_never_read(self):
        import os
        if os.name=='nt':self.skipTest('Linux O_NOFOLLOW acceptance runs on the approved host')
        path=Path(self.tmp.name);(path/'target').write_bytes(b'fixture');(path/'link').symlink_to(path/'target')
        with self.assertRaises(OSError):worker.bounded_file(path/'link',100)
