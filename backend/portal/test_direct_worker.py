import hashlib
import io
import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
from django.test import TestCase, override_settings
from django.core.management import call_command, CommandError
from django.contrib.auth import get_user_model
from .models import Run
from .direct_worker import tick, command, read_evidence
from .services import RuleError
from .source import directory

@override_settings(AUTH_MODE='github')
class WorkerEvidenceTests(TestCase):
    def setUp(self):
        self.runtime=tempfile.TemporaryDirectory()
        self.override=override_settings(ARTIFACT_ROOT=Path(self.runtime.name))
        self.override.enable()
        self.user=get_user_model().objects.create_user('worker-fixture')
        self.run=Run.objects.create(requester=self.user,commit='a'*40)
        root=directory(self.run);root.mkdir();(root/'output').mkdir()
        content=b'fixture source bytes'
        (root/'source.tar.gz').write_bytes(content)
        self.run.source_sha256=hashlib.sha256(content).hexdigest();self.run.save()
        self.report={'schema_version':1,'repository':self.run.repository,'commit':self.run.commit,
            'tests':{'passed':3,'failed':0,'skipped':0,'total':3},
            'scans':{name:{'status':'passed','findings':0} for name in ['source','dependencies','secrets']}}
    def tearDown(self):
        self.override.disable();self.runtime.cleanup()
    def write_report(self):
        (directory(self.run)/'output/release-evidence.json').write_text(json.dumps(self.report))
    def process_result(self, returncode=0):
        def complete(*args, **kwargs):
            self.write_report()
            return Mock(returncode=returncode)
        return complete
    @patch('portal.direct_worker.configured',return_value=True)
    @patch('portal.direct_worker.subprocess.run',return_value=Mock(returncode=0))
    def test_passing_worker_attaches_only_numeric_evidence(self,process,configuration):
        self.report['untrusted_text']='must never enter evidence'
        process.side_effect=self.process_result();tick();self.run.refresh_from_db()
        self.assertEqual(self.run.status,'ready')
        self.assertNotIn('untrusted_text',self.run.evidence)
        self.assertEqual(self.run.artifact_sha256,self.run.source_sha256)
    @patch('portal.direct_worker.configured',return_value=True)
    @patch('portal.direct_worker.subprocess.run',return_value=Mock(returncode=1))
    def test_failing_tests_are_visible_without_becoming_ready(self,process,configuration):
        self.report['tests'].update(passed=2,failed=1)
        process.side_effect=self.process_result(1);tick();self.run.refresh_from_db()
        self.assertEqual(self.run.status,'failed')
        self.assertEqual(self.run.evidence['tests']['failed'],1)
        self.assertEqual(self.run.artifact_sha256,'')
    @patch('portal.direct_worker.configured',return_value=True)
    @patch('portal.direct_worker.subprocess.run',return_value=Mock(returncode=0))
    def test_guest_cannot_replace_artifact_hash(self,process,configuration):
        self.report['artifact']={'sha256':'c'*64}
        process.side_effect=self.process_result();tick();self.run.refresh_from_db()
        self.assertEqual(self.run.artifact_sha256,self.run.source_sha256)
    @patch('portal.direct_worker.configured',return_value=False)
    @patch('portal.direct_worker.subprocess.run')
    def test_missing_sandbox_never_runs_source_on_host(self,process,configuration):
        tick();process.assert_not_called();self.run.refresh_from_db()
        self.assertEqual(self.run.status,'failed')
        self.assertEqual(self.run.error_code,'build_runtime_unconfigured')

    def test_input_mount_exposes_only_the_archive(self):
        args = command(self.run)
        mounts = [args[i+1] for i, value in enumerate(args) if value == '--mount']
        self.assertIn('type=bind,src='+str(directory(self.run).resolve()/'source.tar.gz')+',dst=/input/source.tar.gz,readonly', mounts)
        self.assertFalse(any('dst=/input,readonly' in mount for mount in mounts))

    @patch('portal.direct_worker.configured',return_value=True)
    @patch('portal.direct_worker.subprocess.run',return_value=Mock(returncode=0))
    def test_malformed_guest_reports_fail_with_safe_code(self,process,configuration):
        for report in [[], {'schema_version':True}, {**self.report,'scans':[]},
                       {**self.report,'scans':{'source':[],'dependencies':{},'secrets':{}}}]:
            with self.subTest(report=report):
                Run.objects.filter(pk=self.run.id).update(status='queued',error_code='')
                self.report=report
                process.side_effect=self.process_result()
                tick();self.run.refresh_from_db()
                self.assertEqual(self.run.status,'failed')
                self.assertEqual(self.run.error_code,'invalid_evidence')
                self.assertEqual(self.run.artifact_sha256,'')

    def test_invalid_json_and_oversized_output_are_rejected(self):
        path = directory(self.run)/'output/release-evidence.json'
        for content in [b'not json',b'\xff',b' '*(1024*1024+1)]:
            path.write_bytes(content)
            with self.assertRaises(RuleError) as caught:
                read_evidence(path)
            self.assertEqual(caught.exception.code,'invalid_evidence')

    def test_hardlinked_evidence_is_rejected(self):
        self.write_report()
        path = directory(self.run)/'output/release-evidence.json'
        os.link(path, directory(self.run)/'second-link')
        with self.assertRaises(RuleError) as caught:
            read_evidence(path)
        self.assertEqual(caught.exception.code,'invalid_evidence')

    @patch('portal.direct_worker.configured',return_value=True)
    @patch('portal.direct_worker.subprocess.run')
    def test_artifact_changed_during_execution_cannot_become_ready(self,process,configuration):
        self.write_report()
        def corrupt(*args, **kwargs):
            (directory(self.run)/'source.tar.gz').write_bytes(b'changed bytes')
            self.write_report()
            return Mock(returncode=0)
        process.side_effect=corrupt
        tick();self.run.refresh_from_db()
        self.assertEqual(self.run.status,'failed')
        self.assertEqual(self.run.error_code,'digest_mismatch')
        self.assertEqual(self.run.artifact_sha256,'')

    @patch('portal.direct_worker.configured',return_value=True)
    @patch('portal.direct_worker.subprocess.run')
    def test_failed_timeout_cleanup_blocks_jobs_until_confirmed_recovery(self,process,configuration):
        second = Run.objects.create(requester=self.user,commit='b'*40)
        process.side_effect=[subprocess.TimeoutExpired('docker',1800),subprocess.TimeoutExpired('docker kill',20)]
        tick();self.run.refresh_from_db();second.refresh_from_db()
        self.assertEqual(self.run.error_code,'container_cleanup_failed')
        self.assertEqual(second.status,'queued')
        self.assertEqual(process.call_count,2)
        tick();self.assertEqual(process.call_count,2)
        with self.assertRaises(CommandError):
            call_command('recover_inflight',workers_stopped=True,stdout=io.StringIO())
        call_command('recover_inflight',workers_stopped=True,containers_stopped=True,stdout=io.StringIO())
        self.run.refresh_from_db()
        self.assertEqual(self.run.error_code,'container_cleanup_confirmed')
        self.assertEqual(self.run.status,'failed')

    @patch('portal.direct_worker.configured',return_value=True)
    @patch('portal.direct_worker.subprocess.run')
    def test_nonzero_cleanup_exit_blocks_jobs(self,process,configuration):
        process.side_effect=[subprocess.TimeoutExpired('docker',1800),Mock(returncode=1)]
        tick();self.run.refresh_from_db()
        self.assertEqual(self.run.error_code,'container_cleanup_failed')
        self.assertEqual(process.call_args.kwargs['env'],process.call_args_list[0].kwargs['env'])

    @patch('portal.direct_worker.configured',return_value=True)
    @patch('portal.direct_worker.subprocess.run',return_value=Mock(returncode=0))
    def test_successful_exit_cannot_reuse_stale_evidence(self,process,configuration):
        self.write_report()
        tick();self.run.refresh_from_db()
        self.assertEqual(self.run.status,'failed')
        self.assertEqual(self.run.error_code,'invalid_evidence')
