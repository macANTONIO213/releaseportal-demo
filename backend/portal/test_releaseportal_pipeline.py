import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from django.test import SimpleTestCase

root = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('trusted_releaseportal_pipeline', root / 'ci/releaseportal_pipeline.py')
pipeline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pipeline)


class ReleasePortalPipelineTests(SimpleTestCase):
    def test_secret_dispositions_require_exact_file_and_finding(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            source=Path(temporary);path=source/'lock.txt';path.write_bytes(b'public checksum fixture\n')
            finding={'type':'Hex High Entropy String','line_number':1,'hashed_secret':'a'*40}
            review={'path':'lock.txt','file_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                'type':finding['type'],'line':1,'hashed_secret':finding['hashed_secret'],
                'disposition':'reviewed_false_positive','reason':'Public package integrity checksum; no authentication capability.'}
            report={'plugins_used':[{'name':'HexHighEntropyString'}],'results':{'lock.txt':[finding]}}
            self.assertEqual(pipeline.secret_findings(report,source,[review]),
                {'findings':0,'reviewed_findings':1,'total_findings':1})
            finding['hashed_secret']='b'*40
            self.assertEqual(pipeline.secret_findings(report,source,[review])['findings'],1)
            finding['hashed_secret']='a'*40;path.write_bytes(b'changed fixture\n')
            self.assertEqual(pipeline.secret_findings(report,source,[review])['findings'],1)
            with self.assertRaises(pipeline.PipelineStopped):
                pipeline.secret_findings({'plugins_used':[],'results':{}},source,[review])

    def test_source_dispositions_are_exact_file_bound_and_never_cover_high_findings(self):
        import hashlib
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'backend').mkdir();path=root/'backend/example.py';path.write_bytes(b'import subprocess\n')
            finding={'filename':'backend/example.py','test_id':'B404','line_number':1,'issue_severity':'LOW'}
            review={'path':'backend/example.py','test_id':'B404','line':1,'severity':'LOW',
                'file_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'disposition':'reviewed_false_positive',
                'reason':'Import only; fixed reviewed subprocess boundary, no shell or user command text.'}
            report={'results':[finding],'errors':[]}
            self.assertEqual(pipeline.source_findings(report,root,[review]),{'findings':0,'reviewed_findings':1,'total_findings':1})
            path.write_bytes(b'import subprocess\n# changed\n')
            self.assertEqual(pipeline.source_findings(report,root,[review])['findings'],1)
            finding['issue_severity']='HIGH'
            self.assertEqual(pipeline.source_findings(report,root,[review])['reviewed_findings'],0)
            with self.assertRaises(pipeline.PipelineStopped):
                pipeline.source_findings({'results':[],'errors':['scan failed']},root,[review])

    def extract(self, name='backend/manage.py', kind=tarfile.REGTYPE, link=''):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            archive = path / 'input.tar.gz'; destination = path / 'app'; destination.mkdir()
            with tarfile.open(archive, 'w:gz') as outgoing:
                entry = tarfile.TarInfo(name); entry.type = kind; entry.linkname = link
                if kind == tarfile.REGTYPE:
                    entry.size = 3; outgoing.addfile(entry, io.BytesIO(b'abc'))
                else:outgoing.addfile(entry)
            pipeline.extract_source(archive, destination)
            return (destination / name).read_bytes()

    def test_regular_source_is_extracted_without_executing_it(self):
        self.assertEqual(self.extract(), b'abc')

    def test_traversal_links_and_credential_files_are_rejected(self):
        cases = [('../escape', tarfile.REGTYPE, ''), ('/absolute', tarfile.REGTYPE, ''),
            ('backend/linked', tarfile.SYMTYPE, '/etc/passwd'),
            ('backend/linked', tarfile.LNKTYPE, 'backend/manage.py'),
            ('.env.production', tarfile.REGTYPE, ''), ('private.key', tarfile.REGTYPE, '')]
        for name, kind, link in cases:
            with self.subTest(name=name, kind=kind):
                with self.assertRaises(pipeline.PipelineStopped):self.extract(name, kind, link)

    def test_empty_or_skipped_dependency_audits_are_not_passing(self):
        for report in [{}, {'dependencies': []}, {'dependencies': [{'skip_reason': 'not inspected'}]},
                       {'dependencies': [{'vulns': None}]}]:
            with self.subTest(report=report):
                with self.assertRaises(pipeline.PipelineStopped):pipeline.dependency_count(report)
        self.assertEqual(pipeline.dependency_count({'dependencies': [{'vulns': []}, {'vulns': [{}]}]}), 1)

    def test_frontend_audit_requires_counts_for_every_severity(self):
        with self.assertRaises(pipeline.PipelineStopped):pipeline.frontend_count({'metadata': {}})
        counts = {'info': 0, 'low': 1, 'moderate': 2, 'high': 0, 'critical': 0}
        self.assertEqual(pipeline.frontend_count({'metadata': {'vulnerabilities': counts}}), 3)

    def test_prepared_profile_matches_repository_migrations_and_is_disabled(self):
        profile = json.loads((root / 'ci/releaseportal-profile.example.json').read_text())
        self.assertFalse(profile['execution_enabled'])
        self.assertEqual(pipeline.migration_digest(root), profile['migration_manifest_sha256'])

    def test_expected_failures_are_not_reported_as_passing_tests(self):
        spec = importlib.util.spec_from_file_location('trusted_counter', root / 'ci/releaseportal_test_runner.py')
        counter = importlib.util.module_from_spec(spec); spec.loader.exec_module(counter)
        result = SimpleNamespace(testsRun=4, failures=[], errors=[], skipped=[object()],
            expectedFailures=[object()], unexpectedSuccesses=[object()])
        with patch.object(counter.DiscoverRunner, 'run_suite', return_value=result), patch.object(counter.Path, 'write_text') as write:
            counter.CountingRunner(verbosity=0).run_suite(None)
        self.assertEqual(json.loads(write.call_args.args[0]), {'total':4, 'passed':1, 'failed':1, 'skipped':2})
