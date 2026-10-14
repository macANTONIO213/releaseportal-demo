import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from django.test import SimpleTestCase

TOOLS = Path(__file__).resolve().parents[2] / 'ci'

class EvidenceContractTests(SimpleTestCase):
    def fixture(self, root):
        (root / 'reports').mkdir()
        (root / 'app.py').write_text('print("fixture application")\n')
        def git(*args):
            return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL).decode().strip()
        git('init')
        git('add', 'app.py')
        git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-m', 'fixture')
        commit = git('rev-parse', 'HEAD')
        subprocess.run([sys.executable, str(TOOLS / 'package_source.py')], cwd=root, check=True, capture_output=True)
        (root / 'reports' / 'tests.xml').write_text('<testsuites><testsuite><testcase name="passes"/></testsuite></testsuites>')
        (root / 'reports' / 'dependencies.json').write_text(json.dumps({'dependencies': [{'name':'fixture','vulns':[]}]}))
        (root / 'reports' / 'secrets.json').write_text(json.dumps({'results':{},'plugins_used':[{'name':'fixture'}]}))
        return dict(os.environ, COMMIT_SHA=commit)

    def execute(self, root, env):
        return subprocess.run([sys.executable, str(TOOLS / 'evidence.py')], cwd=root, env=env, capture_output=True)

    def test_actual_report_parsing_and_archive_hash(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = self.fixture(root)
            result = self.execute(root, env)
            self.assertEqual(result.returncode, 0)
            evidence = json.loads((root / 'reports' / 'release-evidence.json').read_text())
            self.assertEqual(evidence['tests']['passed'], 1)
            self.assertEqual(evidence['artifact']['sha256'], hashlib.sha256((root/'reports/source.tar.gz').read_bytes()).hexdigest())

    def test_malformed_scan_does_not_become_zero_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = self.fixture(root)
            (root/'reports/dependencies.json').write_text('{}')
            self.assertNotEqual(self.execute(root, env).returncode, 0)
            self.assertFalse((root/'reports/release-evidence.json').exists())

    def test_failed_test_cannot_generate_release_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = self.fixture(root)
            (root/'reports/tests.xml').write_text('<testsuites><testsuite><testcase name="fails"><failure/></testcase></testsuite></testsuites>')
            self.assertNotEqual(self.execute(root, env).returncode, 0)

    def test_test_modified_source_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            env = self.fixture(root)
            (root/'app.py').write_text('print("changed after package")\n')
            self.assertNotEqual(self.execute(root, env).returncode, 0)
