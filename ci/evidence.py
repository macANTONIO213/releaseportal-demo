"""Generate facts from actual JUnit and scanner reports, never fixtures."""
import hashlib
import json
import os
import subprocess
from pathlib import Path
from defusedxml import ElementTree

if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no']).strip():
    raise SystemExit('Tests modified tracked source; release artifact cannot be accepted')
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD']).decode().strip()
if commit != os.environ['COMMIT_SHA']:
    raise SystemExit('Revision mismatch')
root = ElementTree.parse('reports/tests.xml').getroot()
cases = root.findall('.//testcase')
failed = sum(c.find('failure') is not None or c.find('error') is not None for c in cases)
skipped = sum(c.find('skipped') is not None for c in cases)
dependencies = json.loads(Path('reports/dependencies.json').read_text())
if not isinstance(dependencies.get('dependencies'), list) or not dependencies['dependencies'] or any('skip_reason' in d or not isinstance(d.get('vulns'), list) for d in dependencies['dependencies']):
    raise SystemExit('Dependency scan is incomplete or malformed')
dependency_count = sum(len(d.get('vulns', [])) for d in dependencies.get('dependencies', []))
secret_report = json.loads(Path('reports/secrets.json').read_text())
if not isinstance(secret_report.get('results'), dict) or not secret_report.get('plugins_used'):
    raise SystemExit('Secret scan is incomplete or malformed')
secret_count = sum(len(v) for v in secret_report.get('results', {}).values())
if not cases or failed or dependency_count or secret_count:
    raise SystemExit('Evidence gate failed: tests or scanners need attention. No passing release report generated.')
artifact = Path('reports/source.tar.gz').read_bytes()
report = {'schema_version': 1, 'repository': 'macANTONIO213/releaseportal-demo', 'commit': commit,
    'tests': {'passed': len(cases)-failed-skipped, 'failed': failed, 'skipped': skipped, 'total': len(cases)},
    'scans': {'dependencies': {'status': 'passed', 'findings': dependency_count}, 'secrets': {'status': 'passed', 'findings': secret_count}},
    'artifact': {'name': 'source.tar.gz', 'sha256': hashlib.sha256(artifact).hexdigest(), 'bytes': len(artifact)}}
Path('reports/release-evidence.json').write_text(json.dumps(report, indent=2))
print('Actual build evidence recorded. No deployment performed.')
