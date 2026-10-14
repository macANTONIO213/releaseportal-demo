"""Fixed pipeline inside the reviewed sandbox. Registry-only egress is external.
Only numeric evidence/statuses leave the sandbox; raw logs are not published.
"""
import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path
from defusedxml import ElementTree

source=Path('/work/app')
report={'schema_version':1,'repository':os.environ['PORTAL_REPOSITORY'],'commit':os.environ['COMMIT_SHA'],
    'tests':None,'scans':{name:{'status':'not_run','findings':None} for name in ['source','dependencies','secrets']}}
stage='source'
failed=False
environment={'PATH':os.environ['PATH'],'HOME':'/work','TMPDIR':'/work/tmp',
    'DJANGO_SETTINGS_MODULE':'config.settings.ci','DJANGO_SECRET_KEY':'isolated-public-test-setting-only', # pragma: allowlist secret - disposable CI value
    'EAT_BASE_URL':'https://demo.example.invalid','WINDOWS_AUTH':'False','AWS_EC2_METADATA_DISABLED':'true',
    'ANTHROPIC_API_KEY':'','OIDC_RP_CLIENT_ID':'','OIDC_RP_CLIENT_SECRET':''}
def run(*args):
    return subprocess.run(list(args),cwd=source,env=environment).returncode
try:
    source.mkdir();Path('/work/tmp').mkdir()
    with tarfile.open('/input/source.tar.gz') as archive:
        archive.extractall(source,filter='data')
    lock=source/'deploy/aws-demo/requirements.lock.txt'
    if not (source/'manage.py').is_file() or not lock.is_file() or not (source/'config/settings/ci.py').is_file():
        raise ValueError()
    before={p.relative_to(source).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file()}
    stage='dependencies_install'
    if run('python','-m','venv','/work/venv') or run('/work/venv/bin/python','-m','pip','install','-r',str(lock)) or run('/work/venv/bin/python','-m','pip','install','pytest==9.1.1','pytest-django==4.14.0'):
        raise ValueError()
    stage='source_scan'
    rc=run('bandit','-r','apps','config','--severity-level','medium','--confidence-level','medium','-f','json','-o','/work/source.json')
    finding=json.loads(Path('/work/source.json').read_text())
    if not isinstance(finding.get('results'),list) or finding.get('errors'):
        raise ValueError()
    count=len(finding['results']);report['scans']['source']={'status':'passed' if rc==0 and count==0 else 'failed','findings':count}
    failed=failed or rc!=0 or count!=0
    stage='dependency_scan'
    rc=run('python','-m','pip_audit','--disable-pip','--no-deps','-r',str(lock),'-f','json','-o','/work/dependencies.json')
    deps=json.loads(Path('/work/dependencies.json').read_text())
    if not deps.get('dependencies') or any('skip_reason' in d or not isinstance(d.get('vulns'),list) for d in deps['dependencies']):
        raise ValueError()
    count=sum(len(d['vulns']) for d in deps['dependencies']);report['scans']['dependencies']={'status':'passed' if rc==0 and count==0 else 'failed','findings':count}
    failed=failed or rc!=0 or count!=0
    stage='secret_scan'
    with open('/work/secrets.json','w') as result:
        rc=subprocess.run(['detect-secrets','scan','--no-verify','--all-files',str(source)],env=environment,stdout=result).returncode
    secret_report=json.loads(Path('/work/secrets.json').read_text())
    if not secret_report.get('plugins_used') or not isinstance(secret_report.get('results'),dict):
        raise ValueError()
    count=sum(len(v) for v in secret_report['results'].values());report['scans']['secrets']={'status':'passed' if rc==0 and count==0 else 'failed','findings':count}
    failed=failed or rc!=0 or count!=0
    stage='unit_tests'
    python='/work/venv/bin/python'
    if run(python,'manage.py','check','--settings=config.settings.ci'):
        raise ValueError()
    rc=run(python,'-m','pytest','tests','--ds=config.settings.ci','--override-ini=addopts=','--junitxml=/work/tests.xml')
    cases=ElementTree.parse('/work/tests.xml').getroot().findall('.//testcase')
    failures=sum(c.find('failure') is not None or c.find('error') is not None for c in cases)
    skipped=sum(c.find('skipped') is not None for c in cases)
    report['tests']={'passed':len(cases)-failures-skipped,'failed':failures,'skipped':skipped,'total':len(cases)}
    failed=failed or rc!=0 or not cases or failures!=0
    stage='source_integrity'
    after={p.relative_to(source).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in source.rglob('*') if p.is_file() and p.relative_to(source).as_posix() in before}
    if before!=after:
        raise ValueError()
    stage='evidence_gate'
except Exception:
    failed=True
report['error_code']=stage+'_failed' if failed else ''
Path('/output/release-evidence.json').write_text(json.dumps(report))
raise SystemExit(1 if failed else 0)
