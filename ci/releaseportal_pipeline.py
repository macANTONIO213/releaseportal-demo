"""ReleasePortal-only guest pipeline. Run only in the approved isolated sandbox.

The trusted profile, this entry point and scanner tools come from the pinned
runner image, outside repository paths. No cloud credentials are accepted here.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile


class PipelineStopped(Exception):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def read_json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
        raise PipelineStopped()
    return json.loads(path.read_text())


def extract_source(archive, destination, templates=None):
    templates=templates or {}
    total, names = 0, set()
    with tarfile.open(archive, 'r:gz') as incoming:
        for member in incoming:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or '\\' in member.name or not name.parts:
                raise PipelineStopped()
            if member.isdir():
                continue
            if not member.isfile() or member.name in names or member.size > 25 * 1024 * 1024:
                raise PipelineStopped()
            if any(part in ['.git', '.venv', 'node_modules', '__pycache__'] for part in name.parts):
                raise PipelineStopped()
            if (name.name.startswith('.env') and str(name) not in templates) or name.suffix in ['.pem', '.key', '.sqlite3']:
                raise PipelineStopped()
            if name.parts[0] in ['.npmrc','.pnpmfile.cjs','pnpmfile.cjs','sitecustomize.py','usercustomize.py']:
                raise PipelineStopped()
            names.add(member.name); total += member.size
            if len(names) > 10000 or total > 500 * 1024 * 1024:
                raise PipelineStopped()
            path = destination.joinpath(*name.parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            # Reject links before and during extraction, including parent paths.
            if path.exists() or any(parent.is_symlink() for parent in path.parents):
                raise PipelineStopped()
            content = incoming.extractfile(member).read(member.size + 1)
            if len(content) != member.size:
                raise PipelineStopped()
            if str(name) in templates and hashlib.sha256(content.replace(b'\r\n',b'\n')).hexdigest()!=templates[str(name)]:
                raise PipelineStopped()
            path.write_bytes(content)
    if not names:
        raise PipelineStopped()


def migration_digest(source):
    paths = sorted((source / 'backend/portal/migrations').glob('*.py'))
    if not paths:
        raise PipelineStopped()
    return digest({p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})


def dependency_count(report):
    dependencies = report.get('dependencies')
    if not isinstance(dependencies, list) or not dependencies:
        raise PipelineStopped()
    if any(not isinstance(item, dict) or 'skip_reason' in item or not isinstance(item.get('vulns'), list) for item in dependencies):
        raise PipelineStopped()
    return sum(len(item['vulns']) for item in dependencies)


def frontend_count(report):
    values = report.get('metadata', {}).get('vulnerabilities', {})
    if not isinstance(values, dict) or any(type(values.get(name)) is not int or values[name] < 0
            for name in ['info', 'low', 'moderate', 'high', 'critical']):
        raise PipelineStopped()
    return sum(values[name] for name in ['info', 'low', 'moderate', 'high', 'critical'])


def source_findings(report, source, reviewed):
    """Keep all findings visible; dispositions match exact reviewed file bytes.

    The disposition list comes from the read-only operator profile, never the
    repository. A changed file invalidates every disposition for that file.
    Repository nosec comments are ignored by the scanner.
    """
    results = report.get('results')
    if not isinstance(results, list) or report.get('errors'):
        raise PipelineStopped()
    accepted = 0
    for finding in results:
        name = PurePosixPath(finding['filename'].replace('\\', '/').removeprefix('./'))
        if name.is_absolute() or '..' in name.parts or not str(name).startswith(('backend/', 'scripts/')):
            raise PipelineStopped()
        file_sha = hashlib.sha256((source / str(name)).read_bytes().replace(b'\r\n', b'\n')).hexdigest()
        matches = [r for r in reviewed if r.get('path') == str(name) and r.get('file_sha256') == file_sha and
                   r.get('test_id') == finding['test_id'] and r.get('line') == finding['line_number'] and
                   r.get('severity') == finding['issue_severity'] == 'LOW' and
                   r.get('disposition') == 'reviewed_false_positive' and isinstance(r.get('reason'), str) and len(r['reason']) >= 30]
        if len(matches) == 1:
            accepted += 1
    return {'findings': len(results) - accepted, 'reviewed_findings': accepted, 'total_findings': len(results)}


def secret_findings(report, source, reviewed):
    if not report.get('plugins_used') or not isinstance(report.get('results'),dict):
        raise PipelineStopped()
    total,accepted=0,0
    for filename,findings in report['results'].items():
        name=PurePosixPath(filename.replace('\\','/').removeprefix('./'))
        if name.is_absolute() or '..' in name.parts or not isinstance(findings,list):
            raise PipelineStopped()
        file_sha=hashlib.sha256((source/str(name)).read_bytes().replace(b'\r\n',b'\n')).hexdigest()
        for finding in findings:
            total+=1
            matches=[r for r in reviewed if r.get('path')==str(name) and r.get('file_sha256')==file_sha and
                r.get('line')==finding['line_number'] and r.get('type')==finding['type'] and
                r.get('hashed_secret')==finding['hashed_secret'] and r.get('disposition')=='reviewed_false_positive' and
                isinstance(r.get('reason'),str) and len(r['reason'])>=30]
            if len(matches)==1:
                accepted+=1
    return {'findings':total-accepted,'reviewed_findings':accepted,'total_findings':total}


def main():
    source, output, archive = Path('/work/app'), Path('/output'), Path('/input/source.tar.gz')
    stage, failed = 'profile', False
    report = {'schema_version': 1, 'repository': os.environ.get('PORTAL_REPOSITORY', ''),
        'commit': os.environ.get('COMMIT_SHA', ''), 'tests': None,
        'scans': {name: {'status': 'not_run', 'findings': None} for name in ['source', 'dependencies', 'secrets']}}
    # Explicit environment; no GitHub token, AWS credentials, metadata access or
    # host configuration. The network/proxy restrictions are enforced externally.
    environment = {'PATH': os.environ['PATH'], 'HOME': '/work', 'TMPDIR': '/work/tmp',
        'PORTAL_MODE': 'local', 'PORTAL_RUNTIME_DIR': '/work/runtime',
        'DJANGO_SETTINGS_MODULE': 'config.settings', 'PYTHONPATH': '/tools',
        'PYTHONDONTWRITEBYTECODE': '1', 'CI': '1', 'AWS_EC2_METADATA_DISABLED': 'true'}
    for key in ['HTTP_PROXY', 'HTTPS_PROXY']:
        if os.environ.get(key):
            environment[key] = os.environ[key]
    def run(*args):
        return subprocess.run(list(args), cwd=source, env=environment,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200).returncode
    try:
        profile = read_json(Path('/tools/releaseportal-profile.json'))
        if (profile.get('execution_enabled') is not True or profile.get('name') != 'releaseportal-v1' or
            report['repository'] != profile.get('repository') or not re.fullmatch(r'[a-f0-9]{40}', report['commit'])):
            raise PipelineStopped()
        report['profile_sha256'] = digest(profile)
        source.mkdir(); Path('/work/tmp').mkdir()
        report['source_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
        if report['source_sha256'] != os.environ.get('SOURCE_SHA256'):
            raise PipelineStopped()
        stage = 'source'
        extract_source(archive, source, profile.get('source_template_sha256',{}))
        before = {p.relative_to(source).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in source.rglob('*') if p.is_file()}
        if any(before.get(name) != sha for name, sha in profile['source_lock_sha256'].items()):
            raise PipelineStopped()
        if migration_digest(source) != profile['migration_manifest_sha256']:
            raise PipelineStopped()
        stage = 'secret_scan'
        with Path('/work/secrets.json').open('w') as stream:
            rc = subprocess.run(['detect-secrets', 'scan', '--no-verify', '--all-files',
                '--disable-filter','detect_secrets.filters.allowlist.is_line_allowlisted','.'], cwd=source, env=environment,
                stdout=stream, stderr=subprocess.DEVNULL, timeout=120).returncode
        secret = read_json(Path('/work/secrets.json'))
        if not secret.get('plugins_used') or not isinstance(secret.get('results'), dict):
            raise PipelineStopped()
        counts=secret_findings(secret,source,profile.get('reviewed_secret_findings',[]))
        report['scans']['secrets'] = {'status': 'passed' if rc == counts['findings'] == 0 else 'failed', **counts}
        failed = failed or rc != 0 or counts['findings'] != 0
        stage = 'dependencies_install'
        python = '/work/venv/bin/python'
        if run('python', '-I', '-m', 'venv', '/work/venv') or run(python, '-I', '-m', 'pip', 'install',
                '--only-binary=:all:', '-r', 'backend/requirements.lock.txt'):
            raise PipelineStopped()
        if run('pnpm', 'install', '--frozen-lockfile', '--ignore-scripts'):
            raise PipelineStopped()
        stage = 'source_scan'
        rc = run('bandit', '--ini', '/tools/bandit.ini', '--ignore-nosec', '-r', 'backend', 'scripts', '-f', 'json', '-o', '/work/source.json')
        finding = read_json(Path('/work/source.json'))
        if not isinstance(finding.get('results'), list) or finding.get('errors'):
            raise PipelineStopped()
        counts = source_findings(finding, source, profile.get('reviewed_source_findings', []))
        passed = rc in [0, 1] and counts['findings'] == 0
        report['scans']['source'] = {'status': 'passed' if passed else 'failed', **counts}
        failed = failed or not passed
        stage = 'dependencies_scan'
        python_rc = run('python', '-I', '-m', 'pip_audit', '--disable-pip', '--no-deps', '-r',
            'backend/requirements.lock.txt', '-f', 'json', '-o', '/work/python-dependencies.json')
        with Path('/work/frontend-dependencies.json').open('w') as stream:
            node_rc = subprocess.run(['pnpm', 'audit', '--json'], cwd=source, env=environment,
                stdout=stream, stderr=subprocess.DEVNULL, timeout=120).returncode
        count = dependency_count(read_json(Path('/work/python-dependencies.json'))) + frontend_count(read_json(Path('/work/frontend-dependencies.json')))
        report['scans']['dependencies'] = {'status': 'passed' if python_rc == node_rc == count == 0 else 'failed', 'findings': count}
        failed = failed or python_rc != 0 or node_rc != 0 or count != 0
        stage = 'unit_tests'
        if run(python, '-I', '/tools/releaseportal_run_tests.py', 'check'):
            raise PipelineStopped()
        rc = run(python, '-I', '/tools/releaseportal_run_tests.py', 'test')
        counts = read_json(output / 'django-tests.json')
        if any(type(counts.get(k)) is not int or counts[k] < 0 for k in ['passed', 'failed', 'skipped', 'total']):
            raise PipelineStopped()
        if counts['total'] != counts['passed'] + counts['failed'] + counts['skipped'] or counts['total'] == 0:
            raise PipelineStopped()
        report['tests'] = counts
        failed = failed or rc != 0 or counts['failed'] != 0
        stage = 'frontend_build'
        if run('pnpm', 'run', 'build') or run('pnpm', 'run', 'test:sites'):
            raise PipelineStopped()
        stage = 'source_integrity'
        if any(not (source / name).is_file() or (source / name).is_symlink() or
                hashlib.sha256((source / name).read_bytes()).hexdigest() != sha for name, sha in before.items()):
            raise PipelineStopped()
        # Only a successful run may export source + compiled frontend for the
        # fixed trusted assembler. No repository Dockerfile is executed here.
        if failed:
            raise PipelineStopped()
        stage = 'artifact'
        paths = set(before)
        paths.update(p.relative_to(source).as_posix() for p in (source / 'dist').rglob('*') if p.is_file())
        artifact = output / 'release.tar.gz'
        with tarfile.open(artifact, 'w:gz') as destination:
            for name in sorted(paths):
                path = source / name
                if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
                    raise PipelineStopped()
                content = path.read_bytes()
                if len(content) > 25 * 1024 * 1024:
                    raise PipelineStopped()
                import io
                member = tarfile.TarInfo(name); member.size = len(content); member.mode = 0o644; member.mtime = 0
                destination.addfile(member, io.BytesIO(content))
        if artifact.stat().st_size > 100 * 1024 * 1024:
            raise PipelineStopped()
        report['artifact_sha256'] = hashlib.sha256(artifact.read_bytes()).hexdigest()
        stage = 'complete'
    except Exception:
        failed = True
    report['error_code'] = stage + '_failed' if failed else ''
    if failed:
        (output / 'release.tar.gz').unlink(missing_ok=True)
    (output / 'release-evidence.json').write_text(json.dumps(report))
    return 1 if failed else 0


if __name__ == '__main__':
    raise SystemExit(main())
