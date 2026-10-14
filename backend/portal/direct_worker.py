"""Docker build worker. No GitHub/AWS credentials or host execution of source.
Requires a reviewed digest-pinned Linux runner image and sandbox runtime.
"""
import json
import os
import re
import shutil
import stat
import subprocess
from django.conf import settings
from django.db import close_old_connections
from .models import Run
from .services import RuleError, attach_evidence, record
from .source import directory, read_artifact

def configured():
    return bool(shutil.which('docker') and re.fullmatch(r'[\w./:-]+@sha256:[a-f0-9]{64}', settings.BUILD_IMAGE)
        and re.fullmatch(r'releaseportal-[a-z0-9-]+',getattr(settings,'BUILD_NETWORK',''))
        and getattr(settings,'BUILD_RUNTIME','') in ['runsc','kata-runtime']
        and getattr(settings,'BUILD_EGRESS_CONFIRMED',False))

def command(run):
    root = directory(run).resolve()
    # The Docker socket stays on the trusted worker host, never in the container.
    return ['docker', 'run', '--rm', '--name', 'releaseportal-'+str(run.id), '--runtime', settings.BUILD_RUNTIME,
        '--network', settings.BUILD_NETWORK, '--read-only', '--user', '10001:10001',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=4g', '--cpus=2', '--pids-limit=256',
        '--tmpfs', '/work:rw,exec,nosuid,size=2g,uid=10001,gid=10001',
        '--mount', 'type=bind,src='+str(root/'source.tar.gz')+',dst=/input/source.tar.gz,readonly',
        '--mount', 'type=bind,src='+str(root/'output')+',dst=/output',
        '--env', 'COMMIT_SHA='+run.commit, '--env', 'PORTAL_REPOSITORY='+run.repository,
        settings.BUILD_IMAGE]

def worker_environment():
    return {k:v for k,v in os.environ.items()
        if k in ['PATH','SystemRoot','WINDIR','HOME','USERPROFILE','LOCALAPPDATA','DOCKER_HOST','DOCKER_CONTEXT']}

def read_evidence(path):
    # Guest output is untrusted. Open once without following links and bound the
    # actual read, not just a preceding stat. Nonblocking avoids a guest FIFO.
    limit = 1024*1024
    try:
        if path.parent.is_symlink() or path.is_symlink():
            raise ValueError()
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_BINARY', 0)
        with os.fdopen(os.open(path, flags), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                raise ValueError()
            content = stream.read(limit+1)
        if len(content) > limit:
            raise ValueError()
        report = json.loads(content)
        if not isinstance(report, dict) or type(report.get('schema_version')) is not int or report['schema_version'] != 1:
            raise ValueError()
        scans = report.get('scans')
        if not isinstance(scans, dict) or any(not isinstance(scans.get(name), dict) for name in ['source','dependencies','secrets']):
            raise ValueError()
        return report
    except (OSError, ValueError, UnicodeError):
        raise RuleError('invalid_evidence', 'The worker did not produce valid evidence.') from None

def tick():
    close_old_connections()
    if Run.objects.filter(error_code='container_cleanup_failed').exists():
        return
    for run in Run.objects.filter(status='queued').order_by('created_at')[:4]:
        if Run.objects.filter(error_code='container_cleanup_failed').exists():
            return
        if not Run.objects.filter(pk=run.id, status='queued').update(status='running'):
            continue
        try:
            if not configured():
                raise RuleError('build_runtime_unconfigured', 'Configure the isolated Linux Docker worker first.')
            read_artifact(run)
            root = directory(run)
            output = root/'output'
            if output.is_symlink():
                raise RuleError('invalid_evidence', 'The worker output directory is unsafe.')
            output.mkdir(mode=0o700, exist_ok=True)
            path = output/'release-evidence.json'
            # A successful process exit must never reuse a previous report.
            path.unlink(missing_ok=True)
            # Logs are not returned/stored: repository output could contain secrets.
            outcome = subprocess.run(command(run), env=worker_environment(),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800)
            report = read_evidence(path)
            if report.get('repository') != run.repository or report.get('commit') != run.commit:
                raise RuleError('source_mismatch','Worker evidence belongs to another revision.')
            # Persist bounded numeric/status fields, never arbitrary guest output.
            safe={'schema_version':1,'repository':run.repository,'commit':run.commit,'scans':{},'tests':None}
            tests=report.get('tests')
            if isinstance(tests,dict) and all(type(tests.get(k)) is int and 0 <= tests[k] <= 1000000 for k in ['passed','failed','skipped','total']):
                safe['tests']={k:tests[k] for k in ['passed','failed','skipped','total']}
            for name in ['source','dependencies','secrets']:
                scan=report.get('scans',{}).get(name,{})
                status=scan.get('status') if scan.get('status') in ['passed','failed','not_run'] else 'not_run'
                findings=scan.get('findings') if type(scan.get('findings')) is int and 0 <= scan['findings'] <= 1000000 else None
                safe['scans'][name]={'status':status,'findings':findings}
            if outcome.returncode:
                Run.objects.filter(pk=run.id).update(evidence=safe)
                raise RuleError('pipeline_failed', 'Tests or scans failed; no passing release was generated.')
            report=safe
            # Verify bytes again after guest execution before accepting evidence.
            artifact = read_artifact(run)
            report['artifact'] = {'name':'source.tar.gz', 'bytes':len(artifact), 'sha256':run.source_sha256}
            attach_evidence(run.id, report, run.source_sha256)
        except Exception as error:
            # Safe codes only; never serialize repository output or exception values.
            code = error.code if isinstance(error, RuleError) else 'pipeline_interrupted'
            Run.objects.filter(pk=run.id).update(status='failed', error_code=code)
            record(None, 'direct_pipeline_failed', run.id, code=code)
            if isinstance(error, subprocess.TimeoutExpired):
                try:
                    cleanup = subprocess.run(['docker','kill','releaseportal-'+str(run.id)], env=worker_environment(),
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
                    if cleanup.returncode:
                        Run.objects.filter(pk=run.id).update(error_code='container_cleanup_failed')
                        record(None, 'direct_pipeline_cleanup_required', run.id, code='container_cleanup_failed')
                        return
                except (OSError, subprocess.SubprocessError):
                    Run.objects.filter(pk=run.id).update(error_code='container_cleanup_failed')
                    record(None, 'direct_pipeline_cleanup_required', run.id, code='container_cleanup_failed')
                    # Do not start more guest work with an unresolved container.
                    return
