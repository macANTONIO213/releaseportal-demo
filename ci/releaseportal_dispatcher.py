"""Single-job trusted Linux dispatcher. Repository execution is confined to runsc."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import threading

from portal.controller_http import strict_json
from portal.ecs_release import fingerprint
from portal.errors import RuleError
from portal.remote_jobs import validate_job,safe_report,signed_status


@contextmanager
def database(path):
    db=sqlite3.connect(str(path),timeout=10)
    try:
        db.execute('PRAGMA synchronous=FULL')
        with db:
            yield db
    finally:
        db.close()


class Claims:
    def __init__(self,path):
        self.path=path
        with database(path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, digest TEXT NOT NULL, state TEXT NOT NULL)')

    def available(self):
        with database(self.path) as db:
            if db.execute("SELECT 1 FROM jobs WHERE state IN ('running','reconciliation_required')").fetchone():
                raise ValueError('Reconcile the existing claim before another queue request')

    def claim(self,value):
        with database(self.path) as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM jobs WHERE state IN ('running','reconciliation_required')").fetchone():
                raise ValueError('Reconcile the existing claim before another build')
            previous=db.execute('SELECT digest,state FROM jobs WHERE id=?',(value['run_id'],)).fetchone()
            if previous:
                if previous[0]==fingerprint(value) and previous[1] in ['ready','failed']:
                    return False
                raise ValueError('Conflicting or uncertain job identity')
            db.execute('INSERT INTO jobs VALUES (?,?,?)',(value['run_id'],fingerprint(value),'running'))
            return True

    def finish(self,run,state):
        if state not in ['ready','failed','reconciliation_required']:
            raise ValueError('Invalid claim state')
        with database(self.path) as db:
            db.execute('UPDATE jobs SET state=? WHERE id=?',(state,run))


def environment():
    return {'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME':'/var/empty','DOCKER_HOST':'unix:///var/run/docker.sock','LANG':'C.UTF-8'}


def sandbox_command(value,profile,directory):
    validate_job(value,profile)
    image=profile['runner_image']
    if not re.fullmatch(r'[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/releaseportal/runner@sha256:[a-f0-9]{64}',image):
        raise ValueError('Pinned approved runner image required')
    root=Path(directory).resolve()
    if root.name != value['run_id'] or ',' in str(root):
        raise ValueError('Unsafe workspace')
    return ['/usr/bin/docker','run','--rm','--name','releaseportal-'+value['run_id'],
        '--runtime','runsc','--network','releaseportal-build','--dns','127.0.0.1',
        '--read-only','--log-driver=none','--user','10001:10001','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--memory=4g','--memory-swap=4g','--cpus=2','--pids-limit=256',
        '--tmpfs','/work:rw,exec,nosuid,size=2g,uid=10001,gid=10001',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=64m,uid=10001,gid=10001',
        '--mount',f'type=bind,src={root}/source.tar.gz,dst=/input/source.tar.gz,readonly',
        '--mount',f'type=bind,src={root}/profile.json,dst=/tools/releaseportal-profile.json,readonly',
        '--mount',f'type=bind,src={root}/output,dst=/output',
        '--env','PORTAL_REPOSITORY='+value['repository'],'--env','COMMIT_SHA='+value['commit'],
        '--env','SOURCE_SHA256='+value['source_sha256'],
        '--env','HTTP_PROXY=http://172.26.0.1:3128','--env','HTTPS_PROXY=http://172.26.0.1:3128',image]


def bounded_file(path,limit):
    flags=os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK
    with os.fdopen(os.open(path,flags),'rb') as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>limit:
            raise ValueError('Unsafe guest output')
        content=stream.read(limit+1)
    if len(content)>limit:
        raise ValueError('Guest output exceeds limit')
    return content


class Sandbox:
    def __init__(self,root,run=subprocess.run):
        self.root=Path(root).resolve();self.run=run

    def command(self,args,timeout=30,input=None):
        result=self.run(args,env=environment(),input=input,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout)
        if result.returncode:
            raise ValueError('Trusted host command failed')

    def execute(self,value,profile,source):
        self.command(['/usr/bin/bash','/opt/releaseportal-worker/bin/firewall.sh','--check'])
        directory=self.root/value['run_id']
        directory.mkdir(mode=0o700)
        mounted=False
        try:
            (directory/'source.tar.gz').write_bytes(source)
            (directory/'source.tar.gz').chmod(0o444)
            (directory/'profile.json').write_text(json.dumps(profile))
            (directory/'profile.json').chmod(0o444)
            output=directory/'output';output.mkdir()
            # Guest output cannot fill the encrypted EBS root volume.
            self.command(['/usr/bin/mount','-t','tmpfs','-o','size=128m,uid=10001,gid=10001,mode=0700,nosuid,nodev,noexec',
                          'releaseportal-output',str(output)])
            mounted=True
            try:
                outcome=self.run(sandbox_command(value,profile,directory),env=environment(),
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=1800)
            except subprocess.TimeoutExpired:
                # Kill only this claimed UUID container; never start another job after uncertain cleanup.
                self.command(['/usr/bin/docker','kill','releaseportal-'+value['run_id']])
                raise
            raw=bounded_file(output/'release-evidence.json',1024*1024)
            report=json.loads(raw)
            if outcome.returncode:
                return None,None
            artifact=bounded_file(output/'release.tar.gz',100*1024*1024)
            return report,artifact
        finally:
            if mounted:
                self.command(['/usr/bin/umount',str(directory/'output')])
            # Fixed files only; no recursive traversal or execution of guest-created paths.
            for name in ['source.tar.gz','profile.json']:
                (directory/name).unlink(missing_ok=True)
            (directory/'output').rmdir()
            directory.rmdir()


class Dispatcher:
    def __init__(self,profile,key,queue,storage,claims,sandbox,assembler,logger=None):
        self.profile,self.key,self.queue,self.storage=profile,key,queue,storage
        self.claims,self.sandbox,self.assembler=claims,sandbox,assembler
        self.logger=logger

    def publish(self,value,state,code='',evidence_sha='',artifact_sha='',image=''):
        status={'run_id':value['run_id'],'source_sha256':value['source_sha256'],'profile_sha256':value['profile_sha256'],
            'status':state,'code':code,'evidence_sha256':evidence_sha,'artifact_sha256':artifact_sha,'image':image}
        if self.logger is not None:self.logger(value['run_id'],state,code)
        self.storage.put(value['run_id'],'status.json',json.dumps(signed_status(status,self.key)).encode())

    def tick(self):
        self.claims.available()
        messages=self.queue.receive()
        if not messages:
            return
        message=messages[0]
        value=validate_job(strict_json(message['Body'].encode()),self.profile)
        if not self.claims.claim(value):
            # Acknowledging a known completed SQS duplicate never executes source again.
            self.queue.delete(message['ReceiptHandle'])
            return
        lost=threading.Event();done=threading.Event()
        self.assembler.cancelled=lost
        def heartbeat():
            while not done.wait(300):
                try:
                    self.queue.visibility(message['ReceiptHandle'])
                except Exception:
                    lost.set();return
        thread=threading.Thread(target=heartbeat,daemon=True);thread.start()
        try:
            self.publish(value,'running')
            source=self.storage.get(value['run_id'],'source.tar.gz',value['source_sha256'])
            report,artifact=self.sandbox.execute(value,self.profile,source)
            if lost.is_set():
                raise RuleError('queue_lease_unknown','Queue lease requires reconciliation')
            if report is None:
                self.publish(value,'failed','pipeline_failed')
                self.claims.finish(value['run_id'],'failed')
                self.queue.delete(message['ReceiptHandle'])
                return
            if (report.get('repository')!=value['repository'] or report.get('commit')!=value['commit'] or
                report.get('source_sha256')!=value['source_sha256'] or report.get('profile_sha256')!=value['profile_sha256'] or
                report.get('error_code')!='' or hashlib.sha256(artifact).hexdigest()!=report.get('artifact_sha256')):
                raise ValueError('Guest identity mismatch')
            # assembler is the fixed host COPY-only/ECR gate, never a repository command.
            image,image_scan=self.assembler(source,artifact,report['artifact_sha256'],value)
            report['image'],report['image_scan']=image,image_scan
            report=safe_report(report)
            from portal.ecs_release import make_plan
            make_plan(self.profile,self.profile['baseline_service'],value['commit'],value['source_sha256'],
                      report['artifact_sha256'],image,report)
            if lost.is_set():
                raise RuleError('queue_lease_unknown','Queue lease requires reconciliation')
            self.storage.put(value['run_id'],'release.tar.gz',artifact)
            evidence_sha=self.storage.put(value['run_id'],'release-evidence.json',json.dumps(report).encode())
            self.publish(value,'ready',evidence_sha=evidence_sha,artifact_sha=report['artifact_sha256'],image=image)
            self.claims.finish(value['run_id'],'ready')
            self.queue.delete(message['ReceiptHandle'])
        except BaseException as error:
            self.claims.finish(value['run_id'],'reconciliation_required')
            if not isinstance(error,RuleError):
                try:
                    self.publish(value,'reconciliation_required','worker_outcome_unconfirmed')
                except Exception:
                    pass
            raise
        finally:
            done.set();thread.join(timeout=2)
