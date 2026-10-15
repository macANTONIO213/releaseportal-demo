"""Trusted external-controller core. Disabled until private host acceptance.

The ledger never stores request bodies, credentials, CLI output or runtime env.
Unknown outcomes require reconciliation; restarting never resubmits a write.
"""
import json
from contextlib import contextmanager
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import threading
import time
import urllib.request

from .controller_contract import receipt, validate_snapshot
from .ecs_release import update_request
from .errors import RuleError


class Ledger:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS attempts (release_id TEXT PRIMARY KEY, nonce TEXT UNIQUE NOT NULL, '
                       'plan_digest TEXT NOT NULL, status TEXT NOT NULL, code TEXT NOT NULL, image TEXT NOT NULL, '
                       'task_definition TEXT NOT NULL DEFAULT "")')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db
        finally:
            db.close()

    def claim(self, snapshot):
        try:
            with self.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                # A lost process keeps its claim and blocks subsequent deployments.
                active = db.execute("SELECT 1 FROM attempts WHERE status IN ('accepted','updating','reconciliation_required')").fetchone()
                if active:
                    raise RuleError('controller_busy', 'Reconcile the previous attempt first.')
                db.execute('INSERT INTO attempts(release_id,nonce,plan_digest,status,code,image) VALUES (?,?,?,?,?,?)',
                    (snapshot['release_id'], snapshot['nonce'], snapshot['plan_digest'], 'accepted', '', snapshot['plan']['image']))
        except sqlite3.IntegrityError:
            raise RuleError('controller_replay', 'This release or request was already accepted.') from None

    def set(self, release_id, status, code='', task_definition=''):
        safe = receipt({'release_id': release_id, 'status': status, 'code': code})
        if task_definition and not re.fullmatch(r'arn:aws:ecs:[a-z0-9-]+:[0-9]{12}:task-definition/[A-Za-z0-9_-]+:[0-9]+', task_definition):
            raise RuleError('invalid_task_receipt', 'Unexpected task definition.')
        with self.connect() as db:
            db.execute('UPDATE attempts SET status=?,code=?,task_definition=? WHERE release_id=?',
                       (safe['status'], safe['code'], task_definition, release_id))

    def get(self, release_id):
        with self.connect() as db:
            row = db.execute('SELECT release_id,plan_digest,status,code,image,task_definition FROM attempts WHERE release_id=?', (release_id,)).fetchone()
        return receipt(dict(zip(['release_id','plan_digest','status','code','image','task_definition'], row))) if row else None


class TemporaryCLI:
    """No profile, instance role, login-session or shared-config fallback."""
    def __init__(self, executable, region, credentials, run=subprocess.run):
        key, secret, token = (credentials.get(k) for k in ['access_key_id', 'secret_access_key', 'session_token'])
        if (not isinstance(key, str) or not re.fullmatch(r'ASIA[A-Z0-9]{16}', key) or
            not isinstance(secret, str) or not re.fullmatch(r'[A-Za-z0-9/+=]{40}', secret) or
            not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9/+=]{16,20000}', token)):
            raise RuleError('invalid_credentials', 'Three temporary AWS values are required.')
        self.env = {k: v for k, v in os.environ.items() if k in ['PATH', 'SYSTEMROOT', 'WINDIR', 'LANG', 'SSL_CERT_FILE']}
        self.env.update(AWS_ACCESS_KEY_ID=key, AWS_SECRET_ACCESS_KEY=secret, AWS_SESSION_TOKEN=token,
            AWS_REGION=region, AWS_DEFAULT_REGION=region, AWS_CONFIG_FILE=os.devnull,
            AWS_SHARED_CREDENTIALS_FILE=os.devnull, AWS_EC2_METADATA_DISABLED='true',
            AWS_MAX_ATTEMPTS='1', AWS_RETRY_MODE='standard', AWS_PAGER='', AWS_CLI_AUTO_PROMPT='off')
        self.executable, self.region, self.run = str(executable), region, run

    def erase(self):
        self.env.clear()

    def call(self, operation, payload):
        if operation not in ['describe-express-gateway-service', 'update-express-gateway-service', 'describe-services']:
            raise RuleError('cli_operation_rejected', 'Operation is outside the image update adapter.')
        try:
            # Payload contains image/config references, never credentials. No shell or temp file.
            result = self.run([self.executable, 'ecs', operation, '--region', self.region, '--cli-input-json',
                json.dumps(payload, separators=(',', ':')), '--output', 'json', '--no-cli-pager'],
                env=self.env, capture_output=True, text=True, encoding='utf-8', timeout=90)
            if result.returncode:
                # Never expose or persist provider stderr, tokens, account details or endpoint errors.
                raise RuleError('aws_request_stopped', 'The AWS request stopped; reconcile before another attempt.')
            value = json.loads(result.stdout)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except RuleError:
            raise
        except Exception:
            raise RuleError('aws_outcome_unknown', 'The AWS outcome is uncertain; reconcile before another attempt.') from None


class Controller:
    def __init__(self, profile, key, ledger, cli_factory, sleep=time.sleep, health=None):
        self.profile, self.key, self.ledger, self.cli_factory = profile, key, ledger, cli_factory
        self.lock = threading.Lock()
        self.sleep, self.health = sleep, health or self._health

    def _health(self):
        url = self.profile['health_url']
        if not re.fullmatch(r'https://[a-z0-9.-]+/healthz', url):
            raise RuleError('invalid_health_target', 'Health target must be reviewed HTTPS.')
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(url, timeout=15) as response:
            return response.status == 200 and response.geturl() == url

    def submit(self, snapshot, signature, credentials, now=None):
        cli = None
        try:
            validate_snapshot(snapshot, signature, self.key, self.profile, now)
            if not self.profile.get('execution_enabled'):
                raise RuleError('controller_disabled', 'Controller acceptance is incomplete.')
            cli = self.cli_factory(credentials)
            if not self.lock.acquire(blocking=False):
                raise RuleError('controller_busy', 'Another deployment is active.')
            try:
                self.ledger.claim(snapshot)
                return self._update(snapshot, cli)
            finally:
                self.lock.release()
        finally:
            if cli is not None:
                cli.erase()
            credentials.clear()

    def start(self, snapshot, signature, credentials, now=None):
        """Acknowledge durable claim before returning; deployment survives caller loss."""
        cli, acquired, handed_off = None, False, False
        try:
            validate_snapshot(snapshot, signature, self.key, self.profile, now)
            if not self.profile.get('execution_enabled'):
                raise RuleError('controller_disabled', 'Controller acceptance is incomplete.')
            cli = self.cli_factory(credentials)
            acquired = self.lock.acquire(blocking=False)
            if not acquired:
                raise RuleError('controller_busy', 'Another deployment is active.')
            self.ledger.claim(snapshot)
            accepted = self.ledger.get(snapshot['release_id'])
            def execute():
                try:
                    self._update(snapshot, cli)
                except BaseException:
                    # _update records only sanitized uncertainty. Never log request/traceback.
                    pass
                finally:
                    cli.erase()
                    self.lock.release()
            thread = threading.Thread(target=execute, name='reviewed-image-update', daemon=True)
            thread.start()
            handed_off = True
            return accepted
        finally:
            credentials.clear()
            if not handed_off:
                if cli is not None:
                    cli.erase()
                if acquired:
                    self.lock.release()

    def _update(self, snapshot, cli):
        release_id = snapshot['release_id']
        try:
            current = cli.call('describe-express-gateway-service', {'serviceArn': self.profile['service_arn']})['service']
            request = update_request(self.profile, snapshot['plan'], snapshot['plan_digest'], current)
            # Committed before the external write. A crash here never causes replay.
            self.ledger.set(release_id, 'updating')
            result = cli.call('update-express-gateway-service', request)
            if result.get('service', {}).get('serviceArn') != self.profile['service_arn']:
                raise RuleError('update_receipt_mismatch', 'The update receipt needs reconciliation.')
            return self._observe(snapshot, cli)
        except BaseException:
            self.ledger.set(release_id, 'reconciliation_required', 'deployment_outcome_unconfirmed')
            raise

    def _observe(self, snapshot, cli):
        arn = self.profile['service_arn']
        parts = arn.split(':service/', 1)[1].split('/')
        if len(parts) != 2:
            raise RuleError('invalid_service_target', 'Unexpected service target.')
        for _ in range(80):
            service = cli.call('describe-express-gateway-service', {'serviceArn': arn})['service']
            if service.get('serviceArn') != arn:
                raise RuleError('service_receipt_mismatch', 'Unexpected service receipt.')
            definitions = {c.get('taskDefinitionArn') for c in service.get('activeConfigurations', [])
                if c.get('primaryContainer', {}).get('image') == snapshot['plan']['image']}
            if definitions:
                result = cli.call('describe-services', {'cluster': parts[0], 'services': [arn]})
                if result.get('failures') or len(result.get('services', [])) != 1:
                    raise RuleError('rollout_receipt_mismatch', 'Unexpected rollout receipt.')
                running = result['services'][0]
                if running.get('serviceArn') != arn:
                    raise RuleError('rollout_receipt_mismatch', 'Unexpected rollout target.')
                deployments = running.get('deployments', [])
                if any(d.get('taskDefinition') in definitions and d.get('rolloutState') == 'FAILED' for d in deployments):
                    self.ledger.set(snapshot['release_id'], 'failed', 'aws_rollout_failed')
                    return self.ledger.get(snapshot['release_id'])
                primary = [d for d in deployments if d.get('status') == 'PRIMARY']
                if (len(primary) == 1 and primary[0].get('taskDefinition') in definitions and
                    primary[0].get('rolloutState') == 'COMPLETED' and len(deployments) == 1 and
                    running.get('runningCount') == running.get('desiredCount') == 1 and running.get('pendingCount') == 0):
                    if not self.health():
                        raise RuleError('health_unconfirmed', 'Deployment health needs reconciliation.')
                    self.ledger.set(snapshot['release_id'], 'succeeded', task_definition=primary[0]['taskDefinition'])
                    return self.ledger.get(snapshot['release_id'])
            self.sleep(15)
        raise RuleError('rollout_timeout', 'Rollout did not complete within the observation window.')


if __name__ == '__main__':
    raise SystemExit('Disabled draft: TLS service and rollout acceptance are required before activation.')
