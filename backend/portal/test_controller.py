import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import uuid

from .controller_contract import sign, validate_snapshot
from .controller_runtime import Controller, Ledger, TemporaryCLI
from .ecs_release import make_plan, fingerprint
from .errors import RuleError


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'attempts.sqlite3'
        self.ledger = Ledger(self.path)
        self.profile = {'account': '111122223333', 'region': 'ap-southeast-1',
            'service_arn': 'arn:aws:ecs:ap-southeast-1:111122223333:service/portal/portal',
            'image_repository': '111122223333.dkr.ecr.ap-southeast-1.amazonaws.com/portal',
            'repository': 'example/portal', 'allowed_creator_ids': ['101'], 'allowed_reviewer_ids': ['202'],
            'health_url': 'https://portal.example.invalid/healthz', 'execution_enabled': True}
        self.old = self.profile['image_repository'] + '@sha256:' + 'a' * 64
        self.new = self.profile['image_repository'] + '@sha256:' + 'b' * 64
        self.definition = 'arn:aws:ecs:ap-southeast-1:111122223333:task-definition/portal:9'
        self.service = {'serviceArn': self.profile['service_arn'], 'activeConfigurations': [{
            'cpu': '512', 'memory': '1024', 'primaryContainer': {'image': self.old, 'containerPort': 8055,
                'environment': [{'name': 'PORTAL_OWNER_SIGNIN_ONLY', 'value': '0'}],
                'secrets': [{'name': 'PORTAL_SECRET_KEY', 'valueFrom': 'fixture-reference'}]}}]}
        evidence = {'repository': 'example/portal', 'commit': 'c' * 40, 'error_code': '',
            'source_sha256': 'd' * 64, 'artifact_sha256': 'e' * 64, 'profile_sha256': fingerprint(self.profile),
            'image': self.new, 'image_scan': {'status': 'COMPLETE', 'high': 0, 'critical': 0},
            'tests': {'passed': 1, 'failed': 0, 'skipped': 0, 'total': 1},
            'scans': {k: {'status': 'passed', 'findings': 0} for k in ['source', 'dependencies', 'secrets']}}
        plan = make_plan(self.profile, self.service, 'c' * 40, 'd' * 64, 'e' * 64, self.new, evidence)
        self.snapshot = {'version': 1, 'release_id': str(uuid.uuid4()), 'nonce': str(uuid.uuid4()),
            'creator_id': '101', 'reviewer_id': '202', 'approved_at': 900, 'issued_at': 990,
            'expires_at': 1100, 'plan_digest': fingerprint(plan), 'plan': plan}
        self.key = b'k' * 32
        self.calls = []

    def credentials(self):
        return {'access_key_id': 'ASIA' + 'A' * 16, 'secret_access_key': 's' * 40, 'session_token': 't' * 32}

    def fake(self, args, **kwargs):
        operation = args[2]
        request = json.loads(args[args.index('--cli-input-json') + 1])
        self.calls.append((operation, request, copy.deepcopy(kwargs['env'])))
        self.assertNotIn('--profile', args)
        if operation == 'update-express-gateway-service':
            self.assertEqual(self.ledger.get(self.snapshot['release_id'])['status'], 'updating')
            self.service['activeConfigurations'][0]['primaryContainer'] = request['primaryContainer']
            self.service['activeConfigurations'][0]['taskDefinitionArn'] = self.definition
        if operation == 'describe-services':
            result = {'services': [{'serviceArn': self.profile['service_arn'], 'runningCount': 1,
                'desiredCount': 1, 'pendingCount': 0, 'deployments': [{'status': 'PRIMARY',
                    'taskDefinition': self.definition, 'rolloutState': 'COMPLETED'}]}]}
        else:
            result = {'service': copy.deepcopy(self.service)}
        return SimpleNamespace(returncode=0, stdout=json.dumps(result), stderr='')

    def controller(self, transport=None, health=lambda: True):
        def factory(credentials):
            self.cli = TemporaryCLI('/usr/local/bin/aws', self.profile['region'], credentials, run=transport or self.fake)
            return self.cli
        return Controller(self.profile, self.key, self.ledger, factory, sleep=lambda _: None, health=health)

    def submit(self, controller, credentials=None):
        return controller.submit(self.snapshot, sign(self.snapshot, self.key), credentials or self.credentials(), now=1000)

    def test_completed_rollout_preserves_config_and_erases_credentials(self):
        credentials = self.credentials()
        result = self.submit(self.controller(), credentials)
        self.assertEqual(result['status'], 'succeeded')
        self.assertEqual(result['task_definition'], self.definition)
        self.assertEqual(credentials, {})
        self.assertEqual(self.cli.env, {})
        self.assertEqual(self.service['activeConfigurations'][0]['primaryContainer']['environment'][0]['value'], '0')
        for _, _, env in self.calls:
            self.assertEqual(env['AWS_CONFIG_FILE'], __import__('os').devnull)
            self.assertEqual(env['AWS_EC2_METADATA_DISABLED'], 'true')
            self.assertEqual(env['AWS_MAX_ATTEMPTS'], '1')
            self.assertNotIn('AWS_PROFILE', env)
        database = self.path.read_bytes()
        self.assertNotIn(b's' * 40, database)
        self.assertNotIn(b't' * 32, database)

    def test_tampering_expiry_self_review_and_wrong_identity_stop_before_cli(self):
        cases = [('reviewer_id', '101'), ('reviewer_id', '303'), ('expires_at', 999), ('issued_at', 800)]
        for field, value in cases:
            original = copy.deepcopy(self.snapshot)
            self.snapshot[field] = value
            credentials = self.credentials()
            with self.assertRaises(RuleError):
                self.submit(self.controller(), credentials)
            self.assertEqual(credentials, {})
            self.snapshot = original
        with self.assertRaises(RuleError):
            validate_snapshot(self.snapshot, '0' * 64, self.key, self.profile, now=1000)
        self.assertEqual(self.calls, [])

    def test_uncertain_write_is_not_replayed_after_controller_restart(self):
        def transport(args, **kwargs):
            if args[2] == 'update-express-gateway-service':
                raise TimeoutError('raw secret provider detail')
            return self.fake(args, **kwargs)
        with self.assertRaises(RuleError):
            self.submit(self.controller(transport))
        result = Ledger(self.path).get(self.snapshot['release_id'])
        self.assertEqual(result['status'], 'reconciliation_required')
        before = len(self.calls)
        with self.assertRaises(RuleError):
            self.submit(self.controller())
        self.assertEqual(len(self.calls), before)
        self.assertNotIn(b'raw secret', self.path.read_bytes())

    def test_configuration_drift_stops_before_external_write(self):
        self.service['activeConfigurations'][0]['memory'] = '2048'
        with self.assertRaises(RuleError):
            self.submit(self.controller())
        self.assertEqual([c[0] for c in self.calls], ['describe-express-gateway-service'])
        self.assertEqual(self.ledger.get(self.snapshot['release_id'])['status'], 'reconciliation_required')

    def test_health_failure_never_claims_success(self):
        with self.assertRaises(RuleError):
            self.submit(self.controller(health=lambda: False))
        self.assertEqual(self.ledger.get(self.snapshot['release_id'])['status'], 'reconciliation_required')

    def test_thread_start_failure_retains_claim_and_erases_credentials(self):
        from unittest.mock import patch
        controller=self.controller();credentials=self.credentials()
        with patch('portal.controller_runtime.threading.Thread.start',side_effect=RuntimeError('fixture')):
            with self.assertRaises(RuntimeError):
                controller.start(self.snapshot,sign(self.snapshot,self.key),credentials,now=1000)
        self.assertEqual(credentials,{})
        self.assertEqual(self.cli.env,{})
        self.assertFalse(controller.lock.locked())
        self.assertEqual(self.calls,[])
        self.assertEqual(self.ledger.get(self.snapshot['release_id'])['code'],'controller_start_unconfirmed')

    def test_restart_requires_reconciliation_of_durable_accepted_claim(self):
        self.ledger.claim(self.snapshot)
        restored=Ledger(self.path)
        self.assertEqual(restored.get(self.snapshot['release_id'])['code'],'controller_restarted')
        with self.assertRaises(RuleError):
            restored.claim(self.snapshot)

    def test_extra_plan_metadata_cannot_be_persisted_even_with_valid_hmac(self):
        self.snapshot['plan']['secret'] = 'not-for-storage'
        self.snapshot['plan_digest'] = fingerprint(self.snapshot['plan'])
        with self.assertRaises(RuleError):
            self.submit(self.controller())
        self.assertIsNone(self.ledger.get(self.snapshot['release_id']))

    def test_scope_approval_does_not_enable_controller(self):
        self.profile['execution_enabled'] = False
        self.snapshot['plan']['profile_sha256'] = fingerprint(self.profile)
        self.snapshot['plan_digest'] = fingerprint(self.snapshot['plan'])
        with self.assertRaisesRegex(RuleError, 'acceptance is incomplete'):
            self.submit(self.controller())
        self.assertEqual(self.calls, [])

    def test_ambient_credentials_never_enable_other_aws_operations(self):
        cli = TemporaryCLI('/usr/local/bin/aws', self.profile['region'], self.credentials(), run=self.fake)
        with self.assertRaises(RuleError):
            cli.call('get-caller-identity', {})
        self.assertEqual(self.calls, [])
        cli.erase()
