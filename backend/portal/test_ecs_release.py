import copy
from django.test import SimpleTestCase
from .ecs_release import make_plan, update_request, fingerprint
from .services import RuleError


class EcsReleaseTests(SimpleTestCase):
    def setUp(self):
        self.profile = {'account': '111122223333', 'region': 'ap-southeast-1',
            'service_arn': 'arn:aws:ecs:ap-southeast-1:111122223333:service/portal/portal',
            'image_repository': '111122223333.dkr.ecr.ap-southeast-1.amazonaws.com/portal',
            'repository': 'example/portal'}
        self.old = self.profile['image_repository'] + '@sha256:' + 'a' * 64
        self.new = self.profile['image_repository'] + '@sha256:' + 'b' * 64
        self.service = {'serviceArn': self.profile['service_arn'], 'activeConfigurations': [{
            'cpu': '512', 'memory': '1024', 'networkConfiguration': {'securityGroups': ['sg-fixture']},
            'primaryContainer': {'image': self.old, 'containerPort': 8055,
                'command': ['waitress-serve', 'config.wsgi:application'],
                'secrets': [{'name': 'PORTAL_SECRET_KEY', 'valueFrom': 'fixture-secret-reference'}]}}]}
        self.evidence = {'repository': self.profile['repository'], 'commit': 'c' * 40, 'error_code': '',
            'source_sha256': 'd' * 64, 'artifact_sha256': 'f' * 64, 'profile_sha256': fingerprint(self.profile),
            'image': self.new, 'image_scan': {'status': 'COMPLETE', 'high': 0, 'critical': 0},
            'tests': {'passed': 90, 'failed': 0, 'skipped': 0, 'total': 90},
            'scans': {name: {'status': 'passed', 'findings': 0} for name in ['source', 'dependencies', 'secrets']}}

    def plan(self):
        return make_plan(self.profile, self.service, 'c' * 40, 'd' * 64, 'f' * 64, self.new, self.evidence)

    def test_update_changes_only_image_and_preserves_input(self):
        plan = self.plan()
        request = update_request(self.profile, plan, fingerprint(plan), self.service)
        self.assertEqual(set(request), {'serviceArn', 'primaryContainer'})
        expected = copy.deepcopy(self.service['activeConfigurations'][0]['primaryContainer'])
        expected['image'] = self.new
        self.assertEqual(request['primaryContainer'], expected)
        self.assertEqual(self.service['activeConfigurations'][0]['primaryContainer']['image'], self.old)

    def test_runtime_change_invalidates_approval(self):
        plan = self.plan()
        self.service['activeConfigurations'][0]['networkConfiguration']['securityGroups'] = ['sg-changed']
        with self.assertRaises(RuleError):
            update_request(self.profile, plan, fingerprint(plan), self.service)

    def test_changed_plan_or_wrong_registry_is_rejected(self):
        plan = self.plan(); approved = fingerprint(plan); plan['image'] = self.old
        with self.assertRaises(RuleError):update_request(self.profile, plan, approved, self.service)
        self.new = self.new.replace('111122223333', '999900001111')
        with self.assertRaises(RuleError):self.plan()

    def test_missing_failed_or_mismatched_evidence_is_rejected(self):
        for key, value in [('commit', 'e' * 40), ('source_sha256', 'e' * 64), ('artifact_sha256', 'e' * 64), ('profile_sha256', 'e' * 64), ('error_code', 'frontend_build_failed'),
                           ('tests', {'passed': 89, 'failed': 1, 'skipped': 0, 'total': 90}),
                           ('scans', {'source': {'status': 'not_run', 'findings': None}})]:
            with self.subTest(key=key):
                original = copy.deepcopy(self.evidence)
                self.evidence[key] = value
                with self.assertRaises(RuleError):self.plan()
                self.evidence = original

    def test_multiple_active_revisions_require_reconciliation(self):
        self.service['activeConfigurations'] *= 2
        with self.assertRaises(RuleError):self.plan()

    def test_missing_or_failing_image_scan_cannot_be_reviewed(self):
        for scan in [{}, {'status': 'IN_PROGRESS', 'high': 0, 'critical': 0},
                     {'status': 'COMPLETE', 'high': 1, 'critical': 0},
                     {'status': 'COMPLETE', 'high': False, 'critical': 0}]:
            with self.subTest(scan=scan):
                self.evidence['image_scan'] = scan
                with self.assertRaises(RuleError):self.plan()
