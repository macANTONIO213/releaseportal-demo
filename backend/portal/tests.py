"""Critical safety and integration-contract tests. Fixtures never seed the live database."""
import copy
import json
import uuid
from datetime import timedelta
from unittest.mock import Mock, patch
from django.test import TestCase, Client, override_settings
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import Member, Run, Release, Event
from .services import RuleError, attach_evidence, prepare_release, decide, begin, finish, reset_approval, PROJECT
from .worker import tick
from .jenkins import Jenkins

SHA = 'a' * 40
HASH = 'b' * 64
PUBLIC_TEST_PASSWORD = 'test-fixture-password-only'  # pragma: allowlist secret - isolated test database only, never a live account

def evidence(commit=SHA):
    return {'schema_version': 1, 'repository': PROJECT['repository'], 'commit': commit,
        'tests': {'passed': 5, 'failed': 0, 'skipped': 1, 'total': 6},
        'scans': {'dependencies': {'status': 'passed', 'findings': 0}, 'secrets': {'status': 'passed', 'findings': 0}},
        'artifact': {'name': 'source.tar.gz', 'sha256': HASH, 'bytes': 12}}

@override_settings(AUTH_MODE='invited_password')
class ReleaseSafetyTests(TestCase):
    def setUp(self):
        self.dev = get_user_model().objects.create_user('developer@example.invalid', password=PUBLIC_TEST_PASSWORD)
        self.reviewer = get_user_model().objects.create_user('reviewer@example.invalid', password=PUBLIC_TEST_PASSWORD)
        self.viewer = get_user_model().objects.create_user('viewer@example.invalid', password=PUBLIC_TEST_PASSWORD)
        for user, role in [(self.dev, 'developer'), (self.reviewer, 'reviewer'), (self.viewer, 'viewer')]:
            Member.objects.create(user=user, role=role)
        self.client.force_login(self.dev)

    def ready_run(self):
        run = Run.objects.create(requester=self.dev, commit=SHA)
        return attach_evidence(run.pk, evidence(), HASH)

    def approved(self):
        release = prepare_release(self.ready_run().pk, self.dev)
        return decide(release.pk, self.reviewer, True)

    def result(self, release, outcome='reported_success'):
        return {'outcome': outcome, 'artifact_sha256': HASH, 'plan_digest': release.plan_digest,
            'receipt_reference': 'operator-receipt.json', 'checks': {'https': True, 'login': True, 'readiness': True}}

    def post(self, path, data):
        return self.client.post(path, json.dumps(data), content_type='application/json')

    def test_login_required(self):
        self.client.logout()
        self.assertEqual(self.client.get('/api/dashboard').status_code, 401)

    def test_viewer_cannot_start_build(self):
        self.client.force_login(self.viewer)
        self.assertEqual(self.post('/api/runs', {'commit': SHA}).status_code, 403)

    def test_missing_integration_is_visible_not_simulated(self):
        response = self.post('/api/runs', {'commit': SHA, 'request_key': str(uuid.uuid4())})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(Run.objects.count(), 0)

    @override_settings(JENKINS_URL='http://127.0.0.1:8080', JENKINS_USER='test', JENKINS_TOKEN='fixture')
    def test_idempotent_build_request(self):
        request = {'commit': SHA, 'request_key': str(uuid.uuid4())}
        first = self.post('/api/runs', request)
        second = self.post('/api/runs', request)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.json()['id'], second.json()['id'])
        self.assertEqual(Run.objects.count(), 1)

    def test_failing_tests_block_evidence(self):
        run = Run.objects.create(requester=self.dev, commit=SHA)
        report = evidence()
        report['tests'].update(passed=4, failed=1)
        with self.assertRaises(RuleError):
            attach_evidence(run.id, report, HASH)
        run.refresh_from_db()
        self.assertEqual(run.status, 'queued')

    def test_missing_or_blocking_scan_rejected(self):
        for report in [evidence(), evidence()]:
            run = Run.objects.create(requester=self.dev, commit=SHA)
            if run == Run.objects.first():
                report['scans'].pop('secrets')
            else:
                report['scans']['dependencies']['findings'] = 1
            with self.assertRaises(RuleError):
                attach_evidence(run.id, report, HASH)

    def test_wrong_source_and_artifact_rejected(self):
        for report, actual in [(evidence('c'*40), HASH), (evidence(), 'c'*64)]:
            run = Run.objects.create(requester=self.dev, commit=SHA)
            with self.assertRaises(RuleError):
                attach_evidence(run.id, report, actual)

    def test_completed_evidence_is_immutable(self):
        run = self.ready_run()
        with self.assertRaises(RuleError):
            attach_evidence(run.id, evidence(), HASH)

    def test_self_approval_is_blocked(self):
        release = prepare_release(self.ready_run().id, self.dev)
        with self.assertRaises(RuleError) as error:
            decide(release.id, self.dev, True)
        self.assertEqual(error.exception.code, 'self_approval')

    def test_developer_cannot_call_approval_api(self):
        release = prepare_release(self.ready_run().id, self.dev)
        response = self.post(f'/api/releases/{release.id}/approve', {'acknowledged': True})
        self.assertEqual(response.status_code, 403)

    def test_expired_approval_blocks_handoff(self):
        release = self.approved()
        Release.objects.filter(pk=release.pk).update(approval_expires_at=timezone.now()-timedelta(seconds=1))
        with self.assertRaises(RuleError):
            begin(release.id, self.reviewer)

    def test_reset_requires_a_fresh_decision(self):
        release = self.approved()
        reset_approval(release.id, self.reviewer)
        with self.assertRaises(RuleError):
            begin(release.id, self.reviewer)

    def test_changed_target_invalidates_approval(self):
        release = self.approved()
        release.plan['account'] = '000000000000'
        release.save()
        with self.assertRaises(RuleError):
            begin(release.id, self.reviewer)

    def test_changed_evidence_invalidates_approval(self):
        release = self.approved()
        report = evidence()
        report['artifact']['sha256'] = 'c'*64
        Run.objects.filter(pk=release.run_id).update(evidence=report)
        with self.assertRaises(RuleError):
            begin(release.id, self.reviewer)

    def test_result_requires_actual_handoff_and_assigned_operator(self):
        release = self.approved()
        with self.assertRaises(RuleError):
            finish(release.id, self.reviewer, self.result(release))
        release = begin(release.id, self.reviewer)
        with self.assertRaises(RuleError):
            finish(release.id, self.dev, self.result(release))

    def test_missing_verification_never_becomes_success(self):
        release = begin(self.approved().id, self.reviewer)
        result = self.result(release)
        result['checks']['login'] = False
        with self.assertRaises(RuleError):
            finish(release.id, self.reviewer, result)
        release.refresh_from_db()
        self.assertEqual(release.status, 'awaiting_operator_result')

    def test_result_digest_mismatch_rejected(self):
        release = begin(self.approved().id, self.reviewer)
        result = self.result(release)
        result['artifact_sha256'] = 'c'*64
        with self.assertRaises(RuleError):
            finish(release.id, self.reviewer, result)

    def test_success_is_explicitly_operator_reported(self):
        release = begin(self.approved().id, self.reviewer)
        release = finish(release.id, self.reviewer, self.result(release))
        self.assertEqual(release.status, 'operator_reported_success')
        self.assertEqual(release.deployment_result['evidence_source'], 'operator_reported')

    def test_uncertain_outcome_blocks_next_handoff(self):
        release = begin(self.approved().id, self.reviewer)
        finish(release.id, self.reviewer, self.result(release, 'uncertain'))
        another = self.approved()
        with self.assertRaises(RuleError) as error:
            begin(another.id, self.reviewer)
        self.assertEqual(error.exception.code, 'environment_busy')

    def test_reconciliation_preserves_previous_result(self):
        release = begin(self.approved().id, self.reviewer)
        finish(release.id, self.reviewer, self.result(release, 'uncertain'))
        finish(release.id, self.reviewer, self.result(release, 'failed'), reconcile=True)
        self.assertTrue(Event.objects.filter(action='prior_result_preserved', detail__result__outcome='uncertain').exists())

    def test_record_survives_new_session(self):
        run = self.ready_run()
        another = Client()
        another.force_login(self.reviewer)
        self.assertEqual(another.get('/api/dashboard').json()['runs'][0]['id'], str(run.id))

    def test_csrf_required_even_for_login(self):
        client = Client(enforce_csrf_checks=True)
        self.assertEqual(client.post('/api/login', '{}', content_type='application/json').status_code, 403)

    def test_local_login_with_csrf_and_role(self):
        client = Client(enforce_csrf_checks=True)
        token = client.get('/api/session').json()['csrf']
        response = client.post('/api/login', json.dumps({'username': self.dev.username, 'password': PUBLIC_TEST_PASSWORD}), content_type='application/json', HTTP_X_CSRFTOKEN=token)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['user']['role'], 'developer')

    @override_settings(LOCAL=False)
    def test_local_login_disabled_in_pilot(self):
        self.assertEqual(self.post('/api/login', {}).status_code, 403)

    @override_settings(LOCAL=False, AUTH_MODE='invited_password', PRIVATE_INGRESS_CONFIRMED=True)
    def test_invited_password_login_in_private_pilot(self):
        response = self.post('/api/login', {'username': self.dev.username.upper(), 'password': PUBLIC_TEST_PASSWORD})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['auth_method'], 'invited_password')

    @override_settings(LOCAL=False, AUTH_MODE='invited_password', PRIVATE_INGRESS_CONFIRMED=False)
    def test_private_pilot_cannot_login_without_ingress_confirmation(self):
        self.assertEqual(self.post('/api/login', {'username': self.dev.username, 'password': PUBLIC_TEST_PASSWORD}).status_code, 403)

    @override_settings(AUTH_MODE='corporate')
    def test_corporate_mode_does_not_accept_password_fallback(self):
        self.assertEqual(self.post('/api/login', {'username': self.dev.username, 'password': PUBLIC_TEST_PASSWORD}).status_code, 403)

    def test_uninvited_account_cannot_password_login(self):
        outsider = get_user_model().objects.create_user('outsider@example.invalid', password=PUBLIC_TEST_PASSWORD)
        self.assertEqual(self.post('/api/login', {'username': outsider.username, 'password': PUBLIC_TEST_PASSWORD}).status_code, 401)

    def test_password_mode_disables_oidc_routes(self):
        self.assertEqual(self.client.get('/auth/login').status_code, 503)
        self.assertEqual(self.client.get('/auth/callback').status_code, 403)

    def test_login_rate_limit(self):
        for _ in range(5):
            response = self.post('/api/login', {'username': self.dev.username, 'password': 'incorrect'})  # pragma: allowlist secret - deliberate wrong-password fixture
            self.assertEqual(response.status_code, 401)
        self.assertEqual(self.post('/api/login', {'username': self.dev.username, 'password': 'incorrect'}).status_code, 429)  # pragma: allowlist secret - deliberate wrong-password fixture

    def test_feedback_rejects_secrets_and_invalid_rating(self):
        self.assertEqual(self.post('/api/feedback', {'task': 'overall', 'rating': 5, 'comment': 'AWS_SECRET_ACCESS_KEY=example'}).status_code, 400)  # pragma: allowlist secret - deliberate non-secret rejection fixture
        self.assertEqual(self.post('/api/feedback', {'task': 'overall', 'rating': 9}).status_code, 400)
        self.assertEqual(self.post('/api/feedback', {'task': 'overall', 'rating': 4, 'minutes': 5}).status_code, 201)

    @patch('portal.worker.Jenkins')
    def test_unknown_trigger_is_not_retried(self, client):
        run = Run.objects.create(requester=self.dev, commit=SHA)
        client.return_value.trigger.side_effect = RuleError('queue_unknown', 'Uncertain')
        tick()
        tick()
        self.assertEqual(client.return_value.trigger.call_count, 1)
        run.refresh_from_db()
        self.assertEqual(run.status, 'sync_required')

    @patch('portal.worker.Jenkins')
    def test_restart_after_submission_does_not_duplicate(self, client):
        run = Run.objects.create(requester=self.dev, commit=SHA, status='trigger_pending')
        tick()
        client.return_value.trigger.assert_not_called()
        run.refresh_from_db()
        self.assertEqual(run.status, 'sync_required')

    @patch('portal.worker.Jenkins')
    def test_worker_collects_only_matching_build(self, client):
        run = Run.objects.create(requester=self.dev, commit=SHA, status='running', build_number=1)
        client.return_value.build.return_value = {'building': False, 'result': 'SUCCESS', 'actions': [{'parameters': [
            {'name': 'PORTAL_RUN_ID', 'value': str(run.id)}, {'name': 'COMMIT_SHA', 'value': SHA}]}]}
        client.return_value.evidence.return_value = (evidence(), HASH)
        tick()
        run.refresh_from_db()
        self.assertEqual(run.status, 'ready')

    @patch('portal.worker.Jenkins')
    def test_wrong_build_never_attaches_evidence(self, client):
        run = Run.objects.create(requester=self.dev, commit=SHA, status='running', build_number=1)
        client.return_value.build.return_value = {'building': False, 'result': 'SUCCESS', 'actions': []}
        tick()
        client.return_value.evidence.assert_not_called()
        run.refresh_from_db()
        self.assertEqual(run.status, 'sync_required')

    @override_settings(JENKINS_URL='http://127.0.0.1:8080', JENKINS_USER='test', JENKINS_TOKEN='fixture')
    def test_jenkins_redirect_is_not_followed(self):
        client = Jenkins()
        response = Mock(status_code=302)
        client.session.request = Mock(return_value=response)
        with self.assertRaises(RuleError):
            client.build(1)
        self.assertFalse(client.session.request.call_args.kwargs['allow_redirects'])
