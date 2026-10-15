import hashlib
import json
import re
from datetime import timedelta
from django.db import transaction
from django.utils import timezone
from .models import Event, Release, Run
from .errors import RuleError

PROJECT = {'name': 'Demo application', 'repository': 'macANTONIO213/releaseportal-demo',
           'branch': 'develop', 'environment': 'Development', 'account': '111122223333', 'region': 'ap-southeast-1'}

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def record(actor, action, object_id='', **detail):
    Event.objects.create(actor=actor, action=action, object_id=str(object_id), detail=detail)

def valid_sha(value, length):
    return isinstance(value, str) and bool(re.fullmatch(r'[a-f0-9]{%d}' % length, value))

def validate_evidence(evidence, commit, repository=None):
    if not isinstance(evidence, dict) or evidence.get('schema_version') != 1:
        raise RuleError('invalid_evidence', 'Unsupported evidence schema.')
    if evidence.get('repository') != (repository or PROJECT['repository']) or evidence.get('commit') != commit:
        raise RuleError('source_mismatch', 'Evidence does not match the selected repository and revision.')
    tests = evidence.get('tests', {})
    for name in ['passed', 'failed', 'skipped', 'total']:
        if type(tests.get(name)) is not int or tests[name] < 0:
            raise RuleError('invalid_tests', 'Test evidence is incomplete.')
    if tests['total'] < 1 or tests['passed'] + tests['failed'] + tests['skipped'] != tests['total']:
        raise RuleError('invalid_tests', 'Test totals are inconsistent.')
    if tests['failed'] or not tests['passed']:
        raise RuleError('tests_failed', 'The build has failing or no passing tests.')
    from django.conf import settings
    required_scans = ['dependencies','secrets'] + (['source'] if settings.AUTH_MODE == 'github' else [])
    for name in required_scans:
        scan = evidence.get('scans', {}).get(name, {})
        if scan.get('status') != 'passed' or scan.get('findings') != 0:
            raise RuleError('scan_incomplete', 'Required scans must complete with no blocking findings.')
    artifact = evidence.get('artifact', {})
    if artifact.get('name') not in ['source.tar.gz','release.tar.gz'] or not valid_sha(artifact.get('sha256'), 64):
        raise RuleError('invalid_artifact', 'Artifact identity is invalid.')
    if type(artifact.get('bytes')) is not int or not 0 < artifact['bytes'] <= 100 * 1024 * 1024:
        raise RuleError('invalid_artifact', 'Artifact size is outside the pilot limit.')
    return artifact

@transaction.atomic
def attach_evidence(run_id, evidence, artifact_digest, actor=None):
    run = Run.objects.select_for_update().get(pk=run_id)
    if run.status not in ['queued', 'running', 'sync_required']:
        raise RuleError('immutable_run', 'Completed evidence cannot be replaced. Start a new run.')
    artifact = validate_evidence(evidence, run.commit, run.repository)
    if artifact['sha256'] != artifact_digest:
        raise RuleError('digest_mismatch', 'Downloaded artifact does not match the report.')
    run.evidence = evidence
    run.artifact_sha256 = artifact_digest
    run.artifact_name = artifact['name']
    run.status, run.error_code = 'ready', ''
    run.save()
    record(actor, 'evidence_verified', run.id, sha256=artifact_digest, build=run.build_number)
    return run

@transaction.atomic
def prepare_release(run_id, actor):
    run = Run.objects.select_for_update().get(pk=run_id)
    if run.status != 'ready':
        raise RuleError('not_ready', 'A passing build with verified artifact is required.')
    validate_evidence(run.evidence, run.commit, run.repository)
    if Release.objects.filter(run=run).exists():
        raise RuleError('release_exists', 'This build already has a release.')
    plan = {**PROJECT, 'repository': run.repository, 'template': run.template, 'commit': run.commit, 'artifact_sha256': run.artifact_sha256,
        'execution': 'supervised', 'scope': 'Existing approved development procedure only; no automatic infrastructure changes.',
        'exposure': 'Public HTTPS with application login', 'data': 'Synthetic demo data',
        'email_ai': 'Disabled', 'recovery': 'Stop on uncertain result; reconcile recorded resources before retry.'}
    from django.conf import settings
    if settings.AUTH_MODE == 'github':
        from . import remote_delivery
        if remote_delivery.configured():
            plan=remote_delivery.release_plan(run)
        else:
            from .deployment import plan as direct_plan
            plan.update(direct_plan(run))
    release = Release.objects.create(run=run, creator=actor, plan=plan, plan_digest=digest(plan), artifact_sha256=run.artifact_sha256)
    record(actor, 'release_prepared', release.id, plan_digest=release.plan_digest)
    return release

def check_binding(release):
    if digest(release.plan) != release.plan_digest or release.artifact_sha256 != release.run.artifact_sha256 or release.plan.get('artifact_sha256') != release.artifact_sha256:
        raise RuleError('approval_invalid', 'Release inputs changed. Prepare and review a new release.')
    if release.run.status != 'ready':
        raise RuleError('not_ready', 'Build evidence is no longer ready.')
    artifact = validate_evidence(release.run.evidence, release.run.commit, release.run.repository)
    if artifact['sha256'] != release.artifact_sha256:
        raise RuleError('approval_invalid', 'Artifact evidence no longer matches the approved release.')

@transaction.atomic
def reset_approval(release_id, actor):
    release = Release.objects.select_for_update().select_related('run').get(pk=release_id)
    if release.status != 'approved':
        raise RuleError('wrong_state', 'Only an unstarted approval can be revoked or renewed.')
    check_binding(release)
    release.status, release.approver, release.approved_at, release.approval_expires_at = 'awaiting_approval', None, None, None
    release.save()
    record(actor, 'approval_reset', release.id)
    return release

@transaction.atomic
def decide(release_id, actor, approve):
    release = Release.objects.select_for_update().select_related('run').get(pk=release_id)
    if release.status != 'awaiting_approval':
        raise RuleError('wrong_state', 'This release is not waiting for approval.')
    if release.creator_id == actor.id or release.run.requester_id == actor.id:
        raise RuleError('self_approval', 'Another reviewer must make this release decision.', 403)
    check_binding(release)
    release.status = 'approved' if approve else 'rejected'
    release.approver, release.approved_at = actor, timezone.now()
    from . import remote_delivery
    release.approval_expires_at = timezone.now() + (timedelta(minutes=30) if remote_delivery.configured() else timedelta(hours=8)) if approve else None
    release.save()
    record(actor, 'release_approved' if approve else 'release_rejected', release.id, plan_digest=release.plan_digest)
    return release

@transaction.atomic
def begin(release_id, actor):
    # Lock the single project row-equivalent through all ready build records;
    # PostgreSQL advisory lock serializes starts even when no deployment exists.
    from django.db import connection
    if connection.vendor == 'postgresql':
        with connection.cursor() as cursor:
            cursor.execute('SELECT pg_advisory_xact_lock(%s)', [111122223333])
    release = Release.objects.select_for_update().select_related('run').get(pk=release_id)
    check_binding(release)
    if release.status != 'approved' or not release.approval_expires_at or release.approval_expires_at <= timezone.now():
        raise RuleError('approval_expired', 'An active approval is required.')
    if Release.objects.filter(status__in=['awaiting_operator_result', 'reconciliation_required']).exclude(pk=release.pk).exists():
        raise RuleError('environment_busy', 'Another release needs an operator result or reconciliation.')
    release.status, release.operator = 'awaiting_operator_result', actor
    release.save()
    record(actor, 'handoff_started', release.id)
    return release

@transaction.atomic
def finish(release_id, actor, payload, reconcile=False):
    release = Release.objects.select_for_update().select_related('run').get(pk=release_id)
    allowed_status = 'reconciliation_required' if reconcile else 'awaiting_operator_result'
    if release.status != allowed_status or release.operator_id != actor.id:
        raise RuleError('wrong_operator', 'Only the assigned operator can record this result.', 403)
    check_binding(release)
    outcome = payload.get('outcome')
    if outcome not in ['reported_success', 'failed', 'uncertain']:
        raise RuleError('invalid_result', 'Select a valid deployment outcome.', 400)
    if payload.get('artifact_sha256') != release.artifact_sha256 or payload.get('plan_digest') != release.plan_digest:
        raise RuleError('receipt_mismatch', 'Receipt must identify the approved artifact and plan.')
    checks = payload.get('checks', {})
    if outcome == 'reported_success' and not all(checks.get(k) is True for k in ['https', 'login', 'readiness']):
        raise RuleError('verification_missing', 'HTTPS, login and readiness evidence is required.', 400)
    reference = payload.get('receipt_reference', '')
    if not isinstance(reference, str) or not re.fullmatch(r'[\w./:-]{1,200}', reference):
        raise RuleError('invalid_reference', 'Use a non-secret receipt reference, not a password or URL query.', 400)
    previous = release.deployment_result
    release.deployment_result = {'outcome': outcome, 'artifact_sha256': release.artifact_sha256,
        'plan_digest': release.plan_digest, 'checks': {k: checks.get(k) is True for k in ['https', 'login', 'readiness']},
        'receipt_reference': reference, 'evidence_source': 'operator_reported', 'recorded_at': timezone.now().isoformat()}
    if reconcile:
        record(actor, 'prior_result_preserved', release.id, result=previous)
    release.status = {'reported_success': 'operator_reported_success', 'failed': 'failed', 'uncertain': 'reconciliation_required'}[outcome]
    release.save()
    record(actor, 'operator_result_recorded', release.id, outcome=outcome)
    return release
