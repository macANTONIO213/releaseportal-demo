from datetime import timedelta
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from .models import Run
from .jenkins import Jenkins
from .services import RuleError, attach_evidence, record

def tick():
    now = timezone.now()
    candidates = Run.objects.filter(status__in=['queued', 'trigger_pending', 'running']).filter(Q(next_poll_at__isnull=True) | Q(next_poll_at__lte=now)).order_by('created_at')[:20]
    for run in candidates:
        if run.worker_lease_until and run.worker_lease_until > now:
            continue
        claimed = Run.objects.filter(pk=run.pk, updated_at=run.updated_at).update(worker_lease_until=now + timedelta(seconds=180), updated_at=now)
        if not claimed:
            continue
        try:
            client = Jenkins()
            if run.status == 'trigger_pending':
                # A previous process may have submitted a build before crashing.
                # Never submit another one without an explicit queue/build receipt.
                Run.objects.filter(pk=run.pk).update(status='sync_required', error_code='trigger_outcome_unknown')
                continue
            if run.status == 'queued':
                Run.objects.filter(pk=run.pk).update(status='trigger_pending')
                queue_id = client.trigger(run)
                Run.objects.filter(pk=run.pk).update(queue_id=queue_id, status='running')
                record(None, 'jenkins_triggered', run.id, queue_id=queue_id)
                continue
            if not run.build_number:
                queue = client.queue(run.queue_id)
                if queue.get('cancelled'):
                    Run.objects.filter(pk=run.pk).update(status='failed', error_code='jenkins_cancelled')
                    continue
                number = queue.get('executable', {}).get('number')
                if not number:
                    continue
                if type(number) is not int or number < 1:
                    raise RuleError('invalid_build_number', 'Invalid Jenkins receipt.')
                Run.objects.filter(pk=run.pk).update(build_number=number)
                run.build_number = number
            build = client.build(run.build_number)
            parameters = {p['name']: p.get('value') for action in build.get('actions', []) for p in action.get('parameters', [])}
            if parameters.get('PORTAL_RUN_ID') != str(run.id) or parameters.get('COMMIT_SHA') != run.commit:
                raise RuleError('build_mismatch', 'Jenkins build parameters do not match this run.')
            if build.get('building'):
                continue
            if build.get('result') != 'SUCCESS':
                Run.objects.filter(pk=run.pk).update(status='failed', error_code='jenkins_build_failed')
                record(None, 'build_failed', run.id, build=run.build_number)
                continue
            evidence, artifact_digest = client.evidence(run.build_number)
            attach_evidence(run.id, evidence, artifact_digest)
        except RuleError as exc:
            new_status = 'sync_required' if run.status == 'queued' or exc.code in ['build_mismatch', 'queue_unknown'] else run.status
            if exc.code in ['tests_failed', 'scan_incomplete', 'digest_mismatch', 'artifact_size_mismatch', 'invalid_evidence', 'source_mismatch']:
                new_status = 'failed'
            retries = run.retry_count + 1
            if exc.code in ['jenkins_http_error', 'jenkins_unconfigured'] or retries >= 5:
                new_status = 'sync_required'
            Run.objects.filter(pk=run.pk).update(status=new_status, error_code=exc.code, retry_count=retries,
                next_poll_at=now + timedelta(seconds=min(300, 5 * 2 ** retries)))
            record(None, 'integration_error', run.id, code=exc.code)
        except Exception:
            # Unknown outcome must be reviewed rather than retrying writes.
            Run.objects.filter(pk=run.pk).update(status='sync_required', error_code='worker_error')
            record(None, 'worker_error', run.id)
        finally:
            Run.objects.filter(pk=run.pk).update(worker_lease_until=None)
