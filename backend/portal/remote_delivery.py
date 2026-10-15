"""Remote delivery adapter; inactive without operator-installed acceptance config."""
import base64
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import time
import uuid

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .controller_contract import sign, validate_snapshot
from .controller_http import PrivateClient, status_query, strict_json
from .ecs_release import fingerprint, make_plan
from .errors import RuleError
from .models import Member, Release, Run, Event
from .remote_jobs import RoleCLI, Artifacts, Queue, job, signed_status, safe_report, decode_configuration

_control_health={'fingerprint':'','until':0,'ready':False}


def config():
    path = os.environ.get('PORTAL_REMOTE_CONFIG_FILE', '')
    inline = os.environ.get('PORTAL_REMOTE_CONFIG_JSON', '')
    if path and inline:
        raise RuleError('remote_config_invalid','Only one operator configuration source is permitted.')
    if not path and not inline:
        return None
    if inline:
        if len(inline.encode()) > 1024*1024:
            raise RuleError('remote_config_invalid','Operator configuration exceeds bounds.')
        cfg=decode_configuration(inline)
    else:
        path = Path(path)
        if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size > 1024*1024:
            raise RuleError('remote_config_invalid', 'Operator remote configuration is invalid.')
        cfg = json.loads(path.read_text())
    profile = cfg['profile']
    if (cfg.get('schema_version') != 1 or not re.fullmatch(r'[0-9]{12}',profile['account']) or
        profile['repository'] != 'macANTONIO213/releaseportal-demo' or
        not re.fullmatch(r'[a-f0-9]{64}',cfg.get('acceptance_receipt_sha256',''))):
        raise RuleError('remote_config_invalid', 'A reviewed remote configuration is required.')
    return cfg


def configured(deployment=False):
    cfg = config()
    if not cfg:
        return False
    if cfg.get('pipeline_enabled') is not True or (deployment and cfg.get('deployment_enabled') is not True):
        return False
    required = ['linux_isolation', 'restricted_egress', 'runner_image', 'private_storage', 'queue_integration']
    if deployment:
        required += ['controller_tls', 'reviewer_oauth_guard', 'update_recovery']
    if not all(cfg.get('accepted',{}).get(k) is True for k in required):
        return False
    if deployment:
        reviewers=set(settings.GITHUB_REVIEWER_IDS)&set(settings.GITHUB_ALLOWED_USER_IDS)
        # Actual successful GitHub authorization, not a configured account name
        # or a seeded acceptance flag, supplies the reviewer access evidence.
        if not Event.objects.filter(action='github_signed_in',actor__is_active=True,
            actor__member__github_id__in=reviewers).exists():
            return False
        identity=fingerprint(cfg)
        if _control_health['fingerprint']!=identity or _control_health['until']<time.monotonic():
            try:
                ready=PrivateClient(cfg['controller_private_ip'],cfg['controller_certificate']).ready(key())
            except Exception:
                ready=False
            _control_health.update(fingerprint=identity,until=time.monotonic()+30,ready=ready)
        return _control_health['ready'] is True
    return True


def key():
    try:
        value = base64.b64decode(os.environ['PORTAL_WORKER_CONTROL_KEY'],validate=True)
        if len(value) != 32:
            raise ValueError()
        return value
    except Exception:
        raise RuleError('remote_control_unconfigured','Private worker authentication is unavailable.') from None


def adapters():
    cfg = config()
    if not configured():
        raise RuleError('remote_disabled','Remote worker acceptance is incomplete.')
    profile=cfg['profile']
    cli=RoleCLI(cfg['aws_cli'],profile['region'],'web')
    return cfg,Artifacts(cli,cfg['bucket'],profile['account']),Queue(cli,cfg['queue_url'],profile['account'],cfg['queue_name'])


def enqueue(run, content):
    cfg,storage,queue=adapters()
    if run.repository != cfg['profile']['repository']:
        raise RuleError('repository_unsupported','This repository requires a reviewed runner profile.')
    run.source_sha256=hashlib.sha256(content).hexdigest()
    run.status='trigger_pending'
    run.save(update_fields=['source_sha256','status'])
    try:
        storage.put(str(run.id),'source.tar.gz',content)
        status={'run_id':str(run.id),'source_sha256':run.source_sha256,'profile_sha256':fingerprint(cfg['profile']),
            'status':'running','code':'queued','evidence_sha256':'','artifact_sha256':'','image':''}
        storage.put(str(run.id),'status.json',json.dumps(signed_status(status,key())).encode())
        result=queue.send(job(str(run.id),run.repository,run.commit,run.source_sha256,fingerprint(cfg['profile'])))
        if not isinstance(result.get('MessageId'),str) or str(uuid.UUID(result['MessageId'])) != result['MessageId']:
            raise ValueError()
        run.status='running';run.evidence={'queue_message_id':result['MessageId']}
        run.save(update_fields=['status','evidence'])
    except Exception:
        Run.objects.filter(pk=run.id).update(status='sync_required',error_code='remote_submission_unknown')
        raise RuleError('remote_submission_unknown','Read the worker receipt before submitting another run.') from None


def poll():
    if not configured():
        return
    cfg,storage,_=adapters()
    from .services import attach_evidence,record
    for run in Run.objects.filter(status='running').order_by('created_at')[:4]:
        try:
            envelope=strict_json(storage.get(str(run.id),'status.json'))
            value=envelope['status']; expected=signed_status(value,key())
            if (set(envelope) != {'status','signature'} or not isinstance(envelope['signature'],str) or
                not hmac.compare_digest(expected['signature'],envelope['signature']) or value['run_id'] != str(run.id) or
                value['source_sha256'] != run.source_sha256 or value['profile_sha256'] != fingerprint(cfg['profile'])):
                raise ValueError()
            if value['status']=='running':
                continue
            if value['status']!='ready':
                Run.objects.filter(pk=run.id).update(status='failed' if value['status']=='failed' else 'sync_required',error_code=value['code'])
                continue
            raw=storage.get(str(run.id),'release-evidence.json',value['evidence_sha256'])
            report=safe_report(json.loads(raw))
            if (report.get('source_sha256') != run.source_sha256 or report.get('profile_sha256') != fingerprint(cfg['profile']) or
                report.get('artifact_sha256') != value['artifact_sha256'] or report.get('image') != value['image']):
                raise ValueError()
            artifact=storage.get(str(run.id),'release.tar.gz',value['artifact_sha256'])
            report['artifact']={'name':'release.tar.gz','bytes':len(artifact),'sha256':value['artifact_sha256']}
            # Applies the ECR, tests, scan and exact-profile gates before evidence can be reviewed.
            make_plan(cfg['profile'],cfg['baseline_service'],run.commit,run.source_sha256,value['artifact_sha256'],value['image'],report)
            attach_evidence(run.id,report,value['artifact_sha256'])
        except Exception:
            Run.objects.filter(pk=run.id).update(status='sync_required',error_code='remote_receipt_unconfirmed')
            record(None,'remote_receipt_unconfirmed',run.id)


def release_plan(run):
    cfg=config()
    baseline=copy.deepcopy(cfg['baseline_service'])
    # Advance only the image from a matching controller-confirmed deployment.
    # All other settings stay bound to the installed operator profile; the
    # controller re-reads AWS and checks the exact baseline before any write.
    previous=Release.objects.filter(status='deployed',plan__execution='ecs-service-image-v1',
        plan__profile_sha256=fingerprint(cfg['profile']),plan__target__service_arn=cfg['profile']['service_arn'],
        deployment_result__status='succeeded').order_by('-created_at').first()
    if previous:
        if previous.deployment_result.get('image')!=previous.plan['image'] or previous.deployment_result.get('plan_digest')!=previous.plan_digest:
            raise RuleError('baseline_unconfirmed','The prior controller receipt needs reconciliation.')
        baseline['activeConfigurations'][0]['primaryContainer']['image']=previous.plan['image']
    return make_plan(cfg['profile'],baseline,run.commit,run.source_sha256,run.artifact_sha256,run.evidence['image'],run.evidence)


def deploy(request, release, value):
    from .services import check_binding,record
    if not request.is_secure() or not configured(deployment=True):
        raise RuleError('remote_deployment_disabled','Verified HTTPS and accepted private deployment are required.')
    credentials={k:value.get(k) for k in ['access_key_id','secret_access_key','session_token']}
    if (not all(isinstance(v,str) for v in credentials.values()) or
        not re.fullmatch(r'ASIA[A-Z0-9]{16}',credentials['access_key_id']) or
        not re.fullmatch(r'[A-Za-z0-9/+=]{40}',credentials['secret_access_key']) or
        not re.fullmatch(r'[A-Za-z0-9/+=]{16,20000}',credentials['session_token'])):
        credentials.clear()
        raise RuleError('invalid_credentials','Supply all three temporary AWS values.',400)
    try:
        cfg=config()
        with transaction.atomic():
            release=Release.objects.select_for_update().select_related('run','creator','approver').get(pk=release.id)
            check_binding(release)
            if (release.status!='approved' or not release.approval_expires_at or release.approval_expires_at<=timezone.now() or
                value.get('confirmed') is not True or value.get('plan_digest')!=release.plan_digest or
                release_plan(release.run)!=release.plan):
                raise RuleError('approval_invalid','A current approval of this exact release is required.')
            # Lock single destination across distinct release rows in PostgreSQL.
            from django.db import connection
            if connection.vendor=='postgresql':
                with connection.cursor() as cursor:
                    cursor.execute('SELECT pg_advisory_xact_lock(%s)',[111122223333])
            if Release.objects.filter(status__in=['deploying','reconciliation_required','awaiting_operator_result']).exclude(pk=release.id).exists():
                raise RuleError('environment_busy','Reconcile the previous deployment first.')
            snapshot={'version':1,'release_id':str(release.id),'nonce':str(uuid.uuid4()),
                'creator_id':str(Member.objects.get(user=release.creator).github_id),
                'reviewer_id':str(Member.objects.get(user=release.approver).github_id),
                'approved_at':int(release.approved_at.timestamp()),'issued_at':int(time.time()),
                'expires_at':min(int(release.approval_expires_at.timestamp()),int(release.approved_at.timestamp())+1800),
                'plan_digest':release.plan_digest,'plan':release.plan}
            signature=sign(snapshot,key())
            validate_snapshot(snapshot,signature,key(),cfg['profile'])
            release.status,release.operator='deploying',request.user
            release.save(update_fields=['status','operator'])
            record(request.user,'remote_deployment_started',release.id,plan_digest=release.plan_digest)
        # Transaction committed before handing credentials to the separate process.
        client=PrivateClient(cfg['controller_private_ip'],cfg['controller_certificate'])
        receipt=client.post('/v1/deploy',{'snapshot':snapshot,'signature':signature,'credentials':credentials})
        if receipt.get('release_id')!=str(release.id) or receipt.get('plan_digest')!=release.plan_digest:
            raise ValueError()
        return {'id':str(release.id),'status':'deploying','credentials_persisted':False}
    except Exception:
        Release.objects.filter(pk=release.id,status='deploying').update(status='reconciliation_required')
        raise RuleError('controller_outcome_unknown','Read the private controller receipt before another attempt.') from None
    finally:
        credentials.clear()


def poll_deployments():
    if not configured(deployment=True):
        return
    cfg=config();client=PrivateClient(cfg['controller_private_ip'],cfg['controller_certificate'])
    for release in Release.objects.filter(status__in=['deploying','reconciliation_required']):
        try:
            result=client.post('/v1/receipt',status_query(str(release.id),key()))
            if result.get('release_id')!=str(release.id) or result.get('plan_digest')!=release.plan_digest or result.get('image')!=release.plan['image']:
                raise ValueError()
            states={'succeeded':'deployed','failed':'failed','reconciliation_required':'reconciliation_required'}
            if result.get('status') in states:
                release.status=states[result['status']];release.deployment_result={**result,'application_url':cfg['profile']['health_url'].removesuffix('/healthz')}
                release.save(update_fields=['status','deployment_result'])
        except Exception:
            Release.objects.filter(pk=release.id).update(status='reconciliation_required')
