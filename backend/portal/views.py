import hashlib
import json
import logging
import uuid
from functools import wraps
from datetime import timedelta
from pathlib import Path
from django.conf import settings
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.db import transaction, IntegrityError
from django.http import JsonResponse, HttpResponse, FileResponse
from django.middleware.csrf import get_token
from django.shortcuts import redirect
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST
from authlib.integrations.django_client import OAuth
from .models import Member, Run, Release, Event, Feedback, LoginAttempt
from . import services
from .roles import role_for

logger = logging.getLogger('portal')
oauth = OAuth()
if settings.AUTH_MODE == 'corporate' and settings.OIDC_METADATA:
    oauth.register(name='corporate', server_metadata_url=settings.OIDC_METADATA,
        client_id=settings.OIDC_CLIENT_ID, client_secret=settings.OIDC_CLIENT_SECRET,
        client_kwargs={'scope': 'openid email profile', 'code_challenge_method': 'S256'})

def body(request):
    if len(request.body) > 16384:
        raise services.RuleError('too_large', 'Request exceeds the pilot limit.', 413)
    try:
        value = json.loads(request.body or '{}')
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except ValueError:
        raise services.RuleError('invalid_json', 'Supply a JSON object.', 400)

def api(roles=('viewer', 'developer', 'reviewer')):
    def decorate(fn):
        @wraps(fn)
        def wrapped(request, *args, **kwargs):
            try:
                if not request.user.is_authenticated:
                    return JsonResponse({'error': 'Sign in to continue.', 'code': 'login_required'}, status=401)
                member = Member.objects.filter(user=request.user, user__is_active=True).first()
                if not member or role_for(member) not in roles:
                    return JsonResponse({'error': 'This action is not available to your role.', 'code': 'forbidden'}, status=403)
                return fn(request, *args, **kwargs)
            except services.RuleError as exc:
                return JsonResponse({'error': exc.message, 'code': exc.code, 'correlation_id': request.correlation_id}, status=exc.status)
            except (Run.DoesNotExist, Release.DoesNotExist):
                return JsonResponse({'error': 'Record not found.', 'code': 'not_found'}, status=404)
            except (ValueError, TypeError, KeyError):
                return JsonResponse({'error': 'Invalid request fields.', 'code': 'invalid_fields'}, status=400)
            except Exception:
                logger.error('API failed correlation=%s', request.correlation_id)
                return JsonResponse({'error': 'Unexpected error. Share the reference with support.', 'code': 'internal_error', 'correlation_id': request.correlation_id}, status=500)
        return wrapped
    return decorate

@require_GET
def session(request):
    member = Member.objects.filter(user=request.user).first() if request.user.is_authenticated else None
    return JsonResponse({'csrf': get_token(request), 'mode': 'local' if settings.LOCAL else 'pilot',
        'auth_method': 'corporate' if settings.AUTH_MODE == 'corporate' else ('local_only' if settings.LOCAL else 'invited_password'),
        'user': {'id': request.user.pk, 'name': request.user.get_full_name() or request.user.username, 'role': member.role} if member else None})

@require_POST
def local_login(request):
    permitted = settings.AUTH_MODE == 'invited_password' and (settings.LOCAL or settings.PRIVATE_INGRESS_CONFIRMED)
    if not permitted or (settings.LOCAL and request.META.get('REMOTE_ADDR') not in ['127.0.0.1', '::1']):
        return JsonResponse({'error': 'Password sign-in is disabled for this configuration.', 'code': 'password_disabled'}, status=403)
    try:
        payload = body(request)
    except services.RuleError as exc:
        return JsonResponse({'error': exc.message}, status=exc.status)
    username, password = payload.get('username', ''), payload.get('password', '')
    if not isinstance(username, str) or not isinstance(password, str):
        return JsonResponse({'error': 'Invalid sign-in.'}, status=400)
    username = username.strip().casefold()
    if len(username) > 254 or len(password) > 1024:
        return JsonResponse({'error': 'Invalid sign-in.'}, status=400)
    # Account-wide throttling remains effective across different VPN source IPs.
    key = hashlib.sha256(username.encode()).hexdigest()
    attempt, _ = LoginAttempt.objects.get_or_create(key=key)
    if attempt.failures >= 5 and attempt.updated_at > timezone.now() - timedelta(minutes=15):
        return JsonResponse({'error': 'Too many attempts. Wait 15 minutes.', 'code': 'rate_limited'}, status=429)
    user = authenticate(request, username=username, password=password)
    if not user or not Member.objects.filter(user=user).exists():
        attempt.failures = attempt.failures + 1 if attempt.updated_at > timezone.now() - timedelta(minutes=15) else 1
        attempt.save()
        return JsonResponse({'error': 'Sign-in failed.', 'code': 'invalid_login'}, status=401)
    attempt.delete()
    login(request, user)
    services.record(user, 'signed_in')
    return session.__wrapped__(request)

@require_POST
def signout(request):
    logout(request)
    return JsonResponse({'ok': True})

@require_GET
def oidc_login(request):
    if settings.AUTH_MODE != 'corporate' or not settings.OIDC_METADATA:
        return JsonResponse({'error': 'Corporate login is not configured.'}, status=503)
    return oauth.corporate.authorize_redirect(request, settings.OIDC_REDIRECT_URI)

@require_GET
def oidc_callback(request):
    if settings.AUTH_MODE != 'corporate':
        return JsonResponse({'error': 'Corporate sign-in is deferred for this pilot.'}, status=403)
    try:
        token = oauth.corporate.authorize_access_token(request)
        claims = token.get('userinfo')
        if not claims or not claims.get('sub') or not claims.get('iss') or claims.get('email_verified') is not True:
            raise ValueError()
        email = claims.get('email', '')
        user = get_user_model().objects.get(email__iexact=email, is_active=True)
        with transaction.atomic():
            member = Member.objects.select_for_update().get(user=user)
            if member.oidc_subject and (member.oidc_subject != claims['sub'] or member.oidc_issuer != claims['iss']):
                raise ValueError()
            member.oidc_subject, member.oidc_issuer = claims['sub'], claims['iss']
            member.save()
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
        services.record(user, 'signed_in', method='corporate')
        return redirect('/')
    except Exception:
        # Token and provider exception text never enters logs.
        return JsonResponse({'error': 'Corporate sign-in failed or you are not invited.', 'code': 'oidc_denied'}, status=403)

def run_json(run):
    return {'id': str(run.id), 'commit': run.commit, 'status': run.status, 'created_at': run.created_at.isoformat(),
        'repository':run.repository, 'template':run.template,
        'build_number': run.build_number, 'requester': run.requester_id, 'artifact_sha256': run.artifact_sha256,
        'evidence': run.evidence, 'error_code': run.error_code}

def release_json(release):
    return {'id': str(release.id), 'run_id': str(release.run_id), 'status': release.status, 'plan': release.plan,
        'plan_digest': release.plan_digest, 'artifact_sha256': release.artifact_sha256,
        'creator': release.creator_id, 'approver': release.approver_id, 'operator': release.operator_id,
        'approval_expires_at': release.approval_expires_at.isoformat() if release.approval_expires_at else None,
        'deployment_result': release.deployment_result, 'created_at': release.created_at.isoformat()}

@require_GET
@api()
def dashboard(request):
    return JsonResponse({'project': services.PROJECT, 'jenkins_configured': all([settings.JENKINS_URL, settings.JENKINS_USER, settings.JENKINS_TOKEN]),
        'runs': [run_json(r) for r in Run.objects.order_by('-created_at')[:100]],
        'releases': [release_json(r) for r in Release.objects.order_by('-created_at')[:100]],
        'events': [{'action': e.action, 'object_id': e.object_id, 'created_at': e.created_at.isoformat(), 'actor': e.actor_id, 'detail': e.detail}
                   for e in Event.objects.order_by('-id')[:100]]})

@require_POST
@api(('developer', 'reviewer'))
def create_run(request):
    from .jenkins import Jenkins
    Jenkins() # fail visibly before queuing when no service credential exists
    payload = body(request)
    commit = payload.get('commit', '')
    if not services.valid_sha(commit, 40):
        raise services.RuleError('invalid_commit', 'Enter the full 40-character commit SHA.', 400)
    key = uuid.UUID(payload.get('request_key', ''))
    existing = Run.objects.filter(request_key=key).first()
    if existing:
        if existing.requester_id != request.user.id or existing.commit != commit:
            raise services.RuleError('idempotency_conflict', 'This request key belongs to another request.')
        return JsonResponse(run_json(existing))
    with transaction.atomic():
        if Run.objects.filter(status__in=['queued', 'trigger_pending', 'running', 'sync_required']).count() >= 4:
            raise services.RuleError('queue_full', 'Resolve active runs before starting another.')
        try:
            run = Run.objects.create(requester=request.user, commit=commit, request_key=key)
        except IntegrityError:
            raise services.RuleError('duplicate_request', 'Request already accepted. Refresh the run list.')
        services.record(request.user, 'build_requested', run.id, commit=commit)
    return JsonResponse(run_json(run), status=201)

@require_POST
@api(('developer', 'reviewer'))
def create_release(request):
    return JsonResponse(release_json(services.prepare_release(body(request)['run_id'], request.user)), status=201)

@require_POST
@api(('reviewer',))
def release_action(request, release_id, action):
    payload = body(request)
    if action in ['approve', 'reject']:
        if action == 'approve' and payload.get('acknowledged') is not True:
            raise services.RuleError('review_required', 'Acknowledge the deployment plan.', 400)
        release = services.decide(release_id, request.user, action == 'approve')
    elif action == 'begin':
        release = services.begin(release_id, request.user)
    elif action in ['result', 'reconcile']:
        release = services.finish(release_id, request.user, payload, reconcile=action == 'reconcile')
    elif action == 'reset':
        release = services.reset_approval(release_id, request.user)
    else:
        raise services.RuleError('unknown_action', 'Unknown release action.', 404)
    return JsonResponse(release_json(release))

@require_GET
@api()
def receipt(request, release_id):
    release = Release.objects.select_related('run').get(pk=release_id)
    services.check_binding(release)
    data = {'schema_version': 1, 'execution': release.plan.get('execution','supervised'), **release_json(release), 'run': run_json(release.run),
        'instructions': ['Use only the existing approved deployment procedure.',
            'Verify the artifact digest before executing. No AWS credentials belong in this receipt.',
            'Record HTTPS, login and readiness outcomes; uncertain results need reconciliation.']}
    response = JsonResponse(data, json_dumps_params={'indent': 2})
    response['Content-Disposition'] = 'attachment; filename="release-handoff.json"'
    return response

@require_GET
@api()
def artifact(request, run_id):
    from .jenkins import Jenkins
    run = Run.objects.get(pk=run_id)
    if run.status != 'ready' or not run.build_number:
        raise services.RuleError('not_ready', 'Verified build artifact is required.')
    client = Jenkins()
    report, actual = client.evidence(run.build_number)
    if actual != run.artifact_sha256:
        raise services.RuleError('digest_mismatch', 'Current Jenkins artifact differs from the recorded release.')
    response = client.request('GET', client.job + '/%d/artifact/reports/source.tar.gz' % run.build_number, stream=True)
    data = client.bytes(response, 100*1024*1024)
    if hashlib.sha256(data).hexdigest() != run.artifact_sha256:
        raise services.RuleError('digest_mismatch', 'Artifact changed while downloading.')
    services.record(request.user, 'artifact_downloaded', run.id, sha256=run.artifact_sha256)
    response = HttpResponse(data, content_type='application/gzip')
    response['Content-Disposition'] = 'attachment; filename="source.tar.gz"'
    return response

@require_POST
@api()
def feedback(request):
    value = body(request)
    rating, minutes = value.get('rating'), value.get('minutes')
    if type(rating) is not int or rating not in range(1, 6) or (minutes is not None and (type(minutes) is not int or not 0 <= minutes <= 1440)):
        raise services.RuleError('invalid_feedback', 'Rating must be 1–5 and minutes 0–1440.', 400)
    task, comment = value.get('task', ''), value.get('comment', '')
    if task not in ['build', 'review', 'deployment', 'overall'] or not isinstance(comment, str) or len(comment) > 1000:
        raise services.RuleError('invalid_feedback', 'Choose a task and keep feedback under 1000 characters.', 400)
    if any(token in comment for token in ['AKIA', 'ASIA', 'ghp_', 'github_pat_', 'AWS_SECRET_ACCESS_KEY']):
        raise services.RuleError('secret_in_feedback', 'Remove credentials from feedback.', 400)
    Feedback.objects.create(user=request.user, rating=rating, task=task, comment=comment, minutes=minutes)
    services.record(request.user, 'feedback_submitted', task=task)
    return JsonResponse({'ok': True}, status=201)

@require_GET
@api(('reviewer',))
def metrics(request):
    from django.db.models import Avg
    return JsonResponse({'invited_users': Member.objects.count(), 'build_requests': Run.objects.count(),
        'active_users': Event.objects.filter(actor__isnull=False).values('actor').distinct().count(),
        'release_attempts': Release.objects.count(), 'feedback_count': Feedback.objects.count(),
        'average_rating': Feedback.objects.aggregate(value=Avg('rating'))['value'],
        'average_reported_minutes': Feedback.objects.aggregate(value=Avg('minutes'))['value'],
        'note': 'Time saved and opportunity-based adoption require the separately recorded baseline.'})

@require_GET
def health(request):
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1')
    return JsonResponse({'status': 'ok'})

@require_GET
def index(request):
    path = settings.BASE_DIR.parent / 'dist' / 'client' / 'index.html'
    if not path.exists():
        return HttpResponse('Frontend build is not present.', status=503)
    return FileResponse(path.open('rb'), content_type='text/html')
