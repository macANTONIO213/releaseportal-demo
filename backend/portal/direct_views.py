import json
import secrets
import uuid
from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.db import transaction
from django.http import JsonResponse, HttpResponse
from django.middleware.csrf import get_token
from django.shortcuts import redirect
from django.views.decorators.http import require_GET, require_POST
from . import views, services, github, direct_worker
from .models import Member, Run, Release, Event
from .memory import github_tokens
from .source import save_snapshot, read_artifact
from .roles import role_for

def visible(request, repository):
    github.client_for(request).repository(repository)

@require_GET
def session(request):
    if settings.AUTH_MODE != 'github':
        return views.session.__wrapped__(request)
    member = Member.objects.filter(user=request.user, github_id__isnull=False).first() if request.user.is_authenticated else None
    capability = request.session.get('github_capability', '')
    valid = member and role_for(member) and github_tokens.get(capability, request.user.id)
    return JsonResponse({'csrf':get_token(request),'mode':'local' if settings.LOCAL else 'pilot', 'auth_method':'github',
        'ingress_mode':settings.INGRESS_MODE, 'github_configured':github.configured(), 'user':{'id':request.user.id,'name':member.github_login,'role':role_for(member)} if valid else None})

@require_GET
def sign_in(request):
    if settings.AUTH_MODE != 'github':
        return views.oidc_login(request)
    try:
        return redirect(github.authorization(request))
    except services.RuleError as error:
        return JsonResponse({'error':error.message,'code':error.code}, status=error.status)

@require_GET
def callback(request):
    if settings.AUTH_MODE != 'github':
        return views.oidc_callback(request)
    try:
        token, ttl = github.exchange(request)
        client = github.GitHub(token)
        identity = client.identity()
        if settings.PUBLIC and str(identity['id']) not in settings.GITHUB_ALLOWED_USER_IDS:
            raise services.RuleError('account_not_approved', 'This GitHub identity is not approved for the public pilot.', 403)
        if not client.repositories():
            raise services.RuleError('no_authorized_repositories', 'No approved organization repositories are authorized for this app.',403)
        with transaction.atomic():
            member = Member.objects.select_for_update().filter(github_id=identity['id']).first()
            if member:
                user = member.user
                if not user.is_active:
                    raise services.RuleError('account_disabled','This pilot account is disabled.',403)
            else:
                user = get_user_model()(username='github-'+str(identity['id']))
                user.set_unusable_password()
                user.save()
                member = Member.objects.create(user=user, github_id=identity['id'], role='reviewer' if str(identity['id']) in settings.GITHUB_REVIEWER_IDS else 'developer')
            member.github_login = identity['login']
            member.save()
        github_tokens.remove(request.session.get('github_capability',''))
        login(request,user,backend='django.contrib.auth.backends.ModelBackend')
        request.session['github_capability'] = github_tokens.put(token, user.id, ttl=min(ttl,28800))
        services.record(user,'github_signed_in')
        return redirect('/')
    except services.RuleError as error:
        return JsonResponse({'error':error.message,'code':error.code},status=error.status)
    except Exception:
        return JsonResponse({'error':'GitHub login could not be completed.','code':'github_login_failed'},status=403)

@require_POST
def sign_out(request):
    github_tokens.remove(request.session.get('github_capability',''))
    logout(request)
    return JsonResponse({'ok':True})

@require_GET
@views.api()
def dashboard(request):
    if settings.AUTH_MODE != 'github':
        return views.dashboard.__wrapped__.__wrapped__(request)
    client = github.client_for(request)
    repositories = client.repositories()
    allowed_runs = Run.objects.filter(repository__in=repositories)
    allowed_releases = Release.objects.filter(run__repository__in=repositories)
    own_events = Event.objects.filter(actor=request.user).order_by('-id')[:100]
    return JsonResponse({'project':services.PROJECT,'repositories':repositories,'pipeline_configured':direct_worker.configured(),
        'deployment_configured':settings.AWS_DEPLOYMENT_ENABLED and settings.DEPLOYMENT_TEMPLATE_APPROVED,
        'runs':[views.run_json(r) for r in allowed_runs.order_by('-created_at')[:100]],
        'releases':[views.release_json(r) for r in allowed_releases.order_by('-created_at')[:100]],
        'events':[{'action':e.action,'object_id':e.object_id,'created_at':e.created_at.isoformat(),'actor':e.actor_id,'detail':e.detail} for e in own_events]})

@require_POST
@views.api(('developer','reviewer'))
def create_run(request):
    if settings.AUTH_MODE != 'github':
        return views.create_run.__wrapped__.__wrapped__(request)
    if not direct_worker.configured():
        raise services.RuleError('build_runtime_unconfigured','Configure the isolated build runtime before starting a pipeline.',503)
    payload = views.body(request)
    repository = github.parse_repository(payload.get('repository',''))
    commit = payload.get('commit','')
    if not services.valid_sha(commit,40):
        raise services.RuleError('invalid_commit','Enter the exact 40-character commit SHA.',400)
    key = uuid.UUID(payload.get('request_key',''))
    client = github.client_for(request)
    repository = client.repository(repository)['full_name']
    old = Run.objects.filter(request_key=key).first()
    if old:
        if old.requester_id != request.user.id or old.repository != repository or old.commit != commit:
            raise services.RuleError('idempotency_conflict','This receipt belongs to another request.')
        return JsonResponse(views.run_json(old))
    if Run.objects.filter(status__in=['fetching_source','queued','running']).count() >= 4:
        raise services.RuleError('queue_full','Four pipelines are already active.')
    run = Run.objects.create(requester=request.user,repository=repository,commit=commit,request_key=key,status='fetching_source')
    try:
        save_snapshot(run,client.snapshot(repository,commit))
        run.status='queued'
        run.save(update_fields=['status'])
        services.record(request.user,'direct_build_requested',run.id,repository=repository,commit=commit)
    except services.RuleError as error:
        run.status,run.error_code='failed',error.code
        run.save(update_fields=['status','error_code'])
        raise
    except Exception:
        run.status,run.error_code='failed','snapshot_interrupted'
        run.save(update_fields=['status','error_code'])
        raise services.RuleError('snapshot_interrupted','Source fetch was interrupted. Start a new run after checking its status.',502)
    return JsonResponse(views.run_json(run),status=201)

@require_POST
@views.api(('developer','reviewer'))
def create_release(request):
    payload = views.body(request)
    run = Run.objects.get(pk=payload['run_id'])
    if settings.AUTH_MODE == 'github':
        visible(request,run.repository)
        if run.repository != services.PROJECT['repository']:
            raise services.RuleError('deployment_template_unsupported','This repository needs a reviewed deployment profile before AWS deployment.')
    return JsonResponse(views.release_json(services.prepare_release(run.id,request.user)),status=201)

@require_POST
@views.api(('developer','reviewer'))
def action(request, release_id, action):
    release = Release.objects.select_related('run').get(pk=release_id)
    if settings.AUTH_MODE == 'github':
        visible(request,release.run.repository)
        if action == 'deploy':
            member = Member.objects.get(user=request.user)
            if request.user.id != release.creator_id and role_for(member) != 'reviewer':
                raise services.RuleError('forbidden','Only the release creator or a reviewer can execute this release.',403)
            from .deployment import accept_deployment
            result = accept_deployment(request,release,views.body(request))
            return JsonResponse(result,status=202)
    return views.release_action.__wrapped__(request,release_id,action)

@require_GET
@views.api()
def artifact(request,run_id):
    if settings.AUTH_MODE != 'github':
        return views.artifact.__wrapped__.__wrapped__(request,run_id)
    run = Run.objects.get(pk=run_id)
    visible(request,run.repository)
    if run.status != 'ready':
        raise services.RuleError('not_ready','Passing evidence is required before artifact download.')
    response = HttpResponse(read_artifact(run),content_type='application/gzip')
    response['Content-Disposition']='attachment; filename="source.tar.gz"'
    return response

@require_GET
@views.api()
def receipt(request,release_id):
    release = Release.objects.select_related('run').get(pk=release_id)
    if settings.AUTH_MODE == 'github':
        visible(request,release.run.repository)
    return views.receipt.__wrapped__.__wrapped__(request,release_id)
