import hashlib
import re
import threading
import time
from dataclasses import dataclass, field
from django.conf import settings
from django.db import close_old_connections, transaction
from django.utils import timezone
from .models import Release
from .services import RuleError, check_binding, record, digest
from .source import read_artifact

@dataclass(repr=False)
class Credentials:
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    session_token: str = field(repr=False)
    def erase(self):
        self.access_key_id = self.secret_access_key = self.session_token = ''

def script_bytes():
    return (settings.BASE_DIR.parent/'deploy/update-assessment.sh').read_bytes()

def template_hash():
    return hashlib.sha256(script_bytes()).hexdigest()

def plan(run):
    return {'execution':'direct','target':dict(settings.AWS_TARGET), 'template_sha256':template_hash(),
        'operations':['s3:PutObject (recorded bucket/app.tar.gz; expected owner enforced)',
            'ssm:SendCommand (AWS-RunShellScript; recorded instance only)',
            'ssm:GetCommandInvocation (returned command ID only)'],
        'changes':['Upload the exact tested artifact','Back up existing demo SQLite database',
            'Apply migrations and change application working directory','Restart existing application/worker services'],
        'identity_proof':'Target selected from recorded profile; no independent STS identity proof',
        'scope':'Update existing Demo application only. Dependencies, URL, network and IAM cannot be changed.'}

def accept_deployment(request, release, value):
    if not request.is_secure():
        raise RuleError('https_required','AWS credential entry requires HTTPS, including on a local preview.',400)
    if not settings.AWS_DEPLOYMENT_ENABLED or not settings.DEPLOYMENT_TEMPLATE_APPROVED:
        raise RuleError('deployment_not_configured','The target update template must be reviewed and enabled first.',503)
    if value.get('plan_digest') != release.plan_digest or value.get('confirmed') is not True:
        raise RuleError('plan_not_confirmed','Confirm the exact reviewed deployment plan.',400)
    key, secret, token = (value.get(k,'') for k in ['access_key_id','secret_access_key','session_token'])
    if not all(isinstance(v,str) for v in [key,secret,token]) or not re.fullmatch(r'ASIA[A-Z0-9]{16}',key) or not re.fullmatch(r'[A-Za-z0-9/+=]{40}',secret) or not re.fullmatch(r'[A-Za-z0-9/+=]{16,20000}',token):
        raise RuleError('invalid_credentials','Supply all three temporary AWS values without SET prefixes.',400)
    credentials = Credentials(key,secret,token)
    try:
        artifact = read_artifact(release.run)
        with transaction.atomic():
            from django.db import connection
            if connection.vendor == 'postgresql':
                with connection.cursor() as cursor:
                    cursor.execute('SELECT pg_advisory_xact_lock(%s)',[111122223333])
            release = Release.objects.select_for_update().select_related('run').get(pk=release.id)
            check_binding(release)
            if value.get('plan_digest') != release.plan_digest:
                raise RuleError('plan_changed','The reviewed plan changed before execution.')
            if release.status != 'approved' or not release.approval_expires_at or release.approval_expires_at <= timezone.now():
                raise RuleError('approval_expired','A current approval is required.')
            if release.plan.get('execution') != 'direct' or release.plan.get('target') != settings.AWS_TARGET or release.plan.get('template_sha256') != template_hash():
                raise RuleError('template_changed','The target or update template changed. Prepare a new reviewed release.')
            if Release.objects.filter(status__in=['deploying','reconciliation_required','awaiting_operator_result']).exclude(pk=release.id).exists():
                raise RuleError('environment_busy','Resolve the active or uncertain deployment first.')
            release.status,release.operator='deploying',request.user
            release.save()
            record(request.user,'direct_deployment_started',release.id,plan_digest=release.plan_digest)
        thread = threading.Thread(target=execute,args=(str(release.id),credentials,artifact),daemon=True,name='trusted-deployment')
        thread.start()
        return {'id':str(release.id),'status':'deploying','credentials_persisted':False}
    except Exception:
        credentials.erase()
        raise

def execute(release_id, credentials, artifact, session_factory=None, sleep=time.sleep):
    close_old_connections()
    command_id = None
    try:
        import boto3
        from botocore.config import Config
        release = Release.objects.select_related('run').get(pk=release_id)
        check_binding(release)
        if release.status != 'deploying' or release.plan.get('template_sha256') != template_hash() or release.plan.get('target') != settings.AWS_TARGET:
            raise RuleError('template_changed','Deployment input changed.')
        target = settings.AWS_TARGET
        if hashlib.sha256(artifact).hexdigest() != release.artifact_sha256:
            raise RuleError('digest_mismatch','Deployment bytes do not match the reviewed artifact.')
        factory = session_factory or boto3.Session
        session = factory(aws_access_key_id=credentials.access_key_id,aws_secret_access_key=credentials.secret_access_key,
            aws_session_token=credentials.session_token,region_name=target['region'])
        config = Config(retries={'total_max_attempts':1},connect_timeout=5,read_timeout=30)
        s3,ssm = session.client('s3',config=config),session.client('ssm',config=config)
        s3.put_object(Bucket=target['bucket'],Key=target['key'],Body=artifact,ExpectedBucketOwner=target['account'],ServerSideEncryption='AES256')
        record(release.operator,'artifact_uploaded',release.id,sha256=release.artifact_sha256)
        script = script_bytes().decode().replace('__BUCKET__',target['bucket']).replace('__DIGEST__',release.artifact_sha256)
        response = ssm.send_command(InstanceIds=[target['instance']],DocumentName='AWS-RunShellScript',
            Comment='ReleasePortal reviewed update '+str(release.id),Parameters={'commands':[script],'executionTimeout':['900']})
        command_id = response['Command']['CommandId']
        if not re.fullmatch(r'[a-f0-9-]{36}',command_id):
            raise RuleError('invalid_command_receipt','SSM command receipt is invalid.')
        Release.objects.filter(pk=release_id).update(deployment_result={'command_id':command_id,'evidence_source':'aws_command_receipt'})
        record(release.operator,'ssm_command_submitted',release.id,command_id=command_id)
        for _ in range(120):
            sleep(5)
            try:
                result = ssm.get_command_invocation(CommandId=command_id,InstanceId=target['instance'])
            except Exception as lookup_error:
                if getattr(lookup_error,'response',{}).get('Error',{}).get('Code') == 'InvocationDoesNotExist':
                    continue
                raise
            if result['Status'] in ['Pending','InProgress','Delayed']:
                continue
            if result['Status'] != 'Success':
                raise RuleError('command_failed','Update requires operator reconciliation.')
            # Do not capture/log command output (it can contain app secrets).
            import requests
            checks = []
            for path in ['/health/','/accounts/login/']:
                http = requests.get(target['application_url']+path,timeout=(5,20),allow_redirects=False)
                checks.append(http.status_code == 200)
            if not all(checks):
                raise RuleError('verification_failed','Health/login page verification failed.')
            receipt={'command_id':command_id,'artifact_sha256':release.artifact_sha256,'plan_digest':release.plan_digest,
                'health_and_login_page':True,'authenticated_login_verified':False,'application_url':target['application_url'],
                'evidence_source':'aws_receipt_and_http_checks','recorded_at':timezone.now().isoformat()}
            Release.objects.filter(pk=release_id).update(status='deployed',deployment_result=receipt)
            record(release.operator,'deployment_checked',release.id,command_id=command_id)
            return
        raise RuleError('command_timeout','SSM outcome requires reconciliation.')
    except Exception as error:
        code = error.code if isinstance(error,RuleError) else 'aws_operation_failed'
        # No raw exception, credential, request body, SDK response or shell output is retained.
        Release.objects.filter(pk=release_id).update(status='reconciliation_required',deployment_result={
            'error_code':code,'command_id':command_id,'credentials_persisted':False})
        record(None,'direct_deployment_needs_reconciliation',release_id,code=code,command_id=command_id)
    finally:
        credentials.erase()
        close_old_connections()
