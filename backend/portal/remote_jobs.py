"""Private object/queue adapters for the reviewed remote runner. Not activated by import."""
import hashlib
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid
import zlib

from .controller_contract import canonical, sign
from .errors import RuleError


def decode_configuration(value):
    if not isinstance(value,str) or len(value.encode())>1024*1024:
        raise ValueError('Invalid configuration size')
    if value.startswith('zlib:'):
        decoder=zlib.decompressobj()
        raw=decoder.decompress(base64.b64decode(value[5:],validate=True),1024*1024+1)
        if len(raw)>1024*1024 or not decoder.eof or decoder.unconsumed_tail or decoder.unused_data:
            raise ValueError('Invalid compressed configuration')
        return json.loads(raw)
    return json.loads(value)


def run_id(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError('Invalid run identifier')
    return value


def job(run, repository, commit, source_sha256, profile_sha256):
    value = {'version': 1, 'run_id': run_id(run), 'repository': repository, 'commit': commit,
             'source_sha256': source_sha256, 'profile_sha256': profile_sha256}
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or
        not re.fullmatch(r'[a-f0-9]{40}', commit) or
        any(not re.fullmatch(r'[a-f0-9]{64}', v) for v in [source_sha256, profile_sha256])):
        raise ValueError('Invalid job identity')
    return value


def validate_job(value, profile):
    if not isinstance(value, dict) or set(value) != {'version','run_id','repository','commit','source_sha256','profile_sha256'}:
        raise ValueError('Unexpected job fields')
    if type(value.get('version')) is not int or value != job(value['run_id'], value['repository'], value['commit'], value['source_sha256'], value['profile_sha256']):
        raise ValueError('Invalid job')
    from .ecs_release import fingerprint
    if value['repository'] != profile['repository'] or value['profile_sha256'] != fingerprint(profile):
        raise ValueError('Unreviewed repository or profile')
    return value


class RoleCLI:
    """Explicit workload role mode, no operator profile or developer credentials."""
    OPERATIONS = {'s3api': {'put-object', 'get-object'}, 'sqs': {'send-message', 'receive-message',
        'delete-message', 'change-message-visibility'}}

    def __init__(self, executable, region, mode, run=subprocess.run):
        if mode not in ['web', 'worker'] or not re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]', region):
            raise ValueError('Explicit workload mode/region required')
        self.executable, self.region, self.run = str(executable), region, run
        self.env = {k: v for k, v in os.environ.items() if k in ['PATH','SYSTEMROOT','WINDIR','LANG','SSL_CERT_FILE']}
        self.env.update(AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull,
            AWS_MAX_ATTEMPTS='1', AWS_RETRY_MODE='standard', AWS_PAGER='', AWS_CLI_AUTO_PROMPT='off')
        if mode == 'web':
            uri = os.environ.get('AWS_CONTAINER_CREDENTIALS_RELATIVE_URI', '')
            if not re.fullmatch(r'/v2/credentials/[A-Za-z0-9-]+', uri):
                raise ValueError('Explicit ECS task-role credential endpoint required')
            self.env.update(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=uri, AWS_EC2_METADATA_DISABLED='true')
        else:
            # Only the assigned EC2 workload role; IMDSv2 is enforced by instance options.
            self.env.update(AWS_EC2_METADATA_DISABLED='false', AWS_EC2_METADATA_V1_DISABLED='true')

    def call(self, service, operation, params, output=None, body=None):
        if operation not in self.OPERATIONS.get(service, set()):
            raise ValueError('Unapproved workload operation')
        args = [self.executable, service, operation, '--region', self.region, '--output', 'json',
                '--no-cli-pager', '--cli-input-json', json.dumps(params, separators=(',', ':'))]
        if output is not None:
            if (service, operation) != ('s3api', 'get-object'):
                raise ValueError('Unexpected output file')
            args.append(str(output))
        if body is not None:
            if (service, operation) != ('s3api', 'put-object'):
                raise ValueError('Unexpected input file')
            args.extend(['--body', str(body)])
        try:
            result = self.run(args, env=self.env, capture_output=True, text=True, encoding='utf-8', timeout=120)
            if result.returncode or len(result.stdout) > 1024 * 1024:
                raise ValueError()
            return json.loads(result.stdout or '{}')
        except Exception:
            raise RuleError('workload_outcome_unknown', 'The object/queue operation requires reconciliation.') from None


class Artifacts:
    FILES = {'source.tar.gz': 100*1024*1024, 'release.tar.gz': 100*1024*1024,
             'release-evidence.json': 1024*1024, 'status.json': 65536}

    def __init__(self, cli, bucket, account):
        if not re.fullmatch(r'[a-z0-9][a-z0-9-]{2,62}', bucket) or not re.fullmatch(r'[0-9]{12}', account):
            raise ValueError('Explicit private bucket/account required')
        self.cli, self.bucket, self.account = cli, bucket, account

    def key(self, run, name):
        if name not in self.FILES:
            raise ValueError('Unsupported run object')
        return 'runs/' + run_id(run) + '/' + name

    def put(self, run, name, content):
        key = self.key(run, name)
        if not isinstance(content, bytes) or not 0 < len(content) <= self.FILES[name]:
            raise ValueError('Object exceeds bounds')
        # This is the source/report/artifact only, never temporary credentials or GitHub token.
        with tempfile.TemporaryDirectory(prefix='releaseportal-object-') as temporary:
            path = Path(temporary) / name
            path.write_bytes(content)
            self.cli.call('s3api', 'put-object', {'Bucket': self.bucket, 'Key': key,
                'ExpectedBucketOwner': self.account}, body=path)
        return hashlib.sha256(content).hexdigest()

    def get(self, run, name, expected_sha256=None):
        key = self.key(run, name)
        with tempfile.TemporaryDirectory(prefix='releaseportal-object-') as temporary:
            path = Path(temporary) / name
            self.cli.call('s3api', 'get-object', {'Bucket': self.bucket, 'Key': key,
                'ExpectedBucketOwner': self.account}, output=path)
            if not path.is_file() or path.stat().st_size > self.FILES[name]:
                raise RuleError('invalid_remote_artifact', 'Remote artifact exceeds its bounds.')
            content = path.read_bytes()
        if expected_sha256 and hashlib.sha256(content).hexdigest() != expected_sha256:
            raise RuleError('digest_mismatch', 'Remote artifact differs from the reviewed digest.')
        return content


class Queue:
    def __init__(self, cli, url, account, name):
        expected = f'https://sqs.{cli.region}.amazonaws.com/{account}/{name}'
        if url != expected or not re.fullmatch(r'[0-9]{12}', account):
            raise ValueError('Exact reviewed queue URL required')
        self.cli, self.url = cli, url

    def send(self, value):
        # Closed job schema: credentials cannot accidentally enter the queue body.
        if type(value.get('version')) is not int or value != job(value['run_id'], value['repository'], value['commit'], value['source_sha256'], value['profile_sha256']):
            raise ValueError('Invalid job schema')
        return self.cli.call('sqs', 'send-message', {'QueueUrl': self.url, 'MessageBody': canonical(value).decode()})

    def receive(self):
        result = self.cli.call('sqs', 'receive-message', {'QueueUrl': self.url, 'MaxNumberOfMessages': 1,
            'VisibilityTimeout': 1800, 'WaitTimeSeconds': 20})
        messages = result.get('Messages', [])
        if len(messages) > 1:
            raise ValueError('Only one active build is supported')
        return messages

    def visibility(self, handle):
        return self.cli.call('sqs', 'change-message-visibility', {'QueueUrl': self.url,
            'ReceiptHandle': handle, 'VisibilityTimeout': 1800})

    def delete(self, handle):
        return self.cli.call('sqs', 'delete-message', {'QueueUrl': self.url, 'ReceiptHandle': handle})


def signed_status(value, key):
    """Bounded trusted-host status, independently authenticated from guest output."""
    if set(value) != {'run_id','source_sha256','profile_sha256','status','code','evidence_sha256','artifact_sha256','image'}:
        raise ValueError('Invalid host status fields')
    run_id(value['run_id'])
    if value['status'] not in ['running','failed','ready','reconciliation_required']:
        raise ValueError('Invalid host state')
    if not re.fullmatch(r'[a-z0-9_]{0,60}', value['code']):
        raise ValueError('Invalid host status code')
    for name in ['source_sha256','profile_sha256','evidence_sha256','artifact_sha256']:
        if not re.fullmatch(r'[a-f0-9]{64}|', value[name]):
            raise ValueError('Invalid host digest')
    if value['image'] and not re.fullmatch(r'[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-z0-9/-]+@sha256:[a-f0-9]{64}', value['image']):
        raise ValueError('Invalid image receipt')
    return {'status': value, 'signature': sign({'action': 'runner_status', 'status': value}, key)}


def safe_report(report):
    """Project guest results to bounded numeric/status fields; discard all raw output."""
    result={k:report.get(k) for k in ['schema_version','repository','commit','source_sha256','profile_sha256',
                                    'artifact_sha256','image','error_code']}
    if type(result['schema_version']) is not int or result['schema_version'] != 1:
        raise ValueError('Unsupported report')
    if not isinstance(result['error_code'],str) or not re.fullmatch(r'[a-z0-9_]{0,60}',result['error_code']):
        raise ValueError('Unsafe error code')
    result['tests']={}
    for name in ['passed','failed','skipped','total']:
        count=report.get('tests',{}).get(name)
        if type(count) is not int or not 0 <= count <= 1000000:
            raise ValueError('Invalid test count')
        result['tests'][name]=count
    result['scans']={}
    for name in ['source','dependencies','secrets']:
        scan=report.get('scans',{}).get(name,{})
        if scan.get('status') not in ['passed','failed','not_run']:
            raise ValueError('Invalid scan state')
        result['scans'][name]={'status':scan['status']}
        for field in ['findings','reviewed_findings','total_findings']:
            if field not in scan and field!='findings':
                continue
            count=scan.get(field)
            if type(count) is not int or not 0 <= count <= 1000000:
                raise ValueError('Invalid finding count')
            result['scans'][name][field]=count
        if 'reviewed_findings' in scan and (scan.get('total_findings') != scan['reviewed_findings']+scan['findings']):
            raise ValueError('Inconsistent reviewed finding counts')
    image_scan=report.get('image_scan',{})
    result['image_scan']={k:image_scan.get(k) for k in ['status','high','critical']}
    return result
