"""Pure reviewed-plan contracts. No AWS execution or feature activation."""
import copy
import hashlib
import json
import re

from .errors import RuleError


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def reject():
    raise RuleError('ecs_plan_mismatch', 'The source, image or existing service changed. Prepare a new reviewed release.')


def state(profile, service):
    if service.get('serviceArn') != profile['service_arn']:
        reject()
    configurations = service.get('activeConfigurations', [])
    if len(configurations) != 1:
        reject()
    config = configurations[0]
    allowed = {'image', 'containerPort', 'command', 'environment', 'secrets', 'awsLogsConfiguration'}
    if set(config['primaryContainer']) - allowed:
        reject()
    keys = ['executionRoleArn', 'taskRoleArn', 'networkConfiguration', 'cpu', 'memory',
            'healthCheckPath', 'scalingTarget', 'primaryContainer']
    return {key: copy.deepcopy(config[key]) for key in keys if key in config}


def image_pattern(profile):
    return re.escape(profile['image_repository']) + r'@sha256:[a-f0-9]{64}'


def make_plan(profile, service, commit, source_sha256, artifact_sha256, image, evidence):
    """Profile is trusted server configuration, never repository/job input."""
    account, region = profile['account'], profile['region']
    if (not re.fullmatch(r'[0-9]{12}', account) or
        not profile['service_arn'].startswith(f'arn:aws:ecs:{region}:{account}:service/') or
        not profile['image_repository'].startswith(f'{account}.dkr.ecr.{region}.amazonaws.com/')):
        reject()
    if (not re.fullmatch(r'[a-f0-9]{40}', commit) or
        any(not re.fullmatch(r'[a-f0-9]{64}', value) for value in [source_sha256, artifact_sha256])):
        reject()
    if not re.fullmatch(image_pattern(profile), image):
        reject()
    if (evidence.get('repository') != profile['repository'] or evidence.get('commit') != commit or
        evidence.get('error_code') != ''):
        reject()
    if (evidence.get('source_sha256') != source_sha256 or evidence.get('artifact_sha256') != artifact_sha256 or
        evidence.get('profile_sha256') != fingerprint(profile)):
        reject()
    image_scan = evidence.get('image_scan', {})
    if (evidence.get('image') != image or image_scan.get('status') != 'COMPLETE' or
        any(type(image_scan.get(k)) is not int or image_scan[k] != 0 for k in ['high', 'critical'])):
        reject()
    tests = evidence.get('tests', {})
    if (any(type(tests.get(k)) is not int or tests[k] < 0 for k in ['passed', 'failed', 'skipped', 'total']) or
        tests['total'] < 1 or tests['failed'] != 0 or tests['passed'] < 1 or
        tests['passed'] + tests['failed'] + tests['skipped'] != tests['total']):
        reject()
    for name in ['source', 'dependencies', 'secrets']:
        scan = evidence.get('scans', {}).get(name, {})
        if scan.get('status') != 'passed' or type(scan.get('findings')) is not int or scan['findings'] != 0:
            reject()
    before = state(profile, service)
    if not re.fullmatch(image_pattern(profile), before['primaryContainer']['image']):
        reject()
    return {'execution': 'ecs-service-image-v1', 'repository': profile['repository'], 'commit': commit,
        'source_sha256': source_sha256, 'artifact_sha256': artifact_sha256, 'image': image, 'profile_sha256': fingerprint(profile),
        'evidence_sha256': fingerprint(evidence), 'target': {'account': account, 'region': region,
        'service_arn': profile['service_arn']}, 'baseline_sha256': fingerprint(before),
        'previous_image': before['primaryContainer']['image'],
        'scope': 'Existing service image only; preserve runtime configuration. No schema migrations.'}


def update_request(profile, plan, approved_digest, service):
    if fingerprint(plan) != approved_digest or plan.get('profile_sha256') != fingerprint(profile):
        reject()
    if plan.get('execution') != 'ecs-service-image-v1' or plan.get('target') != {
            'account': profile['account'], 'region': profile['region'], 'service_arn': profile['service_arn']}:
        reject()
    if not re.fullmatch(image_pattern(profile), plan.get('image', '')):
        reject()
    before = state(profile, service)
    if fingerprint(before) != plan['baseline_sha256']:
        reject()
    container = before['primaryContainer']
    container['image'] = plan['image']
    return {'serviceArn': profile['service_arn'], 'primaryContainer': container}
