"""Private-controller protocol. No credentials belong in signed snapshots or receipts."""
import hashlib
import hmac
import json
import re
import time
import uuid

from .ecs_release import fingerprint
from .errors import RuleError

MAX_BODY = 65536


def reject():
    raise RuleError('controller_request_rejected', 'The controller request is invalid or expired.')


def canonical(value):
    try:
        content = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        if len(content) > MAX_BODY:
            reject()
        return content
    except (ValueError, TypeError):
        reject()


def sign(snapshot, key):
    if not isinstance(key, bytes) or len(key) < 32:
        reject()
    return hmac.new(key, b'releaseportal-controller-v1\x00' + canonical(snapshot), hashlib.sha256).hexdigest()


def validate_snapshot(snapshot, signature, key, profile, now=None):
    now = int(time.time()) if now is None else now
    if not isinstance(signature, str) or not hmac.compare_digest(sign(snapshot, key), signature):
        reject()
    fields = {'version', 'release_id', 'nonce', 'creator_id', 'reviewer_id', 'approved_at', 'expires_at',
              'issued_at', 'plan_digest', 'plan'}
    if not isinstance(snapshot, dict) or set(snapshot) != fields or snapshot['version'] != 1:
        reject()
    for field in ['release_id', 'nonce']:
        try:
            if str(uuid.UUID(snapshot[field])) != snapshot[field]:
                reject()
        except (ValueError, TypeError, AttributeError):
            reject()
    creator, reviewer = snapshot['creator_id'], snapshot['reviewer_id']
    if (not isinstance(creator, str) or not isinstance(reviewer, str) or
        not creator.isdecimal() or not reviewer.isdecimal() or creator == reviewer or
        creator not in profile['allowed_creator_ids'] or reviewer not in profile['allowed_reviewer_ids']):
        reject()
    if any(type(snapshot[k]) is not int for k in ['approved_at', 'issued_at', 'expires_at']):
        reject()
    if not (snapshot['approved_at'] <= snapshot['issued_at'] <= now + 15 and
            now - 120 <= snapshot['issued_at'] and now < snapshot['expires_at'] <= snapshot['approved_at'] + 1800):
        reject()
    plan = snapshot['plan']
    if not isinstance(plan, dict) or fingerprint(plan) != snapshot['plan_digest']:
        reject()
    if (plan.get('execution') != 'ecs-service-image-v1' or
        plan.get('repository') != profile['repository'] or plan.get('profile_sha256') != fingerprint(profile) or
        plan.get('target') != {k: profile[k] for k in ['account', 'region', 'service_arn']}):
        reject()
    # All plan fields are closed: arbitrary metadata could carry credentials to disk.
    if set(plan) != {'execution', 'repository', 'commit', 'source_sha256', 'artifact_sha256', 'image',
                     'profile_sha256', 'evidence_sha256', 'target', 'baseline_sha256', 'previous_image', 'scope'}:
        reject()
    for field, length in [('commit', 40), ('source_sha256', 64), ('artifact_sha256', 64),
                          ('profile_sha256', 64), ('evidence_sha256', 64), ('baseline_sha256', 64)]:
        if not isinstance(plan[field], str) or not re.fullmatch(r'[a-f0-9]{%d}' % length, plan[field]):
            reject()
    pattern = re.escape(profile['image_repository']) + r'@sha256:[a-f0-9]{64}'
    if any(not isinstance(plan[k], str) or not re.fullmatch(pattern, plan[k]) for k in ['image', 'previous_image']):
        reject()
    if plan['scope'] != 'Existing service image only; preserve runtime configuration. No schema migrations.':
        reject()
    return snapshot


def receipt(value):
    """Allow only safe controller-produced status fields into transport/storage."""
    fields = {'release_id', 'plan_digest', 'status', 'code', 'image', 'task_definition'}
    if not isinstance(value, dict) or set(value) - fields:
        reject()
    if value.get('status') not in ['accepted', 'updating', 'succeeded', 'failed', 'reconciliation_required']:
        reject()
    if not re.fullmatch(r'[a-z0-9_]{0,60}', value.get('code', '')):
        reject()
    return {k: v for k, v in value.items() if k in fields}
