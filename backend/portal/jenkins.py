import hashlib
import json
import re
from urllib.parse import quote, urlparse
import requests
from django.conf import settings
from .services import RuleError

class Jenkins:
    def __init__(self):
        if not all([settings.JENKINS_URL, settings.JENKINS_USER, settings.JENKINS_TOKEN]):
            raise RuleError('jenkins_unconfigured', 'Jenkins service authentication is not configured.', 503)
        self.base = settings.JENKINS_URL.rstrip('/')
        self.job = '/job/' + '/job/'.join(quote(part, safe='') for part in settings.JENKINS_JOB.split('/'))
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.auth = (settings.JENKINS_USER, settings.JENKINS_TOKEN)

    def request(self, method, path, **kwargs):
        try:
            response = self.session.request(method, self.base + path, timeout=(5, 30), allow_redirects=False, **kwargs)
            if response.status_code not in [200, 201, 202]:
                raise RuleError('jenkins_http_error', 'Jenkins rejected this operation; check service permissions.', 502)
            return response
        except requests.RequestException:
            raise RuleError('jenkins_unavailable', 'Jenkins is unavailable. Retry synchronization; do not blindly repeat a build trigger.', 502)

    def json(self, path, limit=1024*1024):
        response = self.request('GET', path, stream=True)
        data = self.bytes(response, limit)
        try:
            return json.loads(data)
        except (ValueError, UnicodeError):
            raise RuleError('invalid_jenkins_response', 'Jenkins returned invalid metadata.', 502)

    @staticmethod
    def bytes(response, limit):
        chunks, length = [], 0
        try:
            for chunk in response.iter_content(65536):
                length += len(chunk)
                if length > limit:
                    raise RuleError('report_too_large', 'Upstream artifact exceeds the configured limit.', 502)
                chunks.append(chunk)
        finally:
            response.close()
        return b''.join(chunks)

    def trigger(self, run):
        # Service API tokens support Jenkins API authentication; never use a user session cookie.
        response = self.request('POST', self.job + '/buildWithParameters', data={'COMMIT_SHA': run.commit, 'PORTAL_RUN_ID': str(run.id)})
        location = response.headers.get('Location', '')
        parsed, base = urlparse(location), urlparse(self.base)
        if (parsed.scheme, parsed.netloc) != (base.scheme, base.netloc):
            raise RuleError('queue_unknown', 'Build may have started; queue receipt needs reconciliation.', 502)
        match = re.fullmatch(re.escape(base.path.rstrip('/')) + r'/queue/item/(\d+)/?', parsed.path)
        if not match:
            raise RuleError('queue_unknown', 'Build may have started; queue receipt needs reconciliation.', 502)
        return int(match.group(1))

    def queue(self, queue_id):
        return self.json('/queue/item/%d/api/json' % queue_id)

    def build(self, number):
        return self.json(self.job + '/%d/api/json' % number)

    def evidence(self, number):
        path = self.job + '/%d/artifact/reports/' % number
        response = self.request('GET', path + 'release-evidence.json', stream=True)
        try:
            evidence = json.loads(self.bytes(response, 1024*1024))
        except (ValueError, UnicodeError):
            raise RuleError('invalid_evidence', 'Build report is not valid JSON.', 502)
        response = self.request('GET', path + 'source.tar.gz', stream=True)
        artifact = self.bytes(response, 100*1024*1024)
        actual = hashlib.sha256(artifact).hexdigest()
        if evidence.get('artifact', {}).get('bytes') != len(artifact):
            raise RuleError('artifact_size_mismatch', 'Artifact size does not match evidence.', 502)
        return evidence, actual
