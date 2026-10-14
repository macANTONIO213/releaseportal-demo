import base64
import hashlib
import json
import re
import secrets
import time
from urllib.parse import urlencode, urlparse
import requests
from django.conf import settings
from .memory import github_tokens
from .services import RuleError

def parse_repository(value):
    if not isinstance(value, str):
        raise RuleError('invalid_repository', 'Enter an approved GitHub repository.', 400)
    value = value.strip().removesuffix('.git').rstrip('/')
    if value.startswith('https://github.com/'):
        value = value[len('https://github.com/'):]
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', value) or any(x in ['.', '..'] for x in value.split('/')):
        raise RuleError('invalid_repository', 'Use https://github.com/OWNER/REPO.', 400)
    if value.split('/')[0].casefold() not in [x.casefold() for x in settings.GITHUB_ORGANIZATIONS]:
        raise RuleError('organization_not_allowed', 'This organization is outside the approved pilot.', 403)
    return value

def configured():
    return bool(settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET and settings.GITHUB_REDIRECT_URI)

def authorization(request):
    if not configured():
        raise RuleError('github_unconfigured', 'Register and configure the approved GitHub App first.', 503)
    verifier = secrets.token_urlsafe(64)
    state = secrets.token_urlsafe(32)
    request.session['github_oauth'] = {'state': state, 'verifier': verifier, 'time': time.time()}
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b'=').decode()
    return 'https://github.com/login/oauth/authorize?' + urlencode({'client_id': settings.GITHUB_CLIENT_ID,
        'redirect_uri': settings.GITHUB_REDIRECT_URI, 'state': state, 'code_challenge': challenge, 'code_challenge_method': 'S256'})

def exchange(request):
    saved = request.session.pop('github_oauth', None)
    if not saved or time.time()-saved['time'] > 600 or not secrets.compare_digest(saved['state'], request.GET.get('state', '')):
        raise RuleError('oauth_state_invalid', 'GitHub sign-in expired or state was invalid.', 403)
    code = request.GET.get('code', '')
    if not code or len(code) > 300:
        raise RuleError('oauth_code_invalid', 'GitHub did not return a valid authorization code.', 403)
    try:
        transport = requests.Session()
        transport.trust_env = False
        response = transport.post('https://github.com/login/oauth/access_token', json={
            'client_id': settings.GITHUB_CLIENT_ID, 'client_secret': settings.GITHUB_CLIENT_SECRET,
            'code': code, 'redirect_uri': settings.GITHUB_REDIRECT_URI, 'code_verifier': saved['verifier']},
            headers={'Accept': 'application/json'}, timeout=(5,20), allow_redirects=False)
        response.raise_for_status()
        token = response.json()
        if not isinstance(token.get('access_token'), str) or not 0 < token.get('expires_in', 0) <= 28800:
            raise ValueError()
        return token['access_token'], token['expires_in']
    except Exception:
        raise RuleError('github_exchange_failed', 'GitHub authorization failed. Check approved app configuration.', 403)

class GitHub:
    def __init__(self, token, login=None, user_id=None):
        self.token = token
        self.login,self.user_id = login,user_id
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({'Authorization': 'Bearer '+token, 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version':'2022-11-28'})

    def get(self, path):
        try:
            response = self.session.get('https://api.github.com'+path, timeout=(5,20), allow_redirects=False)
            if response.status_code != 200:
                raise ValueError()
            return response.json()
        except Exception:
            raise RuleError('github_access_denied', 'GitHub access is unavailable. Check app installation, SSO authorization and repository permissions.', 403)

    def identity(self):
        user = self.get('/user')
        if type(user.get('id')) is not int or not re.fullmatch(r'[A-Za-z0-9-]{1,100}', user.get('login', '')):
            raise RuleError('invalid_github_identity', 'GitHub identity could not be verified.', 403)
        self.login,self.user_id = user['login'],user['id']
        return user

    def repositories(self):
        repos = []
        installations = self.get('/user/installations?per_page=100').get('installations', [])
        for installation in installations[:20]:
            if installation.get('account', {}).get('login', '').casefold() not in [x.casefold() for x in settings.GITHUB_ORGANIZATIONS]:
                continue
            for page in range(1, 6):
                items = self.get('/user/installations/%d/repositories?per_page=100&page=%d' % (installation['id'], page)).get('repositories', [])
                repos += [r['full_name'] for r in items if r.get('owner',{}).get('login','').casefold() in [x.casefold() for x in settings.GITHUB_ORGANIZATIONS]]
                if len(items) < 100:
                    break
        return sorted(set(repos))

    def repository(self, name):
        name = parse_repository(name)
        if name.casefold() not in [r.casefold() for r in self.repositories()]:
            raise RuleError('installation_scope_denied', 'This repository is not authorized for your GitHub App installation.', 403)
        repo = self.get('/repos/'+name)
        if repo.get('full_name', '').casefold() != name.casefold() or repo.get('archived') or repo.get('disabled'):
            raise RuleError('repository_unavailable', 'Repository is unavailable for pipeline execution.', 403)
        if not self.login:
            self.identity()
        permission = self.get('/repos/'+name+'/collaborators/'+self.login+'/permission')
        if permission.get('user',{}).get('id') != self.user_id or permission.get('permission') not in ['read','write','admin','maintain']:
            raise RuleError('collaborator_required','Repository ownership or collaborator/team permission is required.',403)
        return repo

    def snapshot(self, name, commit):
        self.repository(name)
        result = self.get('/repos/'+name+'/commits/'+commit)
        if result.get('sha') != commit:
            raise RuleError('revision_mismatch', 'GitHub did not resolve the requested exact commit.')
        try:
            response = self.session.get('https://api.github.com/repos/'+name+'/tarball/'+commit, timeout=(5,20), allow_redirects=False)
            if response.status_code != 302:
                raise ValueError()
            location = response.headers['Location']
            parsed = urlparse(location)
            if parsed.scheme != 'https' or parsed.hostname != 'codeload.github.com' or parsed.username or parsed.password:
                raise ValueError()
            # Signed codeload URL is used only in memory. Authorization header is not forwarded.
            transport = requests.Session()
            transport.trust_env = False
            download = transport.get(location, timeout=(5,30), stream=True, allow_redirects=False)
            if download.status_code != 200:
                raise ValueError()
            data = bytearray()
            try:
                for chunk in download.iter_content(65536):
                    data.extend(chunk)
                    if len(data) > 100*1024*1024:
                        raise ValueError()
            finally:
                download.close()
            return bytes(data)
        except Exception:
            raise RuleError('snapshot_failed', 'Source snapshot could not be downloaded safely.', 502)

def client_for(request):
    token = github_tokens.get(request.session.get('github_capability', ''), request.user.id)
    if not token:
        raise RuleError('github_reauthentication_required', 'Sign in with GitHub again; credentials expired or the service restarted.', 401)
    from .models import Member
    member=Member.objects.get(user=request.user)
    return GitHub(token,member.github_login,member.github_id)
