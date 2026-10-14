"""Interactive local configuration. Secrets are masked and never printed.
Run from the ACL-protecting PowerShell helper. This does not provision services.
"""
import getpass
import json
import argparse
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / 'backend'))
from portal.configuration import read_config, write_local_config, runtime_path
path = runtime_path() / 'service-config.dpapi'
path.parent.mkdir(parents=True, exist_ok=True)
config = read_config(path) if path.exists() else {}
parser = argparse.ArgumentParser()
args = parser.parse_args()
config['PORTAL_AUTH_MODE'] = 'github'
print('Configure available integrations. Blank input retains the current value.')
fields = [
    ('PORTAL_GITHUB_CLIENT_ID', 'Registered GitHub App client ID', False),
    ('PORTAL_GITHUB_CLIENT_SECRET', 'GitHub App client secret', True),
    ('PORTAL_GITHUB_REDIRECT_URI', 'Registered HTTPS callback URL', False),
    ('PORTAL_GITHUB_REVIEWER_IDS', 'Approved reviewer GitHub numeric IDs (comma separated)', False),
]
for key, prompt, secret in fields:
    value = getpass.getpass(prompt + ' (hidden): ') if secret else input(prompt + ': ')
    if value.strip():
        config[key] = value.strip()
write_local_config(path, config)
print('GitHub configuration saved with user-bound encryption. No AWS values were requested or stored; no external requests were made.')
