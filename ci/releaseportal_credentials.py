"""Boot-time workload-role credential delivery. No retries, raw output or disk key copy."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

from portal.ecs_release import fingerprint
from portal.remote_jobs import RoleCLI,decode_configuration


class CredentialCLI(RoleCLI):
    OPERATIONS={'secretsmanager':{'get-secret-value'}}


def main():
    root=Path('/opt/releaseportal-worker')
    reference=json.loads((root/'control-reference.json').read_text())
    account,region=reference['account'],reference['region']
    if (not re.fullmatch(r'[0-9]{12}',account) or not re.fullmatch(r'[a-z]{2}-[a-z]+-[0-9]',region) or
        not reference['secret_arn'].startswith(f'arn:aws:secretsmanager:{region}:{account}:secret:/releaseportal/demo/worker-control-')):
        raise ValueError('Invalid exact secret reference')
    if len(Path('/proc/swaps').read_text().splitlines())!=1:
        raise ValueError('Swap is not allowed for controller credentials')
    filesystem=subprocess.check_output(['/usr/bin/findmnt','-n','-o','FSTYPE','/run'],text=True).strip()
    if filesystem!='tmpfs':
        raise ValueError('Process credentials require the RAM filesystem')
    executable=shutil.which('aws')
    if not executable:
        raise ValueError('AWS CLI is required')
    result=CredentialCLI(executable,region,'worker').call('secretsmanager','get-secret-value',
        {'SecretId':reference['secret_arn'],'VersionId':reference['version_id']})
    payload=json.loads(result.pop('SecretString'))
    if set(payload)!={'control_key','configuration'} or len(base64.b64decode(payload['control_key'],validate=True))!=32:
        raise ValueError('Invalid controller credential schema')
    cfg=decode_configuration(payload['configuration'])
    if fingerprint(cfg)!=reference['configuration_sha256']:
        raise ValueError('Configuration receipt changed')
    if cfg['profile']['account']!=account or cfg['profile']['region']!=region:
        raise ValueError('Configuration account mismatch')
    if cfg['controller_certificate'].strip()!=(root/'controller-cert.pem').read_text().strip():
        raise ValueError('Pinned controller certificate changed')
    boot=json.loads((root/'bootstrap-receipt.json').read_text())
    if cfg['controller_private_ip']!=boot['private_ip']:
        raise ValueError('Private interface changed')
    cfg.update(aws_cli=executable,private_ip=boot['private_ip'],certificate=str(root/'controller-cert.pem'))
    path=root/'config.json';path.write_text(json.dumps(cfg));path.chmod(0o644)
    private=Path('/run/releaseportal-private');private.mkdir(mode=0o700,exist_ok=True);private.chmod(0o700)
    key=private/'control.key'
    fd=os.open(key,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        stream.write(payload.pop('control_key'))
    key.chmod(0o600)
    payload.clear();result.clear()


if __name__=='__main__':
    try:main()
    except BaseException:raise SystemExit('worker_credential_delivery_stopped_no_replay') from None
