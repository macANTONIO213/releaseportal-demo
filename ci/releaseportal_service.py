"""Trusted host service entry points, installed outside all repository sandboxes."""
import argparse
import base64
import json
import os
from pathlib import Path
import time

from portal.controller_http import PrivateServer
from portal.controller_runtime import Controller,Ledger,TemporaryCLI
from portal.remote_jobs import RoleCLI,Artifacts,Queue
from releaseportal_dispatcher import Claims,Dispatcher,Sandbox
from releaseportal_image import ImageAssembler
from registry_proxy import RegistryProxy
from releaseportal_logs import StatusLog


def main():
    parser=argparse.ArgumentParser();parser.add_argument('service',choices=['proxy','controller','dispatcher'])
    parser.add_argument('--config',required=True);args=parser.parse_args()
    cfg=json.loads(Path(args.config).read_text())
    if args.service=='proxy':
        RegistryProxy(('172.26.0.1',3128)).serve_forever()
        return
    credential=Path(os.environ['CREDENTIALS_DIRECTORY'])
    key=base64.b64decode((credential/'control.key').read_text().strip(),validate=True)
    if len(key)!=32:
        raise ValueError('Invalid controller credential')
    profile=cfg['profile']
    if args.service=='controller':
        controller=Controller(profile,key,Ledger('/var/lib/releaseportal-controller/attempts.sqlite3'),
            lambda credentials:TemporaryCLI(cfg['aws_cli'],profile['region'],credentials))
        PrivateServer((cfg['private_ip'],9443),controller,cfg['certificate'],str(credential/'tls.key')).serve_forever()
        return
    cli=RoleCLI(cfg['aws_cli'],profile['region'],'worker')
    dispatcher=Dispatcher(profile,key,Queue(cli,cfg['queue_url'],profile['account'],cfg['queue_name']),
        Artifacts(cli,cfg['bucket'],profile['account']),Claims('/var/lib/releaseportal-worker/claims.sqlite3'),
        Sandbox('/var/lib/releaseportal-worker/jobs'),ImageAssembler(profile,cfg['aws_cli']),
        StatusLog(cfg['aws_cli'],profile['region'],cfg['log_group']))
    while True:
        dispatcher.tick()
        time.sleep(2)


if __name__=='__main__':
    try:
        main()
    except BaseException:
        # Never send configuration, request bodies, credentials, guest output or tracebacks to logs.
        raise SystemExit('releaseportal_service_stopped_reconciliation_required') from None
