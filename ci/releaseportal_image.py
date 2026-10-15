"""Trusted fixed image builder. Uses only workload-role ECR calls, never deployment credentials."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile
import time

from portal.remote_jobs import RoleCLI
from portal.errors import RuleError
from releaseportal_assembly import context
from releaseportal_dispatcher import environment


class ImageCLI(RoleCLI):
    OPERATIONS={'ecr':{'get-authorization-token','describe-images','describe-image-scan-findings'}}


class ImageAssembler:
    def __init__(self,profile,aws_cli='/usr/bin/aws',run=subprocess.run,sleep=time.sleep):
        self.profile,self.run,self.sleep=profile,run,sleep
        self.cancelled=None
        self.cli=ImageCLI(aws_cli,profile['region'],'worker',run=run)

    def __call__(self,source,artifact,artifact_sha,value):
        def check_lease():
            if self.cancelled is not None and self.cancelled.is_set():
                raise RuleError('queue_lease_unknown','Queue lease requires reconciliation')
        check_lease()
        bundle=context(source,artifact,self.profile,artifact_sha)
        repository=self.profile['image_repository']
        registry,repo_name=repository.split('/',1)
        tag='run-'+value['run_id']
        target=repository+':'+tag
        result=self.cli.call('ecr','get-authorization-token',{'registryIds':[self.profile['account']]})
        data=result['authorizationData']
        if len(data)!=1 or data[0]['proxyEndpoint']!='https://'+registry:
            raise ValueError('Unexpected ECR authorization endpoint')
        decoded=base64.b64decode(data[0]['authorizationToken'],validate=True)
        if not decoded.startswith(b'AWS:'):
            raise ValueError('Invalid ECR authorization')
        # Docker's credential file exists only in host RAM, is never mounted into a guest,
        # and is removed after this one fixed assembly/push operation.
        with tempfile.TemporaryDirectory(prefix='releaseportal-ecr-',dir='/dev/shm') as temporary:
            env=environment()
            def docker(args,input=None,timeout=120):
                check_lease()
                outcome=self.run(['/usr/bin/docker','--config',temporary,*args],env=env,input=input,
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout)
                if outcome.returncode:
                    raise ValueError('Trusted image operation stopped')
            try:
                docker(['login','--username','AWS','--password-stdin',registry],input=decoded[4:])
                decoded=b'';result.clear();data.clear()
                docker(['pull',self.profile['assembly_base']],timeout=300)
                docker(['build','--platform','linux/amd64','--network=none','--pull=false','--tag',target,'-'],input=bundle,timeout=600)
                docker(['push',target],timeout=600)
            finally:
                decoded=b''
                (Path(temporary)/'config.json').unlink(missing_ok=True)
        self.sleep(30)
        for _ in range(60):
            check_lease()
            scan=self.cli.call('ecr','describe-image-scan-findings',{'repositoryName':repo_name,'registryId':self.profile['account'],
                'imageId':{'imageTag':tag}})
            status=scan.get('imageScanStatus',{}).get('status')
            if status=='COMPLETE':
                counts=scan.get('imageScanFindings',{}).get('findingSeverityCounts',{})
                high,critical=counts.get('HIGH',0),counts.get('CRITICAL',0)
                if type(high) is not int or type(critical) is not int or high or critical:
                    raise ValueError('Image vulnerability gate failed')
                digest=scan['imageId']['imageDigest']
                import re
                if not re.fullmatch(r'sha256:[a-f0-9]{64}',digest):
                    raise ValueError('Invalid image digest')
                return repository+'@'+digest,{'status':'COMPLETE','high':high,'critical':critical}
            if status not in ['IN_PROGRESS','PENDING']:
                raise ValueError('Image scan requires reconciliation')
            self.sleep(15)
        raise ValueError('Image scan acceptance timed out')
