"""Safe status-only CloudWatch delivery on the exact approved worker log group."""
import json
import re
import time
import uuid

from portal.remote_jobs import RoleCLI,run_id


class LogCLI(RoleCLI):
    OPERATIONS={'logs':{'create-log-stream','put-log-events'}}


class StatusLog:
    def __init__(self,executable,region,group):
        if group!='/releaseportal/demo/worker':raise ValueError('Unreviewed log destination')
        self.cli=LogCLI(executable,region,'worker');self.group=group;self.stream='worker-'+str(uuid.uuid4())
        self.cli.call('logs','create-log-stream',{'logGroupName':group,'logStreamName':self.stream})

    def __call__(self,run,status,code):
        run_id(run)
        if status not in ['running','ready','failed','reconciliation_required'] or not re.fullmatch(r'[a-z0-9_]{0,60}',code):
            raise ValueError('Unsafe status event')
        self.cli.call('logs','put-log-events',{'logGroupName':self.group,'logStreamName':self.stream,
            'logEvents':[{'timestamp':int(time.time()*1000),'message':json.dumps({'run_id':run,'status':status,'code':code})}]})
