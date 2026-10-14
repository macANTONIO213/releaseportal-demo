"""One-off database initialization/migrations inside the trusted image only.
Secrets arrive via ECS secret references, never operator AWS credentials.
"""
import os
import sys
from pathlib import Path

def initialize():
    import psycopg
    from psycopg import sql
    with psycopg.connect(host=os.environ['PORTAL_DB_HOST'],port=5432,dbname='releaseportal',
        user='portal_master',password=os.environ['PORTAL_DB_MASTER_PASSWORD'],sslmode='verify-full',
        sslrootcert='/app/deploy/releaseportal/rds-ca.crt',connect_timeout=10) as connection:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1 FROM pg_roles WHERE rolname=%s',['releaseportal_app'])
            if cursor.fetchone():
                raise RuntimeError('Existing database role requires reconciliation.')
            # Send a SCRAM verifier rather than the plaintext password in DDL.
            verifier=connection.pgconn.encrypt_password(os.environ['PORTAL_DB_PASSWORD'].encode(),b'releaseportal_app',b'scram-sha-256').decode()
            cursor.execute(sql.SQL('CREATE ROLE releaseportal_app LOGIN PASSWORD {}').format(sql.Literal(verifier)))
            cursor.execute('ALTER DATABASE releaseportal OWNER TO releaseportal_app')
            cursor.execute('ALTER SCHEMA public OWNER TO releaseportal_app')
    os.environ.pop('PORTAL_DB_MASTER_PASSWORD',None)

def migrate():
    sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'backend'))
    os.environ['DJANGO_SETTINGS_MODULE']='config.settings'
    import django
    django.setup()
    from django.conf import settings
    if settings.LOCAL or settings.AWS_DEPLOYMENT_ENABLED or settings.DEPLOYMENT_TEMPLATE_APPROVED:
        raise RuntimeError('Unsafe migration configuration.')
    from django.core.management import call_command
    call_command('migrate',interactive=False,verbosity=0)

if __name__=='__main__':
    try:
        if sys.argv[1:] == ['initialize']:
            initialize()
        elif sys.argv[1:] == ['migrate']:
            migrate()
        else:
            raise RuntimeError()
        print('PORTAL_DATABASE_TASK_COMPLETE')
    except Exception:
        print('PORTAL_DATABASE_TASK_STOPPED')
        raise SystemExit(1) from None
