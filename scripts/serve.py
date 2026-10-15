import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'backend'))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
from config.wsgi import application
from waitress import serve
from django.conf import settings
# Explicit loopback default. Shared hosting must configure its approved ingress.
host = os.environ.get('PORTAL_BIND_HOST', '127.0.0.1')
if settings.LOCAL and host != '127.0.0.1':
    raise SystemExit('Local authentication may only be served on loopback.')
proxy_options = {}
if settings.PUBLIC:
    # IngressMiddleware checks the original socket peer against approved ALB
    # subnets; the task security group admits only its ALB. Retain only the
    # scheme header, leaving REMOTE_ADDR unchanged and other proxy headers cleared.
    proxy_options = {'trusted_proxy': '*', 'trusted_proxy_headers': {'x-forwarded-proto'},
                     'clear_untrusted_proxy_headers': True}
serve(application, host=host, port=int(os.environ.get('PORTAL_PORT', '8055')), threads=4, **proxy_options)
