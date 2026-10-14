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
serve(application, host=host, port=int(os.environ.get('PORTAL_PORT', '8055')), threads=4)
