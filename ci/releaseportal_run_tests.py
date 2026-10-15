"""Trusted Django entry point: repository manage.py cannot replace test selection."""
import os
from pathlib import Path
import sys

if sys.argv[1:] not in [['check'],['test']]:
    raise SystemExit(2)
backend=Path('/work/app/backend')
# The immutable tools directory stays first, ahead of repository imports.
sys.path.insert(0,'/tools')
sys.path.insert(1,str(backend))
os.environ['DJANGO_SETTINGS_MODULE']='config.settings'
import releaseportal_test_runner  # Preload the immutable runner before application startup.
from django.core.management import execute_from_command_line
args=['trusted-django','check'] if sys.argv[1]=='check' else [
    'trusted-django','test','portal','--testrunner=releaseportal_test_runner.CountingRunner','--verbosity=0']
execute_from_command_line(args)
