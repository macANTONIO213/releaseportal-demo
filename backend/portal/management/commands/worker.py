import time
from django.core.management.base import BaseCommand
from portal.direct_worker import tick

class Command(BaseCommand):
    help = 'Process persisted direct build jobs in the configured isolated Docker runtime. No AWS requests.'
    def add_arguments(self, parser):
        parser.add_argument('--once', action='store_true')
    def handle(self, once, **options):
        while True:
            tick()
            if once:
                return
            time.sleep(5)
