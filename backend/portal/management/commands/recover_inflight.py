from django.core.management.base import BaseCommand, CommandError
from portal.models import Run, Release
from portal.services import record

class Command(BaseCommand):
    help='After worker process loss, mark unfinished jobs for review. No cloud requests or repeated deployment.'
    def add_arguments(self, parser):
        parser.add_argument('--workers-stopped', action='store_true')
        parser.add_argument('--containers-stopped', action='store_true', help='Confirm timed-out build containers were stopped on the configured Docker host.')
    def handle(self, workers_stopped, containers_stopped, **options):
        if not workers_stopped:
            raise CommandError('Stop the old worker/web processes first, then explicitly confirm --workers-stopped.')
        if Run.objects.filter(error_code='container_cleanup_failed').exists() and not containers_stopped:
            raise CommandError('Stop the recorded releaseportal-<run ID> build containers on the configured Docker host, then confirm --containers-stopped.')
        for run in Run.objects.filter(error_code='container_cleanup_failed'):
            run.status,run.error_code='failed','container_cleanup_confirmed'
            run.save()
            record(None,'build_container_cleanup_confirmed',run.id)
        for run in Run.objects.filter(status__in=['fetching_source','running']):
            run.status,run.error_code='failed','worker_process_lost'
            run.save()
            record(None,'build_process_lost',run.id)
        for release in Release.objects.filter(status='deploying'):
            release.status='reconciliation_required'
            release.save()
            record(None,'deployment_process_lost',release.id)
        self.stdout.write('Unfinished work requires review. No credentials were recovered or cloud actions repeated.')
