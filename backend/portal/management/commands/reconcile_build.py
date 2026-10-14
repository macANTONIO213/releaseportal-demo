from django.core.management.base import BaseCommand, CommandError
from portal.models import Run
from portal.jenkins import Jenkins
from portal.services import record

class Command(BaseCommand):
    help = 'Attach a known build to a run after an uncertain trigger; performs scoped Jenkins reads only.'
    def add_arguments(self, parser):
        parser.add_argument('run_id')
        parser.add_argument('build_number', type=int)
    def handle(self, run_id, build_number, **options):
        run = Run.objects.get(pk=run_id)
        if run.status != 'sync_required' or build_number < 1:
            raise CommandError('Only a run requiring synchronization can be reconciled.')
        build = Jenkins().build(build_number)
        params = {p['name']: p.get('value') for a in build.get('actions', []) for p in a.get('parameters', [])}
        if params.get('PORTAL_RUN_ID') != str(run.id) or params.get('COMMIT_SHA') != run.commit:
            raise CommandError('Build does not belong to this run.')
        run.build_number, run.status, run.error_code = build_number, 'running', ''
        run.save()
        record(None, 'build_reconciled', run.id, build=build_number)
        self.stdout.write('Build receipt reconciled. Worker will collect the result.')
