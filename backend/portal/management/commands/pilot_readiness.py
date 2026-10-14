from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import connection
from portal.models import Member

class Command(BaseCommand):
    help = 'Local configuration readiness only. No permission probes or cloud API calls.'
    def handle(self, **options):
        checks = {
            'shared_pilot_mode': not settings.LOCAL,
            'postgresql': connection.vendor == 'postgresql',
            'private_ingress_confirmation': settings.PRIVATE_INGRESS_CONFIRMED,
            'github_app_configuration': bool(settings.GITHUB_CLIENT_ID and settings.GITHUB_CLIENT_SECRET and settings.GITHUB_REDIRECT_URI),
            'isolated_build_runtime': __import__('portal.direct_worker',fromlist=['configured']).configured(),
            'reviewed_deployment_template': settings.DEPLOYMENT_TEMPLATE_APPROVED,
            'deployment_enabled': settings.AWS_DEPLOYMENT_ENABLED,
            'github_developer': Member.objects.filter(role='developer',github_id__isnull=False).exists(),
            'independent_github_reviewer': Member.objects.filter(github_id__in=[int(i) for i in settings.GITHUB_REVIEWER_IDS],user__is_active=True).exists(),
        }
        for name, passed in checks.items():
            self.stdout.write(f'{name}: {"configured" if passed else "required"}')
        self.stdout.write('These are configuration checks, not verification of external integrations.')
        self.stdout.write('VPN restriction must be tested from both allowed VPN and outside-VPN networks before launch.')
