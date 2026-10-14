import getpass
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from portal.models import Member

class Command(BaseCommand):
    help = 'Invite an explicit user. Passwords are prompted, never passed as arguments.'
    def add_arguments(self, parser):
        parser.add_argument('email')
        parser.add_argument('--role', required=True, choices=['viewer', 'developer', 'reviewer'])
        parser.add_argument('--password', '--local-password', dest='local_password', action='store_true')
    def handle(self, email, role, local_password, **options):
        email = email.strip().casefold()
        from django.core.validators import validate_email
        validate_email(email)
        permitted = settings.AUTH_MODE == 'invited_password' and (settings.LOCAL or settings.PRIVATE_INGRESS_CONFIRMED)
        if local_password and not permitted:
            raise CommandError('Password invitations require local mode or the confirmed private pilot.')
        if settings.AUTH_MODE == 'invited_password' and not local_password:
            raise CommandError('Use --password to set a hidden, per-user password for this pilot.')
        if get_user_model().objects.filter(email__iexact=email).exists():
            raise CommandError('User already invited; use the access management procedure to change roles.')
        user = get_user_model()(username=email, email=email)
        if local_password:
            password = getpass.getpass('Individual password (12+ characters, input hidden): ')
            if password != getpass.getpass('Confirm password: '):
                raise CommandError('Passwords do not match.')
            validate_password(password, user)
            user.set_password(password)
        else:
            user.set_unusable_password()
        with transaction.atomic():
            user.save()
            Member.objects.create(user=user, role=role)
        self.stdout.write('Invited user with explicit role. No credentials were printed.')
