"""Explicit initial owner access; this mode grants no reviewer capability."""
from django.core.exceptions import ImproperlyConfigured

def validate_public_identities(allowed, reviewers, owner_only=False):
    if owner_only:
        if allowed != {'284642046'} or reviewers:
            raise ImproperlyConfigured('Owner sign-in requires only the approved macANTONIO213 identity and no reviewer IDs.')
    elif len(allowed) < 2 or not reviewers or not reviewers <= allowed:
        raise ImproperlyConfigured('Public hosting requires approved GitHub user IDs and independent reviewer IDs.')
