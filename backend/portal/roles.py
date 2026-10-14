from django.conf import settings

def role_for(member):
    if settings.AUTH_MODE != 'github':
        return member.role
    if not member.github_id:
        return None
    if settings.PUBLIC and str(member.github_id) not in settings.GITHUB_ALLOWED_USER_IDS:
        return None
    if member.role == 'viewer':
        return 'viewer'
    return 'reviewer' if str(member.github_id) in settings.GITHUB_REVIEWER_IDS else 'developer'
