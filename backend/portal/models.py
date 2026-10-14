import uuid
from django.conf import settings
from django.db import models

class Member(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=[('viewer','Viewer'),('developer','Developer'),('reviewer','Reviewer / operator')])
    oidc_subject = models.CharField(max_length=255, blank=True)
    oidc_issuer = models.CharField(max_length=255, blank=True)
    github_id = models.PositiveBigIntegerField(null=True, unique=True)
    github_login = models.CharField(max_length=100, blank=True)

class Run(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    requester = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    commit = models.CharField(max_length=40)
    repository = models.CharField(max_length=200, default='macANTONIO213/releaseportal-demo')
    template = models.CharField(max_length=40, default='django-demo')
    source_sha256 = models.CharField(max_length=64, blank=True)
    request_key = models.UUIDField(unique=True, null=True)
    status = models.CharField(max_length=32, default='queued')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    queue_id = models.PositiveIntegerField(null=True)
    build_number = models.PositiveIntegerField(null=True)
    evidence = models.JSONField(default=dict)
    artifact_sha256 = models.CharField(max_length=64, blank=True)
    artifact_name = models.CharField(max_length=100, blank=True)
    error_code = models.CharField(max_length=40, blank=True)
    worker_lease_until = models.DateTimeField(null=True)
    retry_count = models.PositiveSmallIntegerField(default=0)
    next_poll_at = models.DateTimeField(null=True)
    class Meta:
        constraints = [models.UniqueConstraint(fields=['build_number'], name='unique_jenkins_build')]

class Release(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    run = models.OneToOneField(Run, on_delete=models.PROTECT)
    creator = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name='created_releases')
    status = models.CharField(max_length=32, default='awaiting_approval')
    plan = models.JSONField(default=dict)
    plan_digest = models.CharField(max_length=64)
    artifact_sha256 = models.CharField(max_length=64)
    approver = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT, related_name='approved_releases')
    approved_at = models.DateTimeField(null=True)
    approval_expires_at = models.DateTimeField(null=True)
    operator = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT, related_name='operated_releases')
    deployment_result = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

class Event(models.Model):
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, on_delete=models.PROTECT)
    action = models.CharField(max_length=64)
    object_id = models.CharField(max_length=64, blank=True)
    detail = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

class Feedback(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    rating = models.PositiveSmallIntegerField()
    task = models.CharField(max_length=40)
    comment = models.CharField(max_length=1000, blank=True)
    minutes = models.PositiveIntegerField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)

class LoginAttempt(models.Model):
    key = models.CharField(max_length=64, unique=True)
    failures = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)
