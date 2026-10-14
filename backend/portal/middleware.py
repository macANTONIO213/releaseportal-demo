import logging
import ipaddress
import uuid
from django.conf import settings
from django.http import JsonResponse
log = logging.getLogger('portal')

class IngressMiddleware:
    """Public requests must arrive from the configured ALB subnet addresses.
    Health probes bypass TLS/Host checks on this one non-sensitive route only.
    """
    def __init__(self, get_response):
        self.get_response = get_response
    def __call__(self, request):
        if not settings.PUBLIC:
            return self.get_response(request)
        try:
            peer = ipaddress.ip_address(request.META.get('REMOTE_ADDR', ''))
            trusted = any(peer in network for network in settings.TRUSTED_PROXY_NETWORKS)
        except ValueError:
            trusted = False
        if not trusted:
            return JsonResponse({'error': 'Untrusted ingress'}, status=403)
        if request.path == '/healthz':
            if request.method not in ['GET', 'HEAD']:
                return JsonResponse({'error': 'Method not allowed'}, status=405)
            try:
                from django.db import connection
                with connection.cursor() as cursor:
                    cursor.execute('SELECT 1')
                response = JsonResponse({'status': 'ok'})
            except Exception:
                response = JsonResponse({'status': 'unavailable'}, status=503)
            response['Cache-Control'] = 'no-store'
            response['X-Content-Type-Options'] = 'nosniff'
            return response
        if request.META.get('HTTP_X_FORWARDED_PROTO') != 'https':
            return JsonResponse({'error': 'HTTPS required'}, status=400)
        try:
            request.get_host()
        except Exception:
            return JsonResponse({'error': 'Invalid host'}, status=400)
        return self.get_response(request)

class CorrelationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    def __call__(self, request):
        request.correlation_id = str(uuid.uuid4())
        try:
            response = self.get_response(request)
        except Exception:
            # Do not log request bodies, upstream responses, or exception values.
            log.error('Unhandled error correlation=%s', request.correlation_id)
            response = JsonResponse({'error': 'Internal error', 'code': 'internal_error', 'correlation_id': request.correlation_id}, status=500)
        response['X-Correlation-ID'] = request.correlation_id
        if request.path.startswith(('/api/', '/auth/')):
            response['Cache-Control'] = 'no-store'
        response['Referrer-Policy'] = 'no-referrer'
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        return response
