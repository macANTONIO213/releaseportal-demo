"""Readiness-only public endpoint. No Django, credentials, storage or APIs."""
import json
import os

def application(environ, start_response):
    healthy = environ.get('PATH_INFO') == '/healthz' and environ.get('REQUEST_METHOD') in ['GET', 'HEAD']
    body = json.dumps({'status': 'ok' if healthy else 'setup_required'}).encode()
    start_response('200 OK' if healthy else '503 Service Unavailable', [
        ('Content-Type', 'application/json'), ('Content-Length', str(len(body))),
        ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'),
        ('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'"),
        ('Referrer-Policy', 'no-referrer')])
    return [] if environ.get('REQUEST_METHOD') == 'HEAD' else [body]

if __name__ == '__main__':
    from waitress import serve
    serve(application, host=os.environ.get('PORTAL_BIND_HOST', '0.0.0.0'), port=8055, threads=4)
