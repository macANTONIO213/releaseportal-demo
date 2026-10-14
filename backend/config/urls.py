from django.urls import path
from portal import views, direct_views

urlpatterns = [
    path('api/session', direct_views.session), path('api/login', views.local_login), path('api/logout', direct_views.sign_out),
    path('auth/login', direct_views.sign_in), path('auth/callback', direct_views.callback),
    path('api/dashboard', direct_views.dashboard), path('api/runs', direct_views.create_run),
    path('api/artifacts/<uuid:run_id>', direct_views.artifact),
    path('api/releases', direct_views.create_release), path('api/releases/<uuid:release_id>/<str:action>', direct_views.action),
    path('api/receipts/<uuid:release_id>', direct_views.receipt), path('api/feedback', views.feedback),
    path('api/metrics', views.metrics), path('healthz', views.health), path('', views.index),
]
