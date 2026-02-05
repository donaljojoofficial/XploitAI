from django.urls import path

from executor.api_heartbeat import heartbeat
from . import views

urlpatterns = [
    path("", views.index, name="dashboard_index"),
    path("attack/<int:pk>/", views.attack_detail, name="dashboard_attack_detail"),
    path('api/heartbeat/', heartbeat, name='executor_heartbeat'),
]

   

