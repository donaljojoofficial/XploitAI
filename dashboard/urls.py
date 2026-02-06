from django.urls import path
from . import views
from . import views_targets

urlpatterns = [
    path("", views.index, name="dashboard_index"),
    path("start/", views.start_attack, name="dashboard_start_attack"),
    path("attack/<int:pk>/", views.attack_detail, name="dashboard_attack_detail"),
    path("attack/<int:pk>/replay/", views.attack_replay, name="dashboard_attack_replay"),
    path("targets/", views_targets.target_management, name="target_management"),
]