from django.urls import path
from . import views
from . import views_targets
from . import views_main
from . import views_executors

urlpatterns = [
    path("", views.index, name="dashboard_index"),
    path("start/", views.start_attack, name="dashboard_start_attack"),
    path("attack/<int:pk>/", views.attack_detail, name="dashboard_attack_detail"),
    path("attack/<int:pk>/replay/", views.attack_replay, name="dashboard_attack_replay"),
    path("attack/<int:pk>/plan/", views.attack_plan, name="dashboard_attack_plan"),
    path("targets/", views_targets.target_management, name="target_management"),
    path("executors/", views_executors.executor_management, name="executor_management"),
    path("activity/load/", views_main.load_more_activity, name="dashboard_load_activity"),
]