from django.urls import path
from . import api_views

urlpatterns = [
    path("heartbeat/", api_views.heartbeat, name="executor_heartbeat"),
    path("tasks/", api_views.get_tasks, name="executor_tasks"),
    path("results/", api_views.report_result, name="executor_results"),
]