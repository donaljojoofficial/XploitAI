from django.urls import path
from . import api_views

urlpatterns = [
    path("heartbeat/", api_views.heartbeat, name="executor_heartbeat"),
    path("tasks/", api_views.get_tasks, name="executor_tasks"),
    path("tasks/<int:task_id>/result/", api_views.report_result, name="executor_task_result"),
    path("results/", api_views.report_result_legacy, name="executor_results_legacy"),
]
