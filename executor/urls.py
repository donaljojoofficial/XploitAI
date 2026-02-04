from django.urls import path
from . import views

urlpatterns = [
    path("next-task/", views.get_next_task, name="executor_next_task"),
    path("report-result/", views.report_result, name="executor_report_result"),
]