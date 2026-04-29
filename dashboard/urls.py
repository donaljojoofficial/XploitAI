from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from . import views_targets
from . import views_main
from . import views_executors
from . import api
from . import auth

urlpatterns = [
    # Authentication routes
    path("register/", auth.register, name="register"),
    path("activate/<uidb64>/<token>/", auth.activate, name="activate"),

    path("login/", auth.login_view, name="login"),
    path("logout/", auth.logout_view, name="logout"),
    path("profile/", auth.profile, name="profile"),
    path("profile/change-password/", auth.change_password, name="change_password"),

    # Dashboard routes (root level)
    path("", views.index, name="dashboard_index"),
    path("history/", views.test_history, name="dashboard_test_history"),
    path("history/delete-all/", views.delete_all_test_history, name="dashboard_test_history_delete_all"),
    path("assistant/", views.assistant_page, name="dashboard_assistant"),
    path("start/", views.start_attack, name="dashboard_start_attack"),
    path("quick-test/start/", views.start_quick_test, name="dashboard_start_quick_test"),
    path("attack/<int:pk>/", views.attack_detail, name="dashboard_attack_detail"),
    path("attack/<int:pk>/phases/<str:phase_key>/", views.attack_phase_detail, name="dashboard_attack_phase_detail"),
    path("attack/<int:pk>/phases/<str:phase_key>/regenerate/", views.regenerate_phase_plan, name="dashboard_regenerate_phase_plan"),
    path("attack/<int:pk>/replay/", views.attack_replay, name="dashboard_attack_replay"),
    path("attack/<int:pk>/plan/", views.attack_plan, name="dashboard_attack_plan"),
    path("attack/<int:pk>/phase-reviews/", views.attack_phase_reviews, name="dashboard_attack_phase_reviews"),
    path("attack/<int:pk>/command-logs/", views.attack_command_logs, name="dashboard_attack_command_logs"),
    path("attack/<int:pk>/delete/", views.delete_test_history_item, name="dashboard_attack_delete"),
    path("attack/<int:pk>/report/generate", views.generate_attack_report, name="dashboard_attack_report_generate"),
    path("attack/<int:pk>/report/latest", views.latest_attack_report, name="dashboard_attack_report_latest"),
    path("targets/", views_targets.target_management, name="target_management"),
    path("executors/", views_executors.executor_management, name="executor_management"),
    path("activity/load/", views_main.load_more_activity, name="dashboard_load_activity"),
    path("attack/<int:pk>/approve/", views.approve_plan, name="approve_plan"),
    path("attack/<int:pk>/resume/", views.resume_attack, name="resume_attack"),
    path("attack/<int:pk>/retry-phase/", views.retry_failed_phase, name="retry_failed_phase"),
    path("attack/<int:pk>/stop/", views.stop_attack, name="stop_attack"),
    path('password-reset/', auth.password_reset_request, name='password_reset'),
    path('password-reset/verify/<uidb64>/', auth.password_reset_verify, name='password_reset_verify'),
    

    # Configuration + settings (mounted separately under /settings/)
    path("configuration/", views.configuration, name="configuration"),
    path("check_status/", views.check_llm_status, name="check_llm_status"),
    path("attack-chat/ask/", api.attack_chat_ask, name="dashboard_attack_chat_ask"),
    path("attack-chat/reset/", api.attack_chat_reset, name="dashboard_attack_chat_reset"),
]
