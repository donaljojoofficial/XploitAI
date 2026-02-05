from django.contrib import admin
from .models import AttackerExecutor

@admin.register(AttackerExecutor)
class AttackerExecutorAdmin(admin.ModelAdmin):
    list_display = ('name', 'ip_address', 'status', 'last_heartbeat', 'created_at')
    list_filter = ('status',)
    search_fields = ('name', 'ip_address')
    readonly_fields = ('created_at', 'last_heartbeat')
