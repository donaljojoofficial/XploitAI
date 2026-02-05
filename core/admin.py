from django.contrib import admin
from .models import AttackerExecutor, AttackTarget

@admin.register(AttackerExecutor)
class AttackerExecutorAdmin(admin.ModelAdmin):
    list_display = ('name', 'ip_address', 'status', 'last_heartbeat', 'created_at')
    list_filter = ('status',)
    search_fields = ('name', 'ip_address')
    readonly_fields = ('created_at', 'last_heartbeat')

@admin.register(AttackTarget)
class AttackTargetAdmin(admin.ModelAdmin):
    list_display = ('name', 'ip_address', 'operating_system', 'is_active', 'created_at')
    list_filter = ('is_active', 'operating_system')
    search_fields = ('name', 'ip_address', 'vulnerability_profile')
    readonly_fields = ('created_at',)
