from django.contrib import admin
from .models import (
    AttackerExecutor, AttackTarget, AttackContext,
    Phase, Command, ExecutionResult, AttackState
)

@admin.register(Phase)
class PhaseAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')
    search_fields = ('name',)

@admin.register(Command)
class CommandAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'phase', 'description')
    list_filter = ('phase',)
    search_fields = ('name', 'description')
    readonly_fields = ('id',)

@admin.register(ExecutionResult)
class ExecutionResultAdmin(admin.ModelAdmin):
    list_display = ('id', 'command', 'attack_state', 'target', 'status', 'created_at')
    list_filter = ('status', 'command', 'created_at')
    search_fields = ('target', 'command__name')
    readonly_fields = ('created_at',)

@admin.register(AttackState)
class AttackStateAdmin(admin.ModelAdmin):
    list_display = ('name', 'current_phase', 'autonomy_status', 'created_at', 'updated_at')
    list_filter = ('current_phase', 'autonomy_status')
    search_fields = ('name',)
    readonly_fields = ('created_at', 'updated_at')

@admin.register(AttackerExecutor)
class AttackerExecutorAdmin(admin.ModelAdmin):
    list_display = ('name', 'ip_address', 'status', 'last_heartbeat', 'created_at')
    list_filter = ('status',)
    search_fields = ('name', 'ip_address')
    readonly_fields = ('created_at', 'last_heartbeat')

@admin.register(AttackTarget)
class AttackTargetAdmin(admin.ModelAdmin):
    list_display = ('name', 'base_url', 'ip_address', 'operating_system', 'is_active', 'created_at')
    list_filter = ('is_active', 'operating_system')
    search_fields = ('name', 'base_url', 'ip_address', 'vulnerability_profile')
    readonly_fields = ('created_at',)

@admin.register(AttackContext)
class AttackContextAdmin(admin.ModelAdmin):
    list_display = ('attacker_executor', 'target', 'status', 'started_at', 'stopped_at', 'stop_reason')
    list_filter = ('status',)
    search_fields = ('attacker_executor__name', 'target__name')
    readonly_fields = ('created_at', 'started_at', 'stopped_at', 'stop_reason')
