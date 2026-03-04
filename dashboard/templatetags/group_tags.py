from django import template

register = template.Library()

@register.filter
def in_group(user, group_name):
    """Return True if the user belongs to the given group."""
    if not hasattr(user, 'groups'):
        return False
    return user.groups.filter(name=group_name).exists()