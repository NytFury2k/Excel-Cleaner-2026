"""
rbac.py - Permission checking backed by the database.

has_permission() reads from session['permissions'], populated at login.
The _FALLBACK dict exists only for backward compat during migration and for the access_control.html display page.
"""

from flask import session

def has_permission(permission):
    """
    Return True if the logged-in user has the given permission .
    Reads from session['permissions'] (a list loaded from DB at login).
    Falls back to the hardcoded dict if session not yet migrated.
    """
    perms = session.get("permissions")
    if perms is not None:
        return permission in perms
    #Fallback for any session started before migration
    role=session.get("role")
    if not role:
        return False
    return permission in _ROLE_PERMISSIONS_FALLBACK.get(role, set())

# Fallback + display dict
_ROLE_PERMISSIONS_FALLBACK={
    "admin":{
        "view_all_users", "create_user", "manage_roles", "reassign_hierarchy", "toggle_user", "reset_password", 
        "view_all_logs", "export_logs", "upload_file", "select_rules", "run_cleaning",
        "download_results", "manage_presets", "change_own_password", "manage_api_tokens"
        },

    "manager":{
        "view_team_users", "create_user", "manage_roles", "reassign_hierarchy", "toggle_user", "reset_password", "view_team_logs",
        "export_logs", "upload_file", "select_rules", "run_cleaning", "download_results", 
        "manage_presets", "change_own_password", "manage_api_tokens"
    },

    "team_lead":{
        "view_team_users", "view_team_logs", "upload_file", "select_rules", "run_cleaning", 
        "download_results", "manage_presets", "change_own_password", "manage_api_tokens",
    },

    "user":{
        "view_self", "view_own_logs", "upload_file", "select_rules", "run_cleaning", 
        "download_results", "manage_presets", "change_own_password", "manage_api_tokens",
    },
}

ROLE_PERMISSIONS = _ROLE_PERMISSIONS_FALLBACK