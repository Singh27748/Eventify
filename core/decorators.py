"""
Decorators - Custom decorators for access control aur permissions ke liye.
Yeh ensure karta hai ki sirf authorized users hi kuch views access kar payen.
"""

from functools import wraps

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect

from .models import Profile


def role_required(role):
    """
    Role required decorator - Kisi specific role ke liye view restrict karta hai.
    Jaise sirf organizers hi kuch pages dekh payen, ya sirf users.
    
    Args:
        role: Required role (Profile.ROLE_USER, Profile.ROLE_ORGANIZER, ya Profile.ROLE_ADMIN)
    """
    def decorator(view_func):
        @login_required(login_url="auth_page")
        @wraps(view_func)
        def wrapped(request, *args, **kwargs):
            profile = getattr(request.user, "profile", None)
            if not profile or profile.role != role:
                messages.error(request, "You are not allowed to access this section.")
                return redirect("dashboard")
            return view_func(request, *args, **kwargs)

        return wrapped

    return decorator


def roles_required(*roles):
    """
    Roles required decorator - Multiple roles ke liye view restrict karta hai.
    
    Args:
        *roles: Required roles (e.g., Profile.ROLE_USER, Profile.ROLE_ORGANIZER)
    """
    def decorator(view_func):
        @login_required(login_url="auth_page")
        @wraps(view_func)
        def wrapped(request, *args, **kwargs):
            profile = getattr(request.user, "profile", None)
            if not profile or profile.role not in roles:
                messages.error(request, "You are not allowed to access this section.")
                return redirect("dashboard")
            return view_func(request, *args, **kwargs)

        return wrapped

    return decorator


def admin_required(view_func):
    """
    Admin required decorator - Sirf admin users ke liye view restrict karta hai.
    """
    @login_required(login_url="auth_page")
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        profile = getattr(request.user, "profile", None)
        if not profile or profile.role != Profile.ROLE_ADMIN:
            messages.error(request, "Admin access required.")
            return redirect("dashboard")
        return view_func(request, *args, **kwargs)

    return wrapped


def organizer_or_admin_required(view_func):
    """
    Organizer or Admin required decorator - Organizer ya Admin users ke liye view restrict karta hai.
    """
    @login_required(login_url="auth_page")
    @wraps(view_func)
    def wrapped(request, *args, **kwargs):
        profile = getattr(request.user, "profile", None)
        if not profile or profile.role not in (Profile.ROLE_ORGANIZER, Profile.ROLE_ADMIN):
            messages.error(request, "Organizer or Admin access required.")
            return redirect("dashboard")
        return view_func(request, *args, **kwargs)

    return wrapped
