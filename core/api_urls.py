from django.urls import path

from . import api_views

urlpatterns = [
    path("login/", api_views.api_login, name="api_login"),
    path("register/send-otp/", api_views.api_register_send_otp, name="api_register_send_otp"),
    path(
        "register/verify-otp/",
        api_views.api_register_verify_otp,
        name="api_register_verify_otp",
    ),
    path("events/", api_views.api_events, name="api_events"),
    path("events/trending/", api_views.api_trending_events, name="api_trending_events"),
]
