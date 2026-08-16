from django.urls import path

urlpatterns = [
    path("must-not-appear/", lambda request: None),
]
