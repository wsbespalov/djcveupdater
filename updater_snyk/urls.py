from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('update/', views.update, name='update'),
    path('stats/', views.stats, name='stats'),
]