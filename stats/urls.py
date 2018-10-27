from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('cpe/', views.stats_cpe, name='stats_cpe')
]