from django.shortcuts import render

# Create your views here.

from django.http import HttpResponse

from .controllers import CWEController

def home(request):
    return HttpResponse('updater_cwe/home')

def update(request):
    cwe_controller = CWEController()
    result = cwe_controller.update()
    return HttpResponse('updater_cwe/update -> {}'.format(result))

def stats(request):
    cwe_controller = CWEController()
    result = cwe_controller.stats()
    return HttpResponse('updater_cwe/stats -> {}'.format(result))