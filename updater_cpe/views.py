from django.shortcuts import render

# Create your views here.

from django.http import HttpResponse

from .controllers import CPEController

def home(request):
    return HttpResponse('updater_cpe/home')

def update(request):
    cpe_controller = CPEController()
    result = cpe_controller.update()
    return HttpResponse('updater_cpe/update -> {}'.format(result))

def stats(request):
    cpe_controller = CPEController()
    result = cpe_controller.stats()
    return HttpResponse('updater/stats -> {}'.format(result))
