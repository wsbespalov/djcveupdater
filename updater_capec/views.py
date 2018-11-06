from django.shortcuts import render


from django.http import HttpResponse

from .controllers import CAPECController

def home(request):
    return HttpResponse('updater_capec/home')

def update(request):
    capec_controller = CAPECController()
    result = capec_controller.update()
    return HttpResponse('updater_cpe/update -> {}'.format(result))

def stats(request):
    capec_controller = CAPECController()
    result = capec_controller.stats()
    return HttpResponse('updater_capec/stats -> {}'.format(result))
