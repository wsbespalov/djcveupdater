from django.shortcuts import render


from django.http import HttpResponse

from .controllers import SNYKController

def home(request):
    return HttpResponse('updater_snyk/home')

def update(request):
    snyk_controller = SNYKController()
    result = snyk_controller.update()
    return HttpResponse('updater_snyk/update -> {}'.format(result))

def stats(request):
    snyk_controller = SNYKController()
    result = snyk_controller.stats()
    return HttpResponse('updater_snyk/stats -> {}'.format(result))
