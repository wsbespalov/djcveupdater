from django.shortcuts import render

from django.http import HttpResponse

from .controllers import VULNERABILITIESController


def home(request):
    return HttpResponse('updater_vulnerability/home')


def update(request):
    cve_controller = VULNERABILITIESController()
    result = cve_controller.update()
    return HttpResponse('updater_vulnerability/update -> {}'.format(result))


def stats(request):
    cve_controller = VULNERABILITIESController()
    result = cve_controller.stats()
    return HttpResponse('updater_vulnerability/stats -> {}'.format(result))
