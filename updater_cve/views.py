from django.shortcuts import render

from django.http import HttpResponse

from .controllers import CVEController


def home(request):
    return HttpResponse('updater_cve/home')


def update(request):
    cve_controller = CVEController()
    result = cve_controller.update()
    return HttpResponse('updater_cve/update -> {}'.format(result))


def stats(request):
    cve_controller = CVEController()
    result = cve_controller.stats()
    return HttpResponse('updater_cve/stats -> {}'.format(result))
