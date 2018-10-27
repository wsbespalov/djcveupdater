from django.shortcuts import render

# Create your views here.

from django.http import HttpResponse

from updater_cpe.controllers import CPEController

import logging
logger = logging.getLogger(__name__)

def home(request):
    return HttpResponse('complete')

def stats_cpe(request):
    cpe_controller = CPEController()
    cpe_count = cpe_controller.stats()
    logger.info(cpe_count)
    return HttpResponse('stats/home: -> CPE: {}'.format(cpe_count["count_before"]))