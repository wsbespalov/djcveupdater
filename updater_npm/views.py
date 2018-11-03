from django.shortcuts import render

from django.http import HttpResponse

from .controllers import NPMController


def home(request):
	return HttpResponse('updater_npm/home')


def update(request):
	npm_controller = NPMController()
	result = npm_controller.update()
	return HttpResponse('updater_npm/update -> {}'.format(result))


def stats(request):
	npm_controller = NPMController()
	result = npm_controller.stats()
	return HttpResponse('updater_npm/stats -> {}'.format(result))