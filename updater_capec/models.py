from __future__ import unicode_literals

import json

from django.db import models

from django.utils import timezone

from django.contrib.postgres.fields import ArrayField
from django.core import serializers


class VULNERABILITY_CAPEC(models.Model):
	id = models.BigAutoField(primary_key=True)
	capec_id = models.TextField(default="")
	name = models.TextField(default="")
	summary = models.TextField(default="")
	prerequisites = models.TextField(default="")
	solutions = models.TextField(default="")
	related_weakness = ArrayField(models.TextField(blank=True), default=list)
	created = models.DateTimeField(default=timezone.now)

	objects = models.Manager()

	class Meta:
		ordering = ['capec_id']
		verbose_name = 'VULNERABILITY_CAPEC'
		verbose_name_plural = 'VULNERABILITY_CAPEC'

	def __str__(self):
		return "{}".format(self.capec_id)

	def __unicode__(self):
		return "CAPEC: {}".format(self.capec_id)

	@property
	def data(self):
		data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
		data["capec_id"] = self.capec_id
		data["name"] = self.name
		data["summary"] = self.summary
		data["prerequisites"] = self.prerequisites
		data["solutions"] = self.solutions
		data["related_weakness"] = self.related_weakness
		data["created"] = self.created
		return data


class VULNERABILITY_CAPEC_NEW(models.Model):
	id = models.BigAutoField(primary_key=True)
	capec_id = models.TextField(default="")
	name = models.TextField(default="")
	summary = models.TextField(default="")
	prerequisites = models.TextField(default="")
	solutions = models.TextField(default="")
	related_weakness = ArrayField(models.TextField(blank=True), default=list)
	created = models.DateTimeField(default=timezone.now)

	objects = models.Manager()

	class Meta:
		ordering = ['capec_id']
		verbose_name = 'VULNERABILITY_CAPEC_NEW'
		verbose_name_plural = 'VULNERABILITY_CAPEC_NEW'

	def __str__(self):
		return "{}".format(self.capec_id)

	def __unicode__(self):
		return "CAPEC: {}".format(self.capec_id)

	@property
	def data(self):
		data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
		data["capec_id"] = self.capec_id
		data["name"] = self.name
		data["summary"] = self.summary
		data["prerequisites"] = self.prerequisites
		data["solutions"] = self.solutions
		data["related_weakness"] = self.related_weakness
		data["created"] = self.created
		return data


class VULNERABILITY_CAPEC_MODIFIED(models.Model):
	id = models.BigAutoField(primary_key=True)
	capec_id = models.TextField(default="")
	name = models.TextField(default="")
	summary = models.TextField(default="")
	prerequisites = models.TextField(default="")
	solutions = models.TextField(default="")
	related_weakness = ArrayField(models.TextField(blank=True), default=list)
	created = models.DateTimeField(default=timezone.now)

	objects = models.Manager()

	class Meta:
		ordering = ['capec_id']
		verbose_name = 'VULNERABILITY_CAPEC_MODIFIED'
		verbose_name_plural = 'VULNERABILITY_CAPEC_MODIFIED'

	def __str__(self):
		return "{}".format(self.capec_id)

	def __unicode__(self):
		return "CAPEC: {}".format(self.capec_id)

	@property
	def data(self):
		data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
		data["capec_id"] = self.capec_id
		data["name"] = self.name
		data["summary"] = self.summary
		data["prerequisites"] = self.prerequisites
		data["solutions"] = self.solutions
		data["related_weakness"] = self.related_weakness
		data["created"] = self.created
		return data
