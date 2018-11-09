from __future__ import unicode_literals

import json

from django.db import models

from django.utils import timezone

from django.contrib.postgres.fields import ArrayField
from django.core import serializers


class STATUS_CAPEC(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default=timezone.now)
    count = models.IntegerField(default=0)

    objects = models.Manager()

    class Meta:
        verbose_name = "STATUS_CAPEC"
        verbose_name_plural = "STATUS_CAPECS"

    def __str__(self):
        return "CAPEC Status: count: {}, created: {}, updated: {}".format(self.count, self.created, self.updated)

    def __unicode__(self):
        return "CAPEC Status"

    def delete(self, *args, **kwargs):
        return super(self.__class__, self).delete(*args, **kwargs)

    def save(self, *args, **kwargs):
        super(self.__class__, self).save(*args, **kwargs)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["name"] = self.name
        data["status"] = self.status
        data["count"] = self.count
        data["created"] = self.created
        data["updated"] = self.updated
        return data


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
        data["id"] = self.id
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
        data["id"] = self.id
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
        data["id"] = self.id
        data["capec_id"] = self.capec_id
        data["name"] = self.name
        data["summary"] = self.summary
        data["prerequisites"] = self.prerequisites
        data["solutions"] = self.solutions
        data["related_weakness"] = self.related_weakness
        data["created"] = self.created
        return data
