from __future__ import unicode_literals
import json

from django.db import models

from django.utils import timezone

from django.core import serializers


class STATUS_CWE(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default=timezone.now)
    count = models.IntegerField(default=0)

    objects = models.Manager()

    class Meta:
        verbose_name = "STATUS_CWE"
        verbose_name_plural = "STATUS_CWES"

    def __str__(self):
        return "CWE Status: count: {}, created: {}, updated: {}".format(self.count, self.created, self.updated)

    def __unicode__(self):
        return "CWE Status"

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


class VULNERABILITY_CWE(models.Model):
    id = models.BigAutoField(primary_key=True)
    cwe_id = models.TextField(unique=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    weaknesses = models.TextField(default="")
    description_summary = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)

    modification = models.IntegerField(default=0)

    objects = models.Manager()

    class Meta:
        ordering = ['cwe_id', "modification"]
        verbose_name = 'VULNERABILITY_CWE'
        verbose_name_plural = 'VULNERABILITY_CWES'

    def __str__(self):
        return "{}".format(self.cwe_id)

    def __unicode__(self):
        return "CWE: {}".format(self.cwe_id)

    def delete(self, *args, **kwargs):
        return super(self.__class__, self).delete(*args, **kwargs)

    def save(self, *args, **kwargs):
        super(self.__class__, self).save(*args, **kwargs)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["cwe_id"] = self.cwe_id
        data["name"] = self.name
        data["status"] = self.status
        data["weaknesses"] = self.weaknesses
        data["description_summary"] = self.description_summary
        data["created"] = self.created
        data["modification"] = self.modification
        return data
