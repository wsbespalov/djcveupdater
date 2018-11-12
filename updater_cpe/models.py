from __future__ import unicode_literals

import json

from django.db import models

from django.utils import timezone

from django.contrib.postgres.fields import ArrayField
from django.core import serializers

class STATUS_CPE(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default=timezone.now)
    count = models.IntegerField(default=0)

    objects = models.Manager()

    class Meta:
        verbose_name = "STATUS_CPE"
        verbose_name_plural = "STATUS_CPE"

    def __str__(self):
        return "CPE Status: count: {}, created: {}, updated: {}".format(self.count, self.created, self.updated)

    def __unicode__(self):
        return "CPE Status"

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


class VULNERABILITY_CPE(models.Model):
    id = models.BigAutoField(primary_key=True)
    cpe_id = models.TextField(default="")
    title = models.TextField(default="")
    cpe_2_2 = models.TextField(default="")
    references = ArrayField(models.TextField(blank=True), default=list)
    created = models.DateTimeField(default=timezone.now)
    component = models.TextField(default="")
    version = models.TextField(default="")
    vendor = models .TextField(default="")

    modification = models.IntegerField(default=0)

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.cpe_id)

    def __unicode__(self):
        return "CPE: {}".format(self.cpe_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["cpe_id"] = self.cpe_id
        data["title"] = self.title
        data["cpe_2_2"] = self.cpe_2_2
        data["references"] = self.references
        data["component"] = self.component
        data["version"] = self.version
        data["vendor"] = self.vendor
        data["created"] = self.created
        data["modification"] = self.modification
        return data

    class Meta:
        ordering = ["cpe_id", "modification"]
        verbose_name = "VULNERABILITY_CPE"
        verbose_name_plural = "VULNERABILITY_CPES"
