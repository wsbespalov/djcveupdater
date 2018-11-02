from __future__ import unicode_literals

import json

from django.db import models

from django.utils import timezone

from django.contrib.postgres.fields import ArrayField
from django.core import serializers


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

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.cpe_id)

    def __unicode__(self):
        return "CPE: {}".format(self.cpe_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["cpe_id"] = self.cpe_id
        data["title"] = self.title
        data["cpe_2_2"] = self.cpe_2_2
        data["references"] = self.references
        data["component"] = self.component
        data["version"] = self.version
        data["vendor"] = self.vendor
        data["created"] = self.created
        return data

    class Meta:
        ordering = ["cpe_id"]
        verbose_name = "VULNERABILITY_CPE"
        verbose_name_plural = "VULNERABILITY_CPES"


class VULNERABILITY_CPE_NEW(models.Model):
    id = models.BigAutoField(primary_key=True)
    cpe_id = models.TextField(default="")
    title = models.TextField(default="")
    cpe_2_2 = models.TextField(default="")
    references = ArrayField(models.TextField(blank=True), default=list)
    created = models.DateTimeField(default=timezone.now)
    component = models.TextField(default="")
    version = models.TextField(default="")
    vendor = models .TextField(default="")

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.cpe_id)

    def __unicode__(self):
        return "CPE: {}".format(self.cpe_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["cpe_id"] = self.cpe_id
        data["title"] = self.title
        data["cpe_2_2"] = self.cpe_2_2
        data["references"] = self.references
        data["component"] = self.component
        data["version"] = self.version
        data["vendor"] = self.vendor
        data["created"] = self.created
        return data

    class Meta:
        ordering = ["cpe_id"]
        verbose_name = "VULNERABILITY_CPE_NEW"
        verbose_name_plural = "VULNERABILITY_CPES_NEW"


class VULNERABILITY_CPE_MODIFIED(models.Model):
    id = models.BigAutoField(primary_key=True)
    cpe_id = models.TextField(default="")
    title = models.TextField(default="")
    cpe_2_2 = models.TextField(default="")
    references = ArrayField(models.TextField(blank=True), default=list)
    created = models.DateTimeField(default=timezone.now)
    component = models.TextField(default="")
    version = models.TextField(default="")
    vendor = models .TextField(default="")

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.cpe_id)

    def __unicode__(self):
        return "CPE: {}".format(self.cpe_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["cpe_id"] = self.cpe_id
        data["title"] = self.title
        data["cpe_2_2"] = self.cpe_2_2
        data["references"] = self.references
        data["component"] = self.component
        data["version"] = self.version
        data["vendor"] = self.vendor
        data["created"] = self.created
        return data

    class Meta:
        ordering = ["cpe_id"]
        verbose_name = "VULNERABILITY_CPE_MODIFIED"
        verbose_name_plural = "VULNERABILITY_CPES_MODIFIED"