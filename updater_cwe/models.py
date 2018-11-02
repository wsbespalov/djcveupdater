from __future__ import unicode_literals
import json

from django.db import models

from django.utils import timezone

from django.core import serializers


class VULNERABILITY_CWE(models.Model):
    cwe_id = models.TextField(unique=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    weaknesses = models.TextField(default="")
    description_summary = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)

    objects = models.Manager()

    class Meta:
        ordering = ['cwe_id']
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
        data["cwe_id"] = self.cwe_id
        data["name"] = self.name
        data["status"] = self.status
        data["weaknesses"] = self.weaknesses
        data["description_summary"] = self.description_summary
        data["created"] = self.created
        return data


class VULNERABILITY_CWE_NEW(models.Model):
    cwe_id = models.TextField(unique=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    weaknesses = models.TextField(default="")
    description_summary = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)

    objects = models.Manager()

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
        data["cwe_id"] = self.cwe_id
        data["name"] = self.name
        data["status"] = self.status
        data["weaknesses"] = self.weaknesses
        data["description_summary"] = self.description_summary
        data["created"] = self.created
        return data

    class Meta:
        ordering = ['cwe_id']
        verbose_name = 'VULNERABILITY_CWE_NEW'
        verbose_name_plural = 'VULNERABILITY_CWES_NEW'


class VULNERABILITY_CWE_MODIFIED(models.Model):
    cwe_id = models.TextField(unique=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    weaknesses = models.TextField(default="")
    description_summary = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)

    objects = models.Manager()

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
        data["cwe_id"] = self.cwe_id
        data["name"] = self.name
        data["status"] = self.status
        data["weaknesses"] = self.weaknesses
        data["description_summary"] = self.description_summary
        data["created"] = self.created
        return data

    class Meta:
        ordering = ['cwe_id']
        verbose_name = 'VULNERABILITY_CWE_MODIFIED'
        verbose_name_plural = 'VULNERABILITY_CWES_MODIFIED'