from __future__ import unicode_literals
import json

from django.db import models

# Create your models here.
from django.utils import timezone

from django.core import serializers

class VULNERABILITY_CWE(models.Model):
    cwe_id = models.TextField(unique=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    weakness = models.TextField(default="")
    description_summary = models.TextField(default="")

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
        data["weakness"] = self.weakness
        data["description_summary"] = self.description_summary
        return data


class VULNERABILITY_CWE_NEW(VULNERABILITY_CWE):
    class Meta:
        ordering = ['cwe_id']
        verbose_name = 'VULNERABILITY_CWE_NEW'
        verbose_name_plural = 'VULNERABILITY_CWES_NEW'


class VULNERABILITY_CWE_MODIFIED(VULNERABILITY_CWE):
    class Meta:
        ordering = ['cwe_id']
        verbose_name = 'VULNERABILITY_CWE_MODIFIED'
        verbose_name_plural = 'VULNERABILITY_CWES_MODIFIED'