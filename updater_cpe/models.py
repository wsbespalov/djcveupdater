from __future__ import unicode_literals

import json

from django.db import models

# Create your models here.

from django.contrib.postgres.fields import ArrayField
from django.core import serializers


class VULNERABILITY_CPE(models.Model):
    cpe_id = models.TextField(default="")
    title = models.TextField(default="")
    cpe_2_2 = models.TextField(default="")
    references = ArrayField(models.TextField(blank=True), default=list)

    objects = models.Manager()

    class Meta:
        ordering = ["cpe_id"]
        verbose_name = "VULNERABILITY_CPE"
        verbose_name_plural = "VULNERABILITY_CPES"

    def __str__(self):
        return "{}".format(self.cpe_id)

    def __unicode__(self):
        return "CPE: {}".format(self.cpe_id)

    def delete(self, *args, **kwargs):
        return super(self.__class__, self).delete(*args, **kwargs)

    def save(self, *args, **kwargs):
        super(VULNERABILITY_CPE, self).save(*args, **kwargs)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["cpe_id"] = self.cpe_id
        data["title"] = self.title
        data["cpe_2_2"] = self.cpe_2_2
        data["references"] = self.references
        return data
