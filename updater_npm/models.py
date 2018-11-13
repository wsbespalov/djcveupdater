from __future__ import unicode_literals

import json

from django.db import models

from django.utils import timezone

from django.contrib.postgres.fields import ArrayField
from django.core import serializers


class STATUS_NPM(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default=timezone.now)
    count = models.IntegerField(default=0)

    objects = models.Manager()

    class Meta:
        verbose_name = "STATUS_NPM"
        verbose_name_plural = "STATUS_NPMS"

    def __str__(self):
        return "NPM Status: count: {}, created: {}, updated: {}".format(self.count, self.created, self.updated)

    def __unicode__(self):
        return "NPM Status"

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


class VULNERABILITY_NPM(models.Model):
    id = models.BigAutoField(primary_key=True)
    npm_id = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default=timezone.now)
    title = models.TextField(default="")
    author = models.TextField(default="")
    module_name = models.TextField(default="")
    published_date = models.DateTimeField(default=timezone.now)
    cves = ArrayField(models.TextField(blank=True), default=list)
    vulnerable_versions = ArrayField(models.TextField(blank=True), default=list)
    slug = models.TextField(default="")
    overview = models.TextField(default="")
    recommendation = models.TextField(default="")
    references = models.TextField(default="")
    legacy_slug = models.TextField(default="")
    allowed_scopes = ArrayField(models.TextField(blank=True), default=list)
    cvss_vector = models.TextField(default="")
    cvss_score = models.FloatField(default=0.0)
    cwe = models.TextField(default="")
    source = models.TextField(default="")

    modification = models.IntegerField(default=0)

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.npm_id)

    def __unicode__(self):
        return "NPM: {}".format(self.npm_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["npm_id"] = self.npm_id
        data["created"] = self.created
        data["updated"] = self.updated
        data["title"] = self.title
        data["author"] = self.author
        data["module_name"] = self.module_name
        data["published_date"] = self.published_date
        data["cves"] = self.cves
        data["vulnerable_versions"] = self.vulnerable_versions
        data["slug"] = self.slug
        data["overview"] = self.overview
        data["recommendation"] = self.recommendation
        data["references"] = self.references
        data["legacy_slug"] = self.legacy_slug
        data["allowed_scopes"] = self.allowed_scopes
        data["cvss_vector"] = self.cvss_vector
        data["cvss_score"] = self.cvss_score
        data["cwe"] = self.cwe
        data["source"] = self.source
        data["modification"] = self.modification
        return data

    class Meta:
        ordering = ["npm_id", "modification"]
        verbose_name = "VULNERABILITY_NPM"
        verbose_name_plural = "VULNERABILITY_NPMS"
