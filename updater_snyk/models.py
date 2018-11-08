from __future__ import unicode_literals

import json

from django.db import models

from django.utils import timezone

from django.contrib.postgres.fields import ArrayField
from django.core import serializers


class STATUS_SNYK(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default=timezone.now)
    count = models.IntegerField(default=0)

    objects = models.Manager()

    class Meta:
        verbose_name = "STATUS_SNYK"
        verbose_name_plural = "STATUS_SNYK"

    def __str__(self):
        return "SNYK Status: count: {}, created: {}, updated: {}".format(self.count, self.created, self.updated)

    def __unicode__(self):
        return "SNYK Status"

    def delete(self, *args, **kwargs):
        return super(self.__class__, self).delete(*args, **kwargs)

    def save(self, *args, **kwargs):
        super(self.__class__, self).save(*args, **kwargs)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["name"] = self.name
        data["count"] = self.count
        data["created"] = self.created
        data["updated"] = self.updated
        return data


class VULNERABILITY_SNYK(models.Model):
    id = models.BigAutoField(primary_key=True)
    snyk_id = models.TextField(default="")
    cve_id = models.TextField(default="")
    cve_url = models.TextField(default="")
    cwe_id = models.TextField(default="")
    cwe_url = models.TextField(default="")
    header_title = models.TextField(default="")
    affecting_github = models.TextField(default="")
    versions = models.TextField(default="")
    overview = models.TextField(default="")
    details = models.TextField(default="")
    references = ArrayField(models.TextField(blank=True), default=list)
    credit = models.TextField(default="")
    source_url = models.TextField(default="")
    source = models.TextField(default="")
    disclosed = models.DateTimeField(default=timezone.now)
    published = models.DateTimeField(default=timezone.now)

    objects = models.Manager()

    class Meta:
        ordering = ['snyk_id']
        verbose_name = 'VULNERABILITY_SNYK'
        verbose_name_plural = 'VULNERABILITY_SNYKS'

    def __str__(self):
        return "{}".format(self.snyk_id)

    def __unicode__(self):
        return "SNYK: {}".format(self.snyk_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["snyk_id"] = self.snyk_id
        data["cve_id"] = self.cve_id
        data["cve_url"] = self.cve_url
        data["cwe_id"] = self.cwe_id
        data["cwe_url"] = self.cwe_url
        data["header_title"] = self.header_title
        data["affecting_github"] = self.affecting_github
        data["versions"] = self.versions
        data["overview"] = self.overview
        data["details"] = self.details
        data["references"] = self.references
        data["credit"] = self.credit
        data["source_url"] = self.source_url
        data["source"] = self.source
        data["disclosed"] = self.disclosed
        data["published"] = self.published
        return data


class VULNERABILITY_SNYK_NEW(models.Model):
    id = models.BigAutoField(primary_key=True)
    snyk_id = models.TextField(default="")
    cve_id = models.TextField(default="")
    cve_url = models.TextField(default="")
    cwe_id = models.TextField(default="")
    cwe_url = models.TextField(default="")
    header_title = models.TextField(default="")
    affecting_github = models.TextField(default="")
    versions = models.TextField(default="")
    overview = models.TextField(default="")
    details = models.TextField(default="")
    references = ArrayField(models.TextField(blank=True), default=list)
    credit = models.TextField(default="")
    source_url = models.TextField(default="")
    source = models.TextField(default="")
    disclosed = models.DateTimeField(default=timezone.now)
    published = models.DateTimeField(default=timezone.now)

    objects = models.Manager()

    class Meta:
        ordering = ['snyk_id']
        verbose_name = 'VULNERABILITY_SNYK_NEW'
        verbose_name_plural = 'VULNERABILITY_SNYKS_NEW'

    def __str__(self):
        return "{}".format(self.snyk_id)

    def __unicode__(self):
        return "SNYK: {}".format(self.snyk_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["snyk_id"] = self.snyk_id
        data["cve_id"] = self.cve_id
        data["cve_url"] = self.cve_url
        data["cwe_id"] = self.cwe_id
        data["cwe_url"] = self.cwe_url
        data["header_title"] = self.header_title
        data["affecting_github"] = self.affecting_github
        data["versions"] = self.versions
        data["overview"] = self.overview
        data["details"] = self.details
        data["references"] = self.references
        data["credit"] = self.credit
        data["source_url"] = self.source_url
        data["source"] = self.source
        data["disclosed"] = self.disclosed
        data["published"] = self.published
        return data


class VULNERABILITY_SNYK_MODIFIED(models.Model):
    id = models.BigAutoField(primary_key=True)
    snyk_id = models.TextField(default="")
    cve_id = models.TextField(default="")
    cve_url = models.TextField(default="")
    cwe_id = models.TextField(default="")
    cwe_url = models.TextField(default="")
    header_title = models.TextField(default="")
    affecting_github = models.TextField(default="")
    versions = models.TextField(default="")
    overview = models.TextField(default="")
    details = models.TextField(default="")
    references = ArrayField(models.TextField(blank=True), default=list)
    credit = models.TextField(default="")
    source_url = models.TextField(default="")
    source = models.TextField(default="")
    disclosed = models.DateTimeField(default=timezone.now)
    published = models.DateTimeField(default=timezone.now)

    objects = models.Manager()

    class Meta:
        ordering = ['snyk_id']
        verbose_name = 'VULNERABILITY_SNYK'
        verbose_name_plural = 'VULNERABILITY_SNYKS_MODIFIED'

    def __str__(self):
        return "{}".format(self.snyk_id)

    def __unicode__(self):
        return "SNYK: {}".format(self.snyk_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["snyk_id"] = self.snyk_id
        data["cve_id"] = self.cve_id
        data["cve_url"] = self.cve_url
        data["cwe_id"] = self.cwe_id
        data["cwe_url"] = self.cwe_url
        data["header_title"] = self.header_title
        data["affecting_github"] = self.affecting_github
        data["versions"] = self.versions
        data["overview"] = self.overview
        data["details"] = self.details
        data["references"] = self.references
        data["credit"] = self.credit
        data["source_url"] = self.source_url
        data["source"] = self.source
        data["disclosed"] = self.disclosed
        data["published"] = self.published
        return data