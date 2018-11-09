from __future__ import unicode_literals

import json

from django.db import models

from django.utils import timezone

from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields import JSONField
from django.core import serializers


def default_access():
    return dict(
        vector="",
        complexity="",
        authentication=""
    )

def default_impact():
    return dict(
        confidentiality="",
        integrity="",
        availability="",
    )


class STATUS_CVE(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default=timezone.now)
    count = models.IntegerField(default=0)

    objects = models.Manager()

    class Meta:
        verbose_name = "STATUS_CVE"
        verbose_name_plural = "STATUS_CVES"

    def __str__(self):
        return "CVE Status: count: {}, created: {}, updated: {}".format(self.count, self.created, self.updated)

    def __unicode__(self):
        return "CVE Status"

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


class VULNERABILITY_CVE(models.Model):
    id = models.BigAutoField(primary_key=True)
    cve_id = models.TextField(default="")
    cwe = ArrayField(models.TextField(blank=True), default=list)
    references = ArrayField(models.TextField(blank=True), default=list)
    vulnerable_configuration = models.TextField(default="")
    data_type = models.TextField(default="")
    data_version = models.TextField(default="")
    data_format = models.TextField(default="")
    description = models.TextField(default="")
    published = models.DateTimeField(default=timezone.now)
    modified = models.DateTimeField(default=timezone.now)
    access = JSONField(default=default_access)
    impact = JSONField(default=default_impact)
    vector_string = models.TextField(default="")
    cvss_time = models.DateTimeField(default=timezone.now)
    cvss = models.FloatField(default=0.0)

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.cve_id)

    def __unicode__(self):
        return "CVE: {}".format(self.cve_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["cve_id"] = self.cve_id
        data["cwe"] = self.cwe
        data["references"] = self.references
        data["vulnerable_configuration"] = self.vulnerable_configuration
        data["data_type"] = self.data_type
        data["data_version"] = self.data_version
        data["data_format"] = self.data_format
        data["description"] = self.description
        data["published"] = self.published
        data["modified"] = self.modified
        data["access"] = self.access
        data["impact"] = self.impact
        data["vector_string"] = self.vector_string
        data["cvss_time"] = self.cvss_time
        data["cvss"] = self.cvss
        return data

    class Meta:
        ordering = ["cve_id"]
        verbose_name = "VULNERABILITY_CVE"
        verbose_name_plural = "VULNERABILITY_CVES"


class VULNERABILITY_CVE_NEW(models.Model):
    id = models.BigAutoField(primary_key=True)
    cve_id = models.TextField(default="")
    cwe = ArrayField(models.TextField(blank=True), default=list)
    references = ArrayField(models.TextField(blank=True), default=list)
    vulnerable_configuration = models.TextField(default="")
    data_type = models.TextField(default="")
    data_version = models.TextField(default="")
    data_format = models.TextField(default="")
    description = models.TextField(default="")
    published = models.DateTimeField(default=timezone.now)
    modified = models.DateTimeField(default=timezone.now)
    access = JSONField(default=default_access)
    impact = JSONField(default=default_impact)
    vector_string = models.TextField(default="")
    cvss_time = models.DateTimeField(default=timezone.now)
    cvss = models.FloatField(default=0.0)

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.cve_id)

    def __unicode__(self):
        return "CVE: {}".format(self.cve_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["cve_id"] = self.cve_id
        data["cwe"] = self.cwe
        data["references"] = self.references
        data["vulnerable_configuration"] = self.vulnerable_configuration
        data["data_type"] = self.data_type
        data["data_version"] = self.data_version
        data["data_format"] = self.data_format
        data["description"] = self.description
        data["published"] = self.published
        data["modified"] = self.modified
        data["access"] = self.access
        data["impact"] = self.impact
        data["vector_string"] = self.vector_string
        data["cvss_time"] = self.cvss_time
        data["cvss"] = self.cvss
        return data

    class Meta:
        ordering = ["cve_id"]
        verbose_name = "VULNERABILITY_CVE_NEW"
        verbose_name_plural = "VULNERABILITY_CVES_NEW"


class VULNERABILITY_CVE_MODIFIED(models.Model):
    id = models.BigAutoField(primary_key=True)
    cve_id = models.TextField(default="")
    cwe = ArrayField(models.TextField(blank=True), default=list)
    references = ArrayField(models.TextField(blank=True), default=list)
    vulnerable_configuration = models.TextField(default="")
    data_type = models.TextField(default="")
    data_version = models.TextField(default="")
    data_format = models.TextField(default="")
    description = models.TextField(default="")
    published = models.DateTimeField(default=timezone.now)
    modified = models.DateTimeField(default=timezone.now)
    access = JSONField(default=default_access)
    impact = JSONField(default=default_impact)
    vector_string = models.TextField(default="")
    cvss_time = models.DateTimeField(default=timezone.now)
    cvss = models.FloatField(default=0.0)

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.cve_id)

    def __unicode__(self):
        return "CVE: {}".format(self.cve_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["cve_id"] = self.cve_id
        data["cwe"] = self.cwe
        data["references"] = self.references
        data["vulnerable_configuration"] = self.vulnerable_configuration
        data["data_type"] = self.data_type
        data["data_version"] = self.data_version
        data["data_format"] = self.data_format
        data["description"] = self.description
        data["published"] = self.published
        data["modified"] = self.modified
        data["access"] = self.access
        data["impact"] = self.impact
        data["vector_string"] = self.vector_string
        data["cvss_time"] = self.cvss_time
        data["cvss"] = self.cvss
        return data

    class Meta:
        ordering = ["cve_id"]
        verbose_name = "VULNERABILITY_CVE_MODIFIED"
        verbose_name_plural = "VULNERABILITY_CVES_MODIFIED"