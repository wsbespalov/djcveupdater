from __future__ import unicode_literals

import json

from math import floor

from django.db import models

from django.utils import timezone

from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields import JSONField
from django.core import serializers


from updater_capec.models import VULNERABILITY_CAPEC
from updater_cpe.models import VULNERABILITY_CPE
from updater_cve.models import VULNERABILITY_CVE
from updater_cwe.models import VULNERABILITY_CWE
from updater_npm.models import VULNERABILITY_NPM
from updater_snyk.models import VULNERABILITY_SNYK


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


class STATUS_VULNERABILITIES(models.Model):
    id = models.BigAutoField(primary_key=True)
    name = models.TextField(default="")
    status = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default=timezone.now)
    count = models.IntegerField(default=0)

    objects = models.Manager()

    class Meta:
        verbose_name = "STATUS_VULNERABILITIES"
        verbose_name_plural = "STATUS_VULNERABILITIES"

    def __str__(self):
        return "VULNERABILITIES Status: count: {}, created: {}, updated: {}".format(self.count, self.created, self.updated)

    def __unicode__(self):
        return "VULNERABILITIES Status"

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


undefined = "undefined"
default_vulnerability_id_undefined = "SPVID:undefined:"
default_vulnerability_id_start = "SPVID:"
default_vulnerability_id_separator = ":"


class VULNERABILITIES(models.Model):
    id = models.BigAutoField(primary_key=True)
    vulnerability_id = models.TextField(default=default_vulnerability_id_undefined)
    component = models.TextField(default=undefined)
    created = models.DateTimeField(default=timezone.now)
    published = models.DateTimeField(default=timezone.now)
    modified = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    cvss_time = models.DateTimeField(default=timezone.now)
    cvss_score = models.FloatField(default=0.0)
    cvss_rank = models.IntegerField(default=0)
    cvss_vector = models.TextField(default=undefined)
    title = models.TextField(default=undefined)
    description = models.TextField(default=undefined)
    details = models.TextField(default=undefined)
    recommendations = models.TextField(default=undefined)
    author = models.TextField(default=undefined)
    type = models.TextField(default=undefined)
    source = models.TextField(default=undefined)
    vulnerabe_versions = ArrayField(models.TextField(blank=True), default=list)
    patched_versions = ArrayField(models.TextField(blank=True), default=list)
    access = JSONField(default=default_access)
    impact = JSONField(default=default_impact)
    references = ArrayField(models.TextField(blank=True), default=list)
    component_versions = ArrayField(models.TextField(blank=True), default=list)
    component_versions_string = ArrayField(models.TextField(blank=True), default=list)
    cves = models.ManyToManyField(VULNERABILITY_CVE)
    cpes = models.ManyToManyField(VULNERABILITY_CPE)
    cwes = models.ManyToManyField(VULNERABILITY_CWE)
    npms = models.ManyToManyField(VULNERABILITY_NPM)
    snyks = models.ManyToManyField(VULNERABILITY_SNYK)
    capecs = models.ManyToManyField(VULNERABILITY_CAPEC)

    modification = models.IntegerField(default=0)

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.vulnerability_id)

    def __unicode__(self):
        return "VULNERABILITY: {}".format(self.vulnerability_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
        data["id"] = self.id
        data["_id"] = self.id
        data["__v"] = 0
        data["vulnerability_id"] = self.vulnerability_id
        data["component"] = self.component
        data["Created"] = self.created
        data["Published"] = self.published
        data["Modified"] = self.modified
        data["LastSeen"] = self.last_seen
        data["cvss_time"] = self.cvss_time
        if self.cvss_score == 0:
            data["cvss"] = 10
            data["rank"] = 10
            data["cvss_type"] = "self-assigned"
        else:
            data["cvss"] = self.cvss_score
            data["rank"] = floor(float(self.cvss_score))
            data["cvss_type"] = "auto"
        data["vector_string"] = self.cvss_vector
        data["title"] = self.cvss_vector
        data["description"] = self.description
        data["details"] = self.details
        data["recommendations"] = self.recommendations
        data["author"] = self.author
        data["type"] = self.type
        data["source"] = self.source
        data["vulnerable_versions"] = self.vulnerabe_versions
        data["patched_versions"] = self.patched_versions
        data["access"] = self.access
        data["impact"] = self.impact
        data["references"] = self.references
        data["component_versions"] = self.component_versions
        data["component_versions_string"] = self.component_versions_string
        data["vulnerable_configurations"] = []
        return data


    class Meta:
        ordering = ["vulnerability_id", "modification"]
        verbose_name = "VULNERABILITIES"
        verbose_name_plural = "VULNERABILITIES"

a = """
from updater_vulnerabilities.models import VULNERABILITIES as V
v = V.objects.create(vulnerability_id="SPID-1")
from updater_cve.models import VULNERABILITY_CVE as C
c = C.objects.get(id=25906)
c2 = C.objects.get(id=25907)
v.data
v.cves.add(c)
v.cves.add(c2)
v.save()
v.cves.all()
v.cves.filter(id=25906).delete()
v.cves.all()
"""

