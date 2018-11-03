from __future__ import unicode_literals

import json

from django.db import models

from django.utils import timezone

from django.contrib.postgres.fields import ArrayField
from django.core import serializers


class VULNERABILITY_NPM(models.Model):
    id = models.BigAutoField(primary_key=True)
    npm_id = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default="")
    title = models.TextField(default="")
    author = models.TextField(default="")
    module_name = models.TextField(default="")
    published_date = models.DateTimeField(default=timezone.now)
    cves = ArrayField(models.TextField, default=list)
    vulnerable_versions = ArrayField(models.TextField, default=list)
    slug = models.TextField(default="")
    overview = models.TextField(default="")
    recommendation = models.TextField(default="")
    references = models.TextField(default="")
    legacy_slug = models.TextField(default="")
    allowwd_scopes = ArrayField(models.TextField, default=list)
    cvss_vector = models.TextField(default="")
    cvss_code = models.TextField(default="")
    cwe = models.TextField(default="")
    source = models.TextField(default="")

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.npm_id)

    def __unicode__(self):
        return "NPM: {}".format(self.npm_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
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
        data["allowed_scopes"] = self.allowwd_scopes
        data["cvss_vector"] = self.cvss_vector
        data["cvss_code"] = self.cvss_code
        data["cwe"] = self.cwe
        data["source"] = self.source

    class Meta:
        ordering = ["npm_id"]
        verbose_name = "VULNERABILITY_NPM"
        verbose_name_plural = "VULNERABILITY_NPMS"


class VULNERABILITY_NPM_NEW(models.Model):
    id = models.BigAutoField(primary_key=True)
    npm_id = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default="")
    title = models.TextField(default="")
    author = models.TextField(default="")
    module_name = models.TextField(default="")
    published_date = models.DateTimeField(default=timezone.now)
    cves = ArrayField(models.TextField, default=list)
    vulnerable_versions = ArrayField(models.TextField, default=list)
    slug = models.TextField(default="")
    overview = models.TextField(default="")
    recommendation = models.TextField(default="")
    references = models.TextField(default="")
    legacy_slug = models.TextField(default="")
    allowwd_scopes = ArrayField(models.TextField, default=list)
    cvss_vector = models.TextField(default="")
    cvss_code = models.TextField(default="")
    cwe = models.TextField(default="")
    source = models.TextField(default="")

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.npm_id)

    def __unicode__(self):
        return "NPM: {}".format(self.npm_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
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
        data["allowed_scopes"] = self.allowwd_scopes
        data["cvss_vector"] = self.cvss_vector
        data["cvss_code"] = self.cvss_code
        data["cwe"] = self.cwe
        data["source"] = self.source

    class Meta:
        ordering = ["npm_id"]
        verbose_name = "VULNERABILITY_NPM_NEW"
        verbose_name_plural = "VULNERABILITY_NPMS_NEW"



class VULNERABILITY_NPM_MODIFIED(models.Model):
    id = models.BigAutoField(primary_key=True)
    npm_id = models.TextField(default="")
    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(default="")
    title = models.TextField(default="")
    author = models.TextField(default="")
    module_name = models.TextField(default="")
    published_date = models.DateTimeField(default=timezone.now)
    cves = ArrayField(models.TextField, default=list)
    vulnerable_versions = ArrayField(models.TextField, default=list)
    slug = models.TextField(default="")
    overview = models.TextField(default="")
    recommendation = models.TextField(default="")
    references = models.TextField(default="")
    legacy_slug = models.TextField(default="")
    allowwd_scopes = ArrayField(models.TextField, default=list)
    cvss_vector = models.TextField(default="")
    cvss_code = models.TextField(default="")
    cwe = models.TextField(default="")
    source = models.TextField(default="")

    objects = models.Manager()

    def __str__(self):
        return "{}".format(self.npm_id)

    def __unicode__(self):
        return "NPM: {}".format(self.npm_id)

    @property
    def data(self):
        data = json.loads(serializers.serialize("json", [self, ]))[0]["fields"]
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
        data["allowed_scopes"] = self.allowwd_scopes
        data["cvss_vector"] = self.cvss_vector
        data["cvss_code"] = self.cvss_code
        data["cwe"] = self.cwe
        data["source"] = self.source

    class Meta:
        ordering = ["npm_id"]
        verbose_name = "VULNERABILITY_NPM_MODIFIED"
        verbose_name_plural = "VULNERABILITY_NPMS_MODIFIED"
