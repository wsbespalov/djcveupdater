from __future__ import unicode_literals
import json

from django.db import models

# Create your models here.
from django.utils import timezone

class VULNERABILITY_CWE(models.Model):
    cwe_id = models.TextField(unique=True)

    objects = models.Manager()

    class Meta:
        ordering = ['cwe_id']
        verbose_name = 'VULNERABILITY_CWE'
        verbose_name_plural = 'VULNERABILITY_CWES'


class VULNERABILITY_CWE_NEW(VULNERABILITY_CWE):
    class Meta:
        ordering = ['cwe_id']
        verbose_name = 'VULNERABILITY_CWE_NEW'
        verbose_name_plural = 'VULNERABILITY_CWES_NEW'


class VULNERABILITY_CWE_MODIFIED(VULNERABILITY_CWE):
    class Meta:
        ordering = ['cwe_id']
        verbose_name = 'VULNERABILITY_CWE'
        verbose_name_plural = 'VULNERABILITY_CWES_MODIFIED'