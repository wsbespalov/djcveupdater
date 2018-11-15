import os
import pytz
from datetime import datetime
import dateparser

from django.utils import timezone
from django.utils.timezone import make_aware
from django.db import transaction

from .models import VULNERABILITIES

from .configurations import VULNERABILITIESConfig

LOCAL_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODIFICATION_CLEAR = 0
MODIFICATION_NEW = 1
MODIFICATION_MODIFIED = 2


def print_debug(message):
    if VULNERABILITIESConfig.debug:
        print(message)


class VULNERABILITIESController():

    @staticmethod
    def count_vulnerabilities_table():
        for x in VULNERABILITIES.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerabilities_all_marks():
        entries = VULNERABILITIES.objects.select_for_update().all().defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerabilities_new_marks():
        entries = VULNERABILITIES.objects.select_for_update().filter(modification=MODIFICATION_NEW).defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerabilities_modified_marks():
        entries = VULNERABILITIES.objects.select_for_update().filter(modification=MODIFICATION_MODIFIED).defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def count_vulnerabilities_table():
        return VULNERABILITIES.objects.count()

    @staticmethod
    def count_vulnerabilities_new_marked():
        return VULNERABILITIES.objects.filter(modification=MODIFICATION_NEW).count()

    @staticmethod
    def count_vulnerabilities_modified_marked():
        return VULNERABILITIES.objects.filter(modification=MODIFICATION_MODIFIED).count()

    @staticmethod
    def get_vulnerabilities_new():
        return VULNERABILITIES.objects.filter(modification=MODIFICATION_NEW)

    @staticmethod
    def get_vulnerabilities_modified():
        return VULNERABILITIES.objects.filter(modification=MODIFICATION_MODIFIED)

    @staticmethod
    def append_vilnerability_in_vulnerabilities_table(vulnerability):
        
        
        
        
        
        
        
        pass

    @staticmethod
    def mark_vilnerability_in_vulnerabilities_table_as_new(cve):
        vulner = VULNERABILITIES.objects.filter(vulnerability_id=cve["vulnerability_id"]).defer("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_NEW
            vulner.save()

    @staticmethod
    def mark_vilnerability_in_vulnerabilities_table_as_modified(cve):
        vulner = VULNERABILITIES.objects.filter(vulnerability_id=cve["vulnerability_id"]).defer("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_MODIFIED
            vulner.save()
