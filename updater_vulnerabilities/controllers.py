import os
from math import floor
import pytz
from datetime import datetime
import dateparser

from django.utils import timezone
from django.utils.timezone import make_aware
from django.db import transaction

from .models import STATUS_VULNERABILITIES
from .models import VULNERABILITIES


from .text_messages import TextMessages

from .configurations import VULNERABILITIESConfig

from .spid import generate_id

from updater_cve.controllers import CVEController


LOCAL_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODIFICATION_CLEAR = 0
MODIFICATION_NEW = 1
MODIFICATION_MODIFIED = 2


def print_debug(message):
    if VULNERABILITIESConfig.debug:
        print(message)


def ask_input(message="Press Enter..."):
    if VULNERABILITIESConfig.enable_input:
        input(message)


def pack_answer(
        status=TextMessages.error.value,
        message=TextMessages.error.value,
        vulner_cnt_before=0,
        vulner_cnt_after=0,
        new_cnt=0,
        modified_cnt=0
):
    return dict(
        vulnerability=dict(
            count_before=vulner_cnt_before,
            count_after=vulner_cnt_after),
        vulnerability_new=dict(
            count=new_cnt),
        vulnerability_modified=dict(
            count=modified_cnt),
        status=status,
        message=message
    )


class VULNERABILITIESController():

    def __init__(self, *args, **kwargs):
        self.cve_controller = CVEController()
        return super().__init__(*args, **kwargs)

    @staticmethod
    def clear_vulnerabilities_table():
        for x in VULNERABILITIES.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerabilities_all_marks():
        entries = VULNERABILITIES.objects.select_for_update().all().only("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerabilities_new_marks():
        entries = VULNERABILITIES.objects.select_for_update().filter(modification=MODIFICATION_NEW).only("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerabilities_modified_marks():
        entries = VULNERABILITIES.objects.select_for_update().filter(modification=MODIFICATION_MODIFIED).only("modification")
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
    def mark_vulnerability_in_vulnerabilities_table_as_new(vulnerability):
        vulner = VULNERABILITIES.objects.filter(vulnerability_id=vulnerability["vulnerability_id"]).only("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_NEW
            vulner.save()

    @staticmethod
    def mark_vulnerability_in_vulnerabilities_table_as_modified(vulnerability):
        vulner = VULNERABILITIES.objects.filter(vulnerability_id=vulnerability["vulnerability_id"]).only("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_MODIFIED
            vulner.save()

    @staticmethod
    def save_status_in_local_status_table(status: dict):
        name = status.get("name", "vulnerability")
        obj = STATUS_VULNERABILITIES.objects.filter(name=name)
        if obj:
            return STATUS_VULNERABILITIES.objects.filter(name=name).update(
                status=status.get("status", ""),
                count=status.get("count", 0),
                updated=status.get("updated", timezone.now())
            )
        return STATUS_VULNERABILITIES.objects.create(
            name=name,
            status=status.get("status", ""),
            count=status.get("count", 0),
            created=status.get("created", timezone.now()),
            updated=status.get("updated", timezone.now())
        )

    @staticmethod
    def get_status_from_local_status_table(name="vulnerability"):
        objects = STATUS_VULNERABILITIES.objects.filter(name=name)
        if objects:
            o = objects[0]
            response = o.data
            response["exists"] = True
            return response
        return dict(
            exists=False,
            count=0,
            name=name,
            status="",
            created=timezone.now(),
            updated=timezone.now()
        )

    @staticmethod
    def delete_row_from_local_status_table_by_name(name):
        obj = STATUS_VULNERABILITIES.objects.filter(name=name)
        if obj:
            return obj.delete()

    @staticmethod
    def save_status_in_global_status_table(status: dict):
        pass

    @staticmethod
    def get_status_from_global_status_table():
        pass

    def stats(self):
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            vulner_cnt_before=self.count_vulnerabilities_table(),
            vulner_cnt_after=self.count_vulnerabilities_table(),
            new_cnt=self.count_vulnerabilities_new_marked(),
            modified_cnt=self.count_vulnerabilities_modified_marked()
        )

    @staticmethod
    def create_cve_source(cve_id):
        return 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cve_id


    @staticmethod
    def check_if_vulnerability_item_changed__compare_by_json_content(old, new):
        if old["component"] != new["component"] or \
            old["modified"] != new["modified"] or \
            old["last_seen"] != new["last_seen"] or \
            old["cvss_time"] != new["cvss_time"] or \
            old["cvss_score"] != new["cvss_score"] or \
            old["cvss_rank"] != new["cvss_rank"] or \
            old["cvss_vector"] != new["cvss_vector"] or \
            old["title"] != new ["title"] or \
            old["description"] != new["description"] or \
            old["details"] != new["details"] or \
            old["recommendations"] != new["recommendations"] or \
            old["author"] != new["author"] or \
            old["type"] != new["type"] or \
            old["source"] != new["source"] or \
            old["vulnerable_versions"] != new["vulnerable_versions"] or \
            old["patched_versions"] != new["patched_versions"] or \
            old["access"] != new["access"] or \
            old["impact"] != new["references"] or \
            old["references"] != new["references"] or \
                old["component_versions_string"] != new["component_versions_string"]:
            return True
        return False

    def create_vulner_in_vulnerability_table__from_json(self, vulnerability):
        uid = -1
        vulner = VULNERABILITIES.objects.filter(vulnerability_id=vulnerability["vulnerability_id"]).first()
        if vulner is None:
            vulner = VULNERABILITIES(
                vulnerability_id=vulnerability["vulnerability_id"],
                parent_id=vulnerability["parent_id"],
                component=vulnerability["component"],
                published=vulnerability["published"],
                modified=vulnerability["modified"],
                cvss_time=vulnerability["cvss_time"],
                cvss_score=vulnerability["cvss_score"],
                cvss_rank=floor(vulnerability["cvss"]),
                cvss_vector=vulnerability["cvss_vector"],
                description=vulnerability["description"],
                type=vulnerability["type"],
                access=vulnerability["access"],
                impact=vulnerability["impact"],
                references=vulnerability["references"],
                cpe_list=vulnerability["cpe_list"],
                component_versions=vulnerability["component_versions"],
                component_versions_string=vulnerability["component_versions_string"],
                source=vulnerability["source"],
                cve_list=vulnerability["cve_list"],
                cwe_list=vulnerability["cwe_list"],
                capec_list=vulnerability["capec_list"],
                cwe_id_list=vulnerability["cwe_id_list"],
                modification=MODIFICATION_NEW
            )
            vulner.save()
            uid = vulner.id
        return uid
        

    def update_vulner_in_vulnerability_table__from_json(self, vulnerability):
        vulner = VULNERABILITIES.objects.filter(vulnerability_id=vulnerability["vulnerability_id"]).first()
        if vulner is not None:
                vulner.component=vulnerability["component"]
                vulner.parent_id=vulnerability["parent_id"]
                vulner.published=vulnerability["published"]
                vulner.modified=vulnerability["modified"]
                vulner.cvss_time=vulnerability["cvss_time"]
                vulner.cvss_score=vulnerability["cvss_score"]
                vulner.cvss_rank=floor(vulnerability["cvss"])
                vulner.cvss_vector=vulnerability["cvss_vector"]
                vulner.description=vulnerability["description"]
                vulner.type=vulnerability["type"]
                vulner.access=vulnerability["access"]
                vulner.impact=vulnerability["impact"]
                vulner.references=vulnerability["references"]
                vulner.cpe_list=vulnerability["cpe_list"]
                vulner.component_versions=vulnerability["component_versions"]
                vulner.component_versions_string=vulnerability["component_versions_string"]
                vulner.source=vulnerability["source"]
                vulner.cve_list=vulnerability["cve_list"]
                vulner.cwe_list=vulnerability["cwe_list"]
                vulner.capec_list=vulnerability["capec_list"]
                vulner.cwe_id_list=vulnerability["cwe_id_list"]
                vulner.modification=MODIFICATION_MODIFIED
                vulner.save()


    def create_vulnerability_cv_and_relations_by_componentversions(uid):
        pass


    def update_vulnerabilities_from_cve_by_id(self, cve_ids):
        for cve_id in cve_ids:
            # Check if this vulnerability already in VULNERABILITIES table: new, modified, skipped
            # Check with list of @filter by parent_id, no @first

            print_debug("process CVE with ID: {}".format(cve_id))

            # Get all Vulners from VULNERABILITY table with parent_id == cve_id

            vulner_with_cve_id_as_parent = VULNERABILITIES.objects.filter(parent_id=cve_id).first()
            
            vulnerability_cve = self.cve_controller.get_one_cve_by_cve_id(cve_id) # -> return Database object
            
            if vulner_with_cve_id_as_parent is not None:
                # this is new vulner
                print_debug("this is a new Vulner")
                generated_vulnerability_id = generate_id(original_id=vulnerability_cve.cve_id, source='cve')
                cve_source = self.create_cve_source(cve_id)
                filtered_and_extended_cve = vulnerability_cve.data
                filtered_and_extended_cve["parent_id"] = cve_id
                filtered_and_extended_cve["type"] = "CVE"
                filtered_and_extended_cve["cvss_score"] = vulnerability_cve.cvss
                filtered_and_extended_cve["cvss_vector"] = vulnerability_cve.vector_string
                filtered_and_extended_cve["vulnerability_id"] = generated_vulnerability_id
                uid = self.create_vulner_in_vulnerability_table__from_json(filtered_and_extended_cve)
                self.create_vulnerability_cv_and_relations_by_componentversions(uid)
            else:
                # check, which vulners changed
                print_debug("this is a NOT new Vulner, so check if it was changed in source")
                result = self.check_if_vulnerability_item_changed__compare_by_json_content(vulner_with_cve_id_as_parent, vulnerability_cve)
                
                pass



            # # resolve
            # if result == "new":
            #     # TODO: reformat vulner
            #     # Generate our special ID
                

            #     reformatted_vulnerability = None # !!!
            #     self.create_vulner_in_vulnerability_table__from_json(reformatted_vulnerability)
            # elif result == "modified":
            #     # TODO: reformat vulner
            #     reformatted_vulnerability = None # !!!
            #     self.update_vulner_in_vulnerability_table__from_json(reformatted_vulnerability)
            # else:
            #     pass

    def update(self):
        # for test

        # mark one vulner as "new"

        # # #
        # process CVE items, marked as "new"
        cve_new_ids = self.cve_controller.get_vulnerability_cve_new_ids()
        result = self.update_vulnerabilities_from_cve_by_id(cve_new_ids)
        cve_new_ids = []

        # process CVE items, marked as "modified"
        # cve_modified_ids = CVEController.get_vulnerability_cve_modified_ids()
        # result = self.update_vulnerabilities_from_cve_by_id(cve_modified_ids)
        # cve_modified_ids = []

        print_debug("complete...")
        ask_input()