import os
import pytz
from datetime import datetime
import dateparser

from django.utils import timezone
from django.utils.timezone import make_aware
from django.db import transaction

from .text_messages import TextMessages

from .configurations import CVEConfig

from .models import STATUS_CVE
from .models import VULNERABILITY_CVE

from .utils import get_meta_info
from .utils import download_nvd_file_by_year
from .utils import load_cve_items_from_nvd_zipped_file

from .cveitem import CVEItem

LOCAL_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

nvd_directory_path = os.path.join(LOCAL_BASE_DIR, CVEConfig.file_storage_root)

MODIFICATION_CLEAR = 0
MODIFICATION_NEW = 1
MODIFICATION_MODIFIED = 2


def print_debug(message):
    if CVEConfig.debug:
        print(message)

def pack_answer(
        status=TextMessages.error.value,
        message=TextMessages.error.value,
        cve_cnt_before=0,
        cve_cnt_after=0,
        new_cnt=0,
        modified_cnt=0
):
    return dict(
        vulnerability=dict(
            count_before=cve_cnt_before,
            count_after=cve_cnt_after),
        vulnerability_new=dict(
            count=new_cnt),
        vulnerability_modified=dict(
            count=modified_cnt),
        status=status,
        message=message
    )


class CVEController():
    @staticmethod
    def clear_vulnerability_cpe_table():
        for x in VULNERABILITY_CVE.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerability_cve_all_marks():
        entries = VULNERABILITY_CVE.objects.select_for_update().all().defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerability_cve_new_marks():
        entries = VULNERABILITY_CVE.objects.select_for_update().filter(modification=MODIFICATION_NEW).defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerability_cve_modified_marks():
        entries = VULNERABILITY_CVE.objects.select_for_update().filter(modification=MODIFICATION_MODIFIED).defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def count_vulnerability_cve_table():
        return VULNERABILITY_CVE.objects.count()

    @staticmethod
    def count_vulnerability_cve_new_marked():
        return VULNERABILITY_CVE.objects.filter(modification=MODIFICATION_NEW).count()

    @staticmethod
    def count_vulnerability_cve_modified_marked():
        return VULNERABILITY_CVE.objects.filter(modification=MODIFICATION_MODIFIED).count()

    @staticmethod
    def get_vulnerability_cve_new():
        return VULNERABILITY_CVE.objects.filter(modification=MODIFICATION_NEW)

    @staticmethod
    def get_vulnerability_cve_modified():
        return VULNERABILITY_CVE.objects.filter(modification=MODIFICATION_MODIFIED)

    @staticmethod
    def append_cve_in_vulnerability_cve_table(cve):
        vulner = VULNERABILITY_CVE.objects.filter(cve_id=cve["cve_id"]).first()
        if vulner is None:
            return VULNERABILITY_CVE.objects.create(
                cve_id=cve["cve_id"],
                cwe=cve["cwe"],
                references=cve["references"],
                vulnerable_configuration=cve["vulnerable_configuration"],
                data_type=cve["data_type"],
                data_version=cve["data_version"],
                data_format=cve["data_format"],
                description=cve["description"],
                published=cve["published"],
                modified=cve["modified"],
                access=cve["access"],
                impact=cve["impact"],
                vector_string=cve["vector_string"],
                cvss_time=cve["cvss_time"],
                cvss=cve["cvss"],
                modification=MODIFICATION_NEW
            )

    @staticmethod
    def mark_cve_in_vulnerability_cve_table_as_new(cve):
        vulner = VULNERABILITY_CVE.objects.filter(cve_id=cve["cve_id"]).defer("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_NEW
            vulner.save()

    @staticmethod
    def mark_cve_in_vulnerability_cve_table_as_modified(cve):
        vulner = VULNERABILITY_CVE.objects.filter(cve_id=cve["cve_id"]).defer("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_MODIFIED
            vulner.save()

    @staticmethod
    def save_status_in_local_status_table(status: dict):
        name = status.get("name", "cve")
        obj = STATUS_CVE.objects.filter(name=name)
        if obj:
            return STATUS_CVE.objects.filter(name=name).update(
                status=status.get("status", ""),
                count=status.get("count", 0),
                updated=status.get("updated", timezone.now())
            )
        return STATUS_CVE.objects.create(
            name=name,
            status=status.get("status", ""),
            count=status.get("count", 0),
            created=status.get("created", timezone.now()),
            updated=status.get("updated", timezone.now())
        )

    @staticmethod
    def get_status_from_local_status_table(name="cve") -> dict:
        objects = STATUS_CVE.objects.filter(name=name)
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
        obj = STATUS_CVE.objects.filter(name=name)
        if obj:
            return obj.delete()

    @staticmethod
    def save_status_in_global_status_table(status: dict):
        pass

    @staticmethod
    def get_status_from_global_status_table() -> dict:
        pass

    @staticmethod
    def check_if_cve_item_changed(old, new):
        if old["cwe"] != new["cwe"] or \
            old["references"] != new["references"] or \
            old["vulnerable_configuration"] != new["vulnerable_configuration"] or\
            old["data_type"] != new["data_type"] or \
            old["data_version"] != new["data_version"] or \
            old["data_format"] != new["data_format"] or \
            old["description"] != new["description"] or \
            old["published"] != new["published"] or \
            old["modified"] != new["modified"] or \
            old["access"] != new["access"] or\
            old["impact"] != new["impact"] or \
            old["vector_string"] != new["vector_string"] or \
            old["cvss_time"] != new["cvss_time"] or \
                old["cvss"] != new["cvss"]:
            return True
        return False

    @staticmethod
    def update_cve_in_cve_table(cve):
        vulner = VULNERABILITY_CVE.objects.filter(cve_id=cve["cve_id"]).first()
        if vulner is not None:
            vulner.cve_id=cve["cve_id"],
            vulner.cwe=cve["cwe"],
            vulner.references=cve["references"],
            vulner.vulnerable_configuration=cve["vulnerable_configuration"],
            vulner.data_type=cve["data_type"],
            vulner.data_version=cve["data_version"],
            vulner.data_format=cve["data_format"],
            vulner.description=cve["description"],
            vulner.published=cve["published"],
            vulner.modified=cve["modified"],
            vulner.access=cve["access"],
            vulner.impact=cve["impact"],
            vulner.vector_string=cve["vector_string"],
            vulner.cvss_time=cve["cvss_time"],
            vulner.cvss=cve["cvss"]
            vulner.modification=MODIFICATION_MODIFIED
            vulner.save()

    def create_or_update_cve_vulnerability(self, cve):
        vulner = VULNERABILITY_CVE.objects.filter(cve_id=cve["cve_id"]).first()
        if vulner is None:
            self.append_cve_in_vulnerability_cve_table(cve)
        else:
            if self.check_if_cve_item_changed(vulner.data, cve):
                self.update_cve_in_cve_table(cve)

    def stats(self):
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            cve_cnt_before=self.count_vulnerability_cve_table(),
            cve_cnt_after=self.count_vulnerability_cve_table(),
            new_cnt=self.count_vulnerability_cve_new_marked(),
            modified_cnt=self.count_vulnerability_cve_modified_marked()
        )

    def update(self):
        if CVEConfig.drop_core_table:
            self.clear_vulnerability_cpe_table()
        self.clear_vulnerability_cve_all_marks()
        print_debug("create parsers")
        count_before = count_after = self.count_vulnerability_cve_table()
        start_year = CVEConfig.start_year
        current_year = timezone.now().year
        if self.count_vulnerability_cve_table() == 0:
            for year in range(start_year, current_year + 1):
                print_debug("clear year: {}".format(year))
                filename = "nvdcve-1.0-{}.json.zip".format(year)
                self.delete_row_from_local_status_table_by_name(filename)
        count = 0
        for year in range(start_year, current_year + 1):
            filename = "nvdcve-1.0-{}.json.zip".format(year)
            print_debug("process file: {}".format(filename))
            full_path = os.path.join(nvd_directory_path, filename)
            stat = self.get_status_from_local_status_table(filename)
            stat_status = stat.get("status", "")
            stat_ts = stat.get("updated", timezone.now())
            (meta, success) = get_meta_info(filename)
            if success:
                ts_meta_string = meta.get("last_modified", None)
                if ts_meta_string is not None:
                    ts_meta = ts_meta_string
                else:
                    ts_meta = timezone.now()
                size = meta.get("size", 0)
                if not stat.get("exists", False):
                    stat_status = "updating"
                    self.save_status_in_local_status_table(dict(
                        name=filename,
                        status="modified",
                        count=size
                    ))
                else:
                    if stat_status != "updating":
                        if ts_meta != stat_ts:
                            self.save_status_in_local_status_table(dict(
                                name=filename,
                                status="modified",
                                updated=ts_meta
                            ))
                        else:
                            self.save_status_in_local_status_table(dict(
                                name=filename,
                                status="not modified",
                                updated=ts_meta
                            ))
            else:
                return pack_answer(
                    status=TextMessages.error.value,
                    message=TextMessages.cant_download_file.value,
                    cve_cnt_before=count_before,
                    cve_cnt_after=count_after,
                    new_cnt=0,
                    modified_cnt=0
                )
            if stat_status == "not modified":
                print_debug("File {} was not modified - skip it")
            elif stat_status == "modified" or stat_status == "updating":
                self.save_status_in_local_status_table(dict(
                    name=filename,
                    status="updating",
                    updated=ts_meta
                ))
                if download_nvd_file_by_year(year):
                    cve_items_from_file, file_data_timestamp = load_cve_items_from_nvd_zipped_file(full_path)
                    for value in cve_items_from_file:
                        cve = CVEItem(value).to_json()
                        cve["published"] = make_aware(cve["published"])
                        cve["modified"] = make_aware(cve["modified"])
                        cve["cvss_time"] = dateparser.parse(file_data_timestamp)
                        print_debug("process cve # {} with ID: {}".format(count, cve["cve_id"]))
                        count += 1

                        self.create_or_update_cve_vulnerability(cve)

        count_after = self.count_vulnerability_cve_table()
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            cve_cnt_before=count_before,
            cve_cnt_after=count_after,
            new_cnt=self.count_vulnerability_cve_new_marked(),
            modified_cnt=self.count_vulnerability_cve_modified_marked()
        )
