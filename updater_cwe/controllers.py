from xml.sax import make_parser

from django.utils import timezone
from django.utils.timezone import make_aware
from django.db import transaction

from .utils import upload_file
from .utils import read_file
from .utils import time_string_to_datetime

from .handlers import CWEHandler

from .models import STATUS_CWE
from .models import VULNERABILITY_CWE

from .configurations import CWEConfig

from .text_messages import TextMessages

MODIFICATION_CLEAR = 0
MODIFICATION_NEW = 1
MODIFICATION_MODIFIED = 2


def print_debug(message):
    if CWEConfig.debug:
        print(message)


def pack_answer(
        status=TextMessages.error.value,
        message=TextMessages.error.value,
        cwe_cnt_before=0,
        cwe_cnt_after=0,
        new_cnt=0,
        modified_cnt=0
):
    return dict(
        vulnerability=dict(
            count_before=cwe_cnt_before,
            count_after=cwe_cnt_after),
        vulnerability_new=dict(
            count=new_cnt),
        vulnerability_modified=dict(
            count=modified_cnt),
        status=status,
        message=message
    )


class CWEController(object):

    @staticmethod
    def clear_vulnerability_cwe_table():
        for x in VULNERABILITY_CWE.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerability_capec_all_marks():
        entries = VULNERABILITY_CWE.objects.select_for_update().all().defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerability_cwe_new_marks():
        entries = VULNERABILITY_CWE.objects.select_for_update().filter(modification=MODIFICATION_NEW).defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerability_cwe_modified_marks():
        entries = VULNERABILITY_CWE.objects.select_for_update().filter(modification=MODIFICATION_MODIFIED).defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def count_vulnerability_cwe_table():
        return VULNERABILITY_CWE.objects.count()

    @staticmethod
    def count_vulnerability_cwe_new_marked():
        return VULNERABILITY_CWE.objects.filter(modification=MODIFICATION_NEW).count()

    @staticmethod
    def count_vulnerability_cwe_modified_marked():
        return VULNERABILITY_CWE.objects.filter(modification=MODIFICATION_MODIFIED).count()

    @staticmethod
    def get_vulnerability_cwe_new():
        return VULNERABILITY_CWE.objects.filter(modification=MODIFICATION_NEW)

    @staticmethod
    def get_vulnerability_cwe_modified():
        return VULNERABILITY_CWE.objects.filter(modification=MODIFICATION_MODIFIED)

    @staticmethod
    def append_cwe_in_vulnerability_cwe_table(cwe):
        vulner = VULNERABILITY_CWE.objects.filter(cwe_id=cwe["cwe_id"]).first()
        if vulner is None:
            return VULNERABILITY_CWE.objects.create(
                cwe_id=cwe['cwe_id'],
                name=cwe['name'],
                status=cwe['status'],
                weaknesses=cwe['weaknesses'],
                description_summary=cwe['description_summary'],
                modification=MODIFICATION_NEW
            )

    @staticmethod
    def mark_cwe_in_vulnerability_cwe_table_as_new(cwe):
        vulner = VULNERABILITY_CWE.objects.filter(cwe_id=cwe["cwe_id"]).defer("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_NEW
            vulner.save()

    @staticmethod
    def mark_cwe_in_vulnerability_cwe_table_as_modified(cwe):
        vulner = VULNERABILITY_CWE.objects.filter(cwe_id=cwe["cwe_id"]).defer("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_MODIFIED
            vulner.save()

    @staticmethod
    def save_status_in_local_status_table(status: dict):
        name = status.get("name", "cwe")
        obj = STATUS_CWE.objects.filter(name=name)
        if obj:
            return STATUS_CWE.objects.filter(name=name).update(
                status=status.get("status", ""),
                count=status.get("count", 0),
                updated=status.get("updated", timezone.now())
            )
        return STATUS_CWE.objects.create(
            name=name,
            status=status.get("status", ""),
            count=status.get("count", 0),
            created=status.get("created", timezone.now()),
            updated=status.get("updated", timezone.now())
        )

    @staticmethod
    def get_status_from_local_status_table(name="cwe") -> dict:
        objects = STATUS_CWE.objects.filter(name=name)
        if objects:
            o = objects[0]
            response = o.data
            response["exists"] = True
            return response
        return dict(
            exists=False,
            count=0,
            created=timezone.now(),
            updated=timezone.now()
        )

    @staticmethod
    def save_status_in_global_status_table(status: dict):
        pass

    @staticmethod
    def get_status_from_global_status_table() -> dict:
        pass


    @staticmethod
    def check_if_cwe_item_changed(old, new):
        if old["name"] != new["name"] or \
            old["status"] != new["status"] or \
            old["weaknesses"] != new["weaknesses"] or \
                old["description_summary"] != new["description_summary"]:
            return True
        return False

    @staticmethod
    def update_cwe_in_cwe_table(cwe):
        vulner = VULNERABILITY_CWE.objects.filter(cwe_id=cwe["cwe_id"]).first()
        if vulner is not None:
            vulner.name=cwe['name'],
            vulner.status=cwe['status'],
            vulner.weaknesses=cwe['weaknesses'],
            vulner.description_summary=cwe['description_summary']
            vulner.modification=MODIFICATION_MODIFIED
            vulner.save()

    def create_or_update_cwe_vulnerability(self, cwe):
        vulner = VULNERABILITY_CWE.objects.filter(cwe_id=cwe['cwe_id']).first()
        if vulner is None:
            self.append_cwe_in_vulnerability_cwe_table(cwe)
            return "created"
        else:
            if self.check_if_cwe_item_changed(vulner.data, cwe):
                self.update_cwe_in_cwe_table(cwe)
                return "updated"
            return "skipped"

    def stats(self):
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            cwe_cnt_before=self.count_vulnerability_cwe_table(),
            cwe_cnt_after=self.count_vulnerability_cwe_table(),
            new_cnt=self.count_vulnerability_cwe_new_marked(),
            modified_cnt=self.count_vulnerability_cwe_modified_marked()
        )

    @staticmethod
    def set_state_in_status_table(status):
        pass

    def update(self):
        if CWEConfig.drop_core_table:
            self.clear_vulnerability_cwe_table()
        self.clear_vulnerability_capec_all_marks()
        print_debug("create parsers")
        count_before = count_after = self.count_vulnerability_cwe_table()
        parser = make_parser()
        cwe_handler = CWEHandler()
        parser.setContentHandler(cwe_handler)
        print_debug("download file")
        (file_path, success, last_modified, size, fmt) = upload_file()
        if success and file_path != '':
            # FIXME: Make last_modified comparison
            (f, success, message) = read_file(file_path)
            if f is None or not success:
                return pack_answer(
                    status=TextMessages.exception.value,
                    message=message,
                    cwe_cnt_before=count_before,
                    cwe_cnt_after=count_after,
                    new_cnt=0,
                    modified_cnt=0
                )
            print_debug("parse file")
            parser.parse(f)

            count = 0
            for cwe in cwe_handler.cwe:
                print_debug('processing: {}'.format(count))
                count += 1
                cwe['cwe_id'] = 'CWE-{}'.format(cwe['id'])
                cwe['description_summary'] = cwe['description_summary'].replace("\t\t\t\t\t", " ")

                self.create_or_update_cwe_vulnerability(cwe)

            count_after = self.count_vulnerability_cwe_table()
            self.save_status_in_local_status_table(dict(
                name="cwe",
                count=count_after,
                updated=last_modified,
                status="updated"
            ))
            return pack_answer(
                status=TextMessages.ok.value,
                message=TextMessages.cwe_updated.value,
                cwe_cnt_before=count_before,
                cwe_cnt_after=count_after,
                new_cnt=self.count_vulnerability_cwe_new_marked(),
                modified_cnt=self.count_vulnerability_cwe_modified_marked()
            )
        return pack_answer(
            status=TextMessages.error.value,
            message=TextMessages.cant_download_file.value,
            cwe_cnt_before=count_before,
            cwe_cnt_after=count_after,
            new_cnt=0,
            modified_cnt=0
        )
