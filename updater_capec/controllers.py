from xml.sax import make_parser

from django.utils import timezone
from django.db import transaction

from .utils import upload_file
from .utils import read_file

from .handlers import CAPECHandler

from .models import VULNERABILITY_CAPEC
from .models import STATUS_CAPEC

from .configurations import CAPECConfig

from .text_messages import TextMessages

MODIFICATION_CLEAR = 0
MODIFICATION_NEW = 1
MODIFICATION_MODIFIED = 2


def print_debug(message):
    if CAPECConfig.debug:
        print(message)


def pack_answer(
        status=TextMessages.error.value,
        message=TextMessages.error.value,
        capec_cnt_before=0,
        capec_cnt_after=0,
        new_cnt=0,
        modified_cnt=0
):
    return dict(
        vulnerability=dict(
            count_before=capec_cnt_before,
            count_after=capec_cnt_after),
        vulnerability_new=dict(
            count=new_cnt),
        vulnerability_modified=dict(
            count=modified_cnt),
        status=status,
        message=message
    )


class CAPECController(object):

    @staticmethod
    def clear_vulnerability_capec_table():
        for x in VULNERABILITY_CAPEC.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerability_capec_all_marks():
        entries = VULNERABILITY_CAPEC.objects.select_for_update().all().only("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerability_capec_new_marks():
        entries = VULNERABILITY_CAPEC.objects.select_for_update().filter(modification=MODIFICATION_NEW).only("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerability_capec_modified_marks():
        entries = VULNERABILITY_CAPEC.objects.select_for_update().filter(modification=MODIFICATION_MODIFIED).only("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def count_vulnerability_capec():
        return VULNERABILITY_CAPEC.objects.count()

    @staticmethod
    def count_vulnerability_capec_new_marked():
        return VULNERABILITY_CAPEC.objects.filter(modification=MODIFICATION_NEW).count()

    @staticmethod
    def count_vulnerability_capec_modified_marked():
        return VULNERABILITY_CAPEC.objects.filter(modification=MODIFICATION_MODIFIED).count()

    @staticmethod
    def get_vulnerability_capec_new():
        return VULNERABILITY_CAPEC.objects.filter(modification=MODIFICATION_NEW)

    @staticmethod
    def get_vulnerability_capec_modified():
        return VULNERABILITY_CAPEC.objects.filter(modification=MODIFICATION_MODIFIED)

    @staticmethod
    def append_capec_in_vulnerability_capec_table(capec: dict):
        vulner = VULNERABILITY_CAPEC.objects.filter(capec_id=capec["capec_id"]).first()
        if vulner is None:
            return VULNERABILITY_CAPEC.objects.create(
                capec_id=capec["capec_id"],
                name=capec["name"],
                summary=capec["summary"],
                prerequisites=capec["prerequisites"],
                solutions=capec["solutions"],
                related_weakness=capec["related_weakness"],
                modification=MODIFICATION_NEW
            )

    @staticmethod
    def mark_capec_in_vulnerability_capec_table_as_new(capec: dict):
        vulner = VULNERABILITY_CAPEC.objects.filter(capec_id=capec["capec_id"]).only("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_NEW
            vulner.save()

    @staticmethod
    def mark_capec_in_vulnerability_capec_table_as_modified(capec: dict):
        vulner = VULNERABILITY_CAPEC.objects.filter(capec_id=capec["capec_id"]).only("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_MODIFIED
            vulner.save()

    @staticmethod
    def save_status_in_local_status_table(status: dict):
        name = status.get("name", "capec")
        obj = STATUS_CAPEC.objects.filter(name=name)
        if obj:
            return STATUS_CAPEC.objects.filter(name=name).update(
                status=status.get("status", ""),
                count=status.get("count", 0),
                updated=status.get("updated", timezone.now())
            )
        return STATUS_CAPEC.objects.create(
            name=name,
            status=status.get("status", ""),
            count=status.get("count", 0),
            created=status.get("created", timezone.now()),
            updated=status.get("updated", timezone.now())
        )

    @staticmethod
    def get_status_from_local_status_table(name="capec") -> dict:
        objects = STATUS_CAPEC.objects.filter(name=name)
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
    def check_if_capec_item_changed(old: dict, new: dict):
        if old["name"] != new["name"] or \
            old["summary"] != new["summary"] or \
            old["prerequisites"] != new["prerequisites"] or \
            old["solutions"] != new["solutions"] or\
            old["related_weakness"] != new["related_weakness"]:
            return True
        return False

    @staticmethod
    def update_capec_in_capec_table(capec: dict):
        vulner = VULNERABILITY_CAPEC.objects.filter(capec_id=capec["capec_id"]).first()
        if vulner is not None:
            vulner.name=capec["name"]
            vulner.summary=capec["summary"],
            vulner.prerequisites=capec["prerequisites"],
            vulner.solutions=capec["solutions"],
            vulner.related_weakness=capec["related_weakness"]
            vulner.modification=MODIFICATION_MODIFIED
            vulner.save()

    def create_or_update_capec_vulnertability(self, capec: dict):
        vulner = VULNERABILITY_CAPEC.objects.filter(capec_id=capec['capec_id']).first()
        if vulner is None:
            self.append_capec_in_vulnerability_capec_table(capec)
            return 'created'
        else:
            if self.check_if_capec_item_changed(vulner.data, capec):
                self.update_capec_in_capec_table(capec)
                return 'updated'
            return 'skipped'

    def stats(self):
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            capec_cnt_before=self.count_vulnerability_capec(),
            capec_cnt_after=self.count_vulnerability_capec(),
            new_cnt=self.count_vulnerability_capec_new_marked(),
            modified_cnt=self.count_vulnerability_capec_modified_marked()
        )

    def update(self):
        if CAPECConfig.drop_core_table:
            self.clear_vulnerability_capec_table()
        self.clear_vulnerability_capec_all_marks()
        print_debug("create parsers")
        count_before = count_after = self.count_vulnerability_capec()
        parser = make_parser()
        capec_handler = CAPECHandler()
        parser.setContentHandler(capec_handler)
        print_debug("download file")
        (file_path, success, last_modified, size, fmt) = upload_file()
        if success and file_path != '':
            # FIXME: Make last_modified comparison
            (f, success, message) = read_file(file_path)
            if f is None or not success:
                return pack_answer(
                    status=TextMessages.exception.value,
                    message=message,
                    capec_cnt_before=count_before,
                    capec_cnt_after=count_after,
                    new_cnt=0,
                    modified_cnt=0
                )
            print_debug("parse file")
            parser.parse(f)

            count = 0
            for capec in capec_handler.capec:
                capec['capec_id'] = 'CAPEC-{}'.format(capec['id'])
                print_debug('processing CAPEC # {} with ID: {}'.format(count, capec["capec_id"]))
                count += 1
                related_weakness = capec.get("related_weakness", [])
                if related_weakness:
                    for index, value in enumerate(related_weakness):
                        related_weakness[index] = "CWE-{}".format(value)
                capec["related_weakness"] = related_weakness

                self.create_or_update_capec_vulnertability(capec)

            print_debug("complete parsing")
            count_after = self.count_vulnerability_capec()
            print_debug("save stats")
            self.save_status_in_local_status_table(dict(
                name="capec",
                count=count_after,
                updated=last_modified,
                status="updated"
            ))
            print_debug("complete")
            return pack_answer(
                status=TextMessages.ok.value,
                message=TextMessages.capec_updated.value,
                capec_cnt_before=count_before,
                capec_cnt_after=count_after,
                new_cnt=self.count_vulnerability_capec_new_marked(),
                modified_cnt=self.count_vulnerability_capec_modified_marked()
            )
        return pack_answer(
            status=TextMessages.error.value,
            message=TextMessages.cant_download_file.value,
            capec_cnt_before=count_before,
            capec_cnt_after=count_after,
            new_cnt=0,
            modified_cnt=0
        )