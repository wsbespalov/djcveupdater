from xml.sax import make_parser

from .utils import upload_file
from .utils import read_file

from .handlers import CWEHandler

from .models import VULNERABILITY_CWE
from .models import VULNERABILITY_CWE_NEW
from .models import VULNERABILITY_CWE_MODIFIED

from .configurations import CWEConfig

import logging
logger = logging.getLogger(__name__)

from .text_messages import TextMessages


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
    def clear_vulnerability_cwe_new_table():
        for x in VULNERABILITY_CWE_NEW.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerability_cwe_modified_table():
        for x in VULNERABILITY_CWE_MODIFIED.objects.all().iterator():
            x.delete()

    @staticmethod
    def count_vulnerability_cwe_table():
        return VULNERABILITY_CWE.objects.count()

    @staticmethod
    def count_vulnerability_cwe_new_table():
        return VULNERABILITY_CWE_NEW.objects.count()

    @staticmethod
    def count_vulnerability_cwe_modified_table():
        return VULNERABILITY_CWE_MODIFIED.objects.count()

    @staticmethod
    def append_cwe_in_vulnerability_cwe_table(cwe):
        return VULNERABILITY_CWE.objects.create(
            cwe_id=cwe['cwe_id'],
            name=cwe['name'],
            status=cwe['status'],
            weaknesses=cwe['weaknesses'],
            description_summary=cwe['description_summary']
        )

    @staticmethod
    def append_cwe_in_vulnerability_cwe_new_table(cwe):
        objects = VULNERABILITY_CWE_NEW.objects.filter(cwe_id=cwe['cwe_id'])
        if len(objects) == 0:
            return VULNERABILITY_CWE_NEW.objects.create(
                cwe_id=cwe['cwe_id'],
                name=cwe['name'],
                status=cwe['status'],
                weaknesses=cwe['weaknesses'],
                description_summary=cwe['description_summary']
            )

    @staticmethod
    def append_cwe_in_vulnerability_cwe_modified_table(cwe):
        objects = VULNERABILITY_CWE_MODIFIED.objects.filter(cwe_id=cwe['cwe_id'])
        if len(objects) == 0:
            return VULNERABILITY_CWE_MODIFIED.objects.create(
                cwe_id=cwe['cwe_id'],
                name=cwe['name'],
                status=cwe['status'],
                weaknesses=cwe['weaknesses'],
                description_summary=cwe['description_summary']
            )

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
        return VULNERABILITY_CWE.objects.filter(cwe_id=cwe["cwe_id"]).update(
            name=cwe['name'],
            status=cwe['status'],
            weaknesses=cwe['weaknesses'],
            description_summary=cwe['description_summary']
        )

    def create_or_update_cwe_vulnerability(self, cwe):
        objects = VULNERABILITY_CWE.objects.filter(cwe_id=cwe['cwe_id'])
        if len(objects) == 0:
            self.append_cwe_in_vulnerability_cwe_table(cwe)
            self.append_cwe_in_vulnerability_cwe_new_table(cwe)
        else:
            o = objects[0].data
            if self.check_if_cwe_item_changed(o, cwe):
                self.update_cwe_in_cwe_table(cwe)
                self.append_cwe_in_vulnerability_cwe_modified_table(cwe)

    def stats(self):
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            cwe_cnt_before=self.count_vulnerability_cwe_table(),
            cwe_cnt_after=self.count_vulnerability_cwe_table(),
            new_cnt=self.count_vulnerability_cwe_new_table(),
            modified_cnt=self.count_vulnerability_cwe_modified_table()
        )

    @staticmethod
    def set_state_in_status_table(status):
        pass

    def update(self):
        self.clear_vulnerability_cwe_new_table()
        self.clear_vulnerability_cwe_modified_table()
        count_before = count_after = self.count_vulnerability_cwe_table()
        parser = make_parser()
        cwe_handler = CWEHandler()
        parser.setContentHandler(cwe_handler)
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
            logger.info(TextMessages.parse_data.value)
            parser.parse(f)
            count = 0
            for cwe in cwe_handler.cwe:
                print_debug('processing: {}'.format(count))
                count += 1
                cwe['cwe_id'] = 'CWE-{}'.format(cwe['id'])
                cwe['description_summary'] = cwe['description_summary'].replace("\t\t\t\t\t", " ")
                self.create_or_update_cwe_vulnerability(cwe)
            count_after = self.count_vulnerability_cwe_table()
            return pack_answer(
                status=TextMessages.ok.value,
                message=TextMessages.cwe_updated.value,
                cwe_cnt_before=count_before,
                cwe_cnt_after=count_after,
                new_cnt=self.count_vulnerability_cwe_new_table(),
                modified_cnt=self.count_vulnerability_cwe_modified_table()
            )
        return pack_answer(
            status=TextMessages.error.value,
            message=TextMessages.cant_download_file.value,
            cwe_cnt_before=count_before,
            cwe_cnt_after=count_after,
            new_cnt=0,
            modified_cnt=0
        )
