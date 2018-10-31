from xml.sax import make_parser
from dateutil.parser import parse as parse_datetime

from .utils import to_string_formatted_cpe
from .utils import get_file

from .configurations import CWEConfig

from .handlers import CWEHandler

from .models import VULNERABILITY_CWE
from .models import VULNERABILITY_CWE_NEW
from .models import VULNERABILITY_CWE_MODIFIED

import logging
logger = logging.getLogger(__name__)

from .text_messages import TextMessages


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
        return VULNERABILITY_CWE.objects.all().delete()

    @staticmethod
    def clear_vulnerability_cwe_new_table():
        return VULNERABILITY_CWE_NEW.objects.all().delete()

    @staticmethod
    def clear_vulnerability_cwe_modified_table():
        return VULNERABILITY_CWE_MODIFIED.objects.all().delete()

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
            weakness=cwe['weakness'],
            description_summary=cwe['description_summary']
        )

    @staticmethod
    def append_cwe_in_vulnerability_cwe_new_table(cwe):
        return VULNERABILITY_CWE_NEW.objects.create(
            cwe_id=cwe['cwe_id'],
            name=cwe['name'],
            status=cwe['status'],
            weakness=cwe['weakness'],
            description_summary=cwe['description_summary']
        )

    @staticmethod
    def append_cwe_in_vulnerability_cwe_modified_table(cwe):
        return VULNERABILITY_CWE_MODIFIED.objects.create(
            cwe_id=cwe['cwe_id'],
            name=cwe['name'],
            status=cwe['status'],
            weakness=cwe['weakness'],
            description_summary=cwe['description_summary']
        )

    def create_or_update_cwe_vulnerability(self, cwe):
        defaults = dict(
            name=cwe['name'],
            status=cwe['status'],
            weakness=cwe['weakness'],
            description_summary=cwe['description_summary']
        )
        cwe, created = VULNERABILITY_CWE.objects.update_or_create(
            defaults,
            cwe_id=cwe['cwe_id']
        )
        if created:
            self.append_cwe_in_vulnerability_cwe_table(cwe.data)
            self.append_cwe_in_vulnerability_cwe_new_table(cwe.data)
        else:
            self.append_cwe_in_vulnerability_cwe_modified_table(cwe.data)

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
        f = None
        try:
            logger.info(TextMessages.download_file.value)
            logger.info('{}'.format(CWEConfig.source))
            (f, r) = get_file(CWEConfig.source)
        except Exception as ex:
            return pack_answer(
                status=TextMessages.exception.value,
                message='{}'.format(ex),
                cwe_cnt_before=count_before,
                cwe_cnt_after=count_after,
                new_cnt=0,
                modified_cnt=0
            )

        # TODO: LAST MODIFIED

        if f is not None:
            logger.info(TextMessages.parse_data.value)
            parser.parse(f)
            for cwe in cwe_handler.cwe:
                cwe['description_summary'] = cwe['description_summary'].replace("\t\t\t\t\t", " ")
                self.create_or_update_cwe_vulnerability(cwe)
        return pack_answer(
            status=TextMessages.error.value,
            message=TextMessages.cant_download_file.value,
            cwe_cnt_before=count_before,
            cwe_cnt_after=count_after,
            new_cnt=0,
            modified_cnt=0
        )




















