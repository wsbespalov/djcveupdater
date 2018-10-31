from xml.sax import make_parser
from dateutil.parser import parse as parse_datetime

from .utils import to_string_formatted_cpe
from .utils import get_file

from .configurations import CPEConfig

from .handlers import CPEHandler

from .models import VULNERABILITY_CPE
from .models import VULNERABILITY_CPE_NEW
from .models import VULNERABILITY_CPE_MODIFIED

import logging
logger = logging.getLogger(__name__)

from .text_messages import TextMessages

from django.conf import settings
from django.core.files.storage import FileSystemStorage


def pack_answer(
        status=TextMessages.error.value,
        message=TextMessages.error.value,
        cpe_cnt_before=0,
        cpe_cnt_after=0,
        new_cnt=0,
        modified_cnt=0
):
    return dict(
        vulnerability=dict(
            count_before=cpe_cnt_before,
            count_after=cpe_cnt_after),
        vulnerability_new=dict(
            count=new_cnt),
        vulnerability_modified=dict(
            count=modified_cnt),
        status=status,
        message=message
    )


class CPEController(object):

    @staticmethod
    def clear_vulnerability_cpe_table():
        return VULNERABILITY_CPE.objects.all().delete()

    @staticmethod
    def clear_vulnerability_cpe_new_table():
        return VULNERABILITY_CPE_NEW.objects.all().delete()

    @staticmethod
    def clear_vulnerability_cpe_modified_table():
        return VULNERABILITY_CPE_MODIFIED.objects.all().delete()

    @staticmethod
    def count_vulnerability_cpe_table():
        return VULNERABILITY_CPE.objects.count()

    @staticmethod
    def count_vulnerability_cpe_new_table():
        return VULNERABILITY_CPE_NEW.objects.count()

    @staticmethod
    def count_vulnerability_cpe_modified_table():
        return VULNERABILITY_CPE_MODIFIED.objects.count()

    @staticmethod
    def append_cpe_in_vulnerability_cpe_table(cpe):
        return VULNERABILITY_CPE.objects.create(
            cpe_id=cpe['cpe_id'],
            title=cpe['title'],
            cpe_2_2=cpe['cpe_2_2'],
            references=cpe['references']
        )

    @staticmethod
    def append_cpe_in_vulnerability_cpe_new_table(cpe):
        return VULNERABILITY_CPE_NEW.objects.update_or_create(
            cpe_id=cpe['cpe_id'],
            title=cpe['title'],
            cpe_2_2=cpe['cpe_2_2'],
            references=cpe['references']
        )

    @staticmethod
    def append_cpe_in_vulnerability_cpe_modified_table(cpe):
        return VULNERABILITY_CPE_MODIFIED.objects.update_or_create(
            cpe_id=cpe['cpe_id'],
            title=cpe['title'],
            cpe_2_2=cpe['cpe_2_2'],
            references=cpe['references']
        )

    def create_or_update_cpe_vulnerability(self, cpe):
        defaults = dict(
            title=['title'],
            cpe_2_2=cpe['cpe_2_2'],
            references=cpe['references']
        )
        cpe, created = VULNERABILITY_CPE.objects.update_or_create(
            defaults,
            cpe_id=cpe["cpe_id"]
        )
        if created:
            self.append_cpe_in_vulnerability_cpe_table(cpe=cpe.data)
            self.append_cpe_in_vulnerability_cpe_new_table(cpe=cpe.data)
        else:
            self.append_cpe_in_vulnerability_cpe_modified_table(cpe=cpe.data)

    def stats(self):
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            cpe_cnt_before=self.count_vulnerability_cpe_table(),
            cpe_cnt_after=self.count_vulnerability_cpe_table(),
            new_cnt=self.count_vulnerability_cpe_new_table(),
            modified_cnt=self.count_vulnerability_cpe_modified_table()
        )

    @staticmethod
    def set_state_in_status_table(status):
        pass

    @staticmethod
    def upload_file():
        import os
        if not os.path.isdir(settings.CPE_MEDIA):
            os.mkdir(settings.CPE_MEDIA)
        import requests


    @staticmethod
    def upload_file2():
        f = None
        try:
            logger.info(TextMessages.download_file.value)
            logger.info('{}'.format(CPEConfig.source))
            (f, r) = get_file(CPEConfig.source)
            if f:
                return f
            return None, TextMessages.cant_download_file.value
        except Exception as ex:
            return None, "{}".format(ex)

    def update(self):
        self.clear_vulnerability_cpe_new_table()
        self.clear_vulnerability_cpe_modified_table()
        count_before = count_after = self.count_vulnerability_cpe_table()
        parser = make_parser()
        cpe_handler = CPEHandler()
        parser.setContentHandler(cpe_handler)
        (f, message) = self.upload_file()
        if f is None:
            return pack_answer(
                status=TextMessages.exception.value,
                message=message,
                cpe_cnt_before=count_before,
                cpe_cnt_after=count_after,
                new_cnt=0,
                modified_cnt=0
            )
        logger.info(TextMessages.parse_data.value)
        parser.parse(f)
        for cpe in cpe_handler.cpe:
            x = dict()
            x['id'] = to_string_formatted_cpe(cpe['name'])
            x['title'] = cpe['title'][0]
            x['cpe_2_2'] = cpe.pop('name')
            if not cpe['references']:
                x['references'] = cpe.pop('references')
            else:
                x['references'] = cpe['references']
            self.create_or_update_cpe_vulnerability(dict(
                cpe_id=x['id'],
                title=x['title'],
                cpe_2_2=x['cpe_2_2'],
                references=x["references"]
            ))
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.cpe_updated.value,
            cpe_cnt_before=count_before,
            cpe_cnt_after=count_after,
            new_cnt=self.count_vulnerability_cpe_new_table(),
            modified_cnt=self.count_vulnerability_cpe_modified_table()
        )
