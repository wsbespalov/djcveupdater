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


def pack_answer(
        status=TextMessages.error.value,
        message=TextMessages.error.value,
        cpe_cnt_before=0,
        cpe_cnt_after=0,
        new_cnt=0,
        modified_cnt=0
):
    return dict(
        vulnerability=dict(count_before=cpe_cnt_before, count_after=cpe_cnt_after),
        vulnerability_new=dict(count=new_cnt),
        vulnerability_modified=dict(count=modified_cnt),
        status=status,
        message=message
    )


class CPEController(object):

    @staticmethod
    def clear_vulnerabilities_table():
        VULNERABILITY_CPE.objects.all().delete()

    @staticmethod
    def clear_vulnerabilities_new_table():
        VULNERABILITY_CPE_NEW.objects.all().delete()

    @staticmethod
    def clear_vulnerabilities_modified_table():
        VULNERABILITY_CPE_MODIFIED.objects.all().delete()

    @staticmethod
    def count_vulnerabilities_cpe():
        return VULNERABILITY_CPE.objects.count()

    @staticmethod
    def count_vulnerabilitie_cpes_new():
        return VULNERABILITY_CPE_NEW.objects.count()

    @staticmethod
    def count_vulnerabilities_cpe_modified():
        return VULNERABILITY_CPE_MODIFIED.objects.count()

    def create_or_update_vulnerability(self, cpe):
        cpe, created = VULNERABILITY_CPE.objects.get_or_create(cpe_id=cpe["cpe_id"])
        if created:
            # if cpe record created
            pass
        else:
            # if cpe record already exists
            # 1. Check for updates
            pass

        # VULNERABILITY_CPE.objects.get_or_create(
        #     cpe_id=x['id'],
        #     title=x['title'],
        #     cpe_2_2=x['cpe_2_2'],
        #     references=x["references"]
        # )
        pass

    def stats(self):
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            cpe_cnt_before=self.count_vulnerabilities_cpe(),
            cpe_cnt_after=self.count_vulnerabilities_cpe(),
            new_cnt=self.count_vulnerabilitie_cpes_new(),
            modified_cnt=self.count_vulnerabilities_cpe_modified()
        )

    def update(self):
        self.clear_vulnerabilities_new_table()
        self.clear_vulnerabilities_modified_table()
        count_before = count_after = self.count_vulnerabilities_cpe()
        parser = make_parser()
        ch = CPEHandler()
        parser.setContentHandler(ch)
        f = None
        try:
            logger.info(TextMessages.download_file.value)
            logger.info('{}'.format(CPEConfig.source))
            (f, r) = get_file(CPEConfig.source)
        except Exception as ex:
            return pack_answer(
                status=TextMessages.exception.value,
                message="{}".format(ex),
                cpe_cnt_before=self.count_vulnerabilities_cpe(),
                cpe_cnt_after=self.count_vulnerabilities_cpe(),
                new_cnt=self.count_vulnerabilitie_cpes_new(),
                modified_cnt=self.count_vulnerabilities_cpe_modified()
            )
        # TODO: LAST MODIFIED
        if f is not None:
            logger.info(TextMessages.parse_data.value)
            parser.parse(f)
            for cpe in ch.cpe:
                x = dict()
                x['id'] = to_string_formatted_cpe(cpe['name'])
                x['title'] = cpe['title'][0]
                x['cpe_2_2'] = cpe.pop('name')
                if not cpe['references']:
                    x['references'] = cpe.pop('references')
                else:
                    x['references'] = cpe['references']
                self.create_or_update_vulnerability(dict(
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
                new_cnt=self.count_vulnerabilitie_cpes_new(),
                modified_cnt=self.count_vulnerabilities_cpe_modified()
            )
        return pack_answer(
            status=TextMessages.error.value,
            message=TextMessages.cant_download_file.value,
            cpe_cnt_before=count_before,
            cpe_cnt_after=count_after,
            new_cnt=self.count_vulnerabilitie_cpes_new(),
            modified_cnt=self.count_vulnerabilities_cpe_modified()
        )