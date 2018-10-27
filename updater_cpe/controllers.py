from xml.sax import make_parser
from dateutil.parser import parse as parse_datetime

from .utils import to_string_formatted_cpe
from .utils import get_file

from .configurations import CPEConfig

from .handlers import CPEHandler

from .models import VULNERABILITY_CPE

import logging
logger = logging.getLogger(__name__)

class CPEController(object):

    def stats(self):
        return dict(
            count_before=VULNERABILITY_CPE.objects.count(),
            count_after=VULNERABILITY_CPE.objects.count(),
            status="ok",
            message="ok"
        )

    def update(self):
        count_before = count_after = VULNERABILITY_CPE.objects.count()
        parser = make_parser()
        ch = CPEHandler()
        parser.setContentHandler(ch)
        f = None
        try:
            logger.info('get file {}'.format(CPEConfig.source))
            (f, r) = get_file(CPEConfig.source)
        except Exception as ex:
            return dict(
                count_before=count_before,
                count_after=count_after,
                status="exception",
                message="{}".format(ex)
            )
        # TODO: LAST MODIFIED
        if f is not None:
            logger.info('parse data')
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
                VULNERABILITY_CPE.objects.get_or_create(
                    cpe_id=x['id'],
                    title=x['title'],
                    cpe_2_2=x['cpe_2_2'],
                    references=x["references"]
                )
            return dict(
                count_before=count_before,
                count_after=count_after,
                status="ok",
                message="cpe updated"
            )
        return dict(
            count_before=count_before,
            count_after=count_after,
            status="error",
            message="cant get cpe file"
        )