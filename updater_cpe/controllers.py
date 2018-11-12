from xml.sax import make_parser

from django.utils import timezone
from django.db import transaction

from .utils import to_string_formatted_cpe
from .utils import time_string_to_datetime
from .utils import upload_file
from .utils import read_file

from .text_messages import TextMessages

from .handlers import CPEHandler

from .models import STATUS_CPE
from .models import VULNERABILITY_CPE

from .configurations import CPEConfig

MODIFICATION_CLEAR = 0
MODIFICATION_NEW = 1
MODIFICATION_MODIFIED = 2


def print_debug(message):
    if CPEConfig.debug:
        print(message)


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
        for x in VULNERABILITY_CPE.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerability_cpe_all_marks():
        entries = VULNERABILITY_CPE.objects.select_for_update().all().defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerability_capec_new_marks():
        entries = VULNERABILITY_CPE.objects.select_for_update().filter(modification=MODIFICATION_NEW).defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerability_capec_modified_marks():
        entries = VULNERABILITY_CPE.objects.select_for_update().filter(modification=MODIFICATION_MODIFIED).defer("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def count_vulnerability_cpe_table():
        return VULNERABILITY_CPE.objects.count()

    @staticmethod
    def count_vulnerability_cpe_new_marked():
        return VULNERABILITY_CPE.objects.filter(modification=MODIFICATION_NEW).count()

    @staticmethod
    def count_vulnerability_cpe_modified_marked():
        return VULNERABILITY_CPE.objects.filter(modification=MODIFICATION_MODIFIED).count()

    @staticmethod
    def get_vulnerability_cpe_new():
        return VULNERABILITY_CPE.objects.filter(modification=MODIFICATION_NEW)

    @staticmethod
    def get_vulnerability_cpe_modified():
        return VULNERABILITY_CPE.objects.filter(modification=MODIFICATION_MODIFIED)

    @staticmethod
    def append_cpe_in_vulnerability_cpe_table(cpe):
        vulner = VULNERABILITY_CPE.objects.filter(cpe_id=cpe["cpe_id"]).first()
        if vulner is None:
            return VULNERABILITY_CPE.objects.create(
                cpe_id=cpe['cpe_id'],
                title=cpe['title'],
                cpe_2_2=cpe['cpe_2_2'],
                references=cpe['references'],
                component=cpe['component'],
                version=cpe['version'],
                vendor=cpe['vendor'],
                modification=MODIFICATION_NEW
            )

    @staticmethod
    def mark_cpe_in_vulnerability_cpe_table_as_new(cpe):
        vulner = VULNERABILITY_CPE.objects.filter(cpe_id=cpe["cpe_id"]).defer("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_NEW
            vulner.save()

    @staticmethod
    def mark_cpe_in_vulnerability_cpe_table_as_modified(cpe):
        vulner = VULNERABILITY_CPE.objects.filter(cpe_id=cpe["cpe_id"]).defer("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_MODIFIED
            vulner.save()

    @staticmethod
    def save_status_in_local_status_table(status: dict):
        name = status.get("name", "cpe")
        obj = STATUS_CPE.objects.filter(name=name)
        if obj:
            return STATUS_CPE.objects.filter(name=name).update(
                status=status.get("status", ""),
                count=status.get("count", 0),
                updated=status.get("updated", timezone.now())
            )
        return STATUS_CPE.objects.create(
            name=name,
            status=status.get("status", ""),
            count=status.get("count", 0),
            created=status.get("created", timezone.now()),
            updated=status.get("updated", timezone.now())
        )

    @staticmethod
    def get_status_from_local_status_table(name="cpe") -> dict:
        objects = STATUS_CPE.objects.filter(name=name)
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
    def check_if_capec_item_changed(old, new):
        if old["title"] != new["title"] or \
            old["cpe_2_2"] != new["cpe_2_2"] or \
            old["references"] != new["references"] or \
            old["component"] != new["component"] or \
            old["version"] != new["version"] or \
                old["vendor"] != new["vendor"]:
            return True
        return False

    @staticmethod
    def update_cpe_in_cpe_table(cpe):
        vulner = VULNERABILITY_CPE.objects.filter(cpe_id=cpe["cpe_id"]).first()
        if vulner is not None:
            vulner.title=cpe['title']
            vulner.cpe_2_2=cpe['cpe_2_2']
            vulner.references=cpe['references']
            vulner.component=cpe['component']
            vulner.version=cpe['version']
            vulner.vendor=cpe['vendor']
            vulner.modification=MODIFICATION_MODIFIED
            vulner.save()

    def create_or_update_cpe_vulnerability(self, cpe):
        vulner = VULNERABILITY_CPE.objects.filter(cpe_id=cpe["cpe_id"]).first()
        if vulner is None:
            self.append_cpe_in_vulnerability_cpe_table(cpe=cpe)
        else:
            if self.check_if_capec_item_changed(vulner.data, cpe):
                self.update_cpe_in_cpe_table(cpe)

    @staticmethod
    def cpe_parser(cpe_string):
        zk = ['cpe', 'part', 'vendor', 'product', 'version',
              'update', 'edition', 'language']
        cpedict = dict((k, '') for k in zk)
        splitup = cpe_string.split(':')
        cpedict.update(dict(zip(zk, splitup)))

        zk = None
        splitup = None

        part = cpedict.get("part", "")  # Returns the cpe part (/o, /h, /a)
        vendor = cpedict.get("vendor", "")
        component = cpedict.get("product", "")
        version = cpedict.get("version", "")
        update = cpedict.get("update", "")
        edition = cpedict.get("edition", "")
        language = cpedict.get("language", "")

        return part, vendor, component, version, update, edition, language

    @staticmethod
    def filter_escape_characters_for_cpe_string(cpe_string):
        # %20	 (blank)
        if "%20" in cpe_string:
            cpe_string = cpe_string.replace("%20", " ")
        # %21	!
        if "%21" in cpe_string:
            cpe_string = cpe_string.replace("%21", "!")
        # %22	"
        if "%22" in cpe_string:
            cpe_string = cpe_string.replace("%22", '"')
        # %23	#
        if "%23" in cpe_string:
            cpe_string = cpe_string.replace("%2#", "#")
        # %24	$
        if "%24" in cpe_string:
            cpe_string = cpe_string.replace("%24", "$")
        # %25	%
        if "%25" in cpe_string:
            cpe_string = cpe_string.replace("%25", "%")
        # %26	&
        if "%26" in cpe_string:
            cpe_string = cpe_string.replace("%26", "&")
        # %27	'
        if "%27" in cpe_string:
            cpe_string = cpe_string.replace("%27", "'")
        # %28	(
        if "%28" in cpe_string:
            cpe_string = cpe_string.replace("%28", "(")
        # %29	)
        if "%29" in cpe_string:
            cpe_string = cpe_string.replace("%29", ")")
        # %2a	*
        if "%2a" in cpe_string:
            cpe_string = cpe_string.replace("%2a", "a")
        # %2b	+
        if "%2b" in cpe_string:
            cpe_string = cpe_string.replace("%2b", "+")
        # %2c	,
        if "%2c" in cpe_string:
            cpe_string = cpe_string.replace("%2c", ",")
        # %2d	-
        if "%2d" in cpe_string:
            cpe_string = cpe_string.replace("%2d", "-")
        # %2e	.
        if "%2e" in cpe_string:
            cpe_string = cpe_string.replace("%2e", ".")
        # %2f	/
        if "%2f" in cpe_string:
            cpe_string = cpe_string.replace("%2f", "/")
        # %3a	:
        if "%3a" in cpe_string:
            cpe_string = cpe_string.replace("%3a", ":")
        # %3b	;
        if "%3b" in cpe_string:
            cpe_string = cpe_string.replace("%3b", ";")
        # %3c	<
        if "%3c" in cpe_string:
            cpe_string = cpe_string.replace("%3c", "<")
        # %3d	=
        if "%3d" in cpe_string:
            cpe_string = cpe_string.replace("%3d", "=")
        # %3e	>
        if "%3e" in cpe_string:
            cpe_string = cpe_string.replace("%3e", ">")
        # %3f	?
        if "%3f" in cpe_string:
            cpe_string = cpe_string.replace("%3f", "?")
        # %40	@
        if "%40" in cpe_string:
            cpe_string = cpe_string.replace("%40", "@")
        # %5b	[
        if "%5b" in cpe_string:
            cpe_string = cpe_string.replace("%5b", "[")
        # %5c	\
        if "%5c" in cpe_string:
            cpe_string = cpe_string.replace("%5c", "\\")
        # %5d	]
        if "%5d" in cpe_string:
            cpe_string = cpe_string.replace("%5d", "]")
        # %5e	^
        if "%5e" in cpe_string:
            cpe_string = cpe_string.replace("%5e", "^")
        # %5f	_
        if "%5f" in cpe_string:
            cpe_string = cpe_string.replace("%5f", "_")
        # %60	`
        if "%60" in cpe_string:
            cpe_string = cpe_string.replace("%60", "`")
        # %7b	{
        if "%7b" in cpe_string:
            cpe_string = cpe_string.replace("%7b", "{")
        # %7c	|
        if "%7c" in cpe_string:
            cpe_string = cpe_string.replace("%7c", "|")
        # %7d	}
        if "%7d" in cpe_string:
            cpe_string = cpe_string.replace("%7d", "}")
        # %7e	~
        if "%7e" in cpe_string:
            cpe_string = cpe_string.replace("%7e", "~")

        return cpe_string

    def stats(self):
        """
        Return tables status in JSON for /stats route
        :return:
        """
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            cpe_cnt_before=self.count_vulnerability_cpe_table(),
            cpe_cnt_after=self.count_vulnerability_cpe_table(),
            new_cnt=self.count_vulnerability_cpe_new_marked(),
            modified_cnt=self.count_vulnerability_cpe_modified_marked()
        )

    @staticmethod
    def set_state_in_status_table(status):
        """
        Set CPE Updater status in external stats table (stats application)
        :param status:
        :return:
        """
        pass

    def update(self):
        if CPEConfig.drop_core_table:
            self.clear_vulnerability_cpe_table()
        self.clear_vulnerability_cpe_all_marks()
        print_debug("create parsers")
        count_before = count_after = self.count_vulnerability_cpe_table()
        parser = make_parser()
        cpe_handler = CPEHandler()
        parser.setContentHandler(cpe_handler)
        print_debug("download file")
        (file_path, success, last_modified, size, fmt) = upload_file()
        if success and file_path != '':
            # FIXME: Make last_modified comparison
            (f, success, message) = read_file(file_path)
            if f is None or not success:
                return pack_answer(
                    status=TextMessages.exception.value,
                    message=message,
                    cpe_cnt_before=count_before,
                    cpe_cnt_after=count_after,
                    new_cnt=0,
                    modified_cnt=0
                )
            print_debug("parse file")
            parser.parse(f)

            count = 0
            for cpe in cpe_handler.cpe:
                print_debug('processing: {}'.format(count))
                count += 1
                x = dict()
                x['cpe_id'] = to_string_formatted_cpe(cpe['name'])
                x['title'] = cpe['title'][0]
                x['cpe_2_2'] = cpe.pop('name')
                if not cpe['references']:
                    x['references'] = cpe.pop('references')
                else:
                    x['references'] = cpe['references']
                part, vendor, component, version, update, edition, language = self.cpe_parser(
                    self.filter_escape_characters_for_cpe_string(x['cpe_2_2']))
                x['component'] = component
                x['version'] = version
                x['vendor'] = vendor
                self.create_or_update_cpe_vulnerability(x)
            print_debug("complete parsing")
            count_after = self.count_vulnerability_cpe_table()
            print_debug("save stats")
            self.save_status_in_local_status_table(dict(
                name="cpe",
                count=count_after,
                updated=time_string_to_datetime(last_modified)
            ))
            print_debug("complete")
            return pack_answer(
                status=TextMessages.ok.value,
                message=TextMessages.cpe_updated.value,
                cpe_cnt_before=count_before,
                cpe_cnt_after=count_after,
                new_cnt=self.count_vulnerability_cpe_new_marked(),
                modified_cnt=self.count_vulnerability_cpe_modified_marked()
            )
        return pack_answer(
            status=TextMessages.error.value,
            message=TextMessages.cant_download_file.value,
            cpe_cnt_before=count_before,
            cpe_cnt_after=count_after,
            new_cnt=self.count_vulnerability_cpe_new_marked(),
            modified_cnt=self.count_vulnerability_cpe_modified_marked()
        )
