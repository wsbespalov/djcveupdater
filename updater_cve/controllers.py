import os
import pytz
from datetime import datetime
import dateparser
import urllib

from django.utils import timezone
from django.utils.timezone import make_aware
from django.db import transaction

from .text_messages import TextMessages

from .configurations import CVEConfig

from .models import STATUS_CVE
from .models import VULNERABILITY_CVE

from updater_cpe.models import VULNERABILITY_CPE
from updater_cwe.models import VULNERABILITY_CWE

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


def ask_input(message="Press Enter..."):
    if CVEConfig.enable_input:
        input(message)


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
        entries = VULNERABILITY_CVE.objects.select_for_update().all().only("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerability_cve_new_marks():
        entries = VULNERABILITY_CVE.objects.select_for_update().filter(modification=MODIFICATION_NEW).only("modification")
        with transaction.atomic():
            for entry in entries:
                entry.modification = MODIFICATION_CLEAR
                entry.save()

    @staticmethod
    def clear_vulnerability_cve_modified_marks():
        entries = VULNERABILITY_CVE.objects.select_for_update().filter(modification=MODIFICATION_MODIFIED).only("modification")
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
    def get_one_cve_by_id(id):
        return VULNERABILITY_CVE.objects.filter(id=id).first()

    @staticmethod
    def get_one_cve_by_cve_id(cve_id):
        return VULNERABILITY_CVE.objects.filter(cve_id=cve_id).first()

    @staticmethod
    def get_vulnerability_cve_new():
        return VULNERABILITY_CVE.objects.filter(modification=MODIFICATION_NEW)

    @staticmethod
    def get_vulnerability_cve_new_ids():
        return VULNERABILITY_CVE.objects.filter(modification=MODIFICATION_NEW).only("cve_id")

    @staticmethod
    def get_vulnerability_cve_modified():
        return VULNERABILITY_CVE.objects.filter(modification=MODIFICATION_MODIFIED)

    @staticmethod
    def get_vulnerability_cve_modified_ids():
        return VULNERABILITY_CVE.objects.filter(modification=MODIFICATION_MODIFIED).only("cve_id")

    @staticmethod
    def append_cve_in_vulnerability_cve_table(cve):
        vulner = VULNERABILITY_CVE.objects.filter(cve_id=cve["cve_id"]).first()
        if vulner is None:
            vulner = VULNERABILITY_CVE.objects.create(
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
                component=cve["component"],
                component_versions=cve["component_versions"],
                component_versions_string=cve["component_versions_string"],
                modification=MODIFICATION_NEW
            )
            if cve["cwe"]:
                for c in cve["cwe"]:
                    w = VULNERABILITY_CWE.objects.filter(cwe_id=c).first()
                    if w is not None:
                        vulner.cwes.add(w)
            vulner.save()

    @staticmethod
    def mark_cve_in_vulnerability_cve_table_as_new(cve):
        vulner = VULNERABILITY_CVE.objects.filter(cve_id=cve["cve_id"]).only("modification").first()
        if vulner is not None:
            vulner.modification = MODIFICATION_NEW
            vulner.save()

    @staticmethod
    def mark_cve_in_vulnerability_cve_table_as_modified(cve):
        vulner = VULNERABILITY_CVE.objects.filter(cve_id=cve["cve_id"]).only("modification").first()
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
    def get_status_from_local_status_table(name="cve"):
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
            vulner.cwe=cve["cwe"]
            vulner.references=cve["references"]
            vulner.vulnerable_configuration=cve["vulnerable_configuration"]
            vulner.data_type=cve["data_type"]
            vulner.data_version=cve["data_version"]
            vulner.data_format=cve["data_format"]
            vulner.description=cve["description"]
            vulner.published=cve["published"]
            vulner.modified=cve["modified"]
            vulner.access=cve["access"]
            vulner.impact=cve["impact"]
            vulner.vector_string=cve["vector_string"]
            vulner.cvss_time=cve["cvss_time"]
            vulner.cvss=cve["cvss"]
            vulner.component=cve["component"]
            vulner.component_versions=cve["component_versions"]
            vulner.component_versions_string=cve["component_versions_string"]
            vulner.modification=MODIFICATION_MODIFIED
            vulner.cwes.clear()
            if cve["cwe"]:
                for c in cve["cwe"]:
                    w = VULNERABILITY_CWE.objects.filter(cwe_id=c).first()
                    if w is not None:
                        vulner.cwes.add(w)
            vulner.save()

    def create_or_update_cve_vulnerability(self, cve):
        vulner = VULNERABILITY_CVE.objects.filter(cve_id=cve["cve_id"]).first()
        if vulner is None:
            self.append_cve_in_vulnerability_cve_table(cve)
            # print_debug("create...\n")
            # print_debug(cve)
            # ask_input()
            return "created"
        else:
            if self.check_if_cve_item_changed(vulner.data, cve):
                self.update_cve_in_cve_table(cve)
                # print_debug("update...\n")
                # print_debug(cve)
                # ask_input()
                return "updated"
            return "skipped"

    def stats(self):
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            cve_cnt_before=self.count_vulnerability_cve_table(),
            cve_cnt_after=self.count_vulnerability_cve_table(),
            new_cnt=self.count_vulnerability_cve_new_marked(),
            modified_cnt=self.count_vulnerability_cve_modified_marked()
        )

    @staticmethod
    def parse_cpe_strings(cpe_string):
        zk = ['cpe', 'part', 'vendor', 'product', 'version',
            'update', 'edition', 'language']
        cpedict = dict((k, '') for k in zk)
        splitup = cpe_string.split(':')
        cpedict.update(dict(zip(zk, splitup)))

        zk = None
        splitup = None

        # Returns the cpe part (/o, /h, /a)
        part = cpedict.get("part", "")

        # Returns vendor
        vendor = cpedict.get("vendor", "")

        # Returns product
        component = cpedict.get("product", "")

        # Returns version
        version = cpedict.get("version", "")

        # Returns update
        update = cpedict.get("update", "")

        # Returns edition
        edition = cpedict.get("edition", "")

        # Returns language
        language = cpedict.get("language", "")

        return part, vendor, component, version, update, edition, language

    @staticmethod
    def filter_escape_characters_in_cpe_string(cpe_string):

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

    def filter_cpe_strings(self, cpe_strings):
        component = ""
        component_versions = []
        component_version_string = ""

        if cpe_strings:
            for cpe_string in cpe_strings:
                part, vendor, component, version, update, edition, language = self.parse_cpe_strings(
                    self.filter_escape_characters_in_cpe_string(
                        cpe_string
                    )
                )
                if component != "" and version != "" and version != "-":
                    try:
                        version = urllib.parse.unquote(version)
                    except Exception as ex:
                        print_debug("[-] Got en exception during filtering cpe strings: {0}".format(ex))

                    component_versions.append("".join([component, ":", version]))
            if component_versions:
                component_versions = list(set(component_versions))
                component_version_string = ",".join(component_versions)
        
        return component, component_versions, component_version_string

    def fix_component_versions_fields(self, cve):
        component, component_versions, component_versions_string = self.filter_cpe_strings(cve["vulnerable_configuration"])
        cve["component"] = component
        cve["component_versions"] = component_versions
        cve["component_versions_string"] = component_versions_string
        return cve

    def fix_fields_of_cve(self, cve, file_data_timestamp):
        published = cve["published"]
        if isinstance(cve["published"], str):
            cve["published"] = dateparser.parse(cve["published"])
        if isinstance(cve["modified"], str):
            cve["modified"] = dateparser.parse(cve["modified"])
        cve["published"] = make_aware(cve["published"])
        cve["modified"] = make_aware(cve["modified"])
        cve["cvss_time"] = dateparser.parse(file_data_timestamp)
        cve = self.fix_component_versions_fields(cve)
        return cve

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
                        # print_debug(value)
                        # ask_input("Value from file")
                        cve = CVEItem(value).to_json()
                        
                        print_debug("process cve # {} with ID: {}".format(count, cve["cve_id"]))
                        count += 1
                        
                        cve = self.fix_fields_of_cve(cve, file_data_timestamp)

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
