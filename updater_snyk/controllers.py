import os
import re
import sys
import time
import json
from datetime import datetime

from django.utils import timezone
from django.utils.timezone import make_aware

from lxml import html
from lxml.cssselect import CSSSelector
from dateutil import parser

from .utils import set_default
from .utils import create_url
from .utils import startswith
from .utils import find_between
from .utils import filter_vuln_links
from .utils import download_page_from_url


from .models import STATUS_SNYK
from .models import VULNERABILITY_SNYK
from .models import VULNERABILITY_SNYK_NEW
from .models import VULNERABILITY_SNYK_MODIFIED

from .text_messages import TextMessages

from .configurations import SNYKConfig

undefined = SNYKConfig.undefined

a_selector = CSSSelector('a')

LOCAL_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

versions_file_path = os.path.join(os.path.join(LOCAL_BASE_DIR, NPMConfig.file_storage_root), NPMConfig.versions_file_name)
source_file_path = os.path.join(os.path.join(LOCAL_BASE_DIR, NPMConfig.file_storage_root), NPMConfig.source_file_name)

def print_debug(message):
    if SNYKConfig.debug:
        print(message)


def pack_answer(
        status=TextMessages.error.value,
        message=TextMessages.error.value,
        snyk_cnt_before=0,
        snyk_cnt_after=0,
        new_cnt=0,
        modified_cnt=0
):
    return dict(
        vulnerability=dict(
            count_before=snyk_cnt_before,
            count_after=snyk_cnt_after),
        vulnerability_new=dict(
            count=new_cnt),
        vulnerability_modified=dict(
            count=modified_cnt),
        status=status,
        message=message
    )


class SNYKController(object):
    
    @staticmethod
    def clear_vulneranility_snyk_table():
        for x in VULNERABILITY_SNYK.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerability_snyk_new_table():
        for x in VULNERABILITY_SNYK_NEW.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerability_snyk_modified_table():
        for x in VULNERABILITY_SNYK_MODIFIED.objects.all().iterator():
            x.delete()

    @staticmethod
    def count_vulnerability_snyk_table():
        return VULNERABILITY_SNYK.objects.count()

    @staticmethod
    def count_vulnerability_snyk_new_tabele():
        return VULNERABILITY_SNYK_NEW.objects.count()

    @staticmethod
    def count_vulnerability_snyk_modified_table():
        return VULNERABILITY_SNYK_MODIFIED.objects.count()

    @staticmethod
    def append_snyk_in_vulnerability_snyk_table(snyk):
        return VULNERABILITY_SNYK.objects.create(
            snyk_id=snyk["snyk_id"],
            cve_id=snyk["cve_id"],
            cve_url=snyk["cve_url"],
            cwe_id=snyk["cwe_id"],
            cwe_url=snyk["cwe_url"],
            header_title=snyk["header_title"],
            affecting_github=snyk["affecting_github"],
            versions=snyk["versions"],
            overview=snyk["overview"],
            details=snyk["details"],
            references=snyk["references"],
            credit=snyk["credit"],
            source_url=snyk["source_url"],
            source=snyk["source"],
            disclosed=snyk["disclosed"],
            published=snyk["published"]
        )

    @staticmethod
    def append_snyk_in_vulnerability_snyk_new_table(snyk):
        objects = VULNERABILITY_SNYK_NEW.objects.filter(snyk_id=snyk["snyk_id"])
        if len(objects) == 0:
            return VULNERABILITY_SNYK_NEW.objects.create(
                snyk_id=snyk["snyk_id"],
                cve_id=snyk["cve_id"],
                cve_url=snyk["cve_url"],
                cwe_id=snyk["cwe_id"],
                cwe_url=snyk["cwe_url"],
                header_title=snyk["header_title"],
                affecting_github=snyk["affecting_github"],
                versions=snyk["versions"],
                overview=snyk["overview"],
                details=snyk["details"],
                references=snyk["references"],
                credit=snyk["credit"],
                source_url=snyk["source_url"],
                source=snyk["source"],
                disclosed=snyk["disclosed"],
                published=snyk["published"]
            )

    @staticmethod
    def append_snyk_in_vulnerability_snyk_modified_table(snyk):
        objects = VULNERABILITY_SNYK_MODIFIED.objects.filter(snyk_id=snyk["snyk_id"])
        if len(objects) == 0:
            return VULNERABILITY_SNYK_MODIFIED.objects.create(
                snyk_id=snyk["snyk_id"],
                cve_id=snyk["cve_id"],
                cve_url=snyk["cve_url"],
                cwe_id=snyk["cwe_id"],
                cwe_url=snyk["cwe_url"],
                header_title=snyk["header_title"],
                affecting_github=snyk["affecting_github"],
                versions=snyk["versions"],
                overview=snyk["overview"],
                details=snyk["details"],
                references=snyk["references"],
                credit=snyk["credit"],
                source_url=snyk["source_url"],
                source=snyk["source"],
                disclosed=snyk["disclosed"],
                published=snyk["published"]
            )

    @staticmethod
    def save_status_in_local_status_table(status: dict):
        obj = STATUS_SNYK.objects.filter(name="capec")
        if obj:
            return STATUS_SNYK.objects.filter(name="capec").update(
                count=status.get("count", 0),
                updated=status.get("updated", timezone.now())
            )
        return STATUS_SNYK.objects.create(
            name="capec",
            count=status.get("count", 0),
            created=timezone.now(),
            updated=status.get("updated", timezone.now())
        )

    @staticmethod
    def get_status_from_local_status_table() -> dict:
        obj = STATUS_SNYK.objects.filter(name="capec")
        if obj:
            return obj.data
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
    def check_if_snyk_item_changed(old: dict, new: dict) -> bool:
        if old["cve_id"] != new["cve_id"] or \
                old["cve_url"] != new["cve_url"] or \
                old["cwe_id"] != new["cwe_id"] or \
                old["cwe_url"] != new["cwe_url"] or \
                old["header_title"] != new["header_title"] or \
                old["affecting_github"] != new["affecting_github"] or \
                old["versions"] != new["versions"] or \
                old["overview"] != new["overview"] or \
                old["details"] != new["details"] or \
                old["references"] != new["references"] or\
                old["credit"] != new["credit"] or \
                old["source_url"] != new["source_url"] or \
                old["source"] != new["source"] or \
                old["disclosed"] != new["disclosed"] or \
                old["published"] != new["published"]:
            return True
        return False

    @staticmethod
    def update_snyk_in_snyk_table(snyk: dict):
        return VULNERABILITY_SNYK.objects.filter(snyk_id=snyk["snyk_id"]).update(
            cve_id=snyk["cve_id"],
            cve_url=snyk["cve_url"],
            cwe_id=snyk["cwe_id"],
            cwe_url=snyk["cwe_url"],
            header_title=snyk["header_title"],
            affecting_github=snyk["affecting_github"],
            versions=snyk["versions"],
            overview=snyk["overview"],
            details=snyk["details"],
            references=snyk["references"],
            credit=snyk["credit"],
            source_url=snyk["source_url"],
            source=snyk["source"],
            disclosed=snyk["disclosed"],
            published=snyk["published"]
        )

    def create_or_update_snyk_vulnertability(self, snyk: dict):
        objects = VULNERABILITY_SNYK.objects.filter(snyk_id=snyk["snyk_id"])
        if len(objects) == 0:
            self.append_snyk_in_vulnerability_snyk_table(snyk)
            self.append_snyk_in_vulnerability_snyk_new_table(snyk)
            return 'created'
        else:
            o = objects[0].data
            if self.check_if_snyk_item_changed(o, snyk):
                self.update_snyk_in_snyk_table(snyk)
                self.append_snyk_in_vulnerability_snyk_modified_table(snyk)
                return 'updated'
            return 'skipped'

    @staticmethod
    def split_and_remove_empty_elements(input_string):
        splitted = input_string.split("||")
        result = []
        for s in splitted:
            result.append(s)
        return result

    def process_vulnerable_versions(self, package_versions, vulnerable_versions):
        if "99.99999.999" in vulnerable_versions:
            return package_versions

        diapasons = self.split_and_remove_empty_elements(vulnerable_versions)

        vulnerable_versions_to_save = []

        for index in range(0, len(diapasons)):
            diap_0__source = diapasons[index]
            diap_0 = diap_0__source.replace(">", "").replace("<", "").replace("=", "")
            diap_0__splitted = diap_0.split(" ")
            diap_0__splitted__cleared = [x for x in diap_0__splitted if x != ""]
            diap_0__bounds = []
            filled = False
            if len(diap_0__splitted__cleared) == 1:
                filled = True
                diap_0__bounds.append(package_versions[0])
                diap_0__bounds.append(diap_0__splitted__cleared[0])
            elif len(diap_0__splitted__cleared) == 2:
                filled = False
                diap_0__bounds.append(diap_0__splitted__cleared[0])
                diap_0__bounds.append(diap_0__splitted__cleared[1])

            start__index = 0
            stop__index = 0

            if not filled:
                if "<" in diap_0__source or ">" in diap_0__source:
                    if ">" in diap_0__source:
                        start__index = package_versions.index(diap_0__bounds[0])
                        if start__index < len(package_versions):
                            start__index += 1
                    if ">=" in diap_0__source:
                        start__index = package_versions.index(diap_0__bounds[0])
                    if "<" in diap_0__source:
                        stop__index = package_versions.index(diap_0__bounds[1])
                    if "<=" in diap_0__source:
                        stop__index = package_versions.index(diap_0__bounds[1])
                        if stop__index < len(package_versions):
                            stop__index += 1
                else:
                    start__index = package_versions.index(diap_0__bounds[0])
                    stop__index = package_versions.index(diap_0__bounds[1])
            else:
                start__index = package_versions.index(diap_0__bounds[0])
                if "<" in diap_0__source or ">" in diap_0__source:
                    if "<" in diap_0__source:
                        stop__index = package_versions.index(diap_0__bounds[1])
                    if "<=" in diap_0__source:
                        stop__index = package_versions.index(diap_0__bounds[1])
                        if stop__index < len(package_versions):
                            stop__index += 1
                else:
                    start__index = package_versions.index(diap_0__bounds[0])
                    stop__index = package_versions.index(diap_0__bounds[1])

            vulnerable__versions__from__package = package_versions[start__index:stop__index]

            vulnerable_versions_to_save += vulnerable__versions__from__package

        return vulnerable_versions_to_save

    def process_patched_versions(self, package_versions, patched_versions):
        if "0.0.0" in patched_versions:
            return []

        diapasons = self.split_and_remove_empty_elements(patched_versions)

        patched__versions__to__save = []

        for index in range(0, len(diapasons)):
            diap_0__source = diapasons[index]
            diap_0 = diap_0__source.replace(">", "").replace("<", "").replace("=", "")

            diap_0__splitted = diap_0.split(" ")
            diap_0__splitted__cleared = [x for x in diap_0__splitted if x != ""]

            diap_0__bounds = []

            filled = False

            if len(diap_0__splitted__cleared) == 1:
                filled = True
                diap_0__bounds.append(diap_0__splitted__cleared[0])
                diap_0__bounds.append(package_versions[-1])
            elif len(diap_0__splitted__cleared) == 2:
                filled = False
                diap_0__bounds.append(diap_0__splitted__cleared[0])
                diap_0__bounds.append(diap_0__splitted__cleared[1])

            start__index = 0
            stop__index = 0

            if not filled:
                if "<" in diap_0__source or ">" in diap_0__source:
                    if ">" in diap_0__source:
                        start__index = package_versions.index(diap_0__bounds[0])
                    if start__index < len(package_versions):
                        start__index += 1
                    if ">=" in diap_0__source:
                        start__index = package_versions.index(diap_0__bounds[0])
                    if "<" in diap_0__source:
                        stop__index = package_versions.index(diap_0__bounds[1])
                    if "<=" in diap_0__source:
                        stop__index = package_versions.index(diap_0__bounds[1])
                        if stop__index < len(package_versions):
                            stop__index += 1
                else:
                    start__index = package_versions.index(diap_0__bounds[0])
                    stop__index = package_versions.index(diap_0__bounds[1])
            else:
                start__index = package_versions.index(diap_0__bounds[0])
                if "<" in diap_0__source or ">" in diap_0__source:
                    if ">" in diap_0__source:
                        stop__index = package_versions.index(diap_0__bounds[1])
                    if ">=" in diap_0__source:
                        stop__index = package_versions.index(diap_0__bounds[1])
                        if stop__index < len(package_versions):
                            stop__index += 1
                else:
                    start__index = package_versions.index(diap_0__bounds[0])
                    stop__index = package_versions.index(diap_0__bounds[1])

            patched__versions__from__package = package_versions[start__index:stop__index]

            patched__versions__to__save += patched__versions__from__package

        return patched__versions__to__save

    def process_npm_vulner_to_get_vulnerable_and_patched_versions(self,
                                                                      module_name,
                                                                      vulnerable_versions,
                                                                      patched_versions):
        vulnerable__versions__for__module = []
        command__get__npm__versions = "npm show {} versions > {}".format(module_name, versions_file_path)
        if os.path.exists(versions_file_path):
            os.remove(versions_file_path)
        try:
            os.system(command__get__npm__versions)
        except Exception as ex:
            return [], []
        if os.path.exists(versions_file_path):
            try:
                with open(versions_file_path, 'r') as versions__file__object:
                    package__versions__from__file = versions__file__object.read()
                    package__versions__from__file = package__versions__from__file.replace("[", "").replace("]", "")
                    package__versions__from__file = package__versions__from__file.replace(" ", "\n")
                    package__versions__from__file = package__versions__from__file.replace(",", "").replace("'", "")
                    package__versions__from__file = [x for x in package__versions__from__file.split("\n") if x != ""]

                    vulnerable__versions__for__module = self.process_vulnerable_versions(
                        package__versions__from__file,
                        vulnerable_versions)
                    patched__versions__for__module = self.process_patched_versions(
                        package__versions__from__file,
                        patched_versions)
                    return vulnerable__versions__for__module, patched__versions__for__module
            except Exception as ex:
                if len(vulnerable__versions__for__module) > 0:
                    return vulnerable__versions__for__module, []
                else:
                    return [], []
        return [], []

    def parse_page(self, page_tree, src):
        try:
            header_title_list = page_tree.xpath('//span[@class="header__title__text"]/text()')
        except Exception as ex:
            header_title_list = []

        if len(header_title_list) > 0:
            header_title = str(header_title_list[0])
        else:
            header_title = "unknown"

        header_title = header_title.replace("\n", "")
        header_title = header_title.lstrip()
        header_title = header_title.rstrip()

        try:
            affecting_list = page_tree.xpath('//a[@class="breadcrumbs__list-item__link"]/text()')
        except Exception as ex:
            affecting_list = []

        if len(affecting_list) >= 3:
            affecting_github = str(affecting_list[2])
        else:
            affecting_github = ""

        affecting_github = affecting_github.replace("\n", "")
        affecting_github = affecting_github.lstrip()
        affecting_github = affecting_github.rstrip()

        try:
            versions_list = page_tree.xpath('//p[@class="header__lede"]//text()')
        except Exception as ex:
            versions_list = []

        if len(versions_list) >= 5:
            versions = versions_list[4]
        else:
            versions = undefined

        versions = versions.replace("\n", "")
        versions = versions.lstrip()
        versions = versions.rstrip()

        if str(versions) == "ALL" or str(versions) == "all" or str(versions) == undefined:
            versions = "?"

        if versions != "?" and src == SNYKConfig.npm:
            if affecting_github != "":
                versions_tuple = self.process_npm_vulner_to_get_vulnerable_and_patched_versions(affecting_github, versions, [])
                if versions_tuple is None:
                    versions_tuple = [], []
                if versions is None:
                    versions = "?"
                else:
                    if isinstance(versions, list):
                        if len(versions) == 0:
                            versions = "?"
                        else:
                            versions = versions_tuple[0]
                    else:
                        versions = "?"
                    pass
                pass
            pass

        try:
            overview_list = page_tree.xpath('//div[@class="card card--markdown"]//text()')
        except Exception as ex:
            overview_list = []

        overview = ""
        is_overview = False
        remedation = ""
        is_remedation = False
        details = ""
        is_details = False

        for over in overview_list:
            if over == "Overview":
                is_overview = True
                is_remedation = False
                is_details = False
                continue
            elif over == "Remediation":
                is_overview = False
                is_remedation = True
                is_details = False
                continue
            elif over == "Details":
                is_overview = False
                is_remedation = False
                is_details = True

            if is_overview:
                overview += over
            elif is_remedation:
                remedation += over
            elif is_details:
                details += over

        if overview == "":
            overview = SNYKConfig.undefined

        overview = overview.replace("\n", " ")
        if overview == "":
            overview = SNYKConfig.undefined
        overview = overview.lstrip()
        overview = overview.rstrip()

        remedation = remedation.replace("\n", " ")
        if remedation == "":
            remedation = SNYKConfig.undefined
        remedation = remedation.lstrip()
        remedation = remedation.rstrip()

        details = details.replace("\n", " ")
        if details == "":
            details = SNYKConfig.undefined
        details = details.lstrip()
        details = details.rstrip()

        references_list_ul = []

        try:
            r = page_tree.xpath('//h2[@id="references"]')[0].getnext().xpath('//li//a')
        except Exception as ex:
            r = None

        if r is None:
            pass
        else:
            for _ in r:
                if _ is not None:
                    if _.text is not None:
                        if "\n " not in _.text:
                            if "href" in _.attrib:
                                if "http://" in _.attrib["href"] or "https://" in _.attrib["href"]:
                                    if "class" not in _.attrib:
                                        references_list_ul.append(_.attrib["href"])

        try:
            card__content = page_tree.xpath('//div[@class="card__content"]')[0].xpath('//dl/dd')
        except Exception as ex:
            card__content = []

        credit = snyk_id = disclosed_str = published_str = SNYKConfig.undefined
        disclosed_dt = published_dt = datetime.utcnow()

        if len(card__content) >= 6:
            credit = str(card__content[0].text.replace("\n", "")).strip()
            credit = credit.lstrip()
            credit = credit.rstrip()

            snyk_id = str(card__content[3].text.replace("\n", "")).strip()
            snyk_id = snyk_id.lstrip()
            snyk_id = snyk_id.rstrip()

            disclosed_str = str(card__content[4].text.replace("\n", "")).strip()
            disclosed_str = disclosed_str.lstrip()
            disclosed_str = disclosed_str.rstrip()
            disclosed_dt = parser.parse(disclosed_str)

            published_str = str(card__content[5].text.replace("\n", "")).strip()
            published_str = published_str.lstrip()
            published_str = published_str.rstrip()
            published_dt = parser.parse(published_str)

        cve = cve_url = cwe = cwe_url = "undefined"

        try:
            card__content_a = page_tree.xpath('//div[@class="card__content"]')[0].xpath('//dl/dd/a')
        except Exception as ex:
            card__content_a = []

        if len(card__content_a) >= 2:
            cve_a = card__content_a[0].attrib
            if "href" in cve_a:
                if "cve.mitre.org" in cve_a["href"] or \
                        "nvd.nist.gov" in cve_a["href"] or \
                        "cloudfoundry.org" in cve_a["href"]:
                    cve_url = cve_a["href"]
                    try:
                        i = cve_url.index("CVE-20")
                        cve = cve_url[i:]
                    except ValueError:
                        cve = "undefined"
                    if not startswith(cve, "CVE-"):
                        cve = "undefined"
                else:
                    cve_url = cve = "undefined"
            else:
                cve_url = cve = "undefined"

            cwe_a = card__content_a[1].attrib
            if "href" in cwe_a:
                if "cwe.mitre.org" in cwe_a["href"]:
                    cwe_url = cwe_a["href"]
                    cwe = find_between(cwe_url, "https://cwe.mitre.org/data/definitions/", ".html")
                    if cwe != "":
                        cwe = re.sub("\D", "", str(cwe))
                        cwe = "CWE-" + cwe
                    else:
                        cwe = "undefined"
                else:
                    cwe_url = cwe = "undefined"
            else:
                cwe_url = cwe = "undefined"

        return dict(
            header_title=header_title,
            affecting_github=affecting_github,
            versions=versions,
            overview=overview,
            details=details,
            references=references_list_ul,
            cve_id=cve,
            cve_url=cve_url,
            cwe_id=cwe,
            cwe_url=cwe_url,
            credit=credit,
            snyk_id=snyk_id,
            disclosed=disclosed_str,
            published=published_str,
            source="",
            source_url="",
            type=""
        )


    def stats(self):
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            snyk_cnt_before=self.count_vulnerability_snyk_table(),
            snyk_cnt_after=self.count_vulnerability_snyk_table(),
            new_cnt=self.count_vulnerability_snyk_new_tabele(),
            modified_cnt=self.count_vulnerability_snyk_modified_table()
        )

    def populate(self):
        count = self.count_vulnerability_snyk_table()
        if count == 0:
            filtered_links = []
            self.clear_vulnerability_snyk_new_table()
            self.clear_vulnerability_snyk_modified_table()
            snyk_count = 0
            for source in SNYKConfig.sources:
                continue_work = True
                page_number = 1
                print_debug("Processing source `{0}`".format(source))
                while continue_work:
                    print_debug("Processing page # {0}".format(page_number))
                    page_url = create_url(page_number, source)
                    tree = download_page_from_url(page_url)
                    if tree is not None:
                        try:
                            f = a_selector(tree)
                            links = [e.get('href') for e in f]
                            filtered_links, cnt = filter_vuln_links(links)
                        except Exception as ex:
                            return pack_answer(
                                status=TextMessages.exception.value,
                                message="{}".format(ex),
                                snyk_cnt_before=self.count_vulnerability_snyk_table(),
                                snyk_cnt_after=self.count_vulnerability_snyk_table(),
                                new_cnt=self.count_vulnerability_snyk_new_tabele(),
                                modified_cnt=self.count_vulnerability_snyk_modified_table()
                            )
                    if len(filtered_links) == 0:
                        print_debug("Complete parsing source `{0}`".format(source))
                        continue_work = False
                    else:
                        for pn in range(len(filtered_links)):
                            d_url = "".join(["https://snyk.io", filtered_links[pn]])
                            page_tree = download_page_from_url(d_url)

                            if page_tree is not None:
                                snyk_vulner = self.parse_page(page_tree, source)
                                snyk_vulner["source"] = "snyk"
                                snyk_vulner["source_url"] = d_url
                                snyk_vulner["type"] = source

                                self.create_or_update_snyk_vulnertability(snyk_vulner)

                                snyk_count += 1
                    page_number += 1
            print_debug("Complete populating {} Snyk vulnerabilities".format(snyk_count))
            return pack_answer(
                status=TextMessages.ok.value,
                message=TextMessages.ok.value,
                snyk_cnt_before=self.count_vulnerability_snyk_table(),
                snyk_cnt_after=self.count_vulnerability_snyk_table(),
                new_cnt=self.count_vulnerability_snyk_new_tabele(),
                modified_cnt=self.count_vulnerability_snyk_modified_table()
            )
        else:
            print_debug("You want populate Snyk vulnerabilities, but Snyk table is not empty.")
            return pack_answer(
                status=TextMessages.error.value,
                message="You want populate Snyk vulnerabilities, but Snyk table is not empty.",
                snyk_cnt_before=self.count_vulnerability_snyk_table(),
                snyk_cnt_after=self.count_vulnerability_snyk_table(),
                new_cnt=self.count_vulnerability_snyk_new_tabele(),
                modified_cnt=self.count_vulnerability_snyk_modified_table()
            )

    def update(self):
        if SNYKConfig.drop_core_table:
            self.clear_vulneranility_snyk_table()
        self.clear_vulnerability_snyk_new_table()
        self.clear_vulnerability_snyk_modified_table()
        count_before = count_after = self.count_vulnerability_snyk_table()

        if count_before == 0:
            print_debug("You want populate Snyk vulnerabilities, but Snyk table is empty. Needs to populate it.")
            return pack_answer(
                status=TextMessages.error.value,
                message="You want populate Snyk vulnerabilities, but Snyk table is empty. Needs to populate it.",
                snyk_cnt_before=count_before,
                snyk_cnt_after=count_after,
                new_cnt=0,
                modified_cnt=0
            )
        else:
            created_snyk_vulners = []
            filtered_links = []
            for source in SNYKConfig.sources:
                continue_work = True
                page_number = 1
                print_debug("Process source `{}`".format(source))
                while continue_work:
                    print_debug("Process page # {}".format(page_number))
                    page_url = create_url(page_number, source)
                    tree = download_page_from_url(page_url)

                    if tree is not None:
                        try:
                            f = a_selector(tree)
                            links = [e.get('href') for e in f]
                            filtered_links, cnt = filter_vuln_links(links)
                        except Exception as ex:
                            print_debug(" Got an exception with tree parsing: {}".format(ex))
                            return pack_answer(
                                status=TextMessages.exception.value,
                                message="{}".format(ex),
                                snyk_cnt_before=self.count_vulnerability_snyk_table(),
                                snyk_cnt_after=self.count_vulnerability_snyk_table(),
                                new_cnt=self.count_vulnerability_snyk_new_tabele(),
                                modified_cnt=self.count_vulnerability_snyk_modified_table()
                            )

                    if len(filtered_links) == 0:
                        print_debug("Complete parsing source `{}`".format(source))
                        continue_work = False
                    else:
                        for pn in range(len(filtered_links)):
                            d_url = "".join(["https://snyk.io", filtered_links[pn]])
                            page_tree = download_page_from_url(d_url)

                            if page_tree is not None:
                                snyk_vulner = self.parse_page(page_tree, source)
                                snyk_vulner["source"] = "snyk"
                                snyk_vulner["source_url"] = d_url
                                snyk_vulner["type"] = source
                                result = self.create_or_update_snyk_vulnertability(snyk_vulner)
                                if result == "updated":
                                    print_debug("Riched end of update")
                                    continue_work = False
                                elif result == "skipped":
                                    print_debug("Riched end of update")
                                    continue_work = False
                                elif result == "created":
                                    print_debug("Find new Snyk vulnerability: {}".format(snyk_vulner["header_title"]))
                    page_number += 1
            print_debug("Complete updating {} Snyk vulnerabilities".format(len(created_snyk_vulners)))
            return pack_answer(
                status=TextMessages.ok.value,
                message=TextMessages.ok.value,
                snyk_cnt_before=self.count_vulnerability_snyk_table(),
                snyk_cnt_after=self.count_vulnerability_snyk_table(),
                new_cnt=self.count_vulnerability_snyk_new_tabele(),
                modified_cnt=self.count_vulnerability_snyk_modified_table()
            )