import os
import re
from re import findall

from django.utils import timezone
from django.utils.timezone import make_aware

from .text_messages import TextMessages

from .models import STATUS_NPM
from .models import VULNERABILITY_NPM
from .models import VULNERABILITY_NPM_NEW
from .models import VULNERABILITY_NPM_MODIFIED

from .configurations import NPMConfig

from .utils import upload_file
from .utils import read_file
from .utils import unify_time
from .utils import time_string_to_datetime

import logging
logger = logging.getLogger(__name__)

LOCAL_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UNDEFINED = NPMConfig.undefined

versions_file_path = os.path.join(os.path.join(LOCAL_BASE_DIR, NPMConfig.file_storage_root), NPMConfig.versions_file_name)
source_file_path = os.path.join(os.path.join(LOCAL_BASE_DIR, NPMConfig.file_storage_root), NPMConfig.source_file_name)

def print_debug(message):
    if NPMConfig.debug:
        print(message)


def pack_answer(
        status=TextMessages.error.value,
        message=TextMessages.error.value,
        npm_cnt_before=0,
        npm_cnt_after=0,
        new_cnt=0,
        modified_cnt=0
):
    return dict(
        vulnerability=dict(
            count_before=npm_cnt_before,
            count_after=npm_cnt_after),
        vulnerability_new=dict(
            count=new_cnt),
        vulnerability_modified=dict(
            count=modified_cnt),
        status=status,
        message=message
    )


class NPMController(object):

    @staticmethod
    def clear_vulnerability_npm_table():
        for x in VULNERABILITY_NPM.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerability_npm_new_table():
        for x in VULNERABILITY_NPM_NEW.objects.all().iterator():
            x.delete()

    @staticmethod
    def clear_vulnerability_npm_modified_table():
        for x in VULNERABILITY_NPM_MODIFIED.objects.all().iterator():
            x.delete()

    @staticmethod
    def count_vulnerability_npm_table():
        return VULNERABILITY_NPM.objects.count()

    @staticmethod
    def count_vulnerability_npm_new_table():
        return VULNERABILITY_NPM_NEW.objects.count()

    @staticmethod
    def count_vulnerability_npm_modified_table():
        return VULNERABILITY_NPM_MODIFIED.objects.count()

    @staticmethod
    def append_npm_in_vulnerability_npm_table(npm):
        return VULNERABILITY_NPM.objects.create(
            npm_id=npm["npm_id"],
            created=npm["created"],
            updated=npm["updated"],
            title=npm["title"],
            author=npm["author"],
            module_name=npm["module_name"],
            published_date=npm["published_date"],
            cves=npm["cves"],
            vulnerable_versions=npm["vulnerable_versions"],
            slug=npm["slug"],
            overview=npm["overview"],
            recommendation=npm["recommendation"],
            references=npm["references"],
            legacy_slug=npm["legacy_slug"],
            allowed_scopes=npm["allowed_scopes"],
            cvss_vector=npm["cvss_vector"],
            cvss_score=npm["cvss_score"],
            cwe=npm["cwe"],
            source=npm["source"]
        )

    @staticmethod
    def append_npm_in_vulnerability_npm_new_table(npm):
        objects = VULNERABILITY_NPM_NEW.objects.filter(npm_id=npm["npm_id"])
        if len(objects) == 0:
            return VULNERABILITY_NPM_NEW.objects.create(
                npm_id=npm["npm_id"],
                created=npm["created"],
                updated=npm["updated"],
                title=npm["title"],
                author=npm["author"],
                module_name=npm["module_name"],
                published_date=npm["published_date"],
                cves=npm["cves"],
                vulnerable_versions=npm["vulnerable_versions"],
                slug=npm["slug"],
                overview=npm["overview"],
                recommendation=npm["recommendation"],
                references=npm["references"],
                legacy_slug=npm["legacy_slug"],
                allowed_scopes=npm["allowed_scopes"],
                cvss_vector=npm["cvss_vector"],
                cvss_score=npm["cvss_score"],
                cwe=npm["cwe"],
                source=npm["source"]
            )

    @staticmethod
    def append_npm_in_vulnerability_npm_nmodified_table(npm):
        objects = VULNERABILITY_NPM_MODIFIED.objects.filter(npm_id=npm["npm_id"])
        if len(objects) == 0:
            return VULNERABILITY_NPM_MODIFIED.objects.create(
                npm_id=npm["npm_id"],
                created=npm["created"],
                updated=npm["updated"],
                title=npm["title"],
                author=npm["author"],
                module_name=npm["module_name"],
                published_date=npm["published_date"],
                cves=npm["cves"],
                vulnerable_versions=npm["vulnerable_versions"],
                slug=npm["slug"],
                overview=npm["overview"],
                recommendation=npm["recommendation"],
                references=npm["references"],
                legacy_slug=npm["legacy_slug"],
                allowed_scopes=npm["allowed_scopes"],
                cvss_vector=npm["cvss_vector"],
                cvss_score=npm["cvss_score"],
                cwe=npm["cwe"],
                source=npm["source"]
            )


    @staticmethod
    def save_status_in_local_status_table(status: dict):
        name = status.get("name", "npm")
        obj = STATUS_NPM.objects.filter(name=name)
        if obj:
            return STATUS_NPM.objects.filter(name=name).update(
                status=status.get("status", ""),
                count=status.get("count", 0),
                updated=status.get("updated", timezone.now())
            )
        return STATUS_NPM.objects.create(
            name=name,
            status=status.get("status", ""),
            count=status.get("count", 0),
            created=status.get("created", timezone.now()),
            updated=status.get("updated", timezone.now())
        )

    @staticmethod
    def get_status_from_local_status_table(name="npm") -> dict:
        objects = STATUS_NPM.objects.filter(name=name)
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
    def check_if_npm_item_changed(old, new):
        if old["created"] != new["created"] or \
            old["updated"] != new["updated"] or \
            old["title"] != new["title"] or \
            old["author"] != new["author"] or \
            old["module_name"] != new["module_name"] or \
            old["published_date"] != new["published_date"] or \
            old["cves"] != new["cves"] or \
            old["vulnerable_versions"] != new["vulnerable_versions"] or \
            old["slug"] != new["slug"] or \
            old["overview"] != new["overview"] or \
            old["recommendation"] != new["recommendation"] or \
            old["references"] != new["references"] or \
            old["legacy_slug"] != new["legacy_slug"] or \
            old["allowed_scopes"] != new["allowed_scopes"] or \
            old["cvss_vector"] != new["cvss_vector"] or \
            old["cvss_score"] != new["cvss_score"] or \
            old["cwe"] != new["cwe"] or \
                old["source"] != new["source"]:
            return True
        return False

    @staticmethod
    def update_npm_in_npm_table(npm):
        return VULNERABILITY_NPM.objects.filter(id=npm["id"]).update(
            created=npm["created"],
            updated=npm["updated"],
            title=npm["title"],
            author=npm["author"],
            module_name=npm["module_name"],
            published_date=npm["published_date"],
            cves=npm["cves"],
            vulnerable_versions=npm["vulnerable_versions"],
            slug=npm["slug"],
            overview=npm["overview"],
            recommendation=npm["recommendation"],
            references=npm["references"],
            legacy_slug=npm["legacy_slug"],
            allowed_scopes=npm["allowed_scopes"],
            cvss_vector=npm["cvss_vector"],
            cvss_score=npm["cvss_score"],
            cwe=npm["cwe"],
            source=npm["source"]
        )

    def create_or_update_npm_vulnerability(self, npm):
        objects = VULNERABILITY_NPM.objects.filter(npm_id=npm["npm_id"])
        if len(objects) == 0:
            self.append_npm_in_vulnerability_npm_table(npm)
            self.append_npm_in_vulnerability_npm_new_table(npm)
        else:
            o2 = objects[0].data
            if self.check_if_npm_item_changed(o2, npm):
                self.update_npm_in_npm_table(npm)
                self.append_npm_in_vulnerability_npm_nmodified_table(npm)

    @staticmethod
    def validate_cwe_field(cwe_field):
        if isinstance(cwe_field, str):
            if cwe_field != 'null':
                digit_part = findall(r'(\d.*)', cwe_field)
                if digit_part:
                    return 'CWE-' + digit_part[0]

    def validate_npm_vulnerability_fields(self, vulnerability):
        if isinstance(vulnerability, dict):
            if vulnerability['id'] is None:
                vulnerability['id'] = UNDEFINED
            if vulnerability['created_at'] is None:
                vulnerability['created_at'] = UNDEFINED
            if vulnerability['updated_at'] is None:
                vulnerability['updated_at'] = UNDEFINED
            if vulnerability['title'] is None:
                vulnerability['title'] = UNDEFINED
            if vulnerability['author'] is None:
                vulnerability['author'] = UNDEFINED
            if vulnerability['module_name'] is None:
                vulnerability['module_name'] = UNDEFINED
            if vulnerability['publish_date'] is None:
                vulnerability['publish_date'] = UNDEFINED
            if vulnerability['cves'] is None:
                vulnerability['cves'] = UNDEFINED
            if vulnerability['vulnerable_versions'] is None:
                vulnerability['vulnerable_versions'] = UNDEFINED
            if vulnerability['patched_versions'] is None:
                vulnerability['patched_versions'] = UNDEFINED
            if vulnerability['slug'] is None:
                vulnerability['slug'] = UNDEFINED
            if vulnerability['overview'] is None:
                vulnerability['overview'] = UNDEFINED
            if vulnerability['recommendation'] is None:
                vulnerability['recommendation'] = UNDEFINED
            if vulnerability['references'] is None:
                vulnerability['references'] = UNDEFINED
            if vulnerability['legacy_slug'] is None:
                vulnerability['legacy_slug'] = UNDEFINED
            if vulnerability['allowed_scopes'] is None:
                vulnerability['allowed_scopes'] = UNDEFINED
            if vulnerability['cvss_vector'] is None:
                vulnerability['cvss_vector'] = UNDEFINED
            if vulnerability['cvss_score'] is None:
                vulnerability['cvss_score'] = 0.0
            if vulnerability['cwe'] is None:
                vulnerability['cwe'] = UNDEFINED

            vulnerability['cwe'] = self.validate_cwe_field(vulnerability['cwe'])

        return vulnerability

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

    @staticmethod
    def make_cvss_vector(npm_cvss_vector):
        cvss_vector = UNDEFINED

        if npm_cvss_vector != UNDEFINED:
            cvss_vector = re.findall(r'CVSS:\d*\.\d*\/(.*)', npm_cvss_vector)[0]
            if cvss_vector:
                if not cvss_vector.startswith('('):
                    cvss_vector = '(' + cvss_vector
                if not cvss_vector.endswith(')'):
                    cvss_vector = cvss_vector + ')'

        return cvss_vector

    @staticmethod
    def get_npm_module_source(module_name):
        command_get_npm_module_source = "npm view {} repository.url > {}".format(module_name, source_file_path)
        if os.path.exists(source_file_path):
            os.remove(source_file_path)
        try:
            os.system(command_get_npm_module_source)
        except Exception as ex:
            return UNDEFINED
        if os.path.exists(source_file_path):
            try:
                with open(source_file_path, 'r') as source__file__object:
                    source__from__file = source__file__object.read()
                    return source__from__file
            except Exception as ex:
                return UNDEFINED

    def stats(self):
        return pack_answer(
            status=TextMessages.ok.value,
            message=TextMessages.ok.value,
            npm_cnt_before=self.count_vulnerability_npm_table(),
            npm_cnt_after=self.count_vulnerability_npm_table(),
            new_cnt=self.count_vulnerability_npm_new_table(),
            modified_cnt=self.count_vulnerability_npm_modified_table()
        )

    def update(self):
        if NPMConfig.drop_core_table:
            self.clear_vulnerability_npm_table()
        self.clear_vulnerability_npm_new_table()
        self.clear_vulnerability_npm_modified_table()
        count_before = count_after = self.count_vulnerability_npm_table()
        (file_path, success, last_modified, size, fmt) = upload_file()
        if success and file_path != '':
            # FIXME: Make last_modified comparison
            (f, success, message) = read_file(file_path)
            if f is None or not success:
                return pack_answer(
                    status=TextMessages.exception.value,
                    message=message,
                    npm_cnt_before=count_before,
                    npm_cnt_after=count_after,
                    new_cnt=0,
                    modified_cnt=0
                )
            npms = f["results"]
            count = 0
            for npm_item in npms:
                print_debug('processing: {}'.format(count))
                count += 1
                npm_item = self.validate_npm_vulnerability_fields(npm_item)
                npm = dict()
                if npm_item is not None:
                    vulnerable_versions_, patched_versions_ = \
                        self.process_npm_vulner_to_get_vulnerable_and_patched_versions(
                            npm_item['module_name'],
                            npm_item['vulnerable_versions'],
                            npm_item['patched_versions']
                        )
                    npm["npm_id"] = 'NPM-' + str(npm_item['id']) if npm_item['id'] != UNDEFINED else UNDEFINED
                    npm["created"] = time_string_to_datetime(unify_time(npm_item['created_at']))
                    npm["updated"] = time_string_to_datetime(unify_time(npm_item['updated_at']))
                    npm["title"] = npm_item['title']
                    npm["author"] = npm_item['author']
                    npm["module_name"] = npm_item['module_name']
                    npm["published_date"] = time_string_to_datetime(unify_time(npm_item['publish_date']))
                    npm["cves"] = npm_item['cves']
                    npm["vulnerable_versions"] = vulnerable_versions_
                    npm["patched_versions"] = patched_versions_
                    npm["slug"] = npm_item['slug']
                    npm["overview"] = npm_item['overview']
                    npm["recommendation"] = npm_item['recommendation']
                    npm["references"] = npm_item['references']
                    npm["legacy_slug"] = npm_item['legacy_slug']
                    npm["allowed_scopes"] = npm_item['allowed_scopes']
                    npm["cvss_vector"] = self.make_cvss_vector(npm_item['cvss_vector'])
                    npm["cvss_score"] = float(npm_item['cvss_score'])
                    npm["cwe"] = npm_item['cwe']
                    npm["source"] = self.get_npm_module_source(npm_item['module_name'])

                    self.create_or_update_npm_vulnerability(npm=npm)

            count_after = self.count_vulnerability_npm_table()
            self.save_status_in_local_status_table(dict(
                name="npm",
                count=count_after,
                updated=last_modified,
                status="updated"
            ))
            return pack_answer(
                status=TextMessages.ok.value,
                message=TextMessages.npm_updated.value,
                npm_cnt_before=count_before,
                npm_cnt_after=count_after,
                new_cnt=self.count_vulnerability_npm_new_table(),
                modified_cnt=self.count_vulnerability_npm_modified_table()
            )
        return pack_answer(
            status=TextMessages.error.value,
            message=TextMessages.cant_download_file.value,
            npm_cnt_before=count_before,
            npm_cnt_after=count_after,
            new_cnt=0,
            modified_cnt=0
        )