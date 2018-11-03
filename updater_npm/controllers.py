from .text_messages import TextMessages

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

UNDEFINED = "undefined"

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
            cvss_code=npm["cvss_code"],
            cwe=npm["cwe"],
            source=npm["source"]
        )

    @staticmethod
    def append_npm_in_vulnerability_npm_new_table(npm):
        objects = VULNERABILITY_NPM_NEW.objects.filter(npm_id=npm["npm_id"])
        if len(object) == 0:
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
            cvss_code=npm["cvss_code"],
            cwe=npm["cwe"],
            source=npm["source"]
        )

    @staticmethod
    def append_npm_in_vulnerability_npm_nmodified_table(npm):
        objects = VULNERABILITY_NPM_MODIFIED.objects.filter(npm_id=npm["npm_id"])
        if len(object) == 0:
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
            cvss_code=npm["cvss_code"],
            cwe=npm["cwe"],
            source=npm["source"]
        )

    def create_or_update_npm_vulnerability(self, npm):
        objects = VULNERABILITY_NPM.objects.filter(npm_id=npm["npm_id"])
        if len(object) == 0:
            self.append_npm_in_vulnerability_npm_table(npm)
            self.append_npm_in_vulnerability_npm_new_table(npm)
        else:
            self.append_npm_in_vulnerability_npm_nmodified_table(npm)

    @staticmethod
    def validate_npm_vulnerability_fields(vulnerability):
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

            vulnerability['cwe'] = _validate_cwe_field(vulnerability['cwe'])

        return vulnerability
        
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
        self.clear_vulnerability_npm_new_table()
        self.clear_vulnerability_npm_modified_table()
        count_before = count_after = self.count_vulnerability_npm_table()
        (file_path, success, last_modified, size, fmt) = upload_file()
        if success and file_path != '':
            # FIXME: Make last_modified comparison
            (f, success, message) = read_file(file_path, fmt=fmt)
            if f is None or not success:
                return pack_answer(
                    status=TextMessages.exception.value,
                    message=message,
                    cpe_cnt_before=count_before,
                    cpe_cnt_after=count_after,
                    new_cnt=0,
                    modified_cnt=0
                )
            npms = f["results"]
            count = 0
            for npm in npms:
                print_debug('processing: {}'.format(count))
                count += 1
                npm = self.validate_npm_vulnerability_fields(npm)
                if npm is not None:
                    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    vulnerable_versions_, patched_versions_ = process_npm_vulner_to_get_vulnerable_and_patched_versions(
                        npm['module_name'], npm['vulnerable_versions'], npm['patched_versions']
                    )
                    npm_id = 'NPM-' + str(npm['id']) if npm['id'] != UNDEFINED else UNDEFINED
                    created = time_string_to_datetime(unify_time(npm['created_at']))
                    updated = time_string_to_datetime(unify_time(npm['updated_at']))
                    title = npm['title']
                    author = npm['author']
                    module_name = npm['module_name']
                    publish_date = time_string_to_datetime(unify_time(npm['publish_date']))
                    cves = npm['cves']
                    vulnerable_versions = vulnerable_versions_
                    patched_versions = patched_versions_
                    slug = npm['slug']
                    overview = npm['overview']
                    recommendation = npm['recommendation']
                    references = npm['references']
                    legacy_slug = npm['legacy_slug']
                    allowed_scopes = npm['allowed_scopes']
                    cvss_vector = make_cvss_vector(npm['cvss_vector'])
                    cvss_score = npm['cvss_score']
                    cwe_number = npm['cwe']

                    source = get_npm_module_source(npm['module_name'])




