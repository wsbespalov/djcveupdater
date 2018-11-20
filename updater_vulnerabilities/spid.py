import re
from datetime import datetime

from django.utils import timezone

from .models import SPID

sp_prefix = 'SP'
sp_delimiter = '-'
sp_max_digits = 12

sources = {'cve':  'C', 'npm':  'N', 'snyk': 'S', 'user': 'U', 'ms': 'M'}


def years(current_year):
    y = str(current_year)
    if len(y) == 4:
        return y[2:]
    else:
        y = str(datetime.utcnow().year)
        return y[2:]


def get_last_sync_SPID():
    si = SPID.objects.all().order_by("sync")
    if si:
        if len(si) > 0:
            return si[0].data
    return dict(id=0, spid="", sync=datetime.utcnow())


def check_if_SPID_is_unique(ID):
    spid = SPID.objects.filter(spid=ID).first()
    if spid is not None:
        return False
    return True


def append_SPID_into_postgres_database(SPIDentifier, sync_datetime=None):
    sid = -1
    if check_if_SPID_is_unique(SPIDentifier):
        sp = SPID.objects.create()
        sp.spid = SPIDentifier
        if sync_datetime is None:
            sp.sync = timezone.cnow()
        sp.save()
        sid = sp.id
    return sid


def generate_id(original_id, source='CVE'):
    
    def only_digits(string):
        sis = re.sub(r"\D", '', string)
        return sis

    def create_id_numbers_set(numbers):
        numbers_length = len(numbers)
        numbers_length_as_string = str(numbers_length)
        zeros = '0'*(sp_max_digits - numbers_length)

        if numbers_length < 10:
            numbers_length_as_string = '0' + numbers_length_as_string

        return ''.join([numbers_length_as_string, numbers, zeros])

    current_year = str(datetime.now().year)
    try:
        src = sources[source.lower()]
    except Exception as ex:
        print('Get wrong Source type: {0} with exception: {1}'.format(source, ex))
        return ''

    if src == 'C':
        original_id_as_list = original_id.split('-')

        if len(original_id_as_list) == 3:
            cve_year = years(original_id_as_list[1])
            cve_numbers = original_id_as_list[2]
            cve_short_year_and_numbers = cve_year + cve_numbers
            cve_numbers_set = create_id_numbers_set(cve_short_year_and_numbers)
            generated_id = sp_delimiter.join([sp_prefix, current_year, src, cve_numbers_set])
            return generated_id
        else:
            return ''

    elif src == 'N':
        npm_year = years(current_year)
        npm_numbers = only_digits(original_id)
        npm_short_year_and_numbers = npm_year + npm_numbers
        set_of_npm_numbers = create_id_numbers_set(npm_short_year_and_numbers)
        generated_id = sp_delimiter.join([sp_prefix, current_year, src, set_of_npm_numbers])
        return generated_id

    elif src == 'M':
        ms_year = years(current_year)
        ms_numbers = only_digits(original_id)
        ms_short_year_and_numbers = ms_year + ms_numbers
        set_of_ms_numbers = create_id_numbers_set(ms_short_year_and_numbers)
        generated_id = sp_delimiter.join([sp_prefix, current_year, src, set_of_ms_numbers])
        return generated_id

    elif src == 'S':
        snyk_year = years(current_year)

        if original_id.startswith('npm:'):
            original_id_splitted = original_id.split(':')

            if len(original_id_splitted) > 2:
                original_id_numbers = original_id_splitted[-1]
                snyk_numbers = only_digits(original_id_numbers)

                if len(snyk_numbers) > 0:
                    snyk_short_year_and_numbers = snyk_year + snyk_numbers
                    set_of_snyk_numbers = create_id_numbers_set(
                        snyk_short_year_and_numbers)
                    generated_id = sp_delimiter.join(
                        [sp_prefix, current_year, src, set_of_snyk_numbers])
                    return generated_id
                return ''
        else:
            original_id_splitted = original_id.split('-')

            if len(original_id_splitted) > 1:
                original_id_numbers = original_id_splitted[-1]
                snyk_numbers = only_digits(original_id_numbers)

                if len(snyk_numbers) > 0:
                    snyk_short_year_and_numbers = snyk_year + snyk_numbers
                    set_of_snyk_numbers = create_id_numbers_set(
                        snyk_short_year_and_numbers)
                    generated_id = sp_delimiter.join(
                        [sp_prefix, current_year, src, set_of_snyk_numbers])
                    return generated_id
                return ''

    elif src == 'U':
        user__year = years(current_year)
        last__SPID__element = get_last_sync_SPID()
        not_uniq = True
        last_ID = last__SPID__element["id"]
        while not_uniq:
            last_ID = last_ID + 1
            ids = SPID.get_or_none(SPID.id == last_ID)
            if ids is None:
                not_uniq = False
        user_numbers = str(last_ID)
        user_short_year_and_numbers = user__year + user_numbers
        set_of_user_numbers = create_id_numbers_set(user_short_year_and_numbers)
        our_ID = sp_delimiter.join([sp_prefix, current_year, src, set_of_user_numbers])
        return our_ID
    else:
        return ""
