import requests
from lxml import html

from .configurations import SNYKConfig
from datetime import datetime
from dateutil.parser import parse as parse_datetime


def time_string_to_datetime(time_string):
    return parse_datetime(time_string)


def unify_time(dt):
    if isinstance(dt, str):
        if 'Z' in dt:
            dt = dt.replace('Z', '')
        return parse_datetime(dt).strftime("%Y-%m-%d %H:%M:%S")

    if isinstance(dt, datetime):
        return parse_datetime(str(dt)).strftime("%Y-%m-%d %H:%M:%S")


def startswith(st, start):
    if str(st).startswith(start):
        return True
    return False


def find_between(s, first, last):
    try:
        start = s.index(first) + len(first)
        end = s.index(last, start)
        return s[start:end]
    except ValueError:
        return ""


def filter_vuln_links(links):
    fl = []
    for l in links:
        if startswith(l, "/vuln/SNYK-") or startswith(l, "/vuln/npm"):
            fl.append(l)
    return fl, len(fl)


def create_url(num, lang):
    page_url = "https://snyk.io/vuln/page/{}?type={}".format(
        num, lang
    )
    return page_url


def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


def download_page_from_url(page_url):
    try:
        page = requests.get(page_url, headers=SNYKConfig.headers)
        if page.status_code == 200:
            try:
                tree = html.fromstring(page.content)
                return tree, True, 'ok'
            except Exception as ex:
                return None, False, "Get an exception with download page from url: {}".format(ex)
    except Exception as ex:
        return None, False,  "Get an exception with requests get operation: {}".format(ex)
    return None, False, "Cant download page for undefined reason"
