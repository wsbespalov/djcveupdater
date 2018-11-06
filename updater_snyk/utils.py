import requests
from lxml import html

from .configurations import SNYKConfig

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
                return tree, False, 'ok'
            except Exception as ex:
                return None, False, "Get an exception with download page from url: {}".format(ex)
    except Exception as ex:
        return None, False,  "Get an exception with requests get operation: {}".format(ex)
    return None, False, "Cant download page for undefined reason"
