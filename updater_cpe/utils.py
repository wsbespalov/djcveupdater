import re
import bz2
import gzip
import re
import ssl
import zipfile
from io import BytesIO
import urllib.parse
import urllib.request as req

from .configurations import CPEConfig

def unquote(cpe):
  return re.compile('%([0-9a-fA-F]{2})',re.M).sub(lambda m: "\\" + chr(int(m.group(1),16)), cpe)


def to_string_formatted_cpe(cpe, autofill=False):
    cpe=cpe.strip()
    if not cpe.startswith('cpe:2.3:'):
        if not cpe.startswith('cpe:/'): return False
        cpe=cpe.replace('cpe:/','cpe:2.3:')
        cpe=cpe.replace('::',':-:')
        cpe=cpe.replace('~-','~')
        cpe=cpe.replace('~',':-:')
        cpe=cpe.replace('::',':')
        cpe=cpe.strip(':-')
        cpe=unquote(cpe)
    if autofill:
        e=cpe.split(':')
        for x in range(0,13-len(e)):
            cpe+=':-'
    return cpe


def get_file(getfile, unpack=True):
    proxy = CPEConfig.proxy
    http_ignore_certs = CPEConfig.http_ignore_certs
    if proxy:
        proxy = req.ProxyHandler({'http': proxy, 'https': proxy})
        auth = req.HTTPBasicAuthHandler()
        opener = req.build_opener(proxy, auth, req.HTTPHandler)
        req.install_opener(opener)
    if http_ignore_certs:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = req.build_opener(urllib.request.HTTPSHandler(context=ctx))
        req.install_opener(opener)

    response = req.urlopen(getfile)

    data = response

    if unpack:
        if   'gzip' in response.info().get('Content-Type'):
            buf = BytesIO(response.read())
            data = gzip.GzipFile(fileobj=buf)
        elif 'bzip2' in response.info().get('Content-Type'):
            data = BytesIO(bz2.decompress(response.read()))
        elif 'zip' in response.info().get('Content-Type'):
            fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
            if len(fzip.namelist())>0:
                data=BytesIO(fzip.read(fzip.namelist()[0]))
    return (data, response)