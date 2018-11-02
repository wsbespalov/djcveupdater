import re
import os
import bz2
import re
import gzip
import zipfile
import requests
from io import BytesIO
from datetime import datetime

from .configurations import CWEConfig
from dateutil.parser import parse as parse_datetime

LOCAL_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def time_string_to_datetime(time_string):
    return parse_datetime(time_string)


def unquote(cpe):
    return re.compile('%([0-9a-fA-F]{2})',re.M).sub(lambda m: "\\" + chr(int(m.group(1),16)), cpe)


def to_string_formatted_cpe(cpe, autofill=False):
    cpe = cpe.strip()
    if not cpe.startswith('cpe:2.3:'):
        if not cpe.startswith('cpe:/'):
            return False
        cpe = cpe.replace('cpe:/', 'cpe:2.3:')
        cpe = cpe.replace('::', ':-:')
        cpe = cpe.replace('~-', '~')
        cpe = cpe.replace('~', ':-:')
        cpe = cpe.replace('::', ':')
        cpe = cpe.strip(':-')
        cpe = unquote(cpe)
    if autofill:
        e = cpe.split(':')
        for x in range(0,13-len(e)):
            cpe += ':-'
    return cpe


def upload_file():
    """
    Upload file from Internet resource
    :return:
    - fullpath: full path of file or None
    - success: True or False
    """
    file_path = ''
    success = False
    size = 0
    fmt = 'undefined'
    last_modified = datetime.utcnow()
    if not os.path.isdir(os.path.join(LOCAL_BASE_DIR, CWEConfig.file_storage_root)):
        os.mkdir(os.path.join(LOCAL_BASE_DIR, CWEConfig.file_storage_root))
    try:
        file_path = os.path.join(os.path.join(LOCAL_BASE_DIR, CWEConfig.file_storage_root), CWEConfig.cwe_file)
        head = requests.head(CWEConfig.source)
        print(head.headers)
        content_type = head.headers.get('Content-Type')

        if 'gzip' in content_type:
            fmt = 'gzip'
        elif 'bzip2' in content_type:
            fmt = 'bzip2'
        elif 'zip' in content_type:
            fmt = 'zip'

        size = int(head.headers.get('Content-Length', 0))
        last_modified_text = head.headers.get('Last-Modified', '')
        last_modified = time_string_to_datetime(last_modified_text)

        print('size: {}'.format(size))
        print('last: {}'.format(last_modified_text))
        print('format: {}'.format(fmt))

        file = requests.get(CWEConfig.source, stream=True)

        with open(file_path, 'wb') as f:
            for chunk in file:
                f.write(chunk)

        return file_path, True, last_modified, size, fmt
    except Exception as ex:
        pass
    return None, False, last_modified, size, fmt


def read_file(getfile, fmt='gzip', unpack=True):
    data = None
    if os.path.exists(getfile):
        print('file exists')
        if os.path.isfile(getfile):
            print('file is a file')
            if unpack:
                if fmt == 'gzip':
                    with gzip.open(getfile, 'rb') as fp:
                        print('read gzip file')
                        data = fp.read()
                        print(len(data))
                        return data, True, 'gzip opened'
                elif fmt == 'bzip2':
                    print('read bzip2 file')
                    zfile = bz2.BZ2File(getfile)
                    data = BytesIO(zfile.read())
                    print(len(data))
                    return data, True, 'bzip2 opened'
                elif fmt == 'zip':
                    print('read zip file')
                    unzipped_file = []
                    zfile = zipfile.ZipFile(getfile, 'r')
                    for name in zfile.namelist():
                        unzipped_file.append(zfile.open(name))
                    zfile.close()
                    zfile = None
                    print(len(unzipped_file))
                    if len(unzipped_file) > 0:
                        data = BytesIO(unzipped_file[0].read())
                        return data, True, 'zip opened'
                    return None, False, 'zip archive is empty'
            with open(getfile, 'rb') as fp:
                data = BytesIO(fp.read())
            return data, True, 'raw file opened'
    return None, False, 'error with file read or unpack'
