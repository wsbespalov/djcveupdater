import os
import json
import requests
from datetime import datetime
from dateutil.parser import parse as parse_datetime

from .configuration import NPMConfig


LOCAL_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def time_string_to_datetime(time_string):
    return parse_datetime(time_string)


def unify_time(dt):
    if isinstance(dt, str):
        if 'Z' in dt:
            dt = dt.replace('Z', '')
        return parse_datetime(dt).strftime("%Y-%m-%d %H:%M:%S")

    if isinstance(dt, datetime):
        return parse_datetime(str(dt)).strftime("%Y-%m-%d %H:%M:%S")


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
    if not os.path.isdir(os.path.join(LOCAL_BASE_DIR, NPMConfig.file_storage_root)):
        os.mkdir(os.path.join(LOCAL_BASE_DIR, NPMConfig.file_storage_root))
    try:
        file_path = os.path.join(os.path.join(LOCAL_BASE_DIR, NPMConfig.file_storage_root), NPMConfig.cpe_file)
        head = requests.head(NPMConfig.source)
        content_type = head.headers.get('Content-Type')

        fmt = "json"

        size = int(head.headers.get('Content-Length', 0))
        last_modified_text = head.headers.get('Last-Modified', '')
        last_modified = time_string_to_datetime(last_modified_text)

        print('size: {}'.format(size))
        print('last: {}'.format(last_modified_text))
        print('format: {}'.format(fmt))

        file = requests.get(NPMConfig.source, stream=True)

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
            with open(getfile, 'r') as fp:
                try:
                    data = json.load(fp)
                except Exception as ex:
                    return None, False, 'json file opened'
            return data, True, 'json file opened'
    return None, False, 'error with file read or unpack'
