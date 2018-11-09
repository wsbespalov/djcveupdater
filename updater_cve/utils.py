import os
import json
import zipfile
import requests
import dateutil
from datetime import datetime
from dateutil.parser import parse as parse_datetime

from .configurations import CVEConfig

LOCAL_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

nvd_directory_path = os.path.join(LOCAL_BASE_DIR, CVEConfig.file_storage_root)


def unify_time(dt):
    if isinstance(dt, str):
        if 'Z' in dt:
            dt = dt.replace('Z', '')
        return parse_datetime(dt).strftime("%Y-%m-%d %H:%M:%S")

    if isinstance(dt, datetime):
        return parse_datetime(str(dt)).strftime("%Y-%m-%d %H:%M:%S")


def get_meta_info(filename):
    meta_filename = "".join(["https://nvd.nist.gov/feeds/json/cve/1.0/", filename[:-8], "meta"])
    success = False
    result = dict()
    try:
        meta_file_text_parsed = requests.get(meta_filename).text.split("\r\n")
        meta_filename = None
        if len(meta_file_text_parsed) == 6:
            last_modified_date_from_server_str = meta_file_text_parsed[0][17:]
            last_modified_date_from_server_dt = dateutil.parser.parse(last_modified_date_from_server_str)
            last_modified_date_from_server_ts = datetime.strptime(
                last_modified_date_from_server_dt.strftime('%Y-%m-%d %H:%M:%S'),
                '%Y-%m-%d %H:%M:%S')
            result["last_modified"] = last_modified_date_from_server_ts

            result["size"] = meta_file_text_parsed[1][5:]
            result["zip_size"] = meta_file_text_parsed[2][8:]
            result["gz_size"] = meta_file_text_parsed[3][7:]

            result["sha256"] = meta_file_text_parsed[4][7:]

            meta_file_text_parsed = None

            success = True
        else:
            success = False
    except Exception as ex:
        result = dict()
        success = False
    return result, success


def download_nvd_file_by_year(year):
    nvd_filename_prefix = "nvdcve-1.0-"
    nvd_filename_suffix = ".json.zip"

    filename = nvd_filename_prefix + str(year) + nvd_filename_suffix
    return download_nvd_file(filename)


def download_nvd_file(filename):
    if not os.path.isdir(nvd_directory_path):
        os.mkdir(nvd_directory_path)

    fullpath = os.path.join(nvd_directory_path, filename)
    print("Download NVD file: {0}".format(filename))

    try:
        url = "https://nvd.nist.gov/feeds/json/cve/1.0/" + filename
        file = requests.get(url, stream=True)

        url = None

        with open(fullpath, 'wb') as f:
            for chunk in file:
                f.write(chunk)

        file = None

    except Exception as ex:
        print("[-] Got an exception during downloading NVD file: {0}".format(ex))
        return False

    if os.path.isfile(fullpath):
        print("File size: {0}".format(os.path.getsize(fullpath)))
        return True

    return False

def load_cve_items_from_nvd_zipped_file(zip_file):
    items = []
    unzipped_file = []
    cve_data_timestamp = None
    zfile = zipfile.ZipFile(zip_file, 'r')

    for name in zfile.namelist():
        unzipped_file.append(zfile.open(name))

    zfile.close()
    zfile = None

    for extracted_content in unzipped_file:
        content = extracted_content.read()

        if isinstance(content, bytes):
            result = json.loads(content.decode("utf-8"))
        elif isinstance(content, str):
            result = json.loads(content)

        if "CVE_Items" in result:
            items = items + result["CVE_Items"]
        if "CVE_data_timestamp" in result:
            cve_data_timestamp = result["CVE_data_timestamp"]

    return items, cve_data_timestamp