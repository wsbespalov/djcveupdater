import enum


class TextMessages(enum.Enum):
    ok = "ok"
    error = "error"
    exception = "exception"
    parse_data = "parse data"
    cpe_updated = "cve updated"
    download_file ="download file"
    cant_download_file = "cant get cve file"
