import enum


class TextMessages(enum.Enum):
    ok = "ok"
    error = "error"
    exception = "exception"
    parse_data = "parse data"
    cwe_updated = "cwe updated"
    download_file = "download file"
    cant_download_file = "cant get cwe file"