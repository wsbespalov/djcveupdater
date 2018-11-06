

class CWEConfig(object):
    drop_core_table = True
    debug = True
    http_ignore_certs = False
    proxy = ""
    source = "http://cwe.mitre.org/data/xml/cwec_v2.8.xml.zip"
    file_storage_root = '/media/'
    cwe_file = 'cwe.zip'