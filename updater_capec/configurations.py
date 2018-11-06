

class CAPECConfig(object):
    drop_core_table = True
    debug = True
    http_ignore_certs = False
    proxy = ""
    source = "http://capec.mitre.org/data/xml/capec_v2.6.xml"
    file_storage_root = 'media'
    capec_file = 'capec.xml'
