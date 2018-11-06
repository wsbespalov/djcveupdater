

class CPEConfig(object):
    drop_core_table = True
    debug = True
    http_ignore_certs = False
    proxy = ""
    source = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.2.xml.zip"
    file_storage_root = 'media'
    cpe_file = 'cpe.zip'
