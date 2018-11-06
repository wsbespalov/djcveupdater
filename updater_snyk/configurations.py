

class SNYKConfig(object):
    drop_core_table = True
    debug = True
    undefined = "undefined"
    http_ignore_certs = False
    proxy = ""
    source = ""
    file_storage_root = 'media'
    capec_file = ''
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36'
    }
    golang = "golang"
    composer = "composer"
    maven = "maven"
    npm = "npm"
    nuget = "nuget"
    pip = "pip"
    rubygems = "rubygems"
    sources = [
        # golang,
        # composer,
        # maven,
        npm,
        # nuget,
        # pip,
        # rubygems
    ]