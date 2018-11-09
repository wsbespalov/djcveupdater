from datetime import datetime

from .utils import unify_time


class CVEItem(object):
    def __init__(self, data):
        cve = data.get("cve", {})

        # Get Data Type -> str
        self.data_type = cve.get("data_type", None)

        # Get Data Format -> str
        self.data_format = cve.get("data_format", None)

        # Get Data Version -> str
        # Data version like 4.0
        self.data_version = cve.get("data_version", None)

        # Get CVE ID like CVE-2002-2446 -> str
        CVE_data_meta = cve.get("CVE_data_meta", {})
        self.cve_id = CVE_data_meta.get("ID", None)

        # GET CWEs -> [str]
        cwe = []
        problemtype = cve.get("problemtype", {})
        problemtype_data = problemtype.get("problemtype_data", [])
        for pd in problemtype_data:
            description = pd.get("description", [])
            for d in description:
                value = d.get("value", None)
                if value is not None:
                    cwe.append(value)
        self.cwe = cwe

        # Get references -> [str]
        references = []
        ref = cve.get("references", {})
        reference_data = ref.get("reference_data", [])
        for rd in reference_data:
            url = rd.get("url", None)
            if url is not None:
                references.append(url)
        self.references = references

        # GET description -> str
        self.description = ""
        descr = cve.get("description", {})
        description_data = descr.get("description_data", [])
        for dd in description_data:
            value = dd.get("value", "")
            self.description = self.description + value

        # GET cpe -> JSON with list -> {"data": cpe22}
        cpe22 = []
        conf = data.get("configurations", {})
        nodes = conf.get("nodes", [])
        for n in nodes:
            cpe = n.get("cpe", [])
            for c in cpe:
                c22 = c.get("cpe22Uri", None)
                # for fuzzy versions
                versionEndIncluding = c.get("versionEndIncluding", None)
                if versionEndIncluding is not None:
                    c22_new = c22 + ":" + str(versionEndIncluding)
                    cpe22.append(c22_new)
                    c22_new2 = c22 + ":?"
                    cpe22.append(c22_new2)
                else:
                    cpe22.append(c22)

        self.vulnerable_configuration = cpe22

        self.published = data.get("publishedDate", datetime.utcnow())
        self.modified = data.get("lastModifiedDate", datetime.utcnow())

        # access
        impact = data.get("impact", {})

        self.access = {}
        baseMetricV2 = impact.get("baseMetricV2", {})
        cvssV2 = baseMetricV2.get("cvssV2", {})
        self.access["vector"] = cvssV2.get("accessVector", "")
        self.access["complexity"] = cvssV2.get("accessComplexity", "")
        self.access["authentication"] = cvssV2.get("authentication", "")

        # impact
        self.impact = {}
        self.impact["confidentiality"] = cvssV2.get("confidentialityImpact", "")
        self.impact["integrity"] = cvssV2.get("integrityImpact", "")
        self.impact["availability"] = cvssV2.get("availabilityImpact", "")

        # vector_string
        self.vector_string = cvssV2.get("vectorString", "")

        # baseScore - cvss
        self.cvss = cvssV2.get("baseScore", 0.0)

        self.cvss_time = datetime.utcnow()

    def to_json(self):
        return dict(
            cve_id=self.cve_id,
            cwe=self.cwe,
            references=self.references,
            vulnerable_configuration=self.vulnerable_configuration,
            data_type=self.data_type,
            data_version=self.data_version,
            data_format=self.data_format,
            description=self.description,
            published=unify_time(self.published),
            modified=unify_time(self.modified),
            access=self.access,
            impact=self.impact,
            vector_string=self.vector_string,
            cvss_time=self.cvss_time,
            cvss=self.cvss,
        )

    def to_tuple(self):
        return (
            self.cve_id,
            self.cwe,
            self.references,
            self.vulnerable_configuration,
            self.data_type,
            self.data_version,
            self.data_format,
            self.description,
            unify_time(self.published),
            unify_time(self.modified),
            self.access,
            self.impact,
            self.vector_string,
            self.cvss_time,
            self.cvss,
        )
