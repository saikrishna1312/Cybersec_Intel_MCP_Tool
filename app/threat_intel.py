import requests
import time
from models.cve_model import CVE
import urllib3
import json
from bs4 import BeautifulSoup
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

### Constants
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_AWG_URL = "https://cveawg.mitre.org/api/cve/{}"
CWE_HTML_ROOT = "https://cwe.mitre.org/data/definitions/"

# Simple caches to avoid over-querying APIs
CISA_CACHE = {}
CVE_CACHE = {}
CWE_CACHE = {}
DEFAULT_CUTOFF_DATE = "2025-05-01"

def pretty_print_cve(cve):
    print(json.dumps(cve.model_dump(), indent=2))

### Fetch full pipeline: CISA → CVE-AWG → CWE
def fetch_cisa_cves(cutoff_date: str = DEFAULT_CUTOFF_DATE):
    response = requests.get(CISA_URL)
    data = response.json()

    cve_list = []

    try:
        cutoff_dt = datetime.strptime(cutoff_date, "%Y-%m-%d")
    except:
        cutoff_dt = datetime.strptime(DEFAULT_CUTOFF_DATE, "%Y-%m-%d")

    vulnerabilities = data.get("vulnerabilities", [])
    filtered_vulns = []

    for item in vulnerabilities:
        item_date = item.get("dateAdded", "")
        if item_date:
            item_dt = datetime.strptime(item_date, "%Y-%m-%d")
            if item_dt >= cutoff_dt:
                filtered_vulns.append(item)

    for item in filtered_vulns:
        cve_id = item.get("cveID", "")
        vul_name = item.get("vulnerabilityName", "")
        date_added = item.get("dateAdded", "")
        short_description = item.get("shortDescription", "")
        req_action = item.get("requiredAction", "")
        due_date = item.get("dueDate", "")

        enriched_data = enrich_with_cve_awg(cve_id)

        score = enriched_data.get("score", 0.0)
        severity = enriched_data.get("severity", "")
        cweID = enriched_data.get("cweID", "")
        cweDescription = enriched_data.get("cweDescription", "")

        # CWE Enrichment
        if cweID:
            cwe_data = enrich_with_cwe(cweID)
        else:
            cwe_data = {}

        cve = CVE(
            cve_id=cve_id,
            vulnerability_name=vul_name,
            date_added=date_added,
            short_description=short_description,
            required_action=req_action,
            due_date=due_date,
            score=score,
            severity=severity,
            cweID=cweID,
            cwe_description=cweDescription,
            cwe_name=cwe_data.get("cwe_name", ""),
            extended_description=cwe_data.get("extended_description", ""),
            consequences=cwe_data.get("consequences", []),
            mitigations=cwe_data.get("mitigations", []),
            introductions=cwe_data.get("introductions", []),
            detection_methods=cwe_data.get("detection_methods", []),
            source="CISA",
        )

        print(f"\n===== Finished Processing CVE {cve_id} =====")
        pretty_print_cve(cve)

        cve_list.append(cve)
        
        # time.sleep(0.3)  # avoid hammering the APIs

    return cve_list

### CVE-AWG Enrichment
def enrich_with_cve_awg(cve_id):
    if cve_id in CVE_CACHE:
        return CVE_CACHE[cve_id]

    url = CVE_AWG_URL.format(cve_id)
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            cna = data.get("containers", {}).get("cna", {})
            metrics = cna.get("metrics", [])
            cvss = {}

            if metrics:
                cvss_data = metrics[0].get("cvssV3_1", {})
                cvss = {
                    "score": cvss_data.get("baseScore", 0.0),
                    "severity": cvss_data.get("baseSeverity", "")
                }

            problem_types = cna.get('problemTypes', [])
            if problem_types and 'descriptions' in problem_types[0]:
                problem = problem_types[0]['descriptions'][0]
                cweID = problem.get('cweId', "")
                cweDescription = problem.get('description', "")
            else:
                cweID, cweDescription = "", ""

            enriched = {
                "score": cvss.get("score", 0.0),
                "severity": cvss.get("severity", ""),
                "cweID": cweID,
                "cweDescription": cweDescription
            }
            CVE_CACHE[cve_id] = enriched
            return enriched

    except Exception as e:
        print(f"Failed to enrich CVE {cve_id}: {e}")

    print(f"Enriching CVE via CVE-AWG for {cve_id}")

    return {
        "score": 0.0,
        "severity": "",
        "cweID": "",
        "cweDescription": ""
    }

### CWE Enrichment
def enrich_with_cwe(cwe_id):
    numeric_id = cwe_id.replace("CWE-", "").strip()

    if numeric_id in CWE_CACHE:
        return CWE_CACHE[numeric_id]

    url = f"{CWE_HTML_ROOT}{numeric_id}.html"
    print(f"Fetching CWE data from {url}")

    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"Failed to fetch CWE {cwe_id}, HTTP {response.status_code}")
            return empty_cwe(numeric_id)

        soup = BeautifulSoup(response.text, "lxml")

        # Extract Name
        name_tag = soup.find("h2")
        cwe_name = name_tag.text.strip() if name_tag else f"CWE-{numeric_id}"

        # Extract Description
        description_tag = soup.find("div", {"id": "Description"})
        cwe_description = description_tag.find("div", class_="indent").text.strip() if description_tag else ""

        # Extract Extended Description
        extended_tag = soup.find("div", {"id": "Extended_Description"})
        extended_description = extended_tag.find("div", class_="indent").text.strip() if extended_tag else ""

        # Extract Common Consequences
        consequences_tag = soup.find("div", {"id": "Common_Consequences"})
        consequences = []
        if consequences_tag:
            rows = consequences_tag.find_all("tr")
            for row in rows[1:]:  
                cols = row.find_all("td")
                if len(cols) >= 2:
                    impact = cols[0].text.strip()
                    details = cols[1].text.strip()
                    consequences.append({"Impact": impact, "Details": details})

        # Extract Potential Mitigations
        mitigations_tag = soup.find("div", {"id": "Potential_Mitigations"})
        mitigations = []
        if mitigations_tag:
            rows = mitigations_tag.find_all("tr")
            for row in rows[1:]:
                cols = row.find_all("td")
                if len(cols) >= 2:
                    phase = cols[0].text.strip()
                    mitigation = cols[1].text.strip()
                    mitigations.append({"Phase": phase, "Mitigation": mitigation})

        enriched = {
            "cwe_name": cwe_name,
            "cwe_description": cwe_description,
            "extended_description": extended_description,
            "consequences": consequences,
            "mitigations": mitigations,
            "introductions": [],
            "detection_methods": []
        }

        CWE_CACHE[numeric_id] = enriched
        return enriched

    except Exception as e:
        print(f"Failed to enrich CWE {cwe_id}: {e}")
        return empty_cwe(numeric_id)


def empty_cwe(numeric_id):
    return {
        "cwe_name": f"CWE-{numeric_id}",
        "cwe_description": "",
        "extended_description": "",
        "consequences": [],
        "mitigations": [],
        "introductions": [],
        "detection_methods": []
    }
