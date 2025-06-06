import requests
from datetime import datetime

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY      = "7c59882b-0ed4-41d5-8650-47db8e668f79"

def extract_cpes_from_config(nodes: list, out: list):
    for node in nodes:
        for match in node.get("cpeMatch", []):
            uri = match.get("criteria")
            if uri and uri.startswith("cpe:2.3:"):
                out.append(uri)
        if "children" in node:
            extract_cpes_from_config(node["children"], out)

def fetch_single_cve(cve_id: str):
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    headers = {
        "User-Agent": "CVECollector/1.0",
        "apiKey":     API_KEY
    }
    res = requests.get(url, headers=headers)
    data = res.json()
    vulns = data.get("vulnerabilities", [])
    return vulns[0]["cve"] if vulns else None

if __name__ == "__main__":
    cve_id = "CVE-2023-0210"
    cve_data = fetch_single_cve(cve_id)
    if not cve_data:
        print("CVE를 찾을 수 없습니다.")
        exit(1)

    print(f"▶ CVE: {cve_id}")
    configs = cve_data.get("configurations", [])
    all_uris = []
    for config_block in configs:
        nodes = config_block.get("nodes", [])
        extract_cpes_from_config(nodes, all_uris)

    print(f"파싱된 CPE 개수: {len(all_uris)}")
    for u in all_uris:
        print("  ", u)
