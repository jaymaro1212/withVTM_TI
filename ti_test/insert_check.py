import requests
from datetime import datetime

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY       = "7c59882b-0ed4-41d5-8650-47db8e668f79"

def fetch_cves(start_iso: str, end_iso: str):
    params = {
        "resultsPerPage": 2000,
        "startIndex":     0,
        "pubStartDate":   start_iso,
        "pubEndDate":     end_iso
    }
    headers = {
        "User-Agent": "CVECollector/1.0",
        "apiKey":     API_KEY
    }
    all_items = []
    while True:
        res = requests.get(NVD_API_BASE, params=params, headers=headers)
        if res.status_code != 200:
            break
        data  = res.json()
        items = data.get("vulnerabilities", [])
        if not items:
            break
        all_items.extend(items)
        if len(items) < 2000:
            break
        params["startIndex"] += len(items)
    return all_items

def extract_cpes_from_config(nodes: list, out: list):
    for node in nodes:
        for match in node.get("cpeMatch", []):
            uri = match.get("criteria")
            if uri and uri.startswith("cpe:2.3:"):
                out.append({
                    "uri": uri,
                    "vulnerable": 1 if match.get("vulnerable", False) else 0,
                    "versionStartIncluding": match.get("versionStartIncluding"),
                    "versionStartExcluding": match.get("versionStartExcluding"),
                    "versionEndIncluding": match.get("versionEndIncluding"),
                    "versionEndExcluding": match.get("versionEndExcluding")
                })
        if "children" in node:
            extract_cpes_from_config(node["children"], out)

def test_cpe_parsing(item):
    cve_id = item["cve"]["id"]
    configs = item.get("configurations", {})
    nodes = configs.get("nodes", [])
    cpe_list = []
    extract_cpes_from_config(nodes, cpe_list)

    print(f"[테스트] CVE={cve_id} 에서 뽑힌 CPE 개수: {len(cpe_list)}")
    for cpe_obj in cpe_list:
        print("  → CPE URI:", cpe_obj["uri"])
    return cpe_list

if __name__ == "__main__":
    # ▼ 2025-06-01 ~ 2025-06-02 구간만 가져와서 테스트
    start_iso = "2025-06-01T00:00:00.000Z"
    end_iso   = "2025-06-02T00:00:00.000Z"

    batch = fetch_cves(start_iso, end_iso)
    print("▶ 2025-06-01 ~ 06-02 CVE 개수:", len(batch))

    # 첫 5건만 테스트
    for item in batch[:5]:
        test_cpe_parsing(item)
