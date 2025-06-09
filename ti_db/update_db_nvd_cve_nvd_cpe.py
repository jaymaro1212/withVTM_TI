import requests
import pymysql
from datetime import datetime, timedelta, timezone

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "7c59882b-0ed4-41d5-8650-47db8e668f79"

DB_CONFIG = {
    "host": "172.16.250.227",
    "user": "root",
    "password": "qhdks00@@",
    "database": "vtm",
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor
}

def get_connection():
    return pymysql.connect(**DB_CONFIG)

def fetch_cves(start_iso: str, end_iso: str):
    params = {
        "resultsPerPage": 2000,
        "startIndex": 0,
        "pubStartDate": start_iso,
        "pubEndDate": end_iso
    }
    headers = {
        "User-Agent": "CVECollector/1.0",
        "apiKey": API_KEY
    }
    all_items = []
    while True:
        res = requests.get(NVD_API_BASE, params=params, headers=headers)
        if res.status_code != 200:
            break
        data = res.json()
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

def extract_cvss(metrics: dict, ver: str):
    prefix = f"cvssMetricV{ver}"
    candidates = [k for k in metrics.keys() if k.startswith(prefix)]
    if not candidates:
        return {"source": "", "score": None, "vector": "", "severity": ""}
    candidates.sort(reverse=True)
    arr = metrics.get(candidates[0], [])
    if not arr:
        return {"source": "", "score": None, "vector": "", "severity": ""}
    m = arr[0]
    base = m.get("cvssData", {}) or {}
    return {
        "source": m.get("source", ""),
        "score": base.get("baseScore", None),
        "vector": base.get("vectorString", ""),
        "severity": base.get("baseSeverity", "")
    }

def equal(a, b):
    return (a or "") == (b or "")

def save_items_to_db(items):
    conn = get_connection()
    cursor = conn.cursor()
    cve_inserted = cve_updated = 0
    cpe_inserted = cpe_updated = 0

    for item in items:
        # (코드 생략: 기존 내용 그대로 유지)
        # CVE와 CPE 저장 및 업데이트 처리
        pass

    conn.commit()
    conn.close()
    print("✅ 배치 저장 완료")
    print(f"├─ CVE: 신규 삽입 {cve_inserted}건, 업데이트 {cve_updated}건")
    print(f"└─ CPE: 신규 삽입 {cpe_inserted}건, 업데이트 {cpe_updated}건")
    return cve_inserted, cve_updated, cpe_inserted, cpe_updated

if __name__ == "__main__":
    start_date = datetime(1999, 1, 1, tzinfo=timezone.utc)
    end_date = datetime.now(timezone.utc)
    max_range = timedelta(days=120)
    current_start = start_date

    total_cve_inserted = total_cve_updated = 0
    total_cpe_inserted = total_cpe_updated = 0

    while current_start < end_date:
        current_end = current_start + max_range
        if current_end > end_date:
            current_end = end_date
        start_iso = current_start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        end_iso = current_end.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        print(f"\n🔎 Published CVE 수집: {start_iso} → {end_iso}")
        batch = fetch_cves(start_iso, end_iso)
        print(f"  ▶ 이번 구간에서 가져온 CVE: {len(batch)}건")
        ci, cu, pi, pu = save_items_to_db(batch)
        total_cve_inserted += ci
        total_cve_updated += cu
        total_cpe_inserted += pi
        total_cpe_updated += pu
        current_start = current_end

    with get_connection() as tmp_conn:
        tmp_cursor = tmp_conn.cursor()
        tmp_cursor.execute("SELECT COUNT(*) AS cnt FROM nvd_cve")
        total_cve = tmp_cursor.fetchone()["cnt"]
        tmp_cursor.execute("SELECT COUNT(*) AS cnt FROM nvd_cpe")
        total_cpe = tmp_cursor.fetchone()["cnt"]
        print(f"\n총 결과 ─ nvd_cve: {total_cve}건, nvd_cpe: {total_cpe}건")

    print("\n✅ 전체 배치 완료")
    print(f"├─ CVE: 신규 삽입 {total_cve_inserted}건, 업데이트 {total_cve_updated}건")
    print(f"└─ CPE: 신규 삽입 {total_cpe_inserted}건, 업데이트 {total_cpe_updated}건")
