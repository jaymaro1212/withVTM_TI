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

def extract_weaknesses(cve: dict) -> str:
  weaknesses = cve.get("weaknesses", [])
  if not weaknesses:
    return ""
  out = []
  for w in weaknesses:
    for d in w.get("description", []):
      if d.get("lang") == "en":
        out.append(d.get("value"))
  return "; ".join(out)

def parse_cpe_uri(uri: str):
  parts = uri.split(":")
  return {
    "part": parts[2] if len(parts) > 2 else "",
    "vendor": parts[3] if len(parts) > 3 else "",
    "product": parts[4] if len(parts) > 4 else "",
    "version": parts[5] if len(parts) > 5 else "",
    "update_col": parts[6] if len(parts) > 6 else "",
    "edition": parts[7] if len(parts) > 7 else "",
    "language": parts[8] if len(parts) > 8 else "",
    "sw_edition": parts[9] if len(parts) > 9 else "",
    "target_sw": parts[10] if len(parts) > 10 else "",
    "target_hw": parts[11] if len(parts) > 11 else "",
    "other": parts[12] if len(parts) > 12 else ""
  }

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

def extract_cvss_data(metrics: dict):
  data = {}
  for version in ["cvssMetricV4", "cvssMetricV31", "cvssMetricV2"]:
    if version in metrics:
      metric = metrics[version][0]
      v = version[-2:] if version != "cvssMetricV31" else "3"
      cvss = metric.get("cvssData", {})
      data[f"cvss{v}_source"] = metric.get("source")
      data[f"cvss{v}_severity"] = metric.get("baseSeverity", "")
      data[f"cvss{v}_score"] = cvss.get("baseScore", "")
      data[f"cvss{v}_vector"] = cvss.get("vectorString", "")
  return data

def null_eq(a, b):
  return (a or '') == (b or '')

def save_items_to_db(items):
  conn = get_connection()
  cursor = conn.cursor()
  cve_inserted = cve_updated = 0
  cpe_inserted = cpe_updated = 0

  for item in items:
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    description = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    published = cve.get("published", "")[:19].replace("T", " ")
    modified = cve.get("lastModified", "")[:19].replace("T", " ")
    cvss_data = extract_cvss_data(cve.get("metrics", {}))
    weaknesses = extract_weaknesses(cve)

    cursor.execute("SELECT c_id, cve_id, modified_date FROM nvd_cve WHERE cve_id = %s", (cve_id,))
    existing = cursor.fetchone()

    if not existing:
      cursor.execute("""
        INSERT INTO nvd_cve (cve_id, description, published_date, modified_date,
          cvss2_source, cvss2_severity, cvss2_score, cvss2_vector,
          cvss3_source, cvss3_severity, cvss3_score, cvss3_vector,
          cvss4_source, cvss4_severity, cvss4_score, cvss4_vector,
          weaknesses)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
      """, (cve_id, description, published, modified,
            cvss_data.get("cvss2_source"), cvss_data.get("cvss2_severity"), cvss_data.get("cvss2_score"), cvss_data.get("cvss2_vector"),
            cvss_data.get("cvss3_source"), cvss_data.get("cvss3_severity"), cvss_data.get("cvss3_score"), cvss_data.get("cvss3_vector"),
            cvss_data.get("cvss4_source"), cvss_data.get("cvss4_severity"), cvss_data.get("cvss4_score"), cvss_data.get("cvss4_vector"),
            weaknesses))
      c_id = cursor.lastrowid
      cve_inserted += 1
    else:
      c_id = existing["c_id"]
      if existing["modified_date"] != modified:
        cursor.execute("""
          UPDATE nvd_cve
          SET description = %s, published_date = %s, modified_date = %s,
              cvss2_source = %s, cvss2_severity = %s, cvss2_score = %s, cvss2_vector = %s,
              cvss3_source = %s, cvss3_severity = %s, cvss3_score = %s, cvss3_vector = %s,
              cvss4_source = %s, cvss4_severity = %s, cvss4_score = %s, cvss4_vector = %s,
              weaknesses = %s
          WHERE cve_id = %s
        """, (description, published, modified,
              cvss_data.get("cvss2_source"), cvss_data.get("cvss2_severity"), cvss_data.get("cvss2_score"), cvss_data.get("cvss2_vector"),
              cvss_data.get("cvss3_source"), cvss_data.get("cvss3_severity"), cvss_data.get("cvss3_score"), cvss_data.get("cvss3_vector"),
              cvss_data.get("cvss4_source"), cvss_data.get("cvss4_severity"), cvss_data.get("cvss4_score"), cvss_data.get("cvss4_vector"),
              weaknesses, cve_id))
        cve_updated += 1

    cpe_list = []
    for config in cve.get("configurations", []):
      extract_cpes_from_config(config.get("nodes", []), cpe_list)

    for cpe in cpe_list:
      uri = cpe["uri"]
      parsed = parse_cpe_uri(uri)
      vulnerable = cpe["vulnerable"]
      vsi = cpe["versionStartIncluding"]
      vse = cpe["versionStartExcluding"]
      vei = cpe["versionEndIncluding"]
      vee = cpe["versionEndExcluding"]

      cursor.execute("SELECT id, vulnerable, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding FROM nvd_cpe WHERE c_id = %s AND cpe_uri = %s", (c_id, uri))
      existing_cpe = cursor.fetchone()

      if not existing_cpe:
        cursor.execute("""
          INSERT INTO nvd_cpe (
            c_id, cve_id, cpe_uri, vulnerable,
            part, vendor, product, version,
            update_col, edition, language,
            sw_edition, target_sw, target_hw, other,
            versionStartIncluding, versionStartExcluding,
            versionEndIncluding, versionEndExcluding,
            published_date, modified_date
          )
          VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (c_id, cve_id, uri, vulnerable,
              parsed["part"], parsed["vendor"], parsed["product"], parsed["version"],
              parsed["update_col"], parsed["edition"], parsed["language"],
              parsed["sw_edition"], parsed["target_sw"], parsed["target_hw"], parsed["other"],
              vsi, vse, vei, vee, published, modified))
        cpe_inserted += 1
      else:
        if (existing_cpe["vulnerable"] != vulnerable or
            not null_eq(existing_cpe["versionStartIncluding"], vsi) or
            not null_eq(existing_cpe["versionStartExcluding"], vse) or
            not null_eq(existing_cpe["versionEndIncluding"], vei) or
            not null_eq(existing_cpe["versionEndExcluding"], vee)):
          cursor.execute("""
            UPDATE nvd_cpe SET vulnerable = %s,
              versionStartIncluding = %s,
              versionStartExcluding = %s,
              versionEndIncluding = %s,
              versionEndExcluding = %s,
              part = %s, vendor = %s, product = %s, version = %s,
              update_col = %s, edition = %s, language = %s,
              sw_edition = %s, target_sw = %s, target_hw = %s, other = %s,
              modified_date = %s
            WHERE id = %s
          """, (vulnerable, vsi, vse, vei, vee,
                parsed["part"], parsed["vendor"], parsed["product"], parsed["version"],
                parsed["update_col"], parsed["edition"], parsed["language"],
                parsed["sw_edition"], parsed["target_sw"], parsed["target_hw"], parsed["other"],
                modified, existing_cpe["id"]))
          cpe_updated += 1

  conn.commit()
  conn.close()
  return cve_inserted, cve_updated, cpe_inserted, cpe_updated

if __name__ == "__main__":
  start_date = datetime(1999, 1, 1, tzinfo=timezone.utc)
  end_date = datetime.now(timezone.utc)
  max_range = timedelta(days=120)
  current_start = start_date

  total_cve_inserted = total_cve_updated = 0
  total_cpe_inserted = total_cpe_updated = 0
  log_summary = []

  while current_start < end_date:
    current_end = min(current_start + max_range, end_date)
    start_iso = current_start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    end_iso = current_end.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    print(f"\n🔎 Published CVE 수집: {start_iso} → {end_iso}")
    batch = fetch_cves(start_iso, end_iso)
    ci, cu, pi, pu = save_items_to_db(batch)

    log_summary.append({
      "start": start_iso,
      "end": end_iso,
      "cve_i": ci, "cve_u": cu,
      "cpe_i": pi, "cpe_u": pu
    })

    total_cve_inserted += ci
    total_cve_updated += cu
    total_cpe_inserted += pi
    total_cpe_updated += pu
    current_start = current_end

  print("\n✅ 전체 배치 완료")
  print(f"├─ CVE: 신규 삽입 {total_cve_inserted}건, 업데이트 {total_cve_updated}건")
  print(f"└─ CPE: 신규 삽입 {total_cpe_inserted}건, 업데이트 {total_cpe_updated}건")

  print("\n📌 구간별 CVE/CPE 변화 요약:")
  for log in log_summary:
    print(f"- [{log['start']} → {log['end']}] CVE(신규: {log['cve_i']}, 업데이트: {log['cve_u']}), CPE(신규: {log['cpe_i']}, 업데이트: {log['cpe_u']})")
