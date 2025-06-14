import requests
import pymysql
from datetime import datetime, timedelta, timezone

API_KEY = "7c59882b-0ed4-41d5-8650-47db8e668f79"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

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

def parse_cpe_uri(uri: str):
  parts = uri.split(":")
  def get(index):
    return parts[index] if len(parts) > index else ""
  return {
    "part": get(2), "vendor": get(3), "product": get(4), "version": get(5),
    "update_col": get(6), "edition": get(7), "language": get(8),
    "sw_edition": get(9), "target_sw": get(10), "target_hw": get(11), "other": get(12)
  }

def fetch_cves(start_iso: str, end_iso: str):
  params = {"resultsPerPage": 2000, "startIndex": 0, "pubStartDate": start_iso, "pubEndDate": end_iso}
  headers = {"User-Agent": "CVECollector/1.0", "apiKey": API_KEY}
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

def extract_cvss_data(metrics):
  data = {}
  for version in ["cvssMetricV4", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
    if version in metrics:
      metric = metrics[version][0]
      v = (
        "40" if version == "cvssMetricV4" else
        "31" if version == "cvssMetricV31" else
        "30" if version == "cvssMetricV30" else
        "20"
      )
      cvss = metric.get("cvssData", {})
      data[f"cvss{v}_source"] = metric.get("source")
      data[f"cvss{v}_severity"] = metric.get("baseSeverity", "")
      data[f"cvss{v}_score"] = cvss.get("baseScore", "")
      data[f"cvss{v}_vector"] = cvss.get("vectorString", "")
  return data



def extract_weaknesses(cve):
  out = []
  for w in cve.get("weaknesses", []):
    for d in w.get("description", []):
      if d.get("lang") == "en":
        out.append(d.get("value"))
  return "; ".join(out)

def extract_cpes_from_config(nodes, out):
  for node in nodes:
    for match in node.get("cpeMatch", []):
      uri = match.get("cpe23Uri") or match.get("criteria")
      if uri and uri.startswith("cpe:2.3:"):
        parsed = parse_cpe_uri(uri)
        out.append({
          "uri": uri,
          "vulnerable": 1 if match.get("vulnerable", False) else 0,
          "versionStartIncluding": match.get("versionStartIncluding"),
          "versionStartExcluding": match.get("versionStartExcluding"),
          "versionEndIncluding": match.get("versionEndIncluding"),
          "versionEndExcluding": match.get("versionEndExcluding"),
          **parsed
        })
    if "children" in node:
      extract_cpes_from_config(node["children"], out)

def null_eq(a, b):
  return (a or '') == (b or '')

def save_items(items):
  conn = get_connection()
  cursor = conn.cursor()
  cve_inserted = cve_updated = 0
  cpe_inserted = cpe_updated = 0

  cursor.execute("SELECT cve_id, c_id, modified_date FROM nvd_cve")
  existing_cves = {row["cve_id"]: row for row in cursor.fetchall()}

  cursor.execute("SELECT c_id, cpe_uri, id, vulnerable, versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding, part, vendor, product FROM nvd_cpe")
  existing_cpes = {
    (
      row["c_id"], row["cpe_uri"],
      row["versionStartIncluding"], row["versionStartExcluding"],
      row["versionEndIncluding"], row["versionEndExcluding"]
    ): row for row in cursor.fetchall()
  }

  for item in items:
    cve = item["cve"]
    cve_id = cve["id"]
    description = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    published = cve.get("published", "")[:19].replace("T", " ")
    modified = cve.get("lastModified", "")[:19].replace("T", " ")
    cvss = extract_cvss_data(cve.get("metrics", {}))
    weaknesses = extract_weaknesses(cve)



    if cve_id not in existing_cves:
      cursor.execute("""
                     INSERT INTO nvd_cve (cve_id, description, published_date, modified_date,
                                          cvss20_source, cvss20_severity, cvss20_score, cvss20_vector,
                                          cvss30_source, cvss30_severity, cvss30_score, cvss30_vector,
                                          cvss31_source, cvss31_severity, cvss31_score, cvss31_vector,
                                          cvss40_source, cvss40_severity, cvss40_score, cvss40_vector,
                                          weaknesses)
                     VALUES (%s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s, %s, %s, %s,
                             %s)
                     """, (
        cve_id, description, published, modified,
        cvss.get("cvss20_source"), cvss.get("cvss20_severity"), cvss.get("cvss20_score"),
        cvss.get("cvss20_vector"),
        cvss.get("cvss30_source"), cvss.get("cvss30_severity"), cvss.get("cvss30_score"),
        cvss.get("cvss30_vector"),
        cvss.get("cvss31_source"), cvss.get("cvss31_severity"), cvss.get("cvss31_score"),
        cvss.get("cvss31_vector"),
        cvss.get("cvss40_source"), cvss.get("cvss40_severity"), cvss.get("cvss40_score"),
        cvss.get("cvss40_vector"), weaknesses
                     ))

      c_id = cursor.lastrowid
      cve_inserted += 1
    else:
      c_id = existing_cves[cve_id]["c_id"]
      if existing_cves[cve_id]["modified_date"] != modified:
        cursor.execute("""
                       UPDATE nvd_cve
                       SET description=%s,
                           published_date=%s,
                           modified_date=%s,
                           cvss20_source=%s,
                           cvss20_severity=%s,
                           cvss20_score=%s,
                           cvss20_vector=%s,
                           cvss30_source=%s,
                           cvss30_severity=%s,
                           cvss30_score=%s,
                           cvss30_vector=%s,
                           cvss31_source=%s,
                           cvss31_severity=%s,
                           cvss31_score=%s,
                           cvss31_vector=%s,
                           cvss40_source=%s,
                           cvss40_severity=%s,
                           cvss40_score=%s,
                           cvss40_vector=%s,
                           weaknesses=%s
                       WHERE cve_id = %s
                       """, (
                         description, published, modified,
                         cvss.get("cvss20_source"), cvss.get("cvss20_severity"), cvss.get("cvss20_score"),
                         cvss.get("cvss20_vector"),
                         cvss.get("cvss30_source"), cvss.get("cvss30_severity"), cvss.get("cvss30_score"),
                         cvss.get("cvss30_vector"),
                         cvss.get("cvss31_source"), cvss.get("cvss31_severity"), cvss.get("cvss31_score"),
                         cvss.get("cvss31_vector"),
                         cvss.get("cvss40_source"), cvss.get("cvss40_severity"), cvss.get("cvss40_score"),
                         cvss.get("cvss40_vector"), weaknesses, cve_id
                       ))

        cve_updated += 1

    cpe_list = []
    for config in cve.get("configurations", []):
      extract_cpes_from_config(config.get("nodes", []), cpe_list)

    for cpe in cpe_list:
      uri = cpe["uri"]
      key = (
        c_id, uri,
        cpe["versionStartIncluding"], cpe["versionStartExcluding"],
        cpe["versionEndIncluding"], cpe["versionEndExcluding"]
      )
      if key not in existing_cpes:
        cursor.execute("""
          INSERT INTO nvd_cpe (
            c_id, cve_id, cpe_uri, vulnerable, part, vendor, product, version,
            update_col, edition, language, sw_edition, target_sw, target_hw, other,
            versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding,
            published_date, modified_date
          )
          VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (c_id, cve_id, uri, cpe["vulnerable"],
              cpe["part"], cpe["vendor"], cpe["product"], cpe["version"],
              cpe["update_col"], cpe["edition"], cpe["language"],
              cpe["sw_edition"], cpe["target_sw"], cpe["target_hw"], cpe["other"],
              cpe["versionStartIncluding"], cpe["versionStartExcluding"],
              cpe["versionEndIncluding"], cpe["versionEndExcluding"],
              published, modified))
        cpe_inserted += 1
      else:
        ex = existing_cpes.get(key)
        if (
          ex["vulnerable"] != cpe["vulnerable"] or
          not null_eq(ex["versionStartIncluding"], cpe["versionStartIncluding"]) or
          not null_eq(ex["versionStartExcluding"], cpe["versionStartExcluding"]) or
          not null_eq(ex["versionEndIncluding"], cpe["versionEndIncluding"]) or
          not null_eq(ex["versionEndExcluding"], cpe["versionEndExcluding"]) or
          not null_eq(ex["part"], cpe["part"]) or not null_eq(ex["vendor"], cpe["vendor"]) or not null_eq(ex["product"], cpe["product"])
        ):
          cursor.execute("""
            UPDATE nvd_cpe SET vulnerable=%s,
            versionStartIncluding=%s, versionStartExcluding=%s,
            versionEndIncluding=%s, versionEndExcluding=%s,
            part=%s, vendor=%s, product=%s, version=%s,
            update_col=%s, edition=%s, language=%s,
            sw_edition=%s, target_sw=%s, target_hw=%s, other=%s,
            modified_date=%s WHERE id=%s
          """, (cpe["vulnerable"], cpe["versionStartIncluding"], cpe["versionStartExcluding"],
                cpe["versionEndIncluding"], cpe["versionEndExcluding"],
                cpe["part"], cpe["vendor"], cpe["product"], cpe["version"],
                cpe["update_col"], cpe["edition"], cpe["language"],
                cpe["sw_edition"], cpe["target_sw"], cpe["target_hw"], cpe["other"],
                modified, ex["id"]))
          cpe_updated += 1

  conn.commit()
  conn.close()
  return cve_inserted, cve_updated, cpe_inserted, cpe_updated

if __name__ == "__main__":
  # start = datetime(1999, 1, 1, tzinfo=timezone.utc)
  start = datetime(2025, 4, 14, tzinfo=timezone.utc)
  end = datetime.now(timezone.utc)
  step = timedelta(days=120)
  ranges = []

  while start < end:
    temp_end = min(start + step, end)
    ranges.append((start, temp_end))
    start = temp_end

  total_cve_i = total_cve_u = total_cpe_i = total_cpe_u = 0
  for start_dt, end_dt in ranges:
    start_iso = start_dt.isoformat(timespec="seconds").replace("+00:00", "Z")
    end_iso = end_dt.isoformat(timespec="seconds").replace("+00:00", "Z")
    print(f"\n📥 {start_iso} ~ {end_iso} 수집 중...")
    items = fetch_cves(start_iso, end_iso)
    cve_i, cve_u, cpe_i, cpe_u = save_items(items)
    print(f"✅ 완료: {start_iso} → {end_iso}")
    print(f"├─ CVE: 신규 {cve_i}건, 업데이트 {cve_u}건")
    print(f"└─ CPE: 신규 {cpe_i}건, 업데이트 {cpe_u}건")
    total_cve_i += cve_i
    total_cve_u += cve_u
    total_cpe_i += cpe_i
    total_cpe_u += cpe_u

  print("\n📊 전체 요약 결과:")
  print(f"├─ CVE: 신규 {total_cve_i}건, 업데이트 {total_cve_u}건")
  print(f"└─ CPE: 신규 {total_cpe_i}건, 업데이트 {total_cpe_u}건")
