import requests
import pymysql
from datetime import datetime
import re

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = ""


def get_connection():
  return pymysql.connect(
    host="172.16.250.227",
    user="root",
    password="qhdks00@@",
    database="vtm",
    charset="utf8mb4",
    cursorclass=pymysql.cursors.DictCursor
  )


def normalize_version(ver_str):
  m = re.match(r'^([0-9]+\.[0-9]+\.[0-9]+)([a-z])$', ver_str)
  if m:
    base, alpha = m.groups()
    return f"{base}.{ord(alpha) - ord('a')}"
  return ver_str


def fetch_cves(start, end, mode="published"):
  params = {
    "resultsPerPage": 2000,
    "startIndex": 0,
  }
  if mode == "published":
    params["pubStartDate"] = start
    params["pubEndDate"] = end
  elif mode == "modified":
    params["lastModStartDate"] = start
    params["lastModEndDate"] = end

  headers = {"User-Agent": "CVECollector/1.0"}
  if API_KEY:
    headers["apiKey"] = API_KEY

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


def save_to_db(items):
  conn = get_connection()
  cursor = conn.cursor()

  insert_count = 0
  update_count = 0
  now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

  for item in items:
    cve_data = item["cve"]
    cve_id = cve_data["id"]

    description = next((d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"), "")
    metrics = cve_data.get("metrics", {})

    def extract_cvss(ver):
      for m in metrics.get(f"cvssMetricV{ver}", []):
        base = m.get("cvssData", {})
        return (
          m.get("source", ""),
          base.get("baseScore", None),
          base.get("vectorString", ""),
          base.get("baseSeverity", "")
        )
      return ("", None, "", "")

    cvss4 = extract_cvss("4")
    cvss3 = extract_cvss("3")
    cvss2 = extract_cvss("2")

    published = cve_data.get("published", "")[:19].replace("T", " ")
    modified = cve_data.get("lastModified", "")[:19].replace("T", " ")

    cursor.execute("SELECT 1 FROM nvd_cve WHERE cve_id = %s", (cve_id,))
    exists = cursor.fetchone()

    cursor.execute("""
      INSERT INTO nvd_cve (
        cve_id, description,
        cvss4_source, cvss4_score, cvss4_vector, cvss4_severity,
        cvss3_source, cvss3_score, cvss3_vector, cvss3_severity,
        cvss2_source, cvss2_score, cvss2_vector, cvss2_severity,
        published_date, modified_date, last_updated_at
      ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
      ON DUPLICATE KEY UPDATE
        description = VALUES(description),
        cvss4_source = VALUES(cvss4_source),
        cvss4_score = VALUES(cvss4_score),
        cvss4_vector = VALUES(cvss4_vector),
        cvss4_severity = VALUES(cvss4_severity),
        cvss3_source = VALUES(cvss3_source),
        cvss3_score = VALUES(cvss3_score),
        cvss3_vector = VALUES(cvss3_vector),
        cvss3_severity = VALUES(cvss3_severity),
        cvss2_source = VALUES(cvss2_source),
        cvss2_score = VALUES(cvss2_score),
        cvss2_vector = VALUES(cvss2_vector),
        cvss2_severity = VALUES(cvss2_severity),
        published_date = VALUES(published_date),
        modified_date = VALUES(modified_date),
        last_updated_at = VALUES(last_updated_at)
    """, (
      cve_id, description,
      *cvss4,
      *cvss3,
      *cvss2,
      published, modified, now
    ))

    if exists:
      update_count += 1
    else:
      insert_count += 1

  conn.commit()
  conn.close()

  print("\n✅ NVD CVE 업데이트 완료")
  print(f"├─ 기존 CVE 업데이트: {update_count}건")
  print(f"├─ 신규 CVE 추가: {insert_count}건")
  print(f"└─ 마지막 업데이트 날짜: {now}")


if __name__ == "__main__":
  start = input("🔎 시작일 입력 (예: 2025-06-01T00:00:00): ").strip() + ".000Z"
  end = input("🔎 종료일 입력 (예: 2025-06-02T00:00:00): ").strip() + ".000Z"
  mode = input("📌 수집 기준 (published 또는 modified): ").strip()
  items = fetch_cves(start, end, mode)
  save_to_db(items)
