from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from database import get_connection
from datetime import datetime, timedelta
import re
from distutils.version import LooseVersion
import requests
import time

nvd = FastAPI()

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = ""  # 필요한 경우 API 키 입력

def parse_iso8601(dt_str: str):
  try:
    return datetime.fromisoformat(dt_str)
  except:
    raise ValueError("날짜 형식은 YYYY-MM-DDTHH:MM:SS 이어야 합니다")

def normalize_version(ver_str):
  m = re.match(r'^(\d+\.\d+\.\d+)([a-z])$', ver_str)
  if m:
    base, alpha = m.groups()
    return f"{base}.{ord(alpha) - ord('a')}"
  return ver_str

def is_version_matched(rpm_v, row, raw_version):
  try:
    def safe(v): return LooseVersion(normalize_version(v.strip())) if v else None
    exact = row['version']
    vsi = row['versionStartIncluding']
    vse = row['versionStartExcluding']
    vei = row['versionEndIncluding']
    vee = row['versionEndExcluding']
    if exact and exact.strip() == raw_version:
      return True
    if (vsi or vse or vei or vee) and (
      (not vsi or rpm_v >= safe(vsi)) and
      (not vse or rpm_v > safe(vse)) and
      (not vei or rpm_v <= safe(vei)) and
      (not vee or rpm_v < safe(vee))
    ):
      return True
  except:
    return False
  return False

def fetch_cves(start: str, end: str, mode: str = "published"):
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
    time.sleep(1)
  return all_items

def save_to_db(items):
  conn = get_connection()
  cursor = conn.cursor()
  for item in items:
    cve_data = item["cve"]
    cve_id = cve_data["id"]
    description = next(
      (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
      ""
    )
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

    cursor.execute("""
      INSERT INTO nvd_cve (
        cve_id, description,
        cvss4_source, cvss4_score, cvss4_vector, cvss4_severity,
        cvss3_source, cvss3_score, cvss3_vector, cvss3_severity,
        cvss2_source, cvss2_score, cvss2_vector, cvss2_severity,
        published_date, modified_date
      ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
      ON DUPLICATE KEY UPDATE
        description=VALUES(description),
        cvss4_source=VALUES(cvss4_source),
        cvss4_score=VALUES(cvss4_score),
        cvss4_vector=VALUES(cvss4_vector),
        cvss4_severity=VALUES(cvss4_severity),
        cvss3_source=VALUES(cvss3_source),
        cvss3_score=VALUES(cvss3_score),
        cvss3_vector=VALUES(cvss3_vector),
        cvss3_severity=VALUES(cvss3_severity),
        cvss2_source=VALUES(cvss2_source),
        cvss2_score=VALUES(cvss2_score),
        cvss2_vector=VALUES(cvss2_vector),
        cvss2_severity=VALUES(cvss2_severity),
        published_date=VALUES(published_date),
        modified_date=VALUES(modified_date)
    """, (
      cve_id, description,
      *cvss4,
      *cvss3,
      *cvss2,
      published, modified
    ))
  conn.commit()
  conn.close()

@nvd.get("/api/update")
async def update_nvd_data(
  start_date: str = Query(...),
  end_date: str = Query(...),
  mode: str = Query("published", pattern="^(published|modified)$")
):
  try:
    start = parse_iso8601(start_date).isoformat() + ".000Z"
    end = parse_iso8601(end_date).isoformat() + ".000Z"
  except ValueError as ve:
    return JSONResponse(status_code=400, content={"detail": str(ve)})

  items = fetch_cves(start, end, mode)
  save_to_db(items)

  return {
    "detail": f"✅ {mode} 기준 업데이트 완료",
    "start_date": start_date,
    "end_date": end_date,
    "count": len(items)
  }
