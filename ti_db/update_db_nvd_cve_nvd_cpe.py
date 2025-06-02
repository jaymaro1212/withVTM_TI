from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from database import get_connection
from datetime import datetime
import re
from distutils.version import LooseVersion
import requests
import time

nvd = FastAPI()

# NVD CVE API 기본 주소
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = ""  # API Key가 필요한 경우 여기에 입력

# 날짜 포맷 검증 및 변환 함수 (ISO 8601 형식으로 변환)
def parse_iso8601(dt_str: str):
  try:
    return datetime.fromisoformat(dt_str)
  except:
    raise ValueError("날짜 형식은 YYYY-MM-DDTHH:MM:SS 이어야 합니다")

# 버전 문자열을 비교 가능하도록 정규화하는 함수 (예: 1.1.1g → 1.1.1.6)
def normalize_version(ver_str):
  m = re.match(r'^(\d+\.\d+\.\d+)([a-z])$', ver_str)
  if m:
    base, alpha = m.groups()
    return f"{base}.{ord(alpha) - ord('a')}"
  return ver_str

# 특정 버전이 CPE 범위 조건에 맞는지 판별하는 함수
def is_version_matched(rpm_v, row, raw_version):
  try:
    def safe(v): return LooseVersion(normalize_version(v.strip())) if v else None

    exact = row['version']
    vsi = row['versionStartIncluding']
    vse = row['versionStartExcluding']
    vei = row['versionEndIncluding']
    vee = row['versionEndExcluding']

    # 정확히 일치하는 버전이 있는 경우
    if exact and exact.strip() == raw_version:
      return True

    # 범위 조건 비교
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

# NVD API에서 CVE 데이터를 수집하는 함수
def fetch_cves(start: str, end: str, mode: str = "published"):
  params = {
    "resultsPerPage": 2000,
    "startIndex": 0,
  }

  # 검색 기준에 따라 파라미터 설정
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

  # 페이징 처리 (2000개씩)
  while True:
    res = requests.get(NVD_API_BASE, params=params, headers=headers)
    if res.status_code != 200:
      break

    data = res.json()
    items = data.get("vulnerabilities", [])
    if not items:
      break

    all_items.extend(items)

    # 마지막 페이지이면 종료
    if len(items) < 2000:
      break

    # 다음 페이지로 이동
    params["startIndex"] += len(items)
    time.sleep(1)  # 요청 간 딜레이 (NVD API rate limit 방지)

  return all_items

# 수집한 CVE 데이터를 DB에 저장하는 함수
def save_to_db(items):
  conn = get_connection()
  cursor = conn.cursor()

  for item in items:
    cve_data = item["cve"]
    cve_id = cve_data["id"]

    # 영어 설명만 추출
    description = next(
      (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
      ""
    )

    # CVSS 점수 추출 함수 (버전별 분기)
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

    # CVSS 4, 3, 2 점수 추출
    cvss4 = extract_cvss("4")
    cvss3 = extract_cvss("3")
    cvss2 = extract_cvss("2")

    # 날짜 포맷 정리 (초 단위까지만 자름)
    published = cve_data.get("published", "")[:19].replace("T", " ")
    modified = cve_data.get("lastModified", "")[:19].replace("T", " ")

    # nvd_cve 테이블에 INSERT (중복 시 UPDATE)
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

# FastAPI 경로: /api/update → 날짜 입력 받아 CVE 데이터 수집 후 저장
@nvd.get("/api/update")
async def update_nvd_data(
  start_date: str = Query(...),  # 예: 2025-05-30T00:00:00
  end_date: str = Query(...),    # 예: 2025-05-31T00:00:00
  mode: str = Query("published", pattern="^(published|modified)$")  # 수집 기준: published 또는 modified
):
  try:
    # 날짜 형식 검증 및 변환 (Z 접미사 포함)
    start = parse_iso8601(start_date).isoformat() + ".000Z"
    end = parse_iso8601(end_date).isoformat() + ".000Z"
  except ValueError as ve:
    return JSONResponse(status_code=400, content={"detail": str(ve)})

  # NVD에서 데이터 수집 및 저장
  items = fetch_cves(start, end, mode)
  save_to_db(items)

  # 결과 반환
  return {
    "detail": f"✅ {mode} 기준 업데이트 완료",
    "start_date": start_date,
    "end_date": end_date,
    "count": len(items)
  }
