from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import pymysql
import re
from distutils.version import LooseVersion
from database import get_connection
import json

app = FastAPI()
templates = Jinja2Templates(directory="templates")

from pydantic import Field

class RpmQuery(BaseModel):
  rpm_info: str = Field(..., description="검색할 RPM 정보")


def get_connection(connect=pymysql.connect(host="172.16.250.227", user="root", password="qhdks00@@", database="vtm",
                                           charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor)):
  return connect

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
  return templates.TemplateResponse("index.html", {"request": request})

@app.get("/cve", response_class=HTMLResponse)
async def show_cve_ui(request: Request, query: str = ""):
  return templates.TemplateResponse("nvd_data.html", {"request": request, "endpoint": "/api/cves", "query": query})

@app.get("/cpe", response_class=HTMLResponse)
async def show_cpe_ui(request: Request, query: str = ""):
  return templates.TemplateResponse("nvd_data.html", {"request": request, "endpoint": "/api/cpes", "query": query})

@app.get("/rpm", response_class=HTMLResponse)
async def show_rpm_ui(request: Request, query: str = ""):
  return templates.TemplateResponse("nvd_data.html", {"request": request, "endpoint": "/api/search", "query": query})

def normalize_version(ver_str):
  m = re.match(r'^(\d+\.\d+\.\d+)([a-z])$', ver_str)
  if m:
    base, alpha = m.groups()
    return f"{base}.{ord(alpha) - ord('a')}"
  return ver_str

def is_version_matched(rpm_v, row, raw_version):
  try:
    def safe(v): return LooseVersion(normalize_version(v.strip())) if v else None
    exact = row["version"]
    vsi = row.get("versionStartIncluding")
    vse = row.get("versionStartExcluding")
    vei = row.get("versionEndIncluding")
    vee = row.get("versionEndExcluding")
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

def handle_rpm_lookup(query: str, offset: int = 0):
  conn = get_connection()
  cursor = conn.cursor(pymysql.cursors.DictCursor)

  if not query:
    cursor.execute(f"""
    SELECT
    cpe.cpe_uri, cpe.vendor, cpe.product, cpe.version,
    cpe.cve_id, cve.cvss_score, cve.risk_score, cve.description, cve.weaknesses
      FROM nvd_cpe AS cpe
      JOIN nvd_cve AS cve ON cpe.cve_id = cve.cve_id
      ORDER BY cpe.c_id DESC LIMIT 20 OFFSET {offset}
    """)
    rows = cursor.fetchall()
    return {"data": rows}

  # 1) .rpm 확장자 제거
  q = query
  if q.lower().endswith('.rpm'):
    q = q[:-4]

  # 2) 마지막 마침표(.) 뒤의 아키텍처(x86_64 등) 제거
  parts = q.rsplit('.', 1)
  if len(parts) == 2:
    base = parts[0]  # e.g. "openssl-1.1.1g-15.el8"
  else:
    base = q

  # 3) product와 version-release 분리: 첫 번째 '-' 기준으로 분리 (split('-', 1) 사용)
  if '-' not in base:
    return JSONResponse(
      status_code=400,
      content={"data": {"status": "ERROR", "detail": "RPM 형식이 올바르지 않음"}}
    )
  product, version_release = base.split('-', 1)
  # e.g. product="openssl", version_release="1.1.1g-15.el8"

  # 4) version-release에서 순수 버전(예: "1.1.1g")만 꺼내기
  raw_version = version_release.split('-', 1)[0]
  # e.g. raw_version="1.1.1g"

  try:
    rpm_v = LooseVersion(normalize_version(raw_version))
  except:
    return JSONResponse(
      status_code=400,
      content={"data": {"status": "ERROR", "detail": "버전 파싱 실패"}}
    )

  # 5) DB에서 product 기준으로 CPE/CVE 조회
  cursor.execute("""
    SELECT
      cpe.cpe_uri, cpe.vendor, cpe.product, cpe.version,
      cpe.versionStartIncluding, cpe.versionStartExcluding,
      cpe.versionEndIncluding, cpe.versionEndExcluding,
      cpe.cve_id, cve.cvss_score, cve.risk_score, cve.description, cve.weaknesses
    FROM nvd_cpe AS cpe
    JOIN nvd_cve AS cve ON cpe.cve_id = cve.cve_id
    WHERE cpe.product = %s
    ORDER BY cve.risk_score DESC
  """, [product])
  rows = cursor.fetchall()

  result = []
  for row in rows:
    if is_version_matched(rpm_v, row, raw_version):

      # CISA 조회
      known_ransomware = ""
      due_date = ""

      cursor.execute("""
                     SELECT knownRansomwareCampaignUse, dueDate
                     FROM cisa_kev
                     WHERE cveID = %s
                     """, [row["cve_id"]])

      cisa_row = cursor.fetchone()

      if cisa_row:
        if cisa_row["knownRansomwareCampaignUse"]:
          known_ransomware = cisa_row["knownRansomwareCampaignUse"]
        if cisa_row["dueDate"]:
          due_date = str(cisa_row["dueDate"])

      # EPSS 점수 조회
      cve_id = row["cve_id"].strip()
      cursor.execute("SELECT epss FROM epss_scores WHERE cve = %s", [cve_id])
      epss_row = cursor.fetchone()
      epss_score = float(epss_row["epss"]) if epss_row and "epss" in epss_row else None  # 또는 0.0

      # PoC 링크 조회
      cursor.execute("SELECT poc_link FROM poc_github WHERE cve_id = %s", [row["cve_id"]])
      poc_links = [p["poc_link"] for p in cursor.fetchall() if p.get("poc_link")]

      # ExploitDB 파일 조회
      cursor.execute("SELECT file FROM exploitdb WHERE cve_code = %s", [row["cve_id"]])
      exploit_files = [e["file"] for e in cursor.fetchall() if e.get("file")]

      # Metasploit reference 조회
      cursor.execute("SELECT reference FROM metasploit WHERE cve_id = %s", [row["cve_id"]])
      msf_rows = cursor.fetchall()
      msf_references = [m["reference"] for m in msf_rows if m.get("reference")]

      # Nuclei 조회
      cursor.execute("SELECT impact, remediation FROM nuclei WHERE cve_id = %s", [row["cve_id"]])
      nuclei_row = cursor.fetchone()
      impact = nuclei_row["impact"] if nuclei_row and "impact" in nuclei_row else ""
      remediation = nuclei_row["remediation"] if nuclei_row and "remediation" in nuclei_row else ""

      # 버전 범위 가공
      version_range = "-"
      if row.get("versionStartIncluding") or row.get("versionStartExcluding") or row.get(
              "versionEndIncluding") or row.get("versionEndExcluding"):
        parts = []
        if row.get("versionStartIncluding"):
          parts.append(f"{row['versionStartIncluding']} 이상")
        elif row.get("versionStartExcluding"):
          parts.append(f"{row['versionStartExcluding']} 초과")
        if row.get("versionEndIncluding"):
          parts.append(f"{row['versionEndIncluding']} 이하")
        elif row.get("versionEndExcluding"):
          parts.append(f"{row['versionEndExcluding']} 미만")
        version_range = " ~ ".join(parts)
      elif row.get("version"):
        version_range = row["version"]

      result.append({
        "cpe_uri": row["cpe_uri"],
        "vendor": row["vendor"],
        "product": row["product"],
        #"version": row["version"] or "-",
        "version": version_range,
        "cve_id": row["cve_id"],
        "cvss_score": row["cvss_score"],
        "epss_score": epss_score,
        "risk_score": row["risk_score"],
        "description": row["description"].replace("\n", " ") if row["description"] else "",
        "weaknesses": row["weaknesses"],
        "impact": impact,
        "remediation": remediation,
        "poc_links": poc_links,
        "exploitdb_files": exploit_files,
        "cisa_knownRansomware": known_ransomware,
        "cve_dueDate": due_date,
        "references": msf_references
      })

  # if result:
  #   return {"data": result}
  # else:
  #   return {"data": []}
  #
  if result:
    top = sorted(result, key=lambda x: x["risk_score"] if x["risk_score"] is not None else 0, reverse=True)[0]
    return JSONResponse(
      content=json.loads(json.dumps({"data": [top]}, ensure_ascii=False)),
      media_type="application/json"
    )
  else:
    return JSONResponse(
      content={"data": []},
      media_type="application/json"
    )


@app.post("/api/search")
async def get_rpms(payload: RpmQuery):
  return handle_rpm_lookup(payload.rpm_info.strip(), offset=0)

@app.get("/api/cves")
async def get_cves(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor()

  if query.strip():
    cursor.execute("""
      SELECT * FROM nvd_cve 
      WHERE cve_id = %s OR description LIKE %s
      ORDER BY published_date DESC LIMIT 20
    """, [query, f"%{query}%"])
  else:
    cursor.execute("SELECT * FROM nvd_cve ORDER BY published_date DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api/cpes")
async def get_cpes(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor()
  if query.strip():
    cursor.execute("""
      SELECT * FROM nvd_cpe 
      WHERE cpe_uri LIKE %s OR cve_id = %s
      ORDER BY c_id DESC LIMIT 20
    """, [f"%{query}%", query])
  else:
    cursor.execute("SELECT * FROM nvd_cpe ORDER BY c_id DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

# 외부 데이터 api 연동

@app.get("/api/cisa_kev")
async def get_cisa_kev(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor()
  if query:
    cursor.execute("SELECT * FROM cisa_kev WHERE cve_id = %s", [query])
  else:
    cursor.execute("SELECT * FROM cisa_kev ORDER BY id DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api/epss")
async def get_epss(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor()
  if query:
    cursor.execute("SELECT * FROM epss_scores WHERE cve = %s", [query])
  else:
    cursor.execute("SELECT * FROM epss_scores ORDER BY id DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api/exploitdb")
async def get_exploitdb(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor()
  if query:
    cursor.execute("SELECT * FROM exploitdb WHERE cve_code = %s", [query])
  else:
    cursor.execute("SELECT * FROM exploitdb ORDER BY id DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api/metasploit")
async def get_metasploit(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor()
  if query:
    cursor.execute("SELECT * FROM metasploit WHERE cve_id = %s", [query])
  else:
    cursor.execute("SELECT * FROM metasploit ORDER BY id DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api/nuclei")
async def get_nuclei(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor()
  if query:
    cursor.execute("SELECT * FROM nuclei WHERE cve_id = %s", [query])
  else:
    cursor.execute("SELECT * FROM nuclei ORDER BY id DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api/poc_github")
async def get_poc_github(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor()
  if query:
    cursor.execute("SELECT * FROM poc_github WHERE cve_id = %s", [query])
  else:
    cursor.execute("SELECT * FROM poc_github ORDER BY id DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api/vulncheck_kev")
async def get_vulncheck_kev(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor()
  if query:
    cursor.execute("SELECT * FROM vulncheck_kev WHERE cve = %s", [query])
  else:
    cursor.execute("SELECT * FROM vulncheck_kev ORDER BY id DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.post("/api/update")
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
  insert_count, update_count = save_to_db(items)

  return {
    "detail": f"✅ {mode} 기준 업데이트 완료",
    "start_date": start_date,
    "end_date": end_date,
    "total_count": len(items),
    "newly_inserted": insert_count,
    "existing_updated": update_count
  }
