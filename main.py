from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import pymysql
import re
from distutils.version import LooseVersion

app = FastAPI()
templates = Jinja2Templates(directory="templates")

from pydantic import Field

class RpmQuery(BaseModel):
  rpm_info: str = Field(..., description="검색할 RPM 정보")


def get_connection():
  return pymysql.connect(
    host="172.16.250.227",
    user="root",
    password="qhdks00@@",
    database="vtm",
    charset="utf8mb4",
    cursorclass=pymysql.cursors.DictCursor
  )

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
  cursor = conn.cursor()

  if not query:
    cursor.execute(f"""
      SELECT
        cpe.cpe_uri, cpe.vendor, cpe.product, cpe.version,
        cpe.cve_id, cve.cvss_score, cve.risk_score, cve.description
      FROM nvd_cpe AS cpe
      JOIN nvd_cve AS cve ON cpe.cve_id = cve.cve_id
      ORDER BY cpe.c_id DESC LIMIT 20 OFFSET {offset}
    """)
    rows = cursor.fetchall()
    conn.close()
    return {"data": rows}

  match = re.match(r'^([a-zA-Z0-9\-_]+)-([\d\.]+\w?)', query)
  if not match:
    return JSONResponse(status_code=400, content={"detail": "RPM 형식이 올바르지 않음"})

  product = match.group(1)
  raw_version = match.group(2)
  rpm_v = LooseVersion(normalize_version(raw_version))

  cursor.execute("""
    SELECT
      cpe.cpe_uri, cpe.vendor, cpe.product, cpe.version,
      cpe.versionStartIncluding, cpe.versionStartExcluding,
      cpe.versionEndIncluding, cpe.versionEndExcluding,
      cpe.cve_id, cve.cvss_score, cve.risk_score, cve.description
    FROM nvd_cpe AS cpe
    JOIN nvd_cve AS cve ON cpe.cve_id = cve.cve_id
    WHERE cpe.product = %s
  """, [product])
  rows = cursor.fetchall()
  conn.close()

  result = []
  for row in rows:
    if is_version_matched(rpm_v, row, raw_version):
      result.append({
        "cpe_uri": row["cpe_uri"],
        "vendor": row["vendor"],
        "product": row["product"],
        "version": row["version"] or "-",
        "cve_id": row["cve_id"],
        "cvss_score": row["cvss_score"],
        "risk_score": row["risk_score"],
        "description": row["description"][:80] + "..." if row["description"] and len(row["description"]) > 80 else row["description"]
      })

  return {"data": result}

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
