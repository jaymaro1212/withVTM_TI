from fastapi import FastAPI, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from typing import List
import pymysql
import re
from database import get_connection
from distutils.version import LooseVersion
from collections import defaultdict
import json

app = FastAPI()
templates = Jinja2Templates(directory="templates")

class RpmQuery(BaseModel):
  rpm_info: str = Field(..., description="검색할 RPM 정보")

class BulkRpmQuery(BaseModel):
  rpm_info: List[str] = Field(..., description="검색할 RPM 정보 리스트")

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
  return templates.TemplateResponse("nvd_data.html", {
    "request": request,
    "endpoint": "/api/search_single",
    "query": query
  })

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
    if exact and exact.strip() in ("*", "-", raw_version):
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

def format_version_range(row):
  s = e = None
  s_incl = e_incl = True
  version = row.get("version")

  if row.get("versionStartIncluding"):
    s = row["versionStartIncluding"]
    s_incl = True
  elif row.get("versionStartExcluding"):
    s = row["versionStartExcluding"]
    s_incl = False

  if row.get("versionEndIncluding"):
    e = row["versionEndIncluding"]
    e_incl = True
  elif row.get("versionEndExcluding"):
    e = row["versionEndExcluding"]
    e_incl = False

  is_all_empty = all(
    not row.get(col) or str(row[col]).strip() in ("", "-", "None")
    for col in ["versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding", "version"]
  )

  if is_all_empty:
    return "모든 버전"

  if not s and not e:
    if version == "*" or version is None:
      return "모든 버전"
    return version

  if s == e and s_incl and e_incl:
    return s

  parts = []
  if s and s not in ("정보 없음", "-", "None", "*"):
    parts.append(f"{s} 이상" if s_incl else f"{s} 초과")
  if e and e not in ("정보 없음", "-", "None", "*"):
    parts.append(f"{e} 이하" if e_incl else f"{e} 미만")

  return " ~ ".join(parts) if parts else "정보 없음"

def handle_rpm_lookup(query: str, offset: int = 0):
  conn = get_connection()
  cursor = conn.cursor(pymysql.cursors.DictCursor)

  if query.lower().endswith('.rpm'):
    query = query[:-4]
  parts = query.rsplit('.', 1)
  base = parts[0] if len(parts) == 2 else query
  if '-' not in base:
    return JSONResponse(content={"data": []})

  try:
    product, version_release = base.split('-', 1)
    raw_version = version_release.split('-', 1)[0]
    rpm_v = LooseVersion(normalize_version(raw_version))
  except:
    return JSONResponse(content={"data": []})

  cursor.execute("""
    SELECT
      cpe.cpe_uri, cpe.vendor, cpe.product, cpe.version,
      cpe.versionStartIncluding, cpe.versionStartExcluding,
      cpe.versionEndIncluding, cpe.versionEndExcluding,
      cpe.cve_id, cve.cvss_score, cve.risk_score, cve.description, cve.weaknesses
    FROM nvd_cpe AS cpe
    JOIN nvd_cve AS cve ON cpe.cve_id = cve.cve_id
    WHERE cpe.product LIKE %s
    ORDER BY cve.risk_score DESC
  """, [product + '%'])
  rows = cursor.fetchall()

  result = []
  for row in rows:
    if is_version_matched(rpm_v, row, raw_version):
      cve_id = row["cve_id"].strip() if "cve_id" in row and row["cve_id"] else ""
      description = row["description"].replace("\n", " ") if row.get("description") else ""

      # CISA
      known_ransomware = ""
      due_date = ""
      cursor.execute("SELECT knownRansomwareCampaignUse, dueDate FROM cisa_kev WHERE cveID = %s", [cve_id])
      cisa_row = cursor.fetchone()
      if cisa_row:
        known_ransomware = cisa_row.get("knownRansomwareCampaignUse", "") or ""
        due_date = str(cisa_row.get("dueDate", "")) if cisa_row.get("dueDate") else ""

      # EPSS
      epss_score = None
      cursor.execute("SELECT epss FROM epss_scores WHERE cve = %s", [cve_id])
      epss_row = cursor.fetchone()
      try:
        if epss_row and epss_row.get("epss") not in (None, ""):
          epss_score = float(epss_row["epss"])
      except:
        epss_score = None

      # PoC
      cursor.execute("SELECT poc_link FROM poc_github WHERE cve_id = %s", [cve_id])
      poc_links = [p["poc_link"] for p in cursor.fetchall() if p.get("poc_link")]

      # ExploitDB
      cursor.execute("SELECT file FROM exploitdb WHERE cve_code = %s", [cve_id])
      exploit_files = [e["file"] for e in cursor.fetchall() if e.get("file")]

      # Metasploit
      cursor.execute("SELECT reference FROM metasploit WHERE cve_id = %s", [cve_id])
      msf_references = [m["reference"] for m in cursor.fetchall() if m.get("reference")]

      # Nuclei
      impact = remediation = fixed_version = ""
      cursor.execute("SELECT impact, remediation, fixed_version FROM nuclei WHERE cve_id = %s", [cve_id])
      nuclei_row = cursor.fetchone()
      if nuclei_row:
        impact = nuclei_row.get("impact", "") or ""
        remediation = nuclei_row.get("remediation", "") or ""
        fixed_version = nuclei_row.get("fixed_version", "") or ""

      version_range = format_version_range(row)

      result.append({
        "cpe_uri": row["cpe_uri"],
        "vendor": row["vendor"],
        "product": row["product"],
        "version": version_range,
        "cve_id": cve_id,
        "cvss_score": row.get("cvss_score"),
        "epss_score": epss_score,
        "risk_score": row.get("risk_score"),
        "description": description,
        "weaknesses": row.get("weaknesses"),
        "fixed_version": fixed_version,
        "impact": impact,
        "remediation": remediation,
        "poc_links": poc_links,
        "exploitdb_files": exploit_files,
        "cisa_knownRansomware": known_ransomware,
        "cve_dueDate": due_date,
        "references": msf_references
      })

  top5 = sorted(result, key=lambda x: float(x["risk_score"]) if x["risk_score"] is not None else 0, reverse=True)[:5]
  return JSONResponse(content=json.loads(json.dumps({"data": top5}, ensure_ascii=False)), media_type="application/json")

@app.post("/api/search_single")
async def get_single_rpm(payload: RpmQuery):
  return handle_rpm_lookup(payload.rpm_info.strip())

@app.post("/api/search")
async def bulk_rpm_search(payload: BulkRpmQuery):
  results = []
  for rpm in payload.rpm_info:
    try:
      response = handle_rpm_lookup(rpm.strip())
      if isinstance(response, JSONResponse):
        data = json.loads(response.body.decode("utf-8")).get("data", [])
        results.append({"rpm_info": rpm, "data": data})
      else:
        results.append({"rpm_info": rpm, "data": []})
    except Exception:
      results.append({"rpm_info": rpm, "data": []})
  return JSONResponse(content=json.loads(json.dumps(results, ensure_ascii=False)), media_type="application/json")

@app.get("/ti_search", response_class=HTMLResponse)
async def ti_search_ui(request: Request):
  return templates.TemplateResponse("ti_search.html", {"request": request})

@app.get("/api/cves")
async def get_cves(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor(pymysql.cursors.DictCursor)

  if not query.strip():
    cursor.execute("""
      SELECT cve_id, published_date, description, cvss_score, risk_score
      FROM nvd_cve
      ORDER BY published_date DESC LIMIT 20
    """)
    rows = cursor.fetchall()
    conn.close()
    return {"data": rows}

  cve_id = query.strip()

  # nvd_cve
  cursor.execute("""
    SELECT cve_id, published_date, description, cvss_score, risk_score, weaknesses
    FROM nvd_cve
    WHERE cve_id = %s
  """, [cve_id])
  cve_row = cursor.fetchone()
  if not cve_row:
    conn.close()
    return {"error": "CVE ID가 존재하지 않습니다."}

  # epss_scores
  cursor.execute("SELECT epss FROM epss_scores WHERE cve = %s", [cve_id])
  epss_row = cursor.fetchone()
  epss_score = epss_row["epss"] if epss_row else None

  # nvd_cpe
  cursor.execute("""
    SELECT cpe_uri, vendor, product, version,
           versionStartIncluding, versionStartExcluding,
           versionEndIncluding, versionEndExcluding
    FROM nvd_cpe
    WHERE cve_id = %s
  """, [cve_id])
  raw_cpe_rows = cursor.fetchall()

  product_map = defaultdict(list)
  for row in raw_cpe_rows:
    version_range = row["version"] or "-"
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

    key = (row["vendor"], row["product"])
    arch = row["cpe_uri"].split(":")[-2]
    product_map[key].append(f"{version_range} ({arch})")

  # 최종 정리
  affected_products = []
  for (vendor, product), versions in product_map.items():
    affected_products.append({
      "vendor": vendor,
      "product": product,
      "versions": versions
    })

  # nuclei
  cursor.execute("""
    SELECT fixed_version, remediation, reference
    FROM nuclei
    WHERE cve_id = %s
  """, [cve_id])
  nuclei_row = cursor.fetchone()
  fixed_version = remediation = nuclei_reference = None
  if nuclei_row:
    fixed_version = nuclei_row.get("fixed_version")
    remediation = nuclei_row.get("remediation")
    nuclei_reference = nuclei_row.get("reference")

  # exploitdb
  cursor.execute("SELECT file FROM exploitdb WHERE cve_code = %s", [cve_id])
  exploitdb_files = [row["file"] for row in cursor.fetchall() if row.get("file")]

  # metasploit
  cursor.execute("SELECT reference FROM metasploit WHERE cve_id = %s", [cve_id])
  metasploit_refs = [row["reference"] for row in cursor.fetchall() if row.get("reference")]

  # poc_github
  cursor.execute("SELECT poc_link FROM poc_github WHERE cve_id = %s", [cve_id])
  poc_links = [row["poc_link"] for row in cursor.fetchall() if row.get("poc_link")]

  conn.close()

  return {
    "data": [{
      "cve_id": cve_row["cve_id"],
      "published_date": str(cve_row["published_date"]),
      "description": cve_row["description"],
      "cvss_score": cve_row["cvss_score"],
      "risk_score": cve_row["risk_score"],
      "weaknesses": cve_row["weaknesses"],
      "epss": epss_score,
      "affected_products": affected_products,
      "fixed_version": fixed_version,
      "remediation": remediation,
      "nuclei_reference": nuclei_reference,
      "exploitdb_files": exploitdb_files,
      "metasploit_refs": metasploit_refs,
      "github_poc_links": poc_links
    }]
  }


@app.get("/api/cpes")
async def get_cpes(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor(pymysql.cursors.DictCursor)

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
  cursor = conn.cursor(pymysql.cursors.DictCursor)
  if query:
    cursor.execute("SELECT * FROM cisa_kev WHERE cveID = %s", [query])
  else:
    cursor.execute("SELECT * FROM cisa_kev ORDER BY dateAdded DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api/epss")
async def get_epss(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor(pymysql.cursors.DictCursor)
  if query:
    cursor.execute("SELECT * FROM epss_scores WHERE cve = %s", [query])
  else:
    cursor.execute("SELECT * FROM epss_scores ORDER BY score_date DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api/exploitdb")
async def get_exploitdb(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor(pymysql.cursors.DictCursor)
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
  cursor = conn.cursor(pymysql.cursors.DictCursor)
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
  cursor = conn.cursor(pymysql.cursors.DictCursor)
  if query:
    cursor.execute("SELECT * FROM nuclei WHERE cve_id = %s", [query])
  else:
    cursor.execute("SELECT * FROM nuclei ORDER BY last_commit_date DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api/poc_github")
async def get_poc_github(query: str = ""):
  conn = get_connection()
  cursor = conn.cursor(pymysql.cursors.DictCursor)
  if query:
    cursor.execute("SELECT * FROM poc_github WHERE cve_id = %s", [query])
  else:
    cursor.execute("SELECT * FROM poc_github ORDER BY id DESC LIMIT 20")
  rows = cursor.fetchall()
  conn.close()
  return {"data": rows}

@app.get("/api_guide", response_class=HTMLResponse)
async def show_api_guide(request: Request):
  return templates.TemplateResponse("api_guide.html", {"request": request})

from collections import defaultdict
from distutils.version import LooseVersion

@app.get("/api/vuln")
async def get_vuln(query: str = ""):
    from time import time
    t0 = time()

    conn = get_connection()
    cursor = conn.cursor(pymysql.cursors.DictCursor)

    if not query.strip():
        cursor.execute("""
            SELECT cve_id, published_date, description, cvss_score, risk_score
            FROM nvd_cve
            ORDER BY published_date DESC LIMIT 20
        """)
        rows = cursor.fetchall()
        conn.close()
        return {"data": rows}

    cve_id = query.strip()

    # 1. CVE 기본 정보
    cursor.execute("""
        SELECT cve_id, published_date, description, cvss_score, risk_score, weaknesses
        FROM nvd_cve
        WHERE cve_id = %s
    """, [cve_id])
    cve_row = cursor.fetchone()
    if not cve_row:
        conn.close()
        return {"error": "CVE ID가 존재하지 않습니다."}

    # 2. EPSS
    cursor.execute("SELECT epss FROM epss_scores WHERE cve = %s", [cve_id])
    epss_row = cursor.fetchone()
    epss_score = epss_row["epss"] if epss_row else None

    # 3. nuclei
    cursor.execute("""
        SELECT fixed_version, remediation, reference
        FROM nuclei
        WHERE cve_id = %s
    """, [cve_id])
    nuclei_row = cursor.fetchone()
    fixed_version = remediation = nuclei_reference = None
    if nuclei_row:
        fixed_version = nuclei_row.get("fixed_version")
        remediation = nuclei_row.get("remediation")
        nuclei_reference = nuclei_row.get("reference")

    # 4. 영향 받는 제품 정리
    cursor.execute("""
        SELECT vendor, product, version,
               versionStartIncluding, versionStartExcluding,
               versionEndIncluding, versionEndExcluding
        FROM nvd_cpe
        WHERE cve_id = %s
    """, [cve_id])
    cpe_rows = cursor.fetchall()

    product_bounds = defaultdict(list)

    for row in cpe_rows:
        vendor = row.get("vendor", "")
        product = row.get("product", "")
        key = product

        s = e = None
        s_incl = e_incl = True
        version = row.get("version")

        if row.get("versionStartIncluding"):
            s = row["versionStartIncluding"]
            s_incl = True
        elif row.get("versionStartExcluding"):
            s = row["versionStartExcluding"]
            s_incl = False

        if row.get("versionEndIncluding"):
            e = row["versionEndIncluding"]
            e_incl = True
        elif row.get("versionEndExcluding"):
            e = row["versionEndExcluding"]
            e_incl = False

        is_all_empty = all(
            not row.get(col) or str(row[col]).strip() in ("", "-", "None")
            for col in [
                "versionStartIncluding",
                "versionStartExcluding",
                "versionEndIncluding",
                "versionEndExcluding",
                "version"
            ]
        )

        if is_all_empty:
            product_bounds[key].append(("정보 없음", "정보 없음", True, True))
        elif not s and not e:
            if version == "*" or version is None:
                product_bounds[key].append(("*", "*", True, True))  # 모든 버전
            else:
                product_bounds[key].append((version, version, True, True))  # 단일 버전
        else:
            product_bounds[key].append((s, e, s_incl, e_incl))

    # 새 포맷 함수 추가
    def format_single_range(s, e, s_incl, e_incl):
        parts = []
        if s and s not in ("정보 없음", "-", "None"):
            parts.append(f"{s} {'이상' if s_incl else '초과'}")
        if e and e not in ("정보 없음", "-", "None"):
            parts.append(f"{e} {'이하' if e_incl else '미만'}")
        return " ~ ".join(parts) if parts else "정보 없음"

    # 변경된 affected_products 생성
    affected_products = []
    for product, bounds in product_bounds.items():
        version_ranges = set()
        for b in bounds:
            if not b or len(b) != 4:
                continue
            s, e, s_incl, e_incl = b

            # 모두 없음 또는 '*' 처리
            if s in ("정보 없음", "-", "None", "*") and e in ("정보 없음", "-", "None", "*"):
                version_ranges.add("모든 버전")
                continue

            # 시작과 끝이 같고 포함일 경우 → 단일 버전
            if s == e and s_incl and e_incl:
                version_ranges.add(s)
                continue

            # 일반 범위 표현
            parts = []
            if s and s not in ("정보 없음", "-", "None", "*"):
                parts.append(f"{s} 이상" if s_incl else f"{s} 초과")
            if e and e not in ("정보 없음", "-", "None", "*"):
                parts.append(f"{e} 이하" if e_incl else f"{e} 미만")

            version_ranges.add(" ~ ".join(parts) if parts else "정보 없음")

        affected_products.append({
            "product_name": product,
            "vulnerable_versions": sorted(version_ranges)
        })

    # 5. Exploit 관련
    def fetch_list(query, param):
        cursor.execute(query, [param])
        return [row[list(row.keys())[0]] for row in cursor.fetchall() if list(row.values())[0]]

    exploitdb_files = fetch_list("SELECT file FROM exploitdb WHERE cve_code = %s", cve_id)
    metasploit_refs = fetch_list("SELECT reference FROM metasploit WHERE cve_id = %s", cve_id)
    poc_links = fetch_list("SELECT poc_link FROM poc_github WHERE cve_id = %s", cve_id)

    conn.close()
    print(f"[✅ DONE] /api/vuln 처리시간: {time() - t0:.2f}s")

    return {
        "data": [{
            "cve_id": cve_row["cve_id"],
            "published_date": str(cve_row["published_date"]),
            "description": cve_row["description"],
            "cvss_score": cve_row["cvss_score"],
            "risk_score": cve_row["risk_score"],
            "weaknesses": cve_row["weaknesses"],
            "epss": epss_score,
            "affected_products": affected_products,
            "remediation": remediation,
            "nuclei_reference": nuclei_reference,
            "exploitdb_files": exploitdb_files,
            "metasploit_refs": metasploit_refs,
            "github_poc_links": poc_links
        }]
    }
