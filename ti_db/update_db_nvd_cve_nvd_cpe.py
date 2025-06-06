import requests
import pymysql
from datetime import datetime, timedelta, timezone

# ─── 1. NVD API 설정 ────────────────────────────────────────────────────────────
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY      = "7c59882b-0ed4-41d5-8650-47db8e668f79"

# ─── 2. DB 연결 정보 ────────────────────────────────────────────────────────────
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

# ─── 3. CVE 목록 가져오기 함수 ───────────────────────────────────────────────────
def fetch_cves(start_iso: str, end_iso: str):
    """
    지정된 기간(start_iso ~ end_iso) 동안 NVD API에서 CVE 목록을 가져옵니다.
    """
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

# ─── 4. CPE 추출 재귀 함수 ────────────────────────────────────────────────────────
def extract_cpes_from_config(nodes: list, out: list):
    """
    configurations.nodes 내부를 재귀적으로 순회하며
    cpeMatch 배열에서 criteria(CPE URI)와
    vulnerable, versionStartIncluding 등 메타데이터를 뽑아서 out 리스트에 추가합니다.
    """
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

# ─── 5. CVSS 추출 헬퍼 ───────────────────────────────────────────────────────────
def extract_cvss(metrics: dict, ver: str):
    """
    metrics 딕셔너리에서 CVSS 데이터를 추출합니다.
    ver = "2"  → "cvssMetricV2"
    ver = "3"  → "cvssMetricV31", "cvssMetricV30", "cvssMetricV3" 중 우선순위로 큰 키를 사용
    ver = "4"  → "cvssMetricV41", "cvssMetricV40", "cvssMetricV4" 중 우선순위로 큰 키를 사용

    반환: { "source": str, "score": float|None, "vector": str, "severity": str }
    """
    prefix = f"cvssMetricV{ver}"
    # metrics 객체 안에서 prefix로 시작하는 키만 모아서, 내림차순 정렬하여 우선순위 높은 버전을 잡는다.
    candidates = [k for k in metrics.keys() if k.startswith(prefix)]
    if not candidates:
        return {"source": "", "score": None, "vector": "", "severity": ""}
    candidates.sort(reverse=True)  # 예: ["cvssMetricV31","cvssMetricV30"] → "cvssMetricV31" 우선
    chosen_key = candidates[0]
    arr = metrics.get(chosen_key, [])
    if not arr:
        return {"source": "", "score": None, "vector": "", "severity": ""}
    m = arr[0]
    base = m.get("cvssData", {}) or {}
    return {
        "source":   m.get("source", ""),
        "score":    base.get("baseScore", None),
        "vector":   base.get("vectorString", ""),
        "severity": base.get("baseSeverity", "")
    }

# ─── 6. 본격적으로 DB에 삽입/업데이트하기 ──────────────────────────────────────────
def save_items_to_db(items):
    """
    fetch_cves로 받아온 CVE 리스트(items)를 nvd_cve, nvd_cpe 테이블에 저장/업데이트합니다.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    cve_inserted = cve_updated = 0
    cpe_inserted = cpe_updated = 0

    for item in items:
        # ─────────────── 6.1) CVE 정보 저장/업데이트 ────────────────────────────────
        cve_data    = item["cve"]
        cve_id      = cve_data["id"]
        description = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
            ""
        )
        metrics = cve_data.get("metrics", {})

        # CVSS v2 / v3 / v4 각각 추출
        cvss2 = extract_cvss(metrics, "2")
        cvss3 = extract_cvss(metrics, "3")
        cvss4 = extract_cvss(metrics, "4")

        # published / lastModified 날짜 문자열 자르고
        published_str = cve_data.get("published", "")[:19]   # "2023-03-27T22:15:21"
        modified_str  = cve_data.get("lastModified", "")[:19]
        try:
            modified_dt = datetime.strptime(modified_str, "%Y-%m-%dT%H:%M:%S")
        except:
            modified_dt = None
        now_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # cvss_score 우선순위: v4 > v3 > v2
        if cvss4["score"] is not None:
            cvss_score = cvss4["score"]
        elif cvss3["score"] is not None:
            cvss_score = cvss3["score"]
        else:
            cvss_score = cvss2["score"]

        # 이미 저장된 CVE인지 체크
        cursor.execute("SELECT c_id, modified_date FROM nvd_cve WHERE cve_id=%s", (cve_id,))
        existing = cursor.fetchone()

        if not existing:
            # ─ 신규 CVE
            cursor.execute("""
                INSERT INTO nvd_cve (
                  cve_id, description,
                  cvss4_source, cvss4_score, cvss4_vector, cvss4_severity,
                  cvss3_source, cvss3_score, cvss3_vector, cvss3_severity,
                  cvss2_source, cvss2_score, cvss2_vector, cvss2_severity,
                  cvss_score,
                  published_date, modified_date, last_updated_at
                ) VALUES (
                  %s, %s,
                  %s, %s, %s, %s,
                  %s, %s, %s, %s,
                  %s, %s, %s, %s,
                  %s,
                  %s, %s, %s
                )
            """, (
                cve_id, description,
                cvss4["source"], cvss4["score"], cvss4["vector"], cvss4["severity"],
                cvss3["source"], cvss3["score"], cvss3["vector"], cvss3["severity"],
                cvss2["source"], cvss2["score"], cvss2["vector"], cvss2["severity"],
                cvss_score,
                published_str.replace("T", " "), modified_str.replace("T", " "), now_ts
            ))
            cve_inserted += 1
            c_id = cursor.lastrowid

        else:
            # ─ 기존 CVE: modified_date 비교 후 업데이트
            c_id      = existing["c_id"]
            db_mod_dt = existing["modified_date"]
            if modified_dt and (not db_mod_dt or modified_dt > db_mod_dt):
                cursor.execute("""
                    UPDATE nvd_cve
                    SET
                      description      = %s,
                      cvss4_source     = %s,
                      cvss4_score      = %s,
                      cvss4_vector     = %s,
                      cvss4_severity   = %s,
                      cvss3_source     = %s,
                      cvss3_score      = %s,
                      cvss3_vector     = %s,
                      cvss3_severity   = %s,
                      cvss2_source     = %s,
                      cvss2_score      = %s,
                      cvss2_vector     = %s,
                      cvss2_severity   = %s,
                      cvss_score       = %s,
                      published_date   = %s,
                      modified_date    = %s,
                      last_updated_at  = %s
                    WHERE cve_id = %s
                """, (
                    description,
                    cvss4["source"], cvss4["score"], cvss4["vector"], cvss4["severity"],
                    cvss3["source"], cvss3["score"], cvss3["vector"], cvss3["severity"],
                    cvss2["source"], cvss2["score"], cvss2["vector"], cvss2["severity"],
                    cvss_score,
                    published_str.replace("T", " "), modified_str.replace("T", " "), now_ts,
                    cve_id
                ))
                cve_updated += 1

        # ─────────────── 6.2) CPE 정보 파싱 & 저장 ────────────────────────────────────
        cpe_list = []

        # ★ 여기가 핵심 수정 부분: “item['cve']['configurations']” 에서 CPE를 꺼냅니다
        configs = cve_data.get("configurations", [])  # ⬅️ 반드시 cve_data 내부에서 가져와야 함
        for config_block in configs:
            nodes = config_block.get("nodes", [])
            extract_cpes_from_config(nodes, cpe_list)

        published_date_cpe = published_str.replace("T", " ")

        for cpe_obj in cpe_list:
            uri             = cpe_obj["uri"]
            vulnerable_flag = cpe_obj["vulnerable"]
            vsi             = cpe_obj.get("versionStartIncluding")
            vse             = cpe_obj.get("versionStartExcluding")
            vei             = cpe_obj.get("versionEndIncluding")
            vee             = cpe_obj.get("versionEndExcluding")

            parts = uri.split(":")
            part        = parts[2]  if len(parts) > 2  else None
            vendor      = parts[3]  if len(parts) > 3  else None
            product     = parts[4]  if len(parts) > 4  else None
            version_cpe = parts[5]  if len(parts) > 5  else None
            update_col  = parts[6]  if len(parts) > 6  else None
            edition     = parts[7]  if len(parts) > 7  else None
            language    = parts[8]  if len(parts) > 8  else None
            sw_edition  = parts[9]  if len(parts) > 9  else None
            target_sw   = parts[10] if len(parts) > 10 else None
            target_hw   = parts[11] if len(parts) > 11 else None
            other       = parts[12] if len(parts) > 12 else None

            cursor.execute(
                "SELECT id FROM nvd_cpe WHERE c_id=%s AND cpe_uri=%s",
                (c_id, uri)
            )
            existing_cpe = cursor.fetchone()

            if not existing_cpe:
                # 신규 CPE
                cursor.execute("""
                    INSERT INTO nvd_cpe (
                      c_id, cve_id, cpe_uri,
                      part, vendor, product, version,
                      update_col, edition, language,
                      sw_edition, target_sw, target_hw,
                      other, vulnerable,
                      versionStartIncluding, versionStartExcluding,
                      versionEndIncluding, versionEndExcluding,
                      published_date
                    ) VALUES (
                      %s, %s, %s,
                      %s, %s, %s, %s,
                      %s, %s, %s,
                      %s, %s, %s,
                      %s, %s,
                      %s, %s,
                      %s, %s,
                      %s
                    )
                """, (
                    c_id, cve_id, uri,
                    part, vendor, product, version_cpe,
                    update_col, edition, language,
                    sw_edition, target_sw, target_hw,
                    other, vulnerable_flag,
                    vsi, vse,
                    vei, vee,
                    published_date_cpe
                ))
                cpe_inserted += 1

            else:
                # 기존 CPE → UPDATE
                cpe_id = existing_cpe["id"]
                cursor.execute("""
                    UPDATE nvd_cpe
                    SET
                      part                  = %s,
                      vendor                = %s,
                      product               = %s,
                      version               = %s,
                      update_col            = %s,
                      edition               = %s,
                      language              = %s,
                      sw_edition            = %s,
                      target_sw             = %s,
                      target_hw             = %s,
                      other                 = %s,
                      vulnerable            = %s,
                      versionStartIncluding = %s,
                      versionStartExcluding = %s,
                      versionEndIncluding   = %s,
                      versionEndExcluding   = %s,
                      published_date        = %s
                    WHERE id = %s
                """, (
                    part, vendor, product, version_cpe,
                    update_col, edition, language,
                    sw_edition, target_sw, target_hw,
                    other, vulnerable_flag,
                    vsi, vse,
                    vei, vee,
                    published_date_cpe,
                    cpe_id
                ))
                cpe_updated += 1

    conn.commit()
    conn.close()

    print("✅ 배치 저장 완료")
    print(f"├─ CVE: 신규 삽입 {cve_inserted}건, 업데이트 {cve_updated}건")
    print(f"└─ CPE: 신규 삽입 {cpe_inserted}건, 업데이트 {cpe_updated}건")

# ─── 7. 메인 루프: 1999년 1월부터 오늘까지 120일씩 쪼개서 전부 돌리기 ──────────────────
if __name__ == "__main__":
    start_date = datetime(1999, 1, 1, tzinfo=timezone.utc)
    end_date   = datetime.now(timezone.utc)
    max_range  = timedelta(days=120)

    current_start = start_date

    while current_start < end_date:
        current_end = current_start + max_range
        if current_end > end_date:
            current_end = end_date

        # iso 포맷 예: "2025-06-01T00:00:00.000Z"
        start_iso = current_start.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        end_iso   = current_end.isoformat(timespec="milliseconds").replace("+00:00", "Z")

        print(f"\n🔎 Published CVE 수집: {start_iso} → {end_iso}")
        batch = fetch_cves(start_iso, end_iso)
        print(f"  ▶ 이번 구간에서 가져온 CVE: {len(batch)}건")

        save_items_to_db(batch)

        with get_connection() as tmp_conn:
            tmp_cursor = tmp_conn.cursor()
            tmp_cursor.execute("SELECT COUNT(*) AS cnt FROM nvd_cve")
            total_cve = tmp_cursor.fetchone()["cnt"]
            tmp_cursor.execute("SELECT COUNT(*) AS cnt FROM nvd_cpe")
            total_cpe = tmp_cursor.fetchone()["cnt"]
            print(f"└─ 현재까지 nvd_cve: {total_cve}건, nvd_cpe: {total_cpe}건")

        current_start = current_end

    print("\n✅ 전체 배치 완료")
