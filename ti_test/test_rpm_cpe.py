#!/usr/bin/env python3
import sys
import time
import re
import requests

# ─────────────────────────────────────────────────────────────────────────────
# 로컬 FastAPI 주소: 172.16.250.227:8000 (이미 환경에 맞춰 두었습니다)
LOCAL_API_BASE = "http://172.16.250.227:8000"
SEARCH_ENDPOINT = f"{LOCAL_API_BASE}/api/search"
# ─────────────────────────────────────────────────────────────────────────────

def normalize_version(ver_str: str) -> str:
    """
    '1.1.1g' 같은 문자열에서 알파벳을 숫자로 바꿔주는 로직.
    FastAPI handle_rpm_lookup과 동일하게 구현되어야 합니다.
    """
    m = re.match(r'^(\d+\.\d+\.\d+)([a-z])$', ver_str)
    if m:
        base, alpha = m.groups()
        return f"{base}.{ord(alpha) - ord('a')}"
    return ver_str

def parse_rpm(rpm_str: str):
    """
    예: "openssl-1.1.1g-15.el8.x86_64"
    1) ".rpm" 확장자 제거
    2) 마지막 마침표 이후 아키텍처 제거
    3) 첫 번째 '-' 기준으로 product / version-release 분리
    4) version-release에서 순수 버전(예: "1.1.1g")만 추출
    → (product, raw_version) 또는 (None, None) 반환
    """
    q = rpm_str.strip()
    if not q:
        return None, None

    # 1) .rpm 확장자 제거
    if q.lower().endswith(".rpm"):
        q = q[:-4]

    # 2) 마지막 마침표 이후 아키텍처 제거
    parts = q.rsplit(".", 1)
    base = parts[0] if len(parts) == 2 else q

    # 3) 첫 번째 '-' 기준 분리
    if "-" not in base:
        return None, None
    product, version_release = base.split("-", 1)

    # 4) version-release에서 순수 버전만 추출
    raw_version = version_release.split("-", 1)[0]

    return product, raw_version

def fetch_local_cpe(rpm_str: str):
    """
    로컬 FastAPI /api/search 를 POST 방식 호출해서
    JSON 응답 중 'data' → {'cpe_uri': ...} 반환.
    매칭 없거나 에러 시 None 반환.
    """
    headers = {"Content-Type": "application/json"}
    payload = {"rpm_info": rpm_str}
    try:
        resp = requests.post(SEARCH_ENDPOINT, json=payload, headers=headers, timeout=5)
        resp.raise_for_status()
        j = resp.json()
        data = j.get("data")
        if not data:
            return None
        return data.get("cpe_uri")
    except Exception:
        return None

def fetch_external_cpe(product: str, raw_version: str):
    """
    NVD CPE Match API 호출:
    match_string = "cpe:2.3:a:<product>:<product>:<normalized_version>:*:*:*:*:*:*:*"
    vendor와 product를 동일하게 가정.
    결과가 없으면 None 반환.
    """
    norm_ver = normalize_version(raw_version)
    cpe_match = f"cpe:2.3:a:{product}:{product}:{norm_ver}:*:*:*:*:*:*:*"
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    params = {
        "cpeMatchString": cpe_match,
        "resultsPerPage": 1
    }
    try:
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
        prods = data.get("products", [])
        if not prods:
            return None
        return prods[0].get("cpe23Uri")
    except Exception:
        return None

def compare_rpm(rpm_str: str) -> str:
    """
    1) 로컬 CPE 조회
    2) product / raw_version 파싱
    3) 외부(NVD) CPE 조회
    4) 비교 결과 메시지 생성 후 반환
    """
    rpm = rpm_str.strip()
    if not rpm:
        return "`입력된 RPM 문자열이 비어 있습니다.`"

    # (1) 로컬 DB CPE 조회
    local_cpe = fetch_local_cpe(rpm)
    if not local_cpe:
        return f"* `{rpm}` → 🔍 로컬 매칭 없음"

    # (2) product, raw_version 추출
    product, raw_version = parse_rpm(rpm)
    if not product or not raw_version:
        return f"* `{rpm}` → ❌ RPM 형식 파싱 실패"

    # (3) 외부(NVD) CPE 조회
    external_cpe = fetch_external_cpe(product, raw_version)
    if not external_cpe:
        return f"* `{rpm}` → ❌ 외부(NVD) CPE 없음 / 로컬: `{local_cpe}`"

    # (4) 둘 비교
    if local_cpe == external_cpe:
        return f"* `{rpm}` → ✅ 일치 (로컬/외부 모두 `{local_cpe}`)"
    else:
        return (
            f"* `{rpm}` → ⚠️ 불일치\n"
            f"    - 로컬:   `{local_cpe}`\n"
            f"    - 외부:   `{external_cpe}`"
        )

def main():
    # 무조건 input() 창을 띄우도록 구성
    print("\n=== RPM → 로컬 DB vs. 외부(NVD) CPE 비교 툴 ===\n")
    print("비교할 RPM 이름들을 쉼표(또는 공백)로 구분하여 입력하세요.\n")

    txt = input("RPM 목록 입력: ").strip()
    if not txt:
        print("입력 값이 없습니다. 종료합니다.")
        return

    # 쉼표 또는 공백으로 분리
    if "," in txt:
        rpm_inputs = [s.strip() for s in txt.split(",") if s.strip()]
    else:
        rpm_inputs = [s for s in txt.split() if s]

    if not rpm_inputs:
        print("유효한 RPM 문자열이 입력되지 않았습니다. 종료합니다.")
        return

    results = []
    for rpm in rpm_inputs:
        res = compare_rpm(rpm)
        results.append(res)
        # NVD API Rate Limit 고려: 초당 약 2회 이하로 호출
        time.sleep(0.6)

    # 결과를 한 번에 출력
    print("\n===== 비교 결과 =====")
    print("\n".join(results))

if __name__ == "__main__":
    main()
