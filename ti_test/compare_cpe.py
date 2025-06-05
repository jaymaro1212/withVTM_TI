#!/usr/bin/env python3
import sys
import time
import re
import requests
import json

# ─────────────────────────────────────────────────────────────────────────────
# 로컬 FastAPI 서버 주소 (본인의 환경: 172.16.250.227:8000으로 설정되어 있다고 가정)
LOCAL_API_BASE  = "http://172.16.250.227:8000"
SEARCH_ENDPOINT = f"{LOCAL_API_BASE}/api/search"
# ─────────────────────────────────────────────────────────────────────────────

def normalize_version(ver_str: str) -> str:
    """
    '1.1.1g'처럼 마지막에 붙은 알파벳을 숫자로 바꿔주는 로직.
    FastAPI handle_rpm_lookup 내부와 동일하게 구현해야 비교가 정확합니다.
    """
    m = re.match(r'^(\d+\.\d+\.\d+)([a-z])$', ver_str)
    if m:
        base, alpha = m.groups()
        return f"{base}.{ord(alpha) - ord('a')}"
    return ver_str

def parse_rpm(rpm_str: str):
    """
    RPM 문자열 예: "openssl-1.1.1g-15.el8.x86_64"
    1) .rpm 확장자 제거
    2) 마지막 '.' 뒤 아키텍처 제거
    3) 첫 번째 '-' 기준으로 product / version-release 분리
    4) version-release에서 순수 버전(예: "1.1.1g")만 추출
    → 리턴: (product, raw_version) 또는 (None, None) if 파싱 실패
    """
    q = rpm_str.strip()
    if not q:
        return None, None

    # 1) .rpm 확장자 제거
    if q.lower().endswith(".rpm"):
        q = q[:-4]

    # 2) 마지막 '.' 뒤 아키텍처 제거
    parts = q.rsplit(".", 1)
    base = parts[0] if len(parts) == 2 else q

    # 3) 첫 번째 '-' 기준 분리
    if "-" not in base:
        return None, None
    product, version_release = base.split("-", 1)

    # 4) version-release에서 순수 버전만
    raw_version = version_release.split("-", 1)[0]
    return product, raw_version

def fetch_local_raw_json(rpm_str: str):
    """
    로컬 FastAPI /api/search에 POST 요청한 “원본 JSON 응답”을 그대로 반환합니다.
    에러나 매칭 없으면 None 반환.
    """
    headers = {"Content-Type": "application/json"}
    payload = {"rpm_info": rpm_str}
    try:
        resp = requests.post(SEARCH_ENDPOINT, json=payload, headers=headers, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"  [로컬 API 호출 중 예외 발생]: {e}")
        return None

def fetch_external_raw_json(product: str, raw_version: str):
    """
    NVD CPE Match API에 GET 요청한 “원본 JSON 응답”을 그대로 반환합니다.
    에러나 매칭 없으면 None 반환.
    """
    norm_ver = normalize_version(raw_version)
    cpe_match = f"cpe:2.3:a:{product}:{product}:{norm_ver}:*:*:*:*:*:*:*"
    url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    params = {"cpeMatchString": cpe_match, "resultsPerPage": 1}
    try:
        r = requests.get(url, params=params, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        print(f"  [외부 NVD API 호출 중 예외 발생]: {e}")
        return None

def extract_local_cpe(raw_json: dict):
    """
    로컬 API의 raw JSON에서 data→cpe_uri를 추출하여 반환.
    데이터가 없거나 형식이 다르면 None 반환.
    """
    if not raw_json:
        return None
    data = raw_json.get("data")
    if not data:
        return None
    # data가 리스트인지 dict인지 모르지만, handle_rpm_lookup답게
    # data가 딕셔너리 하나(단일 결과)라고 가정
    if isinstance(data, dict):
        return data.get("cpe_uri")
    # 혹시 리스트 형태로, 첫 번째만 쓸 수도 있음
    if isinstance(data, list) and len(data) > 0:
        return data[0].get("cpe_uri")
    return None

def extract_external_cpe(raw_json: dict):
    """
    외부 NVD API의 raw JSON에서 products[0].cpe23Uri를 추출하여 반환.
    데이터가 없거나 형식이 다르면 None 반환.
    """
    if not raw_json:
        return None
    prods = raw_json.get("products")
    if not prods or not isinstance(prods, list) or len(prods) == 0:
        return None
    first = prods[0]
    return first.get("cpe23Uri")

def compare_rpm(rpm_str: str) -> str:
    """
    1) 로컬 raw JSON 호출 → 실제 JSON 출력
    2) 추출된 local_cpe
    3) product/raw_version 파싱
    4) 외부 raw JSON 호출 → 실제 JSON 출력
    5) 추출된 external_cpe
    6) 일치/불일치/없음 메시지
    """
    lines = []
    lines.append(f"★ 비교 대상 RPM: `{rpm_str}`")

    # 1) 로컬 raw JSON
    raw_local = fetch_local_raw_json(rpm_str)
    if raw_local is None:
        lines.append("  → [로컬] 호출 실패 (None)")
    else:
        # 깔끔하게 보기 위해 JSON을 pretty-print
        pretty_local = json.dumps(raw_local, indent=2, ensure_ascii=False)
        lines.append("  → [로컬 API 원본 JSON]:")
        for row in pretty_local.splitlines():
            lines.append(f"      {row}")

    # 2) local_cpe 추출
    local_cpe = extract_local_cpe(raw_local)
    lines.append(f"  → [로컬에서 추출된 CPE]: {local_cpe if local_cpe else '없음'}")

    # 3) product / raw_version 파싱
    product, raw_version = parse_rpm(rpm_str)
    if not product or not raw_version:
        lines.append("  → ❌ RPM 형식 파싱 실패, 외부 API 호출을 건너뜁니다.")
        return "\n".join(lines)

    lines.append(f"  → [파싱 결과] product=`{product}`, raw_version=`{raw_version}`")

    # 4) 외부 raw JSON 호출
    raw_ext = fetch_external_raw_json(product, raw_version)
    if raw_ext is None:
        lines.append("  → [외부 NVD API] 호출 실패 (None)")
    else:
        pretty_ext = json.dumps(raw_ext, indent=2, ensure_ascii=False)
        lines.append("  → [외부 NVD API 원본 JSON]:")
        for row in pretty_ext.splitlines():
            lines.append(f"      {row}")

    # 5) external_cpe 추출
    external_cpe = extract_external_cpe(raw_ext)
    lines.append(f"  → [외부에서 추출된 CPE]: {external_cpe if external_cpe else '없음'}")

    # 6) 최종 비교
    if not local_cpe and not external_cpe:
        lines.append("  → 🔍 둘 다 매칭되는 CPE가 없습니다.")
    elif not local_cpe:
        lines.append("  → 🔍 로컬에는 매칭되지만, 외부(NVD)에는 매칭되지 않습니다.")
    elif not external_cpe:
        lines.append("  → 🔍 외부(NVD)에는 매칭되지만, 로컬에는 매칭되지 않습니다.")
    else:
        if local_cpe == external_cpe:
            lines.append("  → ✅ 로컬과 외부(NVD) CPE가 일치합니다.")
        else:
            lines.append("  → ⚠️ 로컬과 외부(NVD) CPE가 불일치합니다.")
            lines.append(f"      - 로컬 CPE:   {local_cpe}")
            lines.append(f"      - 외부 CPE:   {external_cpe}")

    return "\n".join(lines)

def main():
    print("\n=== RPM → 로컬 DB vs. 외부(NVD) CPE 비교 (디버그 모드) ===\n")
    print("비교할 RPM 이름들을 쉼표(또는 공백)로 구분하여 입력하세요.\n")
    print("예) libstdc++-11.4.1-3.el9.x86_64, openssl-1.1.1g-15.el8.x86_64 zlib-1.2.11-40.el9.x86_64\n")

    txt = input("RPM 목록 입력: ").strip()
    if not txt:
        print("입력 값이 없습니다. 종료합니다.")
        return

    if "," in txt:
        rpm_inputs = [s.strip() for s in txt.split(",") if s.strip()]
    else:
        rpm_inputs = [s for s in txt.split() if s]

    if not rpm_inputs:
        print("유효한 RPM 문자열이 입력되지 않았습니다. 종료합니다.")
        return

    print("\n===== 디버그 비교 결과 =====\n")
    for rpm in rpm_inputs:
        print(compare_rpm(rpm))
        print("\n" + ("─" * 80) + "\n")
        # NVD API Rate Limit 고려: 초당 약 2회 이하로 호출
        time.sleep(0.6)

if __name__ == "__main__":
    main()
