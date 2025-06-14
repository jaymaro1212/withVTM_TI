import requests
import json

# 👉 발급받은 NVD API 키
API_KEY = "7c59882b-0ed4-41d5-8650-47db8e668f79"

# 👉 조회 대상 CVE ID
CVE_ID = "CVE-2024-47575"
NVD_API_URL = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE_ID}"

headers = {
    "User-Agent": "CVE-Test/1.0",
    "apiKey": API_KEY
}

# 👉 NVD 요청 및 응답 처리
response = requests.get(NVD_API_URL, headers=headers)
if response.status_code != 200:
    print(f"요청 실패: {response.status_code}")
    exit()

data = response.json()
items = data.get("vulnerabilities", [])

if not items:
    print("❌ CVE 데이터가 없습니다.")
    exit()

cve = items[0]["cve"]

print(f"\n✅ CVE ID: {cve['id']}")
print("\n📦 configurations 구조:")
print(json.dumps(cve.get("configurations", []), indent=2, ensure_ascii=False))
