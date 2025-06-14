import requests
import json

# API 서버 주소 (예: localhost:8000 이거나 실제 서버 IP)
BASE_URL = "http://172.16.250.227:8000"
# cve_id = "CVE-2021-44228"
cve_id = "CVE-2024-47575"
# cve_id = "CVE-2023-45799"
# 요청
response = requests.get(f"{BASE_URL}/api/vuln", params={"query": cve_id})

# 결과 출력
if response.status_code == 200:
  data = response.json()
  print(json.dumps(data, indent=2, ensure_ascii=False))
else:
  print(f"요청 실패: {response.status_code}")
