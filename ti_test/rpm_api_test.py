# import requests
# import json
#
# url = "http://172.16.250.227:8000/api/search"
# payload = {
#   "rpm_info": [
#     "log4j-2.14.1-1.el8.x86_64",
#     "filesystem-3.16-2.el9.x86_64",
#     "python3-setuptools-wheel-53.0.0-12.el9.noarch",
#     "publicsuffix-LIST-dafsa-20210518-3.el9.noarch",
#     "ncurses-base-6.2-10.20210508.el9.noarch"
#   ]
# }
#
# res = requests.post(url, json=payload)
# data = res.json()
# print("🔎 전체 응답 구조:\n", json.dumps(data, indent=2, ensure_ascii=False))

import requests
import json

URL = "http://172.16.250.227:8000/api/search"  # FastAPI 서버 주소

payload = {
  "rpm_info": [
    "log4j-2.14.1-1.el8.x86_64",
    "filesystem-3.16-2.el9.x86_64",
    "python3-setuptools-wheel-53.0.0-12.el9.noarch",
    "publicsuffix-LIST-dafsa-20210518-3.el9.noarch",
    "ncurses-base-6.2-10.20210508.el9.noarch"
  ]
}

try:
  print("🔍 요청 중...")
  res = requests.post(URL, json=payload)
  print("📡 응답 코드:", res.status_code)
  res.raise_for_status()

  data = res.json()
  print("✅ 응답 결과:\n", json.dumps(data, indent=2, ensure_ascii=False))

except requests.exceptions.RequestException as e:
  print("❌ 요청 실패:", e)
except Exception as e:
  print("⚠️ JSON 파싱 실패:", e)
