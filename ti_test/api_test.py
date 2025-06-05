import requests
import json

url = "http://172.16.250.227:8000/api/search"
payload = { "rpm_info": "log4j-2.14.1-1.el8.x86_64" }

res = requests.post(url, json=payload)
data = res.json()
print("🔎 전체 응답 구조:\n", json.dumps(data, indent=2, ensure_ascii=False))
