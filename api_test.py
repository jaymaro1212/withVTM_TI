import requests

url = "http://172.16.250.227:8000/api/search"
payload = {
  "rpm_info": "openssl-1.1.1g-15.el8.x86_64"
}

response = requests.post(url, json=payload)

if response.status_code == 200:
  data = response.json()
  items = data.get("data", [])
  print("데이터 개수:", len(items))
  for item in items:
    print(item)
else:
  print("오류 발생:", response.status_code, response.text)
