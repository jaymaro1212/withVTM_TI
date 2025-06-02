import requests

url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
params = {
    "pubStartDate": "1999-01-01T00:00:00.000+00:00",
    "pubEndDate": "2025-05-27T23:59:59.000+00:00",
    "resultsPerPage": 1
}
headers = {
    "apiKey": "7c59882b-0ed4-41d5-8650-47db8e668f79",
    "User-Agent": "CVECollector/1.0"
}

res = requests.get(url, headers=headers, params=params)

if res.status_code == 200:
    print("🧮 총 CVE 개수:", res.json().get("totalResults"))
else:
    print("❌ 오류 발생:", res.status_code)
