import requests

# CISA KEV CSV URL
url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv'
csv_path = '/tmp/cisa_kev.csv_new'  # 저장할 파일 경로

# User-Agent 추가해서 요청
headers = {
    'User-Agent': 'Mozilla/5.0'
}

# 다운로드 및 저장
response = requests.get(url, headers=headers)

with open(csv_path, 'wb') as f:
    f.write(response.content)

print("CSV 파일 저장됨", file=sys.stderr)
