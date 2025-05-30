

import pandas as pd
import requests

# CISA KEV CSV URL
url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv'
csv_path = '/tmp/cisa_kev.csv_new'  # <-- 요청하신 파일명

# 요청 헤더 추가
headers = {
    'User-Agent': 'Mozilla/5.0'
}

# CSV 다운로드
response = requests.get(url, headers=headers)

# 파일 저장 (new 이름으로!)
with open(csv_path, 'wb') as f:
    f.write(response.content)

# 파일 미리보기 (문제 있을 때 확인)
with open(csv_path, 'r', encoding='utf-8') as f:
    preview = f.read(500)
    print("파일 미리보기:\n", preview)

# CSV 로드
cisa_kev_df = pd.read_csv(csv_path, encoding='utf-8', engine='python')

# 항목 수 출력
print(f"총 {len(cisa_kev_df)}개의 항목이 로드되었습니다.")
