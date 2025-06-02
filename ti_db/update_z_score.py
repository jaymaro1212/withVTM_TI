import pymysql
import numpy as np
from pymysql.cursors import DictCursor

# DB 연결
def get_connection():
  return pymysql.connect(
    host='172.16.250.227',
    user='root',
    password='qhdks00@@',
    database='vtm',
    charset='utf8mb4',
    autocommit=True,
    cursorclass=DictCursor
  )

# GRPN 점수 계산 함수
def calculate_grpn(cvss_score, version):
  if version == 'v2':
    cvss_tiers = {
      "Low": (0.1, 3.9),
      "Medium": (4.0, 6.9),
      "High": (7.0, 10.0),
    }
  elif version in ['v3', 'v4']:
    cvss_tiers = {
      "Low": (0.1, 3.9),
      "Medium": (4.0, 6.9),
      "High": (7.0, 8.9),
      "Critical": (9.0, 10.0),
    }
  else:
    return 0.0

  grpn_segments = {
    "Low": (0.01, 0.25),
    "Medium": (0.26, 0.50),
    "High": (0.51, 0.75),
    "Critical": (0.76, 1.00),
  }

  for level, (tier_min, tier_max) in cvss_tiers.items():
    if tier_min <= cvss_score <= tier_max:
      segment_start, segment_end = grpn_segments[level]
      break
  else:
    return 0.0

  relative_position = 0.0 if tier_max - tier_min == 0 else (cvss_score - tier_min) / (tier_max - tier_min)
  grpn_score = segment_start + relative_position * (segment_end - segment_start)
  return round(grpn_score, 4)

# 연결 및 컬럼 생성
conn = get_connection()
cursor = conn.cursor()

for col in ['z_score', 'grpn_score', 'integrated_score']:
  cursor.execute(f"SHOW COLUMNS FROM nvd_cve LIKE '{col}'")
  if cursor.fetchone() is None:
    print(f"🛠 {col} 컬럼 생성 중...")
    cursor.execute(f"ALTER TABLE nvd_cve ADD COLUMN {col} FLOAT")
  else:
    print(f"{col} 컬럼 이미 존재함")

# 전체 CVSS 점수 조회 및 평균/표준편차 계산
cursor.execute("""
  SELECT cve_id,
         ROUND(GREATEST(
           IF(cvss4_score IS NOT NULL, cvss4_score, -1),
           IF(cvss3_score IS NOT NULL, cvss3_score, -1),
           IF(cvss_score  IS NOT NULL, cvss_score, -1)
         ), 1) AS cvss,
         CASE 
           WHEN IF(cvss4_score IS NOT NULL, cvss4_score, -1) >= IF(cvss3_score IS NOT NULL, cvss3_score, -1)
                AND IF(cvss4_score IS NOT NULL, cvss4_score, -1) >= IF(cvss_score IS NOT NULL, cvss_score, -1)
           THEN 'v4'
           WHEN IF(cvss3_score IS NOT NULL, cvss3_score, -1) >= IF(cvss_score IS NOT NULL, cvss_score, -1)
           THEN 'v3'
           ELSE 'v2'
         END AS cvss_version
  FROM nvd_cve
  WHERE GREATEST(
           IF(cvss4_score IS NOT NULL, cvss4_score, -1),
           IF(cvss3_score IS NOT NULL, cvss3_score, -1),
           IF(cvss_score  IS NOT NULL, cvss_score, -1)
         ) > 0
""")
rows = cursor.fetchall()

# 전체 Z-score 계산
cvss_list = [row["cvss"] for row in rows]
mean = np.mean(cvss_list)
std = np.std(cvss_list)

print("통합 점수 계산 및 DB 저장 중...")
for row in rows:
  cve_id = row["cve_id"]
  cvss = row["cvss"]
  version = row["cvss_version"]

  z = round((cvss - mean) / std, 4)
  grpn = calculate_grpn(cvss, version)
  integrated = round((z * 0.5) + (grpn * 0.5), 4)

  cursor.execute("""
    UPDATE nvd_cve
    SET z_score = %s, grpn_score = %s, integrated_score = %s
    WHERE cve_id = %s
  """, (z, grpn, integrated, cve_id))

conn.close()
print("integrated_score 저장 완료")
