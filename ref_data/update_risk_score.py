import pymysql
import pandas as pd
from math import gamma
import math
from sqlalchemy import create_engine

# 위험도 계산 함수 정의
def logistic(x, alpha=1.0, mu=5.0):
  return 1 / (1 + math.exp(-alpha * (x - mu)))

def beta_pdf(x, a, b):
  if not (0 <= x <= 1): return 0
  beta_ab = gamma(a) * gamma(b) / gamma(a + b)
  return (x ** (a - 1) * (1 - x) ** (b - 1)) / beta_ab

def prior_from_cvss(cvss):
  return logistic(cvss) if pd.notna(cvss) else 0

def update_with_kev(p0, kev, p1=0.8, p0_=0.2):
  return (p0*p1)/(p0*p1+(1-p0)*p0_) if kev else (p0*(1-p1))/(p0*(1-p1)+(1-p0)*(1-p0_))

def update_with_epss(p1, epss, a1=5, b1=2, a0=2, b0=5):
  if pd.isna(epss): return p1
  le1, le0 = beta_pdf(epss, a1, b1), beta_pdf(epss, a0, b0)
  return (p1*le1) / (p1*le1 + (1-p1)*le0) if (p1*le1 + (1-p1)*le0) != 0 else 0

def risk_score_to_10(prob):
  return round(max(0.0, min(1.0, prob)) * 10.0, 5)

# DB 연결
conn = pymysql.connect(
  host='172.16.250.227',
  user='root',
  password='qhdks00@@',
  database='vtm',
  charset='utf8mb4',
  autocommit=True
)
cursor = conn.cursor()
engine = create_engine("mysql+pymysql://root:qhdks00%40%40@172.16.250.227/vtm")

# 컬럼 확인 및 생성
columns_to_check = [
  ("cvss_version", "VARCHAR(20)"),
  ("cvss_severity", "VARCHAR(20)"),
  ("cvss_score", "FLOAT"),
  ("risk_score", "FLOAT")
]

print("🔎 컬럼 존재 여부 확인 중...")
for col_name, col_type in columns_to_check:
  print(f"🔍 {col_name} 컬럼 확인 중...")
  cursor.execute(f"SHOW COLUMNS FROM nvd_cve LIKE '{col_name}'")
  if cursor.fetchone() is None:
    print(f" {col_name} 컬럼 생성 중...")
    cursor.execute(f"ALTER TABLE nvd_cve ADD COLUMN {col_name} {col_type}")
  else:
    print(f" {col_name} 컬럼 이미 존재함")

# CVE 데이터 로딩
print("\n CVE 데이터 불러오는 중...")
cve_df = pd.read_sql("""
  SELECT cve_id,
         cvss20_score, cvss20_severity,
         cvss30_score, cvss30_severity,
         cvss31_score, cvss31_severity,
         cvss40_score, cvss40_severity
  FROM nvd_cve
""", engine)

# KEV / EPSS 데이터 병합
print("📥 KEV / EPSS 데이터 병합 중...")
kev_df = pd.read_sql("SELECT DISTINCT cveID FROM cisa_kev", engine)
epss_df = pd.read_sql("SELECT cve, epss FROM epss_scores", engine)

cve_df["kev_status"] = cve_df["cve_id"].isin(kev_df["cveID"]).astype(int)
cve_df = cve_df.merge(epss_df, how="left", left_on="cve_id", right_on="cve")
cve_df.drop(columns=["cve"], inplace=True)

# CVSS 우선순위 선택
def get_cvss_priority(row):
  for score_col, sev_col, version_label in [
    ("cvss40_score", "cvss40_severity", "CVSS 4.0"),
    ("cvss31_score", "cvss31_severity", "CVSS 3.1"),
    ("cvss30_score", "cvss30_severity", "CVSS 3.0"),
    ("cvss20_score", "cvss20_severity", "CVSS 2.0"),
  ]:
    score = row.get(score_col)
    if pd.notna(score):
      return version_label, row.get(sev_col), score
  return None, None, None

# 업데이트
print("⚙️ risk_score 및 cvss_* 계산 + 덮어쓰기 중...")
updated = 0
for _, row in cve_df.iterrows():
  if not row["cve_id"]:
    continue
  cve_id = row["cve_id"].strip()
  cvss_version, cvss_severity, cvss_score = get_cvss_priority(row)

  p0 = prior_from_cvss(cvss_score)
  p1 = update_with_kev(p0, row["kev_status"])
  p2 = update_with_epss(p1, row["epss"])
  risk = risk_score_to_10(p2)

  cursor.execute("""
    UPDATE nvd_cve
    SET
      risk_score = %s,
      cvss_version = %s,
      cvss_severity = %s,
      cvss_score = %s
    WHERE cve_id = %s
  """, (risk, cvss_version, cvss_severity, cvss_score, cve_id))
  updated += 1

# 마무리
cursor.close()
conn.close()
print(f"\n업데이트 완료: {updated}건 반영됨")
