import pymysql
import pandas as pd
from math import gamma
import math

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

# 1. risk_score 컬럼 추가 (없으면 추가)
cursor.execute("""
    ALTER TABLE nvd_cve ADD COLUMN IF NOT EXISTS risk_score FLOAT;
""")

# 2. 필요한 데이터 불러오기
cve_df = pd.read_sql("SELECT cve_id, cvss_score FROM nvd_cve", conn)
kev_df = pd.read_sql("SELECT DISTINCT cveID FROM cisa_kev", conn)
epss_df = pd.read_sql("SELECT cve, epss FROM epss_scores", conn)

# 3. KEV 병합
cve_df["kev_status"] = cve_df["cve_id"].isin(kev_df["cveID"]).astype(int)

# 4. EPSS 병합
cve_df = cve_df.merge(epss_df, how="left", left_on="cve_id", right_on="cve")
cve_df.drop(columns=["cve"], inplace=True)

# 5. 위험도 계산 함수
def logistic(x, alpha=1.0, mu=5.0): return 1 / (1 + math.exp(-alpha * (x - mu)))
def beta_pdf(x, a, b): return (x**(a-1) * (1-x)**(b-1)) / (gamma(a)*gamma(b)/gamma(a+b)) if 0 <= x <= 1 else 0
def prior_from_cvss(cvss): return logistic(cvss) if pd.notna(cvss) else 0
def update_with_kev(p0, kev, p1=0.8, p0_=0.2):
    return (p0*p1)/(p0*p1+(1-p0)*p0_) if kev else (p0*(1-p1))/(p0*(1-p1)+(1-p0)*(1-p0_))
def update_with_epss(p1, epss, a1=5, b1=2, a0=2, b0=5):
    if pd.isna(epss): return p1
    le1, le0 = beta_pdf(epss, a1, b1), beta_pdf(epss, a0, b0)
    return (p1*le1) / (p1*le1 + (1-p1)*le0) if (p1*le1 + (1-p1)*le0) != 0 else 0

# 6. 위험도 계산 및 업데이트
for _, row in cve_df.iterrows():
    p0 = prior_from_cvss(row["cvss_score"])
    p1 = update_with_kev(p0, row["kev_status"])
    p2 = update_with_epss(p1, row["epss"])
    score = round(p2, 5)
    cursor.execute(
        "UPDATE nvd_cve SET risk_score = %s WHERE cve_id = %s",
        (score, row["cve_id"])
    )

# 종료
cursor.close()
conn.close()
print("risk_score update completed.")

