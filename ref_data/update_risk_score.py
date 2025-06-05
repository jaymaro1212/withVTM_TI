import pymysql
import pandas as pd
from math import gamma
import math
from datetime import datetime
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

# DB 연결 (pymysql)
conn = pymysql.connect(
    host='172.16.250.227',
    user='root',
    password='qhdks00@@',
    database='vtm',
    charset='utf8mb4',
    autocommit=True
)
cursor = conn.cursor()

# SQLAlchemy 엔진 (read_sql용)
engine = create_engine("mysql+pymysql://root:qhdks00%40%40@172.16.250.227/vtm")

# risk_score 컬럼 없으면 생성
cursor.execute("SHOW COLUMNS FROM nvd_cve LIKE 'risk_score'")
if cursor.fetchone() is None:
    print("🛠 risk_score 컬럼 생성 중...")
    cursor.execute("ALTER TABLE nvd_cve ADD COLUMN risk_score FLOAT")
else:
    print("risk_score 컬럼 이미 존재함")

# 미계산 CVE 조회
print("위험도 미계산 데이터 조회 중...")
cve_df = pd.read_sql("""
    SELECT cve_id, cvss_score
    FROM nvd_cve
    WHERE risk_score IS NULL
""", engine)

if cve_df.empty:
    print("업데이트할 대상이 없습니다.")
else:
    # KEV / EPSS 데이터 로딩
    kev_df = pd.read_sql("SELECT DISTINCT cveID FROM cisa_kev", engine)
    epss_df = pd.read_sql("SELECT cve, epss FROM epss_scores", engine)

    # 병합
    cve_df["kev_status"] = cve_df["cve_id"].isin(kev_df["cveID"]).astype(int)
    cve_df = cve_df.merge(epss_df, how="left", left_on="cve_id", right_on="cve")
    cve_df.drop(columns=["cve"], inplace=True)

    # 위험도 계산 및 업데이트
    print("risk_score 계산 중...")
    for _, row in cve_df.iterrows():
        if not row["cve_id"]:
            continue
        cve_id = row["cve_id"].strip()

        p0 = prior_from_cvss(row["cvss_score"])
        p1 = update_with_kev(p0, row["kev_status"])
        p2 = update_with_epss(p1, row["epss"])
        score = risk_score_to_10(p2)

        cursor.execute(
            "UPDATE nvd_cve SET risk_score = %s WHERE cve_id = %s",
            (score, cve_id)
        )

# 마무리
cursor.close()
conn.close()
print("risk_score 업데이트 완료")
