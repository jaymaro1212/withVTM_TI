import pymysql
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from pymysql.cursors import DictCursor


# DB 연결 함수
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


def calculate_grpn(cvss_score, version):
    """
    GRPN 점수 계산 함수 (척도는 고정, 등급 점수 범위만 버전에 따라 다름)
    :param cvss_score: float, CVSS 점수
    :param version: str, 'v2' 또는 'v3'
    :return: (GRPN 점수, 등급 이름, 등급 내 상대 위치)
    """
    # 1. 등급별 CVSS 점수 구간 (버전별)
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
        raise ValueError("지원하지 않는 버전입니다. 'v2', 'v3', 'v4' 중 선택해주세요.")

    # 2. GRPN 척도 구간 (모든 버전 동일)
    grpn_segments = {
        "Low": (0.01, 0.25),
        "Medium": (0.26, 0.50),
        "High": (0.51, 0.75),
        "Critical": (0.76, 1.00),
    }

    # 3. 등급 매칭
    for level, (tier_min, tier_max) in cvss_tiers.items():
        if tier_min <= cvss_score <= tier_max:
            segment_start, segment_end = grpn_segments[level]
            break
    else:
        return 0.0, "None", 0.0  # CVSS 0.0 또는 잘못된 값

    # 4. 등급 내 상대 위치
    if tier_max - tier_min == 0:
        relative_position = 0.0
    else:
        relative_position = (cvss_score - tier_min) / (tier_max - tier_min)

    # 5. GRPN 점수 계산
    segment_width = segment_end - segment_start
    grpn_score = segment_start + (relative_position * segment_width)

    return round(grpn_score, 4)


# 개별 CVE의 CVSS 점수 추출
def get_cvss_by_cve(conn, cve_id: str):
    query = f'''
SELECT 
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
WHERE cve_id = %s
  AND GREATEST(
        IF(cvss4_score IS NOT NULL, cvss4_score, -1),
        IF(cvss3_score IS NOT NULL, cvss3_score, -1),
        IF(cvss_score  IS NOT NULL, cvss_score, -1)
      ) > 0;

    '''
    with conn.cursor() as cur:
        cur.execute(query, (cve_id,))
        result = cur.fetchone()
        return (result['cvss'], result['cvss_version']) if result else (None, None)


# CVSS 점수 추출 쿼리
query = '''
        SELECT *
        FROM (
                 SELECT ROUND(GREATEST(
                                      IF(cvss4_score IS NOT NULL, cvss4_score, -1),
                                      IF(cvss3_score IS NOT NULL, cvss3_score, -1),
                                      IF(cvss_score  IS NOT NULL, cvss_score, -1)
                              ), 1) AS cvss
                 FROM nvd_cve
             ) A
        WHERE cvss > 0 \
        '''

# DB에서 데이터 가져오기
conn = get_connection()
cur = conn.cursor()
cur.execute(query)
rows = cur.fetchall()

# 리스트 → NumPy 배열
data = np.array([row['cvss'] for row in rows])

# Z-score 계산
mean = np.mean(data)
std = np.std(data)
z_scores = (data - mean) / std

# CVE-2024-38193  cvss:7.8
cve_id = 'CVE-2023-25608'
target_cvss, target_version = get_cvss_by_cve(conn, cve_id)

conn.close()
target_z = (target_cvss - mean) / std
grpn_value = calculate_grpn(target_cvss, target_version)
result = round((target_z * 0.5) + (grpn_value * 0.5), 4)
print(
    f"{cve_id}\nCVSS:{target_cvss} ({target_version}) / Z-Score:{target_z:.2f} / grpn:{grpn_value}\nIntegrated_Score:{result}")

"""
# 히스토그램 (막대만)
plt.figure(figsize=(10, 5))
sns.histplot(z_scores, bins=50)

# 세로선 추가 (7.8에 해당하는 Z-score 위치)
plt.axvline(x=target_z, color='red', linestyle='--', label=f'{cve_id}(CVSS:{target_cvss}) (Z={target_z:.2f})')

plt.title("CVSS Z-Score Distribution")
plt.xlabel("Z-Score")
plt.ylabel("Frequency")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()
"""