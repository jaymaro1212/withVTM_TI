import pymysql
import re
from distutils.version import LooseVersion

# 입력값
rpm_input = 'openssl-1.1.1g-15.el8.x86_64'

# 제품명과 버전 추출
match = re.match(r'^([a-zA-Z0-9\-_]+)-(\d+\.\d+\.\w+)', rpm_input)
if not match:
  raise ValueError("rpm_info에서 product/version을 추출할 수 없습니다.")
product = match.group(1)
raw_version = match.group(2)

# 버전 정규화 (예: 1.1.1g → 1.1.1.6)
def normalize_version(ver_str):
  m = re.match(r'^(\d+\.\d+\.\d+)([a-z])$', ver_str)
  if m:
    base, alpha = m.groups()
    return f"{base}.{ord(alpha) - ord('a')}"
  return ver_str

rpm_version = LooseVersion(normalize_version(raw_version))

# DB 연결
conn = pymysql.connect(
  host='172.16.250.227',
  user='root',
  password='qhdks00@@',
  db='vtm',
  charset='utf8mb4',
  cursorclass=pymysql.cursors.DictCursor
)
cursor = conn.cursor()

# CPE + CVE 조회
query = """
SELECT
  cpe.cpe_uri,
  cpe.version,
  cpe.versionStartIncluding,
  cpe.versionStartExcluding,
  cpe.versionEndIncluding,
  cpe.versionEndExcluding,
  cpe.cve_id,
  cve.cvss_score,
  cve.risk_score,
  cve.description
FROM nvd_cpe AS cpe
JOIN nvd_cve AS cve ON cpe.cve_id = cve.cve_id
WHERE cpe.product = %s
"""
cursor.execute(query, (product,))
rows = cursor.fetchall()

# 버전 매칭 함수
def is_version_matched(rpm_v, row, raw_version):
  try:
    def safe(v): return LooseVersion(normalize_version(v.strip())) if v else None
    exact = row['version']
    vsi = row['versionStartIncluding']
    vse = row['versionStartExcluding']
    vei = row['versionEndIncluding']
    vee = row['versionEndExcluding']

    if exact and exact.strip() == raw_version:
      return True

    if (vsi or vse or vei or vee) and (
      (not vsi or rpm_v >= safe(vsi)) and
      (not vse or rpm_v > safe(vse)) and
      (not vei or rpm_v <= safe(vei)) and
      (not vee or rpm_v < safe(vee))
    ):
      return True
  except:
    return False
  return False

# 매칭 필터
matched = []
for row in rows:
  if is_version_matched(rpm_version, row, raw_version):
    matched.append({
      "cpe_uri": row["cpe_uri"],
      "version": row["version"] or "-",
      "versionStartIncluding": row["versionStartIncluding"] or "-",
      "versionStartExcluding": row["versionStartExcluding"] or "-",
      "versionEndIncluding": row["versionEndIncluding"] or "-",
      "versionEndExcluding": row["versionEndExcluding"] or "-",
      "cve_id": row["cve_id"],
      "cvss_score": row["cvss_score"],
      "risk_score": row["risk_score"],
      "description": row["description"][:80] + "..." if row["description"] and len(row["description"]) > 80 else row["description"]
    })

# 출력
if matched:
  print(f"총 매칭된 CPE/CVE 항목: {len(matched)}건\n")
  print("{:<60} {:<10} {:<25} {:<25} {:<25} {:<25} {:<20} {:<8} {:<8} {}".format(
    "cpe_uri", "version",
    "versionStartIncluding", "versionStartExcluding",
    "versionEndIncluding", "versionEndExcluding",
    "cve_id", "cvss_score", "risk_score", "description"
  ))
  print("-" * 220)
  for r in matched:
    print("{:<60} {:<10} {:<25} {:<25} {:<25} {:<25} {:<20} {:<8} {:<8} {}".format(
      r["cpe_uri"], r["version"],
      r["versionStartIncluding"], r["versionStartExcluding"],
      r["versionEndIncluding"], r["versionEndExcluding"],
      r["cve_id"], r["cvss_score"], r["risk_score"], r["description"] or "-"
    ))
else:
  print("매칭되는 CPE/CVE 결과가 없습니다.")

cursor.close()
conn.close()
