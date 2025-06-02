import pymysql

# DB 연결
conn = pymysql.connect(
    host='172.16.250.227',
    user='root',
    password='qhdks00@@',
    database='vtm',
    charset='utf8mb4'
)
cursor = conn.cursor()

# 1. cve_id 기준으로 가장 최신 CVE
cursor.execute("""
  SELECT cve_id, published_date 
  FROM nvd_cve 
  ORDER BY cve_id DESC 
  LIMIT 1
""")
latest_by_cve_id = cursor.fetchone()

# 2. published_date 기준으로 가장 최신 CVE
cursor.execute("""
  SELECT cve_id, published_date 
  FROM nvd_cve 
  ORDER BY published_date DESC 
  LIMIT 1
""")
latest_by_date = cursor.fetchone()

# 출력
print("* Last CVE by CVE ID:")
if latest_by_cve_id:
  print(f"CVE ID: {latest_by_cve_id[0]}")
  print(f"Published: {latest_by_cve_id[1]}")
else:
  print("No data")

print("\n* Last CVE by Published Date:")
if latest_by_date:
  print(f"CVE ID: {latest_by_date[0]}")
  print(f"Published: {latest_by_date[1]}")
else:
  print("No data")

cursor.close()
conn.close()
