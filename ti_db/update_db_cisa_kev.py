import requests
import pymysql
from datetime import datetime

CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def get_connection():
  return pymysql.connect(
    host="172.16.250.227",
    user="root",
    password="qhdks00@@",
    database="vtm",
    charset="utf8mb4",
    cursorclass=pymysql.cursors.DictCursor
  )

def parse_date(date_str):
  try:
    return datetime.strptime(date_str, "%Y-%m-%d").strftime("%Y-%m-%d")
  except:
    return None

def update_cisa_kev():
  res = requests.get(CISA_URL)
  data = res.json()
  items = data.get("vulnerabilities", [])

  conn = get_connection()
  cursor = conn.cursor()
  now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

  insert_count = 0
  update_count = 0

  for item in items:
    cve_id = item.get("cveID", "")
    vendor = item.get("vendorProject", "")
    product = item.get("product", "")
    vuln_name = item.get("vulnerabilityName", "")
    date_added = parse_date(item.get("dateAdded", ""))
    description = item.get("shortDescription", "")
    action = item.get("requiredAction", "")
    due_date = parse_date(item.get("dueDate", ""))

    cursor.execute("SELECT 1 FROM cisa_kev WHERE cveID = %s", (cve_id,))
    exists = cursor.fetchone()

    cursor.execute("""
      INSERT INTO cisa_kev (
        cveID, vendorProject, product, vulnerabilityName,
        dateAdded, shortDescription, requiredAction, dueDate, last_updated_at
      ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
      ON DUPLICATE KEY UPDATE
        vendorProject = VALUES(vendorProject),
        product = VALUES(product),
        vulnerabilityName = VALUES(vulnerabilityName),
        dateAdded = VALUES(dateAdded),
        shortDescription = VALUES(shortDescription),
        requiredAction = VALUES(requiredAction),
        dueDate = VALUES(dueDate),
        last_updated_at = VALUES(last_updated_at)
    """, (
      cve_id, vendor, product, vuln_name,
      date_added, description, action, due_date, now
    ))

    if exists:
      update_count += 1
    else:
      insert_count += 1

  conn.commit()
  conn.close()

  print("✅ CISA KEV 업데이트 완료")
  print(f"├─ 기존 CVE 업데이트: {update_count}건")
  print(f"├─ 신규 CVE 추가: {insert_count}건")
  print(f"└─ 마지막 업데이트 날짜: {now}")

if __name__ == "__main__":
  update_cisa_kev()
