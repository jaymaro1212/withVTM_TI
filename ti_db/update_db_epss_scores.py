import requests
import pymysql
import csv
from io import StringIO
from datetime import datetime

def get_connection():
  return pymysql.connect(
    host="172.16.250.227",
    user="root",
    password="qhdks00@@",
    database="vtm",
    charset="utf8mb4",
    cursorclass=pymysql.cursors.DictCursor
  )

def update_epss_scores_by_date(date_str):
  url = f"https://epss.empiricalsecurity.com/epss_scores-{date_str}.csv"
  print(f"📥 다운로드 중: {url}")

  res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
  if res.status_code != 200:
    print(f"❌ 다운로드 실패: HTTP {res.status_code}")
    return

  csv_text = res.text.lstrip('\ufeff')  # BOM 제거
  reader = csv.DictReader(StringIO(csv_text))

  conn = get_connection()
  cursor = conn.cursor()
  now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

  insert_count = 0
  update_count = 0

  for row in reader:
    cve_id = row.get("cve", "").strip()
    if not cve_id:
      continue
    epss_score = float(row.get("epss", 0))
    percentile = float(row.get("percentile", 0))
    score_date = row.get("date", date_str)

    cursor.execute("SELECT 1 FROM epss_scores WHERE cve = %s", (cve_id,))
    exists = cursor.fetchone()

    cursor.execute("""
      INSERT INTO epss_scores (cve, epss, percentile, score_date, last_updated_at)
      VALUES (%s, %s, %s, %s, %s)
      ON DUPLICATE KEY UPDATE
        epss = VALUES(epss),
        percentile = VALUES(percentile),
        score_date = VALUES(score_date),
        last_updated_at = VALUES(last_updated_at)
    """, (cve_id, epss_score, percentile, score_date, now))

    if exists:
      update_count += 1
    else:
      insert_count += 1

  conn.commit()
  conn.close()

  print("\n✅ EPSS 업데이트 완료")
  print(f"├─ 기존 CVE 업데이트: {update_count}건")
  print(f"├─ 신규 CVE 추가: {insert_count}건")
  print(f"└─ 마지막 업데이트 날짜: {now}")

if __name__ == "__main__":
  today = datetime.today().strftime("%Y-%m-%d")
  update_epss_scores_by_date(today)
