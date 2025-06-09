import requests
import pymysql
import csv
import gzip
from io import BytesIO
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

def update_epss_scores_current():
  url = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
  print(f"📥 다운로드 중: {url}")

  res = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
  if res.status_code != 200:
    print(f"❌ 다운로드 실패: HTTP {res.status_code}")
    return

  with gzip.open(BytesIO(res.content), mode='rt', encoding='utf-8') as f:
    lines = f.readlines()

  # 첫 줄 주석 제거
  lines = [line for line in lines if not line.startswith("#")]
  reader = csv.DictReader(lines)

  conn = get_connection()
  cursor = conn.cursor()
  now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

  insert_count = 0
  update_count = 0
  delete_count = 0
  current_csv_cves = set()

  # INSERT / UPDATE 처리
  for row in reader:
    cve_id = row.get("cve", "").strip()
    if not cve_id:
      continue

    current_csv_cves.add(cve_id)
    epss_score = float(row.get("epss", 0))
    percentile = float(row.get("percentile", 0))

    cursor.execute("SELECT epss, percentile FROM epss_scores WHERE cve = %s", (cve_id,))
    existing = cursor.fetchone()

    if existing:
      old_epss = float(existing['epss'])
      old_percentile = float(existing['percentile'])

      if epss_score != old_epss or percentile != old_percentile:
        cursor.execute("""
          UPDATE epss_scores
          SET epss = %s,
              percentile = %s,
              last_updated_at = %s
          WHERE cve = %s
        """, (epss_score, percentile, now, cve_id))
        update_count += 1
    else:
      cursor.execute("""
        INSERT INTO epss_scores (cve, epss, percentile, score_date, last_updated_at)
        VALUES (%s, %s, %s, %s, %s)
      """, (cve_id, epss_score, percentile, now, now))
      insert_count += 1

  # 삭제 대상 찾기: DB에만 있는 CVE
  cursor.execute("SELECT cve FROM epss_scores")
  db_cves = set(row["cve"] for row in cursor.fetchall() if row["cve"])

  to_delete = db_cves - current_csv_cves
  if to_delete:
    cursor.execute(
      f"DELETE FROM epss_scores WHERE cve IN ({','.join(['%s'] * len(to_delete))})",
      list(to_delete)
    )
    delete_count = cursor.rowcount

  conn.commit()
  conn.close()

  print("\n✅ EPSS 업데이트 완료")
  print(f"├─ 신규 CVE 추가: {insert_count}건")
  print(f"├─ 기존 CVE 업데이트: {update_count}건")
  print(f"├─ 최신 CSV에 없는 CVE 삭제: {delete_count}건")
  print(f"└─ 작업 종료 시각: {now}")

if __name__ == "__main__":
  update_epss_scores_current()
