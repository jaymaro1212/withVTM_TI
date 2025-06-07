import pymysql
import pandas as pd

# DB 연결 및 cve 조회
def export_db_cves_to_csv():
  conn = pymysql.connect(
    host="172.16.250.227",
    user="root",
    password="qhdks00@@",
    database="vtm",
    charset="utf8mb4",
    cursorclass=pymysql.cursors.DictCursor
  )
  cursor = conn.cursor()
  cursor.execute("SELECT cve FROM epss_scores")
  rows = cursor.fetchall()
  conn.close()

  # pandas로 DataFrame 변환
  df = pd.DataFrame(rows)
  df.to_csv("epss_db_cve_list.csv", index=False)
  print("✅ epss_db_cve_list.csv 저장 완료")

export_db_cves_to_csv()
