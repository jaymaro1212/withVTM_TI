import requests
import pymysql
import json
import re
from datetime import datetime

URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

def get_connection():
  return pymysql.connect(
    host="172.16.250.227",
    user="root",
    password="qhdks00@@",
    database="vtm",
    charset="utf8mb4",
    cursorclass=pymysql.cursors.DictCursor
  )

def parse_references(refs):
  cve_ids = []
  if isinstance(refs, list):
    for ref in refs:
      if isinstance(ref, str) and ref.startswith("CVE-"):
        cve_ids.append(ref)
  return cve_ids, refs

def update_metasploit():
  res = requests.get(URL)
  res.encoding = 'utf-8'
  data = json.loads(res.text)

  conn = get_connection()
  cursor = conn.cursor()

  insert_count = 0
  update_count = 0
  now = datetime.now().strftime("%Y-%m-%d")

  for fullname, item in data.items():
    if not isinstance(item, dict):
      continue

    mod_time = item.get("mod_time", "")

    name = str(item.get("name", ""))
    disclosure_date = str(item.get("disclosure_date", ""))
    description = str(item.get("description", ""))
    type_ = str(item.get("type", ""))
    path = str(item.get("path", ""))
    autofilter_ports = str(item.get("autofilter_ports", ""))
    autofilter_services = str(item.get("autofilter_services", ""))
    vuln_check = int(item.get("check", 0))
    rank = str(item.get("rank", ""))

    references = item.get("references", [])
    cve_ids, reference_list = parse_references(references)

    if not cve_ids:
      cve_ids = ["N/A"]

    reference_json = json.dumps(reference_list, ensure_ascii=False)

    for cve_id in cve_ids:
      cursor.execute("""
        SELECT id, mod_time FROM metasploit
        WHERE fullname = %s AND cve_id = %s
      """, (fullname, cve_id))
      row = cursor.fetchone()

      if row:
        if row["mod_time"] != mod_time:
          cursor.execute("""
            UPDATE metasploit SET
              name = %s,
              disclosure_date = %s,
              description = %s,
              type = %s,
              path = %s,
              autofilter_ports = %s,
              autofilter_services = %s,
              mod_time = %s,
              vuln_check = %s,
              rank = %s,
              reference = %s
            WHERE id = %s
          """, (
            name,
            disclosure_date,
            description,
            type_,
            path,
            autofilter_ports,
            autofilter_services,
            mod_time,
            vuln_check,
            rank,
            reference_json,
            row["id"]
          ))
          update_count += 1
      else:
        cursor.execute("""
          INSERT INTO metasploit (
            name, disclosure_date, description, fullname, type,
            path, autofilter_ports, autofilter_services,
            mod_time, vuln_check, rank, reference, cve_id
          ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
          name,
          disclosure_date,
          description,
          fullname,
          type_,
          path,
          autofilter_ports,
          autofilter_services,
          mod_time,
          vuln_check,
          rank,
          reference_json,
          cve_id
        ))
        insert_count += 1

  conn.commit()
  conn.close()

  print("✅ Metasploit 업데이트 완료")
  print(f"├─ 기존 항목 업데이트: {update_count}건")
  print(f"├─ 신규 항목 추가: {insert_count}건")
  print(f"└─ 마지막 업데이트 날짜: {now}")

if __name__ == "__main__":
  update_metasploit()
