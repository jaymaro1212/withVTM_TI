import pymysql
import requests
import re

def get_connection():
  return pymysql.connect(
    host="172.16.250.227",
    user="root",
    password="qhdks00@@",
    database="vtm",
    charset="utf8mb4",
    cursorclass=pymysql.cursors.DictCursor
  )

def fetch_and_insert():
  url = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md"
  res = requests.get(url)
  res.encoding = "utf-8"
  lines = res.text.splitlines()

  conn = get_connection()
  cursor = conn.cursor()

  insert_count = 0
  update_count = 0
  i = 0

  while i < len(lines):
    if lines[i].startswith("### CVE-"):
      match = re.search(r"(CVE-\d{4}-\d{4,7})\s*(\((\d{4}-\d{2}-\d{2})\))?", lines[i])
      if not match:
        i += 1
        continue

      cve_id = match.group(1)
      published_date = match.group(3) if match.group(3) else ""
      i += 1

      # Description 추출
      description = ""
      while i < len(lines):
        if "<code>" in lines[i]:
          code = ""
          while i < len(lines) and "</code>" not in lines[i]:
            code += lines[i].replace("<code>", "").strip() + " "
            i += 1
          if i < len(lines):
            code += lines[i].replace("</code>", "").strip()
            i += 1
          description = code.strip()
          break
        elif lines[i].strip() == "":
          i += 1
        else:
          break

      # poc_cve에 존재 여부 확인 및 저장
      cursor.execute("SELECT c_id, description FROM poc_cve WHERE cve_id = %s", (cve_id,))
      result = cursor.fetchone()

      if result:
        c_id = result["c_id"]
        if result["description"] != description:
          cursor.execute("UPDATE poc_cve SET description = %s, published_date = %s WHERE c_id = %s",
                         (description, published_date, c_id))
          update_count += 1
      else:
        cursor.execute("INSERT INTO poc_cve (cve_id, description, published_date) VALUES (%s, %s, %s)",
                       (cve_id, description, published_date))
        c_id = cursor.lastrowid
        insert_count += 1

      # poc_github에 github.com 포함된 모든 줄 파싱
      while i < len(lines):
        line = lines[i].strip()

        if "github.com" not in line:
          if line.startswith("### CVE-"):  # 다음 CVE 시작되면 중단
            break
          i += 1
          continue

        match = re.search(r"https://github\.com/[^\s\)\]]+", line)
        if match:
          poc_link = match.group(0)
          full_name = poc_link.replace("https://github.com/", "")

          cursor.execute("SELECT id FROM poc_github WHERE cve_id = %s AND poc_link = %s", (cve_id, poc_link))
          exists = cursor.fetchone()
          if not exists:
            cursor.execute(
              "INSERT INTO poc_github (c_id, cve_id, full_name, poc_link) VALUES (%s, %s, %s, %s)",
              (c_id, cve_id, full_name, poc_link)
            )
        i += 1
    else:
      i += 1

  conn.commit()
  conn.close()

  print("✅ PoC-in-GitHub 업데이트 완료")
  print(f"├─ 업데이트: {update_count}건")
  print(f"└─ 신규 추가: {insert_count}건")

fetch_and_insert()
