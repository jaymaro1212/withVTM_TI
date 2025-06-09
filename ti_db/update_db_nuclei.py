import os
import json
import pymysql
import yaml
import re
from git import Repo
from datetime import datetime

def get_connection():
  return pymysql.connect(
    host="172.16.250.227",
    user="root",
    password="qhdks00@@",
    database="vtm",
    charset="utf8mb4",
    autocommit=True,
    cursorclass=pymysql.cursors.DictCursor
  )

def create_table(cursor):
  cursor.execute("""
  CREATE TABLE IF NOT EXISTS nuclei (
    cve_id VARCHAR(50) PRIMARY KEY,
    name TEXT,
    description TEXT,
    severity VARCHAR(20),
    remediation TEXT,
    reference TEXT,
    vendor VARCHAR(255),
    product VARCHAR(255),
    impact TEXT,
    raw MEDIUMTEXT,
    matchers JSON,
    fixed_version VARCHAR(50),
    last_commit_date DATE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  """)

def extract_fixed_version(text):
  if not text:
    return None
  match = re.search(r'version\s+(\d+(?:\.\d+)+)', text, re.IGNORECASE)
  if match:
    return match.group(1)
  match = re.search(r'\b(\d+(?:\.\d+){1,3})\b', text)
  if match:
    return match.group(1)
  return None

REPO_URL = "https://github.com/projectdiscovery/nuclei-templates.git"
LOCAL_REPO_PATH = "nuclei-templates"

if not os.path.exists(LOCAL_REPO_PATH):
  Repo.clone_from(REPO_URL, LOCAL_REPO_PATH)
repo = Repo(LOCAL_REPO_PATH)

def update_nuclei_templates():
  conn = get_connection()
  cursor = conn.cursor()
  create_table(cursor)

  insert_count = 0
  update_count = 0
  today = datetime.now().strftime("%Y-%m-%d")

  for year in range(2000, 2026):
    year_dir = os.path.join(LOCAL_REPO_PATH, "http", "cves", str(year))
    if not os.path.exists(year_dir):
      continue

    for root, _, files in os.walk(year_dir):
      for file in files:
        if not file.endswith(".yaml"):
          continue

        file_path = os.path.join(root, file)
        rel_path = os.path.relpath(file_path, LOCAL_REPO_PATH)

        try:
          commits = list(repo.iter_commits(paths=rel_path, max_count=1))
          last_commit_date = datetime.fromtimestamp(commits[0].committed_date).strftime('%Y-%m-%d') if commits else None
        except:
          last_commit_date = None

        try:
          with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        except:
          continue

        if not data or "info" not in data:
          continue

        info = data["info"]
        http = data.get("http", [{}])[0]

        cve_id = data.get("id") or info.get("cve-id")
        if not cve_id:
          continue

        name = info.get("name")
        description = info.get("description")
        severity = info.get("severity")
        remediation = info.get("remediation")
        reference = ', '.join(info.get("reference", [])) if isinstance(info.get("reference"), list) else info.get("reference")
        vendor = info.get("metadata", {}).get("vendor")
        product = info.get("metadata", {}).get("product")
        impact = info.get("impact")
        raw = "\n\n".join(http.get("raw", [])) if http.get("raw") else None
        matchers = json.dumps(http.get("matchers"), ensure_ascii=False) if http.get("matchers") else None
        fixed_version = extract_fixed_version(remediation)

        cursor.execute("SELECT cve_id, last_commit_date FROM nuclei WHERE cve_id = %s", (cve_id,))
        row = cursor.fetchone()

        if row:
          if row["last_commit_date"] != last_commit_date:
            cursor.execute("""
              UPDATE nuclei SET
                name=%s,
                description=%s,
                severity=%s,
                remediation=%s,
                reference=%s,
                vendor=%s,
                product=%s,
                impact=%s,
                raw=%s,
                matchers=%s,
                fixed_version=%s,
                last_commit_date=%s
              WHERE cve_id=%s
            """, (
              name,
              description,
              severity,
              remediation,
              reference,
              vendor,
              product,
              impact,
              raw,
              matchers,
              fixed_version,
              last_commit_date,
              cve_id
            ))
            update_count += 1
        else:
          cursor.execute("""
            INSERT INTO nuclei (
              cve_id, name, description,
              severity, remediation, reference,
              vendor, product, impact,
              raw, matchers, fixed_version,
              last_commit_date
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
          """, (
            cve_id, name, description,
            severity, remediation, reference,
            vendor, product, impact,
            raw, matchers, fixed_version,
            last_commit_date
          ))
          insert_count += 1

  conn.commit()
  conn.close()

  print("✅ nuclei 템플릿 DB 업데이트 완료")
  print(f"├─ 신규 항목 추가: {insert_count}건")
  print(f"├─ 기존 항목 업데이트: {update_count}건")
  print(f"└─ 실행 일자: {today}")

if __name__ == "__main__":
  update_nuclei_templates()
