import os
import requests
import yaml
import pymysql
from datetime import datetime

NUCLEI_REPO_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves/"

DB_CONFIG = {
  "host": "172.16.250.227",
  "user": "root",
  "password": "qhdks00@@",
  "database": "vtm",
  "charset": "utf8mb4",
  "cursorclass": pymysql.cursors.DictCursor
}

def get_connection():
  return pymysql.connect(**DB_CONFIG)

def fetch_yaml_list():
  index_url = "https://api.github.com/repos/projectdiscovery/nuclei-templates/contents/cves"
  res = requests.get(index_url)
  if res.status_code == 200:
    return [f["name"] for f in res.json() if f["name"].endswith(".yaml")]
  else:
    print("YAML 리스트 가져오기 실패")
    return []

def parse_yaml(url):
  res = requests.get(url)
  if res.status_code != 200:
    return None
  try:
    return yaml.safe_load(res.text)
  except:
    return None

def save_or_update(conn, cve_id, data):
  with conn.cursor() as cur:
    cur.execute("""
      INSERT INTO nuclei (
        cve_id, name, description, severity, reference,
        cvss2_score, cvss2_vector, cvss2_severity,
        cvss3_score, cvss3_vector, cvss3_severity,
        cvss4_score, cvss4_vector, cvss4_severity,
        cwe_id, epss_score, impact, remediation,
        vendor, product, modified_date
      ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
      ON DUPLICATE KEY UPDATE
        name=VALUES(name), description=VALUES(description), severity=VALUES(severity),
        reference=VALUES(reference), cvss2_score=VALUES(cvss2_score), cvss2_vector=VALUES(cvss2_vector),
        cvss2_severity=VALUES(cvss2_severity), cvss3_score=VALUES(cvss3_score), cvss3_vector=VALUES(cvss3_vector),
        cvss3_severity=VALUES(cvss3_severity), cvss4_score=VALUES(cvss4_score), cvss4_vector=VALUES(cvss4_vector),
        cvss4_severity=VALUES(cvss4_severity), cwe_id=VALUES(cwe_id), epss_score=VALUES(epss_score),
        impact=VALUES(impact), remediation=VALUES(remediation),
        vendor=VALUES(vendor), product=VALUES(product), modified_date=VALUES(modified_date)
    """, (
      cve_id,
      data.get("name"), data.get("description"), data.get("severity"), ', '.join(data.get("reference", [])),
      data.get("cvss2_score"), data.get("cvss2_vector"), data.get("cvss2_severity"),
      data.get("cvss3_score"), data.get("cvss3_vector"), data.get("cvss3_severity"),
      data.get("cvss4_score"), data.get("cvss4_vector"), data.get("cvss4_severity"),
      data.get("cwe_id"), data.get("epss_score"),
      data.get("impact"), data.get("remediation"),
      data.get("vendor"), data.get("product"),
      datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

def main():
  yaml_files = fetch_yaml_list()
  print(f"🔍 총 YAML 템플릿 수: {len(yaml_files)}")

  conn = get_connection()
  insert_count = 0
  update_count = 0

  for filename in yaml_files:
    cve_id = filename.replace(".yaml", "").upper()
    url = NUCLEI_REPO_URL + filename
    parsed = parse_yaml(url)
    if not parsed:
      continue

    data = {
      "name": parsed.get("info", {}).get("name"),
      "description": parsed.get("info", {}).get("description"),
      "severity": parsed.get("info", {}).get("severity"),
      "reference": parsed.get("info", {}).get("reference", []),
      "cvss2_score": None,
      "cvss2_vector": None,
      "cvss2_severity": None,
      "cvss3_score": None,
      "cvss3_vector": None,
      "cvss3_severity": None,
      "cvss4_score": None,
      "cvss4_vector": None,
      "cvss4_severity": None,
      "cwe_id": None,
      "epss_score": None,
      "impact": None,
      "remediation": None,
      "vendor": None,
      "product": None
    }

    try:
      save_or_update(conn, cve_id, data)
      insert_count += 1
    except Exception as e:
      print(f"{cve_id} 저장 실패: {e}")

  conn.commit()
  conn.close()

  print("nuclei 테이블 업데이트 완료")
  print(f"├─ 저장/업데이트: {insert_count}건")
  print("└─ 작업 종료")

if __name__ == "__main__":
  main()
