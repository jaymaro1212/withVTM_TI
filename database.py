import pymysql

def get_connection():
  return pymysql.connect(
    host="172.16.250.227",       # 또는 실제 DB IP
    user="root",            # DB 사용자명
    password="qhdks00@@",   # DB 비밀번호
    db="vtm",               # 사용할 DB 이름
    charset="utf8mb4",
    cursorclass=pymysql.cursors.DictCursor
  )
