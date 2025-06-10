from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = (
    "mysql+pymysql://root:qhdks00%40%40@172.16.250.227:3306/vtm"
)

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_connection():
    try:
        db = SessionLocal()
        conn = db.connection().connection
        return conn
    except Exception as e:
        print(f"DB 연결 오류: {e}")
        raise RuntimeError("DB 연결 실패")
