import os
import psycopg2
from psycopg2.extras import RealDictCursor

def get_connection():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("متغیر محیطی DATABASE_URL تنظیم نشده است!")
    
    # Render گاهی آدرس را با postgres:// شروع می‌کند که psycopg2 نیاز به postgresql:// دارد
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
        
    conn = psycopg2.connect(db_url, cursor_factory=RealDictCursor)
    return conn
