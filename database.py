from pathlib import Path
import sqlite3

# مسیر همین پوشه فعلی
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "koreyadak.db"  # مستقیم به فایل چسبید

def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection
