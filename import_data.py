import json
import re
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "koreyadak.db"
JSON_PATH = BASE_DIR / "data" / "parts.json"


def normalize_part_number(value: str) -> str:
    return re.sub(r"\s+", "", value).upper()


def import_parts():
    if not JSON_PATH.exists():
        raise FileNotFoundError(f"parts.json not found: {JSON_PATH}")

    parts = json.loads(JSON_PATH.read_text(encoding="utf-8"))

    connection = sqlite3.connect(DB_PATH)

    # Make sure the table exists.
    connection.execute("""
        CREATE TABLE IF NOT EXISTS parts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            part_number TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            compatible_cars TEXT NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0
        )
    """)

    inserted = 0
    skipped = 0

    for part in parts:
        try:
            connection.execute(
                """
                INSERT INTO parts (part_number, name, compatible_cars, stock)
                VALUES (?, ?, ?, ?)
                """,
                (
                    part["part_number"].strip(),
                    part["name"].strip(),
                    part["compatible_cars"].strip(),
                    int(part.get("stock", 0)),
                ),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            # Same part number already exists.
            skipped += 1

    connection.commit()

    total = connection.execute("SELECT COUNT(*) FROM parts").fetchone()[0]
    connection.close()

    print(f"Imported: {inserted}")
    print(f"Skipped (already existed): {skipped}")
    print(f"Total in database: {total}")


if __name__ == "__main__":
    import_parts()
