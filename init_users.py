from Backend.database import get_connection
from Backend.main import hash_password, utc_now

USERS = ["Behnam", "Alireza", "Erfan"]
INITIAL_PASSWORD = "12345678"


def create_initial_users():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            must_change_password INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    now = utc_now()

    for username in USERS:
        exists = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if exists is None:
            connection.execute("""
                INSERT INTO users
                (username, password_hash, must_change_password, created_at, updated_at)
                VALUES (?, ?, 1, ?, ?)
            """, (
                username,
                hash_password(INITIAL_PASSWORD),
                now,
                now,
            ))
            print(f"Created user: {username}")
        else:
            print(f"Already exists: {username}")

    connection.commit()
    connection.close()
    print("Done.")


if __name__ == "__main__":
    create_initial_users()
