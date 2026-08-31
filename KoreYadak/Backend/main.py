from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
import hashlib
import hmac
import secrets
import re
import sqlite3
from datetime import datetime, timezone

from Backend.database import get_connection

app = FastAPI(title="Kore Yadak API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,31}$")
PASSWORD_LETTER_RE = re.compile(r"[A-Za-z]")
PASSWORD_DIGIT_RE = re.compile(r"\d")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    # scrypt is provided by Python's standard library.
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=64,
    )
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, digest_hex = stored.split("$")
        if algorithm != "scrypt":
            return False

        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)

        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )

        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def validate_username(username: str):
    if not isinstance(username, str):
        raise ValueError("نام کاربری نامعتبر است.")
    username = username.strip()

    if not USERNAME_RE.fullmatch(username):
        raise ValueError(
            "نام کاربری باید 3 تا 32 کاراکتر باشد، با حرف انگلیسی شروع شود "
            "و فقط شامل حروف انگلیسی، عدد، نقطه، خط تیره یا زیرخط باشد."
        )

    return username


def validate_password(password: str):
    if not isinstance(password, str):
        raise ValueError("رمز عبور نامعتبر است.")

    if not 8 <= len(password) <= 32:
        raise ValueError("رمز عبور باید بین 8 تا 32 کاراکتر باشد.")

    # Password may contain ONLY English letters and numbers.
    # Persian/Arabic letters, spaces, emoji and symbols are rejected.
    if not re.fullmatch(r"[A-Za-z0-9]+", password):
        raise ValueError("رمز عبور فقط می‌تواند شامل حروف انگلیسی و اعداد باشد.")

    if not PASSWORD_LETTER_RE.search(password):
        raise ValueError("رمز عبور باید حداقل یک حرف انگلیسی داشته باشد.")

    if not PASSWORD_DIGIT_RE.search(password):
        raise ValueError("رمز عبور باید حداقل یک عدد داشته باشد.")

    return password


def ensure_auth_tables():
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

    connection.commit()
    connection.close()


def authenticate_token(token: str):
    if not token:
        raise HTTPException(status_code=401, detail="نیاز به ورود دارید.")

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    connection = get_connection()
    row = connection.execute("""
        SELECT
            u.id,
            u.username,
            u.must_change_password
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
    """, (token_hash,)).fetchone()
    connection.close()

    if row is None:
        raise HTTPException(status_code=401, detail="جلسه ورود معتبر نیست.")

    return row


def get_bearer_token(authorization: str | None):
    if not authorization:
        raise HTTPException(status_code=401, detail="نیاز به ورود دارید.")

    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="توکن ورود نامعتبر است.")

    return authorization[7:].strip()


class LoginRequest(BaseModel):
    username: str
    password: str


class ChangeCredentialsRequest(BaseModel):
    current_password: str
    new_username: str
    new_password: str
    new_password_repeat: str


ensure_auth_tables()


@app.get("/")
def home():
    return {"message": "Kore Yadak Backend is running!"}


# -------------------------
# Authentication
# -------------------------

@app.post("/api/auth/login")
def login(data: LoginRequest):
    username = data.username.strip()

    connection = get_connection()
    user = connection.execute("""
        SELECT id, username, password_hash, must_change_password
        FROM users
        WHERE username = ?
    """, (username,)).fetchone()

    if user is None or not verify_password(data.password, user["password_hash"]):
        connection.close()
        raise HTTPException(
            status_code=401,
            detail="نام کاربری یا رمز عبور اشتباه است."
        )

    # One fresh session token is created for each login.
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    connection.execute("""
        INSERT INTO sessions (user_id, token_hash, created_at)
        VALUES (?, ?, ?)
    """, (user["id"], token_hash, utc_now()))

    connection.commit()
    connection.close()

    return {
        "token": raw_token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "must_change_password": bool(user["must_change_password"]),
        }
    }


@app.get("/api/auth/me")
def me(authorization: str | None = Header(default=None)):
    token = get_bearer_token(authorization)
    user = authenticate_token(token)

    return {
        "id": user["id"],
        "username": user["username"],
        "must_change_password": bool(user["must_change_password"]),
    }


def get_password_hash(user_id: int):
    connection = get_connection()
    row = connection.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    connection.close()

    if row is None:
        raise HTTPException(status_code=401, detail="کاربر پیدا نشد.")

    return row["password_hash"]


@app.post("/api/auth/change-credentials")
def change_credentials(
    data: ChangeCredentialsRequest,
    authorization: str | None = Header(default=None)
):
    token = get_bearer_token(authorization)
    user = authenticate_token(token)

    if not verify_password(data.current_password, get_password_hash(user["id"])):
        raise HTTPException(status_code=400, detail="رمز عبور فعلی اشتباه است.")

    try:
        new_username = validate_username(data.new_username)
        validate_password(data.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if data.new_password != data.new_password_repeat:
        raise HTTPException(status_code=400, detail="تکرار رمز عبور یکسان نیست.")

    # Prevent changing to the same username only because of casing/spacing surprises.
    connection = get_connection()

    duplicate = connection.execute("""
        SELECT id FROM users
        WHERE username = ? AND id != ?
    """, (new_username, user["id"])).fetchone()

    if duplicate is not None:
        connection.close()
        raise HTTPException(status_code=409, detail="این نام کاربری قبلاً استفاده شده است.")

    new_hash = hash_password(data.new_password)

    connection.execute("""
        UPDATE users
        SET username = ?,
            password_hash = ?,
            must_change_password = 0,
            updated_at = ?
        WHERE id = ?
    """, (new_username, new_hash, utc_now(), user["id"]))

    connection.commit()
    connection.close()

    return {
        "message": "اطلاعات حساب با موفقیت تغییر کرد.",
        "username": new_username
    }


@app.post("/api/auth/logout")
def logout(authorization: str | None = Header(default=None)):
    token = get_bearer_token(authorization)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    connection = get_connection()
    connection.execute(
        "DELETE FROM sessions WHERE token_hash = ?",
        (token_hash,)
    )
    connection.commit()
    connection.close()

    return {"message": "خروج با موفقیت انجام شد."}


# -------------------------
# Parts
# -------------------------

@app.get("/api/parts")
def get_parts(
    q: str = Query(default=""),
    car: str = Query(default="")
):
    connection = get_connection()

    conditions = []
    parameters = []

    if q.strip():
        # جداسازی کلمات جستجو شده برای حل مشکل پارت‌نامبرهای چندبخشی
        terms = q.strip().split()
        for term in terms:
            search = f"%{term}%"
            conditions.append("""
                (
                    part_number LIKE ?
                    OR name LIKE ?
                    OR compatible_cars LIKE ?
                )
            """)
            parameters.extend([search, search, search])

    if car.strip():
        conditions.append("compatible_cars LIKE ?")
        parameters.append(f"%{car.strip()}%")

    query = """
        SELECT id, part_number, name, compatible_cars, stock
        FROM parts
    """

    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id"

    rows = connection.execute(query, parameters).fetchall()
    connection.close()

    return [dict(row) for row in rows]


@app.get("/api/parts/{part_id}")
def get_part(part_id: int):
    connection = get_connection()

    row = connection.execute("""
        SELECT id, part_number, name, compatible_cars, stock
        FROM parts
        WHERE id = ?
    """, (part_id,)).fetchone()

    connection.close()

    if row is None:
        raise HTTPException(status_code=404, detail="Part not found")

    return dict(row)


@app.get("/api/cars")
def get_cars():
    connection = get_connection()
    rows = connection.execute(
        "SELECT compatible_cars FROM parts"
    ).fetchall()
    connection.close()

    cars = set()

    for row in rows:
        text = row["compatible_cars"] or ""
        for name in text.replace(",", "،").split("،"):
            name = name.strip()
            if name:
                cars.add(name)

    return sorted(cars)

class PartCreate(BaseModel):
    name: str
    part_number: str
    compatible_cars: str
    stock: int

class PartUpdate(BaseModel):
    name: str
    part_number: str
    compatible_cars: str
    stock: int

class StockUpdate(BaseModel):
    stock: int

@app.post("/api/parts")
def add_part(
    data: PartCreate,
    authorization: str | None = Header(default=None)
):
    # بررسی لاگین بودن کاربر
    token = get_bearer_token(authorization)
    authenticate_token(token)

    part_number = data.part_number.strip()
    
    connection = get_connection()

    # جلوگیری از ثبت پارت نامبر تکراری و برگرداندن نام قطعه قبلی
    duplicate = connection.execute(
        "SELECT id, name FROM parts WHERE part_number = ?", 
        (part_number,)
    ).fetchone()

    if duplicate is not None:
        connection.close()
        raise HTTPException(
            status_code=409,
            detail=f"این پارت نامبر قبلاً برای «{duplicate['name']}» ثبت شده است."
        )

    cursor = connection.execute("""
        INSERT INTO parts (part_number, name, compatible_cars, stock)
        VALUES (?, ?, ?, ?)
    """, (
        part_number,
        data.name.strip(),
        data.compatible_cars.strip(),
        data.stock
    ))

    new_id = cursor.lastrowid
    connection.commit()
    connection.close()

    return {
        "message": "قطعه جدید با موفقیت اضافه شد.",
        "id": new_id
    }


@app.put("/api/parts/{part_id}")
def update_part(
    part_id: int,
    data: PartUpdate,
    authorization: str | None = Header(default=None)
):
    token = get_bearer_token(authorization)
    authenticate_token(token)

    part_number = data.part_number.strip()
    connection = get_connection()

    # بررسی اینکه آیا پارت نامبر جدید قبلاً برای یک قطعه دیگر ثبت شده یا نه
    duplicate = connection.execute("""
        SELECT id FROM parts 
        WHERE part_number = ? AND id != ?
    """, (part_number, part_id)).fetchone()

    if duplicate is not None:
        connection.close()
        raise HTTPException(
            status_code=409,
            detail="این پارت نامبر متعلق به قطعه دیگری است."
        )

    connection.execute("""
        UPDATE parts
        SET part_number = ?, name = ?, compatible_cars = ?, stock = ?
        WHERE id = ?
    """, (
        part_number,
        data.name.strip(),
        data.compatible_cars.strip(),
        data.stock,
        part_id
    ))

    connection.commit()
    connection.close()

    return {"message": "اطلاعات قطعه با موفقیت به‌روزرسانی شد."}


@app.patch("/api/parts/{part_id}/stock")
def update_stock(
    part_id: int,
    data: StockUpdate,
    authorization: str | None = Header(default=None)
):
    token = get_bearer_token(authorization)
    authenticate_token(token)

    connection = get_connection()
    connection.execute(
        "UPDATE parts SET stock = ? WHERE id = ?",
        (data.stock, part_id)
    )

    connection.commit()
    connection.close()

    return {"message": "موجودی با موفقیت تغییر کرد."}


@app.delete("/api/parts/{part_id}")
def delete_part(
    part_id: int,
    authorization: str | None = Header(default=None)
):
    token = get_bearer_token(authorization)
    authenticate_token(token)

    connection = get_connection()
    connection.execute(
        "DELETE FROM parts WHERE id = ?", 
        (part_id,)
    )

    connection.commit()
    connection.close()

    return {"message": "قطعه با موفقیت حذف شد."}
