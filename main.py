from fastapi import FastAPI, HTTPException, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from pathlib import Path
import hashlib
import hmac
import secrets
import re
import sqlite3
from datetime import datetime, timezone

from database import get_connection

app = FastAPI(title="Kore Yadak API")

# -------------------------
# Routes (HTML Serving)
# -------------------------
@app.get("/")
async def serve_guest():
    return FileResponse("index.html")

@app.get("/admin")
async def serve_admin():
    return FileResponse("admin.html")

@app.get("/admin/buy")
async def serve_buy():
    return FileResponse("buy.html")

@app.get("/admin/sell")
async def serve_sell():
    return FileResponse("sell.html")

@app.get("/admin/report")
async def serve_report():
    return FileResponse("report.html")

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


def ensure_parts_table():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS parts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            part_number TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            compatible_cars TEXT NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0,
            is_genuine INTEGER NOT NULL DEFAULT 0,
            price REAL DEFAULT 0,
            price_updated_at TEXT,
            last_updated_by TEXT
        )
    """)

    existing_cols = [row[1] for row in connection.execute("PRAGMA table_info(parts)").fetchall()]

    if "is_genuine" not in existing_cols:
        connection.execute("ALTER TABLE parts ADD COLUMN is_genuine INTEGER NOT NULL DEFAULT 0")
    if "price" not in existing_cols:
        connection.execute("ALTER TABLE parts ADD COLUMN price REAL DEFAULT 0")
    if "price_updated_at" not in existing_cols:
        connection.execute("ALTER TABLE parts ADD COLUMN price_updated_at TEXT")
    if "last_updated_by" not in existing_cols:
        connection.execute("ALTER TABLE parts ADD COLUMN last_updated_by TEXT")

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
ensure_parts_table()


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

# جلوگیری از ثبت موجودی منفی در قطعات
@app.post("/api/parts")
def create_part(data: PartCreate, authorization: str | None = Header(default=None)):
    token = get_bearer_token(authorization)
    authenticate_token(token)
    
    if data.stock < 0:
        raise HTTPException(status_code=400, detail="موجودی نمی‌تواند کمتر از صفر باشد.")
    if data.price < 0:
        raise HTTPException(status_code=400, detail="قیمت نمی‌تواند منفی باشد.")
    # ادامه کدهای اینسرت دیتابیس...
# -------------------------
# Invoices (Sell)
# -------------------------

class SellInvoiceItemBase(BaseModel):
    part_id: int | None
    part_name: str
    part_number: str
    car: str
    quantity: int
    unit_price: float
    total_price: float

class SellInvoiceCreate(BaseModel):
    title: str
    shamsi_date: str
    is_paid: bool
    deduct_inventory: bool
    items: list[SellInvoiceItemBase]

def ensure_invoice_tables():
    connection = get_connection()
    connection.execute("""
        CREATE TABLE IF NOT EXISTS sell_invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            shamsi_date TEXT NOT NULL,
            is_paid INTEGER NOT NULL DEFAULT 0,
            creator_name TEXT,
            last_editor_name TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    connection.execute("""
        CREATE TABLE IF NOT EXISTS sell_invoice_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL,
            part_id INTEGER,
            part_name TEXT NOT NULL,
            part_number TEXT NOT NULL,
            car TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            total_price REAL NOT NULL,
            FOREIGN KEY (invoice_id) REFERENCES sell_invoices(id) ON DELETE CASCADE
        )
    """)
    connection.commit()
    connection.close()

# اجرای ساخت جداول فاکتور
ensure_invoice_tables()

@app.get("/api/invoices/sell")
def get_sell_invoices(authorization: str | None = Header(default=None)):
    token = get_bearer_token(authorization)
    authenticate_token(token)

    connection = get_connection()
    rows = connection.execute("SELECT * FROM sell_invoices ORDER BY id DESC").fetchall()
    connection.close()
    return [dict(row) for row in rows]

@app.get("/api/invoices/sell/{invoice_id}")
def get_sell_invoice(invoice_id: int, authorization: str | None = Header(default=None)):
    token = get_bearer_token(authorization)
    authenticate_token(token)

    connection = get_connection()
    invoice = connection.execute("SELECT * FROM sell_invoices WHERE id = ?", (invoice_id,)).fetchone()
    if not invoice:
        connection.close()
        raise HTTPException(status_code=404, detail="فاکتور یافت نشد")
    
    items = connection.execute("SELECT * FROM sell_invoice_items WHERE invoice_id = ?", (invoice_id,)).fetchall()
    connection.close()
    
    result = dict(invoice)
    result["items"] = [dict(item) for item in items]
    return result

@app.post("/api/invoices/sell")
def create_sell_invoice(data: SellInvoiceCreate, authorization: str | None = Header(default=None)):
    token = get_bearer_token(authorization)
    user = authenticate_token(token)
    
    connection = get_connection()
    try:
        cursor = connection.execute("""
            INSERT INTO sell_invoices (title, shamsi_date, is_paid, creator_name, last_editor_name, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (data.title, data.shamsi_date, 1 if data.is_paid else 0, user["username"], user["username"], utc_now(), utc_now()))
        
        invoice_id = cursor.lastrowid
        
        for item in data.items:
            connection.execute("""
                INSERT INTO sell_invoice_items (invoice_id, part_id, part_name, part_number, car, quantity, unit_price, total_price)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (invoice_id, item.part_id, item.part_name, item.part_number, item.car, item.quantity, item.unit_price, item.total_price))
            
            # کسر خودکار از موجودی در صورت تیک خوردن گزینه
            if data.deduct_inventory and item.part_id:
                connection.execute("UPDATE parts SET stock = stock - ? WHERE id = ?", (item.quantity, item.part_id))
                
        connection.commit()
        return {"message": "فاکتور با موفقیت ثبت شد", "id": invoice_id}
    except Exception as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        connection.close()

# متد آپدیت فاکتور (برای حل مشکل عدم امکان ویرایش)
@app.put("/api/invoices/sell/{invoice_id}")
def update_sell_invoice(invoice_id: int, data: SellInvoiceCreate, authorization: str | None = Header(default=None)):
    token = get_bearer_token(authorization)
    user = authenticate_token(token)
    
    connection = get_connection()
    # بررسی وجود فاکتور
    invoice = connection.execute("SELECT id FROM sell_invoices WHERE id = ?", (invoice_id,)).fetchone()
    if not invoice:
        connection.close()
        raise HTTPException(status_code=404, detail="فاکتور یافت نشد")
        
    # حذف اقلام قبلی و ثبت اقلام جدید (ساده‌ترین راه آپدیت)
    connection.execute("DELETE FROM sell_invoice_items WHERE invoice_id = ?", (invoice_id,))
    
    # آپدیت هدر فاکتور
    connection.execute("""
        UPDATE sell_invoices 
        SET title = ?, shamsi_date = ?, is_paid = ?, last_editor_name = ?, updated_at = ?
        WHERE id = ?
    """, (data.title, data.shamsi_date, int(data.is_paid), user["username"], utc_now(), invoice_id))
    
    # ثبت مجدد اقلام با بررسی موجودی منفی
    for item in data.items:
        if item.quantity <= 0:
            raise HTTPException(status_code=400, detail="تعداد کالا باید بیشتر از صفر باشد.")
            
        connection.execute("""
            INSERT INTO sell_invoice_items (invoice_id, part_id, part_name, part_number, car, quantity, unit_price, total_price)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (invoice_id, item.part_id, item.part_name, item.part_number, item.car, item.quantity, item.unit_price, item.total_price))
    
    connection.commit()
    connection.close()
    return {"message": "فاکتور با موفقیت ویرایش شد"}
    

@app.patch("/api/invoices/sell/{invoice_id}/status")
def update_invoice_status(invoice_id: int, status: dict, authorization: str | None = Header(default=None)):
    # این تابع فقط وضعیت پرداخت را تغییر می‌دهد و تاریخ ویرایش یا ویرایشگر را عوض نمی‌کند
    token = get_bearer_token(authorization)
    authenticate_token(token)
    
    is_paid = 1 if status.get("is_paid") else 0
    connection = get_connection()
    connection.execute("UPDATE sell_invoices SET is_paid = ? WHERE id = ?", (is_paid, invoice_id))
    connection.commit()
    connection.close()
    return {"message": "وضعیت پرداخت تغییر کرد."}
# -------------------------
# Parts
# -------------------------

@app.get("/api/parts")
def get_parts(
    q: str = Query(default=""),
    car: str = Query(default=""),
    in_stock: bool = Query(default=False)
):
    connection = get_connection()

    conditions = []
    parameters = []

    if q.strip():
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

    if in_stock:
        conditions.append("stock > 0")

    query = """
        SELECT id, part_number, name, compatible_cars, stock, is_genuine, price, price_updated_at, last_updated_by
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
        SELECT id, part_number, name, compatible_cars, stock, is_genuine, price, price_updated_at, last_updated_by
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
    is_genuine: bool = False
    price: float = 0.0


class PartUpdate(BaseModel):
    name: str
    part_number: str
    compatible_cars: str
    stock: int
    is_genuine: bool = False
    price: float | None = None


class PriceUpdate(BaseModel):
    price: float


class StockUpdate(BaseModel):
    stock: int


@app.post("/api/parts")
def add_part(
    data: PartCreate,
    authorization: str | None = Header(default=None)
):
    token = get_bearer_token(authorization)
    user = authenticate_token(token)

    part_number = data.part_number.strip()
    
    connection = get_connection()

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

    now_str = utc_now() if data.price > 0 else None

    cursor = connection.execute("""
        INSERT INTO parts (part_number, name, compatible_cars, stock, is_genuine, price, price_updated_at, last_updated_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        part_number,
        data.name.strip(),
        data.compatible_cars.strip(),
        data.stock,
        1 if data.is_genuine else 0,
        data.price,
        now_str,
        user["username"]
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
    user = authenticate_token(token)

    part_number = data.part_number.strip()
    connection = get_connection()

    existing = connection.execute("""
        SELECT price, price_updated_at FROM parts WHERE id = ?
    """, (part_id,)).fetchone()

    if existing is None:
        connection.close()
        raise HTTPException(status_code=404, detail="قطعه یافت نشد.")

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

    new_price = data.price if data.price is not None else existing["price"]

    if float(new_price) != float(existing["price"] or 0):
        price_updated_at = utc_now()
    else:
        price_updated_at = existing["price_updated_at"]

    connection.execute("""
        UPDATE parts
        SET part_number = ?, name = ?, compatible_cars = ?, stock = ?, is_genuine = ?, price = ?, price_updated_at = ?, last_updated_by = ?
        WHERE id = ?
    """, (
        part_number,
        data.name.strip(),
        data.compatible_cars.strip(),
        data.stock,
        1 if data.is_genuine else 0,
        new_price,
        price_updated_at,
        user["username"],
        part_id
    ))

    connection.commit()
    connection.close()

    return {"message": "اطلاعات قطعه با موفقیت به‌روزرسانی شد."}


@app.patch("/api/parts/{part_id}/price")
def update_price(
    part_id: int,
    data: PriceUpdate,
    authorization: str | None = Header(default=None)
):
    token = get_bearer_token(authorization)
    user = authenticate_token(token)

    connection = get_connection()
    existing = connection.execute("""
        SELECT price, price_updated_at FROM parts WHERE id = ?
    """, (part_id,)).fetchone()

    if existing is None:
        connection.close()
        raise HTTPException(status_code=404, detail="قطعه یافت نشد.")

    if float(data.price) != float(existing["price"] or 0):
        price_updated_at = utc_now()
    else:
        price_updated_at = existing["price_updated_at"]

    connection.execute("""
        UPDATE parts 
        SET price = ?, price_updated_at = ?, last_updated_by = ? 
        WHERE id = ?
    """, (data.price, price_updated_at, user["username"], part_id))

    connection.commit()
    connection.close()

    return {"message": "قیمت با موفقیت به‌روزرسانی شد."}


@app.patch("/api/parts/{part_id}/stock")
def update_stock(
    part_id: int,
    data: StockUpdate,
    authorization: str | None = Header(default=None)
):
    token = get_bearer_token(authorization)
    user = authenticate_token(token)

    connection = get_connection()
    connection.execute("""
        UPDATE parts 
        SET stock = ?, last_updated_by = ? 
        WHERE id = ?
    """, (data.stock, user["username"], part_id))

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
