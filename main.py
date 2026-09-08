import hashlib
import hmac
import re
import secrets
import io
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from typing import Optional
from fastapi.responses import Response
from weasyprint import HTML

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator

from database import get_connection

# ------------------------------------------------------------------------------
# Context Manager & Database Initialization
# ------------------------------------------------------------------------------

@contextmanager
def get_db():
    """Context manager for automatic connection lifecycle and transaction safety."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db_schema():
    """Initializes tables and high-performance search indexes."""
    with get_db() as conn:
        with conn.cursor() as cursor:
            # Users Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    must_change_password INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # Sessions Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
            """)

            # Parts Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS parts (
                    id SERIAL PRIMARY KEY,
                    part_number TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    compatible_cars TEXT NOT NULL,
                    stock INTEGER NOT NULL DEFAULT 0,
                    is_genuine INTEGER NOT NULL DEFAULT 0,
                    price REAL DEFAULT 0,
                    price_updated_at TEXT,
                    last_updated_by TEXT
                );
            """)

            # Sell Invoices
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sell_invoices (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    shamsi_date TEXT NOT NULL,
                    is_paid INTEGER NOT NULL DEFAULT 0,
                    deduct_inventory INTEGER NOT NULL DEFAULT 1,
                    update_price INTEGER NOT NULL DEFAULT 0,
                    creator_name TEXT,
                    last_editor_name TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # Sell Invoice Items
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sell_invoice_items (
                    id SERIAL PRIMARY KEY,
                    invoice_id INTEGER NOT NULL REFERENCES sell_invoices(id) ON DELETE CASCADE,
                    part_id INTEGER,
                    part_name TEXT NOT NULL,
                    part_number TEXT NOT NULL,
                    car TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    unit_price REAL NOT NULL,
                    total_price REAL NOT NULL
                );
            """)

            # Buy Invoices
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS buy_invoices (
                    id SERIAL PRIMARY KEY,
                    title TEXT NOT NULL,
                    shamsi_date TEXT NOT NULL,
                    is_paid INTEGER NOT NULL DEFAULT 0,
                    add_inventory INTEGER NOT NULL DEFAULT 1,
                    update_price INTEGER NOT NULL DEFAULT 0,
                    creator_name TEXT,
                    last_editor_name TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # Buy Invoice Items
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS buy_invoice_items (
                    id SERIAL PRIMARY KEY,
                    invoice_id INTEGER NOT NULL REFERENCES buy_invoices(id) ON DELETE CASCADE,
                    part_id INTEGER,
                    part_name TEXT NOT NULL,
                    part_number TEXT NOT NULL,
                    car TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    unit_price REAL NOT NULL,
                    total_price REAL NOT NULL
                );
            """)
            
            # High-Performance Query Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_parts_part_num ON parts(part_number);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_parts_name ON parts(name);")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern FastAPI Lifespan handler replacing deprecated @app.on_event."""
    init_db_schema()
    yield


app = FastAPI(title="Kore Yadak API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# ------------------------------------------------------------------------------
# Helpers & Utilities
# ------------------------------------------------------------------------------

USERNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{2,31}$")
PASSWORD_LETTER_RE = re.compile(r"[A-Za-z]")
PASSWORD_DIGIT_RE = re.compile(r"\d")


def utc_now() -> str:
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


# ------------------------------------------------------------------------------
# Authentication Dependency Injection
# ------------------------------------------------------------------------------

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="نیاز به ورود دارید."
        )

    token_hash = hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest()

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.username, u.must_change_password, u.password_hash
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = %s
            """, (token_hash,))
            user = cursor.fetchone()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="جلسه ورود معتبر نیست."
        )

    return user


# ------------------------------------------------------------------------------
# Pydantic Validation Models
# ------------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


class ChangeCredentialsRequest(BaseModel):
    current_password: str
    new_username: str
    new_password: str
    new_password_repeat: str

    @field_validator("new_username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not USERNAME_RE.fullmatch(v):
            raise ValueError(
                "نام کاربری باید 3 تا 32 کاراکتر باشد، با حرف انگلیسی شروع شود "
                "و فقط شامل حروف انگلیسی، عدد، نقطه، خط تیره یا زیرخط باشد."
            )
        return v

    @field_validator("new_password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not (8 <= len(v) <= 32):
            raise ValueError("رمز عبور باید بین 8 تا 32 کاراکتر باشد.")
        if not re.fullmatch(r"[A-Za-z0-9]+", v):
            raise ValueError("رمز عبور فقط می‌تواند شامل حروف انگلیسی و اعداد باشد.")
        if not PASSWORD_LETTER_RE.search(v):
            raise ValueError("رمز عبور باید حداقل یک حرف انگلیسی داشته باشد.")
        if not PASSWORD_DIGIT_RE.search(v):
            raise ValueError("رمز عبور باید حداقل یک عدد داشته باشد.")
        return v


class SellInvoiceItemBase(BaseModel):
    part_id: Optional[int] = None
    part_name: str
    part_number: str
    car: str
    quantity: int = Field(gt=0, description="Quantity must be greater than zero")
    unit_price: float
    total_price: float

class BuyInvoiceCreate(BaseModel):
    title: str
    shamsi_date: str
    is_paid: bool
    add_inventory: bool
    update_price: bool = False
    items: list[SellInvoiceItemBase]

class SellInvoiceCreate(BaseModel):
    title: str
    shamsi_date: str
    is_paid: bool
    deduct_inventory: bool
    update_price: bool = False
    items: list[SellInvoiceItemBase]


class PartCreate(BaseModel):
    name: str
    part_number: str
    compatible_cars: str
    stock: int = Field(ge=0, description="Stock cannot be negative")
    is_genuine: bool = False
    price: float = Field(ge=0.0, description="Price cannot be negative")


class PartUpdate(BaseModel):
    name: str
    part_number: str
    compatible_cars: str
    stock: int
    is_genuine: bool = False
    price: Optional[float] = None


class PriceUpdate(BaseModel):
    price: float


class StockUpdate(BaseModel):
    stock: int


# ------------------------------------------------------------------------------
# Routes: Static HTML Serving
# ------------------------------------------------------------------------------

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

@app.get("/login")
async def serve_login():
    return FileResponse("login.html")


# ------------------------------------------------------------------------------
# Routes: Authentication
# ------------------------------------------------------------------------------

@app.post("/api/auth/login")
def login(data: LoginRequest):
    username = data.username.strip()

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, username, password_hash, must_change_password
                FROM users
                WHERE username = %s
            """, (username,))
            user = cursor.fetchone()

            if user is None or not verify_password(data.password, user["password_hash"]):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="نام کاربری یا رمز عبور اشتباه است."
                )

            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

            cursor.execute("""
                INSERT INTO sessions (user_id, token_hash, created_at)
                VALUES (%s, %s, %s)
            """, (user["id"], token_hash, utc_now()))

    return {
        "token": raw_token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "must_change_password": bool(user["must_change_password"]),
        }
    }


@app.get("/api/auth/me")
def me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "must_change_password": bool(current_user["must_change_password"]),
    }


@app.post("/api/auth/change-credentials")
def change_credentials(
    data: ChangeCredentialsRequest,
    current_user: dict = Depends(get_current_user)
):
    if not verify_password(data.current_password, current_user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="رمز عبور فعلی اشتباه است."
        )

    if data.new_password != data.new_password_repeat:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="تکرار رمز عبور یکسان نیست."
        )

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id FROM users
                WHERE username = %s AND id != %s
            """, (data.new_username, current_user["id"]))
            if cursor.fetchone() is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="این نام کاربری قبلاً استفاده شده است."
                )

            new_hash = hash_password(data.new_password)
            cursor.execute("""
                UPDATE users
                SET username = %s,
                    password_hash = %s,
                    must_change_password = 0,
                    updated_at = %s
                WHERE id = %s
            """, (data.new_username, new_hash, utc_now(), current_user["id"]))

    return {
        "message": "اطلاعات حساب با موفقیت تغییر کرد.",
        "username": data.new_username
    }


@app.post("/api/auth/logout")
def logout(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if credentials and credentials.credentials:
        token_hash = hashlib.sha256(credentials.credentials.encode("utf-8")).hexdigest()
        with get_db() as conn:
            with conn.cursor() as cursor:
                cursor.execute("DELETE FROM sessions WHERE token_hash = %s", (token_hash,))

    return {"message": "خروج با موفقیت انجام شد."}


# ------------------------------------------------------------------------------
# Routes: Invoices (Sell)
# ------------------------------------------------------------------------------

@app.get("/api/invoices/sell")
def get_sell_invoices(current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM sell_invoices ORDER BY id DESC")
            return cursor.fetchall()


@app.get("/api/invoices/sell/{invoice_id}")
def get_sell_invoice(
    invoice_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM sell_invoices WHERE id = %s", (invoice_id,))
            invoice = cursor.fetchone()
            if not invoice:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="فاکتور یافت نشد")

            cursor.execute("SELECT * FROM sell_invoice_items WHERE invoice_id = %s", (invoice_id,))
            items = cursor.fetchall()

    result = dict(invoice)
    result["items"] = items
    return result


@app.post("/api/invoices/sell")
def create_sell_invoice(
    data: SellInvoiceCreate,
    current_user: dict = Depends(get_current_user)
):
    now = utc_now()
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO sell_invoices (
                    title, shamsi_date, is_paid, deduct_inventory, update_price,
                    creator_name, last_editor_name, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                data.title, data.shamsi_date, int(data.is_paid),
                int(data.deduct_inventory), int(data.update_price),
                current_user["username"], current_user["username"], now, now
            ))
            invoice_id = cursor.fetchone()["id"]

            for item in data.items:
                cursor.execute("""
                    INSERT INTO sell_invoice_items (
                        invoice_id, part_id, part_name, part_number, car, quantity, unit_price, total_price
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    invoice_id, item.part_id, item.part_name, item.part_number,
                    item.car, item.quantity, item.unit_price, item.total_price
                ))

                if data.deduct_inventory and item.part_id:
                    cursor.execute(
                        "UPDATE parts SET stock = GREATEST(0, stock - %s) WHERE id = %s",
                        (item.quantity, item.part_id)
                    )

                if data.update_price and item.part_id:
                    cursor.execute("""
                        UPDATE parts 
                        SET price = %s, price_updated_at = %s, last_updated_by = %s 
                        WHERE id = %s
                    """, (item.unit_price, now, current_user["username"], item.part_id))

    return {"message": "فاکتور با موفقیت ثبت شد", "id": invoice_id}


@app.put("/api/invoices/sell/{invoice_id}")
def update_sell_invoice(
    invoice_id: int,
    data: SellInvoiceCreate,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, deduct_inventory FROM sell_invoices WHERE id = %s", (invoice_id,))
            old_invoice = cursor.fetchone()
            if not old_invoice:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="فاکتور یافت نشد")

            if old_invoice["deduct_inventory"]:
                cursor.execute("SELECT part_id, quantity FROM sell_invoice_items WHERE invoice_id = %s AND part_id IS NOT NULL", (invoice_id,))
                for old_item in cursor.fetchall():
                    cursor.execute(
                        "UPDATE parts SET stock = stock + %s WHERE id = %s",
                        (old_item["quantity"], old_item["part_id"])
                    )

            cursor.execute("DELETE FROM sell_invoice_items WHERE invoice_id = %s", (invoice_id,))
            
            cursor.execute("""
                UPDATE sell_invoices 
                SET title = %s, shamsi_date = %s, is_paid = %s, deduct_inventory = %s,
                    update_price = %s, last_editor_name = %s, updated_at = %s
                WHERE id = %s
            """, (
                data.title, data.shamsi_date, int(data.is_paid),
                int(data.deduct_inventory), int(data.update_price),
                current_user["username"], utc_now(), invoice_id
            ))

            now = utc_now()
            for item in data.items:
                cursor.execute("""
                    INSERT INTO sell_invoice_items (
                        invoice_id, part_id, part_name, part_number, car, quantity, unit_price, total_price
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    invoice_id, item.part_id, item.part_name, item.part_number,
                    item.car, item.quantity, item.unit_price, item.total_price
                ))

                if data.deduct_inventory and item.part_id:
                    cursor.execute(
                        "UPDATE parts SET stock = GREATEST(0, stock - %s) WHERE id = %s",
                        (item.quantity, item.part_id)
                    )

                if data.update_price and item.part_id:
                    cursor.execute("""
                        UPDATE parts 
                        SET price = %s, price_updated_at = %s, last_updated_by = %s 
                        WHERE id = %s
                    """, (item.unit_price, now, current_user["username"], item.part_id))

    return {"message": "فاکتور با موفقیت ویرایش شد"}


@app.patch("/api/invoices/sell/{invoice_id}/status")
def update_invoice_status(
    invoice_id: int,
    status_data: dict,
    current_user: dict = Depends(get_current_user)
):
    is_paid = 1 if status_data.get("is_paid") else 0
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE sell_invoices SET is_paid = %s WHERE id = %s", (is_paid, invoice_id))

    return {"message": "وضعیت پرداخت تغییر کرد."}


@app.delete("/api/invoices/sell/{invoice_id}")
def delete_sell_invoice(
    invoice_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, deduct_inventory FROM sell_invoices WHERE id = %s", (invoice_id,))
            old_invoice = cursor.fetchone()
            if not old_invoice:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="فاکتور یافت نشد")

            if old_invoice["deduct_inventory"]:
                cursor.execute("SELECT part_id, quantity FROM sell_invoice_items WHERE invoice_id = %s AND part_id IS NOT NULL", (invoice_id,))
                for old_item in cursor.fetchall():
                    cursor.execute(
                        "UPDATE parts SET stock = stock + %s WHERE id = %s",
                        (old_item["quantity"], old_item["part_id"])
                    )

            cursor.execute("DELETE FROM sell_invoice_items WHERE invoice_id = %s", (invoice_id,))
            cursor.execute("DELETE FROM sell_invoices WHERE id = %s", (invoice_id,))

    return {"message": "فاکتور با موفقیت حذف شد."}

# ------------------------------------------------------------------------------
# Buy invoices
# ------------------------------------------------------------------------------

@app.get("/api/invoices/buy")
def get_buy_invoices(current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM buy_invoices ORDER BY id DESC")
            return cursor.fetchall()

@app.post("/api/invoices/buy")
def create_buy_invoice(
    data: BuyInvoiceCreate,
    current_user: dict = Depends(get_current_user)
):
    now = utc_now()
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO buy_invoices (
                    title, shamsi_date, is_paid, add_inventory, update_price,
                    creator_name, last_editor_name, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                data.title, data.shamsi_date, int(data.is_paid),
                int(data.add_inventory), int(data.update_price),
                current_user["username"], current_user["username"], now, now
            ))
            invoice_id = cursor.fetchone()["id"]

            for item in data.items:
                part_id = item.part_id

                if not part_id and item.part_number:
                    cursor.execute("SELECT id FROM parts WHERE part_number = %s", (item.part_number,))
                    db_part = cursor.fetchone()
                    if db_part:
                        part_id = db_part["id"]
                    else:
                        cursor.execute("""
                            INSERT INTO parts (part_number, name, compatible_cars, stock, last_updated_by)
                            VALUES (%s, %s, %s, 0, %s)
                            RETURNING id
                        """, (item.part_number, item.part_name, item.car, current_user["username"]))
                        part_id = cursor.fetchone()["id"]

                cursor.execute("""
                    INSERT INTO buy_invoice_items (
                        invoice_id, part_id, part_name, part_number, car, quantity, unit_price, total_price
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    invoice_id, part_id, item.part_name, item.part_number,
                    item.car, item.quantity, item.unit_price, item.total_price
                ))

                if data.add_inventory and part_id:
                    cursor.execute(
                        "UPDATE parts SET stock = stock + %s WHERE id = %s",
                        (item.quantity, part_id)
                    )

                if data.update_price and part_id:
                    cursor.execute("""
                        UPDATE parts 
                        SET price = %s, price_updated_at = %s, last_updated_by = %s 
                        WHERE id = %s
                    """, (item.unit_price, now, current_user["username"], part_id))

    return {"message": "فاکتور خرید با موفقیت ثبت شد", "id": invoice_id}

@app.get("/api/invoices/buy/{invoice_id}")
def get_buy_invoice(
    invoice_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM buy_invoices WHERE id = %s", (invoice_id,))
            invoice = cursor.fetchone()
            if not invoice:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="فاکتور یافت نشد")

            cursor.execute("SELECT * FROM buy_invoice_items WHERE invoice_id = %s", (invoice_id,))
            items = cursor.fetchall()

    result = dict(invoice)
    result["items"] = items
    return result


@app.put("/api/invoices/buy/{invoice_id}")
def update_buy_invoice(
    invoice_id: int,
    data: BuyInvoiceCreate,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, add_inventory FROM buy_invoices WHERE id = %s", (invoice_id,))
            old_invoice = cursor.fetchone()
            if not old_invoice:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="فاکتور یافت نشد")

            if old_invoice["add_inventory"]:
                cursor.execute("SELECT part_id, quantity FROM buy_invoice_items WHERE invoice_id = %s AND part_id IS NOT NULL", (invoice_id,))
                for old_item in cursor.fetchall():
                    cursor.execute(
                        "UPDATE parts SET stock = GREATEST(0, stock - %s) WHERE id = %s",
                        (old_item["quantity"], old_item["part_id"])
                    )

            cursor.execute("DELETE FROM buy_invoice_items WHERE invoice_id = %s", (invoice_id,))
            
            cursor.execute("""
                UPDATE buy_invoices 
                SET title = %s, shamsi_date = %s, is_paid = %s, add_inventory = %s,
                    update_price = %s, last_editor_name = %s, updated_at = %s
                WHERE id = %s
            """, (
                data.title, data.shamsi_date, int(data.is_paid),
                int(data.add_inventory), int(data.update_price),
                current_user["username"], utc_now(), invoice_id
            ))

            now = utc_now()
            for item in data.items:
                part_id = item.part_id
                
                if not part_id and item.part_number:
                    cursor.execute("SELECT id FROM parts WHERE part_number = %s", (item.part_number,))
                    db_part = cursor.fetchone()
                    if db_part:
                        part_id = db_part["id"]
                    else:
                        cursor.execute("""
                            INSERT INTO parts (part_number, name, compatible_cars, stock, last_updated_by)
                            VALUES (%s, %s, %s, 0, %s)
                            RETURNING id
                        """, (item.part_number, item.part_name, item.car, current_user["username"]))
                        part_id = cursor.fetchone()["id"]

                cursor.execute("""
                    INSERT INTO buy_invoice_items (
                        invoice_id, part_id, part_name, part_number, car, quantity, unit_price, total_price
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    invoice_id, part_id, item.part_name, item.part_number,
                    item.car, item.quantity, item.unit_price, item.total_price
                ))

                if data.add_inventory and part_id:
                    cursor.execute(
                        "UPDATE parts SET stock = stock + %s WHERE id = %s",
                        (item.quantity, part_id)
                    )

                if data.update_price and part_id:
                    cursor.execute("""
                        UPDATE parts 
                        SET price = %s, price_updated_at = %s, last_updated_by = %s 
                        WHERE id = %s
                    """, (item.unit_price, now, current_user["username"], part_id))

    return {"message": "فاکتور خرید با موفقیت ویرایش شد"}


@app.delete("/api/invoices/buy/{invoice_id}")
def delete_buy_invoice(
    invoice_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, add_inventory FROM buy_invoices WHERE id = %s", (invoice_id,))
            old_invoice = cursor.fetchone()
            if not old_invoice:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="فاکتور یافت نشد")

            if old_invoice["add_inventory"]:
                cursor.execute("SELECT part_id, quantity FROM buy_invoice_items WHERE invoice_id = %s AND part_id IS NOT NULL", (invoice_id,))
                for old_item in cursor.fetchall():
                    cursor.execute(
                        "UPDATE parts SET stock = GREATEST(0, stock - %s) WHERE id = %s",
                        (old_item["quantity"], old_item["part_id"])
                    )

            cursor.execute("DELETE FROM buy_invoice_items WHERE invoice_id = %s", (invoice_id,))
            cursor.execute("DELETE FROM buy_invoices WHERE id = %s", (invoice_id,))

    return {"message": "فاکتور خرید با موفقیت حذف شد."}


# ------------------------------------------------------------------------------
# Routes: Parts Management
# ------------------------------------------------------------------------------

@app.get("/api/parts")
def get_parts(
    q: str = Query(default=""),
    car: str = Query(default=""),
    in_stock: bool = Query(default=False)
):
    conditions = []
    parameters = []

    if q.strip():
        terms = q.strip().split()
        for term in terms:
            search = f"%{term}%"
            conditions.append("""
                (
                    part_number ILIKE %s
                    OR name ILIKE %s
                    OR compatible_cars ILIKE %s
                )
            """)
            parameters.extend([search, search, search])

    if car.strip():
        conditions.append("compatible_cars ILIKE %s")
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

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, parameters)
            return cursor.fetchall()


@app.get("/api/parts/{part_id}")
def get_part(part_id: int):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, part_number, name, compatible_cars, stock, is_genuine, price, price_updated_at, last_updated_by
                FROM parts WHERE id = %s
            """, (part_id,))
            row = cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Part not found")

    return dict(row)


@app.get("/api/cars")
def get_cars():
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT compatible_cars FROM parts")
            rows = cursor.fetchall()

    cars = set()
    for row in rows:
        text = row.get("compatible_cars") or ""
        for name in text.replace(",", "،").split("،"):
            clean_name = name.strip()
            if clean_name:
                cars.add(clean_name)

    return sorted(cars)


@app.post("/api/parts")
def add_part(
    data: PartCreate,
    current_user: dict = Depends(get_current_user)
):
    part_number = data.part_number.strip()

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT name FROM parts WHERE part_number = %s", (part_number,))
            duplicate = cursor.fetchone()
            if duplicate is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"این پارت نامبر قبلاً برای «{duplicate['name']}» ثبت شده است."
                )

            now_str = utc_now() if data.price > 0 else None
            cursor.execute("""
                INSERT INTO parts (part_number, name, compatible_cars, stock, is_genuine, price, price_updated_at, last_updated_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                part_number, data.name.strip(), data.compatible_cars.strip(),
                data.stock, 1 if data.is_genuine else 0, data.price,
                now_str, current_user["username"]
            ))
            new_id = cursor.fetchone()["id"]

    return {"message": "قطعه جدید با موفقیت اضافه شد.", "id": new_id}


@app.put("/api/parts/{part_id}")
def update_part(
    part_id: int,
    data: PartUpdate,
    current_user: dict = Depends(get_current_user)
):
    part_number = data.part_number.strip()
    safe_stock = max(0, data.stock)

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT price, price_updated_at FROM parts WHERE id = %s", (part_id,))
            existing = cursor.fetchone()
            if existing is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="قطعه یافت نشد.")

            cursor.execute("SELECT id FROM parts WHERE part_number = %s AND id != %s", (part_number, part_id))
            if cursor.fetchone() is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="این پارت نامبر متعلق به قطعه دیگری است."
                )

            new_price = data.price if data.price is not None else existing["price"]
            price_updated_at = (
                utc_now() if float(new_price or 0) != float(existing["price"] or 0)
                else existing["price_updated_at"]
            )

            cursor.execute("""
                UPDATE parts
                SET part_number = %s, name = %s, compatible_cars = %s, stock = %s,
                    is_genuine = %s, price = %s, price_updated_at = %s, last_updated_by = %s
                WHERE id = %s
            """, (
                part_number, data.name.strip(), data.compatible_cars.strip(),
                safe_stock, 1 if data.is_genuine else 0, new_price,
                price_updated_at, current_user["username"], part_id
            ))

    return {"message": "اطلاعات قطعه با موفقیت به‌روزرسانی شد."}


@app.patch("/api/parts/{part_id}/price")
def update_price(
    part_id: int,
    data: PriceUpdate,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT price, price_updated_at FROM parts WHERE id = %s", (part_id,))
            existing = cursor.fetchone()
            if existing is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="قطعه یافت نشد.")

            price_updated_at = (
                utc_now() if float(data.price) != float(existing["price"] or 0)
                else existing["price_updated_at"]
            )

            cursor.execute("""
                UPDATE parts 
                SET price = %s, price_updated_at = %s, last_updated_by = %s 
                WHERE id = %s
            """, (data.price, price_updated_at, current_user["username"], part_id))

    return {"message": "قیمت با موفقیت به‌روزرسانی شد."}


@app.patch("/api/parts/{part_id}/stock")
def update_stock(
    part_id: int,
    data: StockUpdate,
    current_user: dict = Depends(get_current_user)
):
    safe_stock = max(0, data.stock)

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE parts 
                SET stock = %s, last_updated_by = %s 
                WHERE id = %s
            """, (safe_stock, current_user["username"], part_id))

    return {"message": "موجودی با موفقیت تغییر کرد."}


@app.delete("/api/parts/{part_id}")
def delete_part(
    part_id: int,
    current_user: dict = Depends(get_current_user)
):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM parts WHERE id = %s", (part_id,))

    return {"message": "قطعه با موفقیت حذف شد."}

# ------------------------------------------------------------------------------
# Helpers: Report Data Fetcher
# ------------------------------------------------------------------------------

def fetch_report_dataset(report_type: str, from_date: str = "", to_date: str = "", keyword: str = ""):
    """تابع کمکی برای استخراج داده‌های گزارش براساس فیلترها از دیتابیس"""
    keyword_clean = f"%{keyword.strip()}%" if keyword.strip() else None

    with get_db() as conn:
        with conn.cursor() as cursor:
            # ۱. قطعات ناموجود در انبار
            if report_type == "out_of_stock":
                query = """
                    SELECT id, name, part_number, compatible_cars, stock, price, is_genuine
                    FROM parts
                    WHERE stock <= 0
                """
                params = []
                if keyword_clean:
                    query += " AND (name ILIKE %s OR part_number ILIKE %s OR compatible_cars ILIKE %s)"
                    params.extend([keyword_clean, keyword_clean, keyword_clean])
                query += " ORDER BY id DESC"
                cursor.execute(query, params)
                return cursor.fetchall()

            # ۱.۲. قطعات موجود در انبار
            elif report_type == "in_stock":
                query = """
                    SELECT id, name, part_number, compatible_cars, stock, price, is_genuine
                    FROM parts
                    WHERE stock > 0
                """
                params = []
                if keyword_clean:
                    query += " AND (name ILIKE %s OR part_number ILIKE %s OR compatible_cars ILIKE %s)"
                    params.extend([keyword_clean, keyword_clean, keyword_clean])
                query += " ORDER BY id DESC"
                cursor.execute(query, params)
                return cursor.fetchall()

            # ۲. فاکتورهای فروش تسویه نشده
            elif report_type == "unpaid_sell":
                query = """
                    SELECT s.id, s.title, s.shamsi_date AS date, s.is_paid, 'sell' AS invoice_kind,
                           COALESCE(SUM(i.total_price), 0) AS total_price
                    FROM sell_invoices s
                    LEFT JOIN sell_invoice_items i ON s.id = i.invoice_id
                    WHERE s.is_paid = 0
                """
                params = []
                if from_date.strip():
                    query += " AND s.shamsi_date >= %s"
                    params.append(from_date.strip())
                if to_date.strip():
                    query += " AND s.shamsi_date <= %s"
                    params.append(to_date.strip())
                if keyword_clean:
                    query += " AND (s.title ILIKE %s OR s.creator_name ILIKE %s OR i.part_name ILIKE %s)"
                    params.extend([keyword_clean, keyword_clean, keyword_clean])
                query += " GROUP BY s.id ORDER BY s.id DESC"
                cursor.execute(query, params)
                return cursor.fetchall()

            # ۲.۲. فاکتورهای فروش تسویه شده
            elif report_type == "paid_sell":
                query = """
                    SELECT s.id, s.title, s.shamsi_date AS date, s.is_paid, 'sell' AS invoice_kind,
                           COALESCE(SUM(i.total_price), 0) AS total_price
                    FROM sell_invoices s
                    LEFT JOIN sell_invoice_items i ON s.id = i.invoice_id
                    WHERE s.is_paid = 1
                """
                params = []
                if from_date.strip():
                    query += " AND s.shamsi_date >= %s"
                    params.append(from_date.strip())
                if to_date.strip():
                    query += " AND s.shamsi_date <= %s"
                    params.append(to_date.strip())
                if keyword_clean:
                    query += " AND (s.title ILIKE %s OR s.creator_name ILIKE %s OR i.part_name ILIKE %s)"
                    params.extend([keyword_clean, keyword_clean, keyword_clean])
                query += " GROUP BY s.id ORDER BY s.id DESC"
                cursor.execute(query, params)
                return cursor.fetchall()

            # ۳. فاکتورهای خرید تسویه نشده
            elif report_type == "unpaid_buy":
                query = """
                    SELECT b.id, b.title, b.shamsi_date AS date, b.is_paid, 'buy' AS invoice_kind,
                           COALESCE(SUM(i.total_price), 0) AS total_price
                    FROM buy_invoices b
                    LEFT JOIN buy_invoice_items i ON b.id = i.invoice_id
                    WHERE b.is_paid = 0
                """
                params = []
                if from_date.strip():
                    query += " AND b.shamsi_date >= %s"
                    params.append(from_date.strip())
                if to_date.strip():
                    query += " AND b.shamsi_date <= %s"
                    params.append(to_date.strip())
                if keyword_clean:
                    query += " AND (b.title ILIKE %s OR b.creator_name ILIKE %s OR i.part_name ILIKE %s)"
                    params.extend([keyword_clean, keyword_clean, keyword_clean])
                query += " GROUP BY b.id ORDER BY b.id DESC"
                cursor.execute(query, params)
                return cursor.fetchall()

            # ۳.۲. فاکتورهای خرید تسویه شده
            elif report_type == "paid_buy":
                query = """
                    SELECT b.id, b.title, b.shamsi_date AS date, b.is_paid, 'buy' AS invoice_kind,
                           COALESCE(SUM(i.total_price), 0) AS total_price
                    FROM buy_invoices b
                    LEFT JOIN buy_invoice_items i ON b.id = i.invoice_id
                    WHERE b.is_paid = 1
                """
                params = []
                if from_date.strip():
                    query += " AND b.shamsi_date >= %s"
                    params.append(from_date.strip())
                if to_date.strip():
                    query += " AND b.shamsi_date <= %s"
                    params.append(to_date.strip())
                if keyword_clean:
                    query += " AND (b.title ILIKE %s OR b.creator_name ILIKE %s OR i.part_name ILIKE %s)"
                    params.extend([keyword_clean, keyword_clean, keyword_clean])
                query += " GROUP BY b.id ORDER BY b.id DESC"
                cursor.execute(query, params)
                return cursor.fetchall()

            # ۴. فاکتورهای تسویه شده (کل)
            elif report_type == "paid_all":
                query = """
                    SELECT 'فروش' AS invoice_type, 'sell' AS invoice_kind, s.id, s.title, s.shamsi_date AS date, s.is_paid,
                           COALESCE(SUM(i.total_price), 0) AS total_price
                    FROM sell_invoices s
                    LEFT JOIN sell_invoice_items i ON s.id = i.invoice_id
                    WHERE s.is_paid = 1
                """
                params1 = []
                if from_date.strip():
                    query += " AND s.shamsi_date >= %s"
                    params1.append(from_date.strip())
                if to_date.strip():
                    query += " AND s.shamsi_date <= %s"
                    params1.append(to_date.strip())
                if keyword_clean:
                    query += " AND (s.title ILIKE %s OR s.creator_name ILIKE %s)"
                    params1.extend([keyword_clean, keyword_clean])
                query += " GROUP BY s.id"

                query += """
                    UNION ALL
                    SELECT 'خرید' AS invoice_type, 'buy' AS invoice_kind, b.id, b.title, b.shamsi_date AS date, b.is_paid,
                           COALESCE(SUM(i.total_price), 0) AS total_price
                    FROM buy_invoices b
                    LEFT JOIN buy_invoice_items i ON b.id = i.invoice_id
                    WHERE b.is_paid = 1
                """
                params2 = []
                if from_date.strip():
                    query += " AND b.shamsi_date >= %s"
                    params2.append(from_date.strip())
                if to_date.strip():
                    query += " AND b.shamsi_date <= %s"
                    params2.append(to_date.strip())
                if keyword_clean:
                    query += " AND (b.title ILIKE %s OR b.creator_name ILIKE %s)"
                    params2.extend([keyword_clean, keyword_clean])
                query += " GROUP BY b.id ORDER BY date DESC, id DESC"

                cursor.execute(query, params1 + params2)
                return cursor.fetchall()

    return []


def generate_single_invoice_pdf_bytes(invoice_type: str, invoice_id: int) -> bytes:
    """تولید بایت‌های فایل PDF رسمی یک فاکتور مجزا (فروش یا خرید)"""
    table_name = "sell_invoices" if invoice_type == "sell" else "buy_invoices"
    items_table = "sell_invoice_items" if invoice_type == "sell" else "buy_invoice_items"
    type_title = "فاکتور فروش" if invoice_type == "sell" else "فاکتور خرید"

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT * FROM {table_name} WHERE id = %s", (invoice_id,))
            invoice = cursor.fetchone()
            if not invoice:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="فاکتور یافت نشد")

            cursor.execute(f"""
                SELECT i.*, COALESCE(p.is_genuine, 0) AS is_genuine 
                FROM {items_table} i 
                LEFT JOIN parts p ON i.part_id = p.id 
                WHERE i.invoice_id = %s
            """, (invoice_id,))
            items = cursor.fetchall()

    total_sum = sum(item.get('total_price', 0) for item in items)
    status_text = "تسویه شده" if invoice.get('is_paid') else "تسویه نشده"
    status_class = "badge-paid" if invoice.get('is_paid') else "badge-unpaid"

    item_rows = ""
    for idx, item in enumerate(items, 1):
        is_gen = item.get('is_genuine', 0)
        gen_badge = '<span class="badge badge-genuine">اصلی (GENUINE)</span>' if is_gen else '<span class="badge badge-normal">متفرقه</span>'
        
        item_rows += f"""
        <tr>
            <td style="text-align: center;">{idx}</td>
            <td><b>{item.get('part_name', '')}</b> {gen_badge}</td>
            <td><code dir="ltr">{item.get('part_number', '')}</code></td>
            <td>{item.get('car', '')}</td>
            <td style="text-align: center;">{item.get('quantity', 0)}</td>
            <td style="text-align: left;">{item.get('unit_price', 0):,.0f} تومان</td>
            <td style="text-align: left;"><b>{item.get('total_price', 0):,.0f} تومان</b></td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
        <meta charset="utf-8">
        <style>
            @import url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css');
            
            @page {{
                size: A4 portrait;
                margin: 12mm;
                @bottom-center {{
                    content: "صفحه " counter(page) " از " counter(pages);
                    font-size: 8pt;
                    font-family: 'Vazirmatn', sans-serif;
                    color: #64748b;
                }}
            }}
            body {{
                font-family: 'Vazirmatn', sans-serif;
                direction: rtl;
                color: #0f172a;
                margin: 0;
                padding: 0;
                font-size: 9.5pt;
            }}
            .header {{
                border-bottom: 2px solid #4f46e5;
                padding-bottom: 12px;
                margin-bottom: 15px;
            }}
            .header h1 {{
                margin: 0 0 4px 0;
                font-size: 18pt;
                color: #312e81;
            }}
            .header p {{
                margin: 0;
                font-size: 9pt;
                color: #64748b;
            }}
            .invoice-details {{
                width: 100%;
                margin-bottom: 15px;
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 10px 14px;
                box-sizing: border-box;
            }}
            .details-grid {{
                display: table;
                width: 100%;
            }}
            .details-row {{
                display: table-row;
            }}
            .details-cell {{
                display: table-cell;
                padding: 4px 8px;
                font-size: 9pt;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 10px;
            }}
            th {{
                background-color: #4f46e5;
                color: white;
                font-weight: bold;
                padding: 8px;
                text-align: right;
                font-size: 9.5pt;
            }}
            td {{
                padding: 8px;
                border-bottom: 1px solid #e2e8f0;
                font-size: 9pt;
            }}
            tr:nth-child(even) {{
                background-color: #f8fafc;
            }}
            .badge {{
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 7.5pt;
                font-weight: bold;
                display: inline-block;
            }}
            .badge-paid {{ background: #dcfce7; color: #15803d; }}
            .badge-unpaid {{ background: #fef3c7; color: #b45309; }}
            .badge-genuine {{ background: #fef3c7; color: #b45309; border: 1px solid #f59e0b; }}
            .badge-normal {{ background: #f1f5f9; color: #64748b; }}

            .summary-box {{
                margin-top: 20px;
                width: 100%;
                border-top: 2px solid #e2e8f0;
                padding-top: 12px;
            }}
            .total-row {{
                text-align: left;
                font-size: 12pt;
                font-weight: bold;
                color: #1e1b4b;
                padding: 10px;
                background: #e0e7ff;
                border-radius: 6px;
            }}
            .footer-notes {{
                margin-top: 40px;
                display: table;
                width: 100%;
                text-align: center;
                font-size: 9.5pt;
                color: #64748b;
            }}
            .signature-box {{
                display: table-cell;
                width: 50%;
                padding-top: 30px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>کُره یدک | {type_title}</h1>
            <p>سامانه تخصصی مدیریت قطعات خودروهای کره‌ای</p>
        </div>

        <div class="invoice-details">
            <div class="details-grid">
                <div class="details-row">
                    <div class="details-cell"><b>شماره فاکتور:</b> #{invoice.get('id')}</div>
                    <div class="details-cell"><b>عنوان / طرف حساب:</b> {invoice.get('title', '')}</div>
                    <div class="details-cell"><b>تاریخ فاکتور:</b> {invoice.get('shamsi_date', '')}</div>
                    <div class="details-cell"><b>وضعیت پرداخت:</b> <span class="badge {status_class}">{status_text}</span></div>
                </div>
                <div class="details-row">
                    <div class="details-cell"><b>ثبت کننده:</b> {invoice.get('creator_name', 'سیستم')}</div>
                    <div class="details-cell"><b>آخرین ویرایش:</b> {invoice.get('last_editor_name', '-')}</div>
                </div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th style="width: 5%; text-align: center;">#</th>
                    <th style="width: 30%;">نام قطعه / اصالت</th>
                    <th style="width: 20%;">پارت نامبر</th>
                    <th style="width: 15%;">خودرو</th>
                    <th style="width: 8%; text-align: center;">تعداد</th>
                    <th style="width: 11%; text-align: left;">قیمت واحد</th>
                    <th style="width: 11%; text-align: left;">قیمت کل</th>
                </tr>
            </thead>
            <tbody>
                {item_rows if item_rows else '<tr><td colspan="7" style="text-align:center;">هیچ اقلامی در این فاکتور ثبت نشده است.</td></tr>'}
            </tbody>
        </table>

        <div class="summary-box">
            <div class="total-row">
                مبلغ کل فاکتور: {total_sum:,.0f} تومان
            </div>
        </div>

        <div class="footer-notes">
            <div class="signature-box">امضاء و مهر صادرکننده</div>
            <div class="signature-box">امضاء و تایید تحویل‌گیرنده</div>
        </div>
    </body>
    </html>
    """

    return HTML(string=html_content).write_pdf()


# ------------------------------------------------------------------------------
# Routes: Reports API
# ------------------------------------------------------------------------------

@app.get("/api/reports/data")
def get_report_data(
    type: str = Query(default="out_of_stock"),
    from_date: str = Query(default="", alias="from"),
    to_date: str = Query(default="", alias="to"),
    keyword: str = Query(default=""),
    current_user: dict = Depends(get_current_user)
):
    """دریافت لیست داده‌های گزارش برای نمایش در جدول پیش‌نمایش فرانت‌اند"""
    return fetch_report_dataset(type, from_date, to_date, keyword)


@app.get("/api/reports/pdf")
def generate_report_pdf(
    type: str = Query(default="out_of_stock"),
    from_date: str = Query(default="", alias="from"),
    to_date: str = Query(default="", alias="to"),
    keyword: str = Query(default=""),
    current_user: dict = Depends(get_current_user)
):
    """تولید و استریم مستقیم فایل PDF گزارش با استفاده از WeasyPrint"""
    data = fetch_report_dataset(type, from_date, to_date, keyword)

    # عناوین فارسی انواع گزارش
    report_titles = {
        "out_of_stock": "گزارش قطعات ناموجود در انبار",
        "in_stock": "گزارش قطعات موجود در انبار",
        "unpaid_sell": "گزارش فاکتورهای فروش تسویه نشده",
        "paid_sell": "گزارش فاکتورهای فروش تسویه شده",
        "unpaid_buy": "گزارش فاکتورهای خرید تسویه نشده",
        "paid_buy": "گزارش فاکتورهای خرید تسویه شده",
        "paid_all": "گزارش فاکتورهای تسویه شده (کل)"
    }

    report_title = report_titles.get(type, "گزارش سیستم")

    # ساخت سطر‌های جدول HTML
    table_rows = ""
    total_sum = 0

    if type in ["out_of_stock", "in_stock"]:
        for idx, item in enumerate(data, 1):
            is_gen = item.get('is_genuine', 0)
            gen_badge = '<span class="badge badge-genuine">اصلی (GENUINE)</span>' if is_gen else '<span class="badge badge-normal">متفرقه</span>'
            stock_color = '#dc2626' if item.get('stock', 0) <= 0 else '#16a34a'
            
            table_rows += f"""
            <tr>
                <td>{idx}</td>
                <td><b>{item.get('name', '')}</b> {gen_badge}</td>
                <td>{item.get('part_number', '')} / {item.get('compatible_cars', '')}</td>
                <td style="color: {stock_color}; font-weight: bold;">{item.get('stock', 0)} عدد</td>
                <td>{item.get('price', 0):,.0f} تومان</td>
            </tr>
            """
    else:
        for idx, item in enumerate(data, 1):
            price = item.get('total_price', 0)
            total_sum += price
            status_text = "تسویه شده" if item.get('is_paid') else "تسویه نشده"
            status_class = "badge-paid" if item.get('is_paid') else "badge-unpaid"
            inv_type_text = f" ({item.get('invoice_type')})" if item.get('invoice_type') else ""
            
            table_rows += f"""
            <tr>
                <td>{idx}</td>
                <td><b>{item.get('title', '')}</b>{inv_type_text}</td>
                <td>{item.get('date', '')}</td>
                <td><span class="badge {status_class}">{status_text}</span></td>
                <td><b>{price:,.0f} تومان</b></td>
            </tr>
            """

    # هدر‌های جدول
    if type in ["out_of_stock", "in_stock"]:
        table_headers = """
            <th>ردیف</th>
            <th>نام قطعه / اصالت</th>
            <th>پارت نامبر / خودرو</th>
            <th>موجودی</th>
            <th>آخرین قیمت</th>
        """
    else:
        table_headers = """
            <th>ردیف</th>
            <th>عنوان / مشخصات</th>
            <th>تاریخ</th>
            <th>وضعیت</th>
            <th>مبلغ کل</th>
        """

    # جمع کل برای گزارشات مالی
    total_section = ""
    if type not in ["out_of_stock", "in_stock"]:
        total_section = f"""
        <div class="total-box">
            مجموع مبالغ این گزارش: {total_sum:,.0f} تومان
        </div>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head>
        <meta charset="utf-8">
        <style>
            @import url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css');
            
            @page {{
                size: A4 portrait;
                margin: 12mm;
                @bottom-center {{
                    content: "صفحه " counter(page) " از " counter(pages);
                    font-size: 8pt;
                    font-family: 'Vazirmatn', sans-serif;
                    color: #64748b;
                }}
            }}
            body {{
                font-family: 'Vazirmatn', sans-serif;
                direction: rtl;
                color: #0f172a;
                margin: 0;
                padding: 0;
                font-size: 10pt;
            }}
            .header {{
                text-align: center;
                border-bottom: 2px solid #4f46e5;
                padding-bottom: 8px;
                margin-bottom: 15px;
            }}
            .header h1 {{
                margin: 0 0 4px 0;
                font-size: 16pt;
                color: #312e81;
            }}
            .header p {{
                margin: 0;
                font-size: 9pt;
                color: #64748b;
            }}
            .meta-info {{
                background: #f8fafc;
                padding: 8px 12px;
                border-radius: 6px;
                border: 1px solid #e2e8f0;
                margin-bottom: 15px;
                font-size: 8.5pt;
                color: #334155;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th {{
                background-color: #4f46e5;
                color: white;
                font-weight: bold;
                padding: 7px 8px;
                text-align: right;
                font-size: 9pt;
            }}
            td {{
                padding: 7px 8px;
                border-bottom: 1px solid #e2e8f0;
                font-size: 8.5pt;
            }}
            tr:nth-child(even) {{
                background-color: #f8fafc;
            }}
            .badge {{
                padding: 2px 6px;
                border-radius: 4px;
                font-size: 7.5pt;
                font-weight: bold;
                display: inline-block;
            }}
            .badge-paid {{ background: #dcfce7; color: #15803d; }}
            .badge-unpaid {{ background: #fef3c7; color: #b45309; }}
            .badge-genuine {{ background: #fef3c7; color: #b45309; border: 1px solid #f59e0b; }}
            .badge-normal {{ background: #f1f5f9; color: #64748b; }}
            .total-box {{
                margin-top: 15px;
                text-align: left;
                font-size: 11pt;
                font-weight: bold;
                color: #1e1b4b;
                padding: 10px;
                background: #e0e7ff;
                border-radius: 6px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>کُره یدک | {report_title}</h1>
            <p>سیستم مدیریت انبار و فاکتورها</p>
        </div>

        <div class="meta-info">
            <span><b>تعداد موارد:</b> {len(data)} مورد</span> | 
            <span><b>از تاریخ:</b> {from_date if from_date else 'ابتدا'}</span> | 
            <span><b>تا تاریخ:</b> {to_date if to_date else 'اکنون'}</span>
        </div>

        <table>
            <thead>
                <tr>
                    {table_headers}
                </tr>
            </thead>
            <tbody>
                {table_rows if table_rows else '<tr><td colspan="5" style="text-align:center;">موردی یافت نشد.</td></tr>'}
            </tbody>
        </table>

        {total_section}
    </body>
    </html>
    """

    pdf_bytes = HTML(string=html_content).write_pdf()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=Report_{type}.pdf"
        }
    )


# ------------------------------------------------------------------------------
# Routes: Single Invoice PDF Exports
# ------------------------------------------------------------------------------

@app.get("/api/invoices/sell/{invoice_id}/pdf")
def generate_sell_invoice_pdf(
    invoice_id: int,
    current_user: dict = Depends(get_current_user)
):
    """تولید فایل PDF تک‌فاکتور فروش با تمام جزئیات و نشان اصلی بودن قطعات"""
    pdf_bytes = generate_single_invoice_pdf_bytes("sell", invoice_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=Invoice_Sell_{invoice_id}.pdf"
        }
    )


@app.get("/api/invoices/buy/{invoice_id}/pdf")
def generate_buy_invoice_pdf(
    invoice_id: int,
    current_user: dict = Depends(get_current_user)
):
    """تولید فایل PDF تک‌فاکتور خرید با تمام جزئیات و نشان اصلی بودن قطعات"""
    pdf_bytes = generate_single_invoice_pdf_bytes("buy", invoice_id)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=Invoice_Buy_{invoice_id}.pdf"
        }
    )
