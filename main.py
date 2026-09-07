import hashlib
import hmac
import re
import secrets
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from typing import Optional

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
                        "UPDATE parts SET stock = stock - %s WHERE id = %s",
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
            cursor.execute("SELECT id FROM sell_invoices WHERE id = %s", (invoice_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="فاکتور یافت نشد")

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
            cursor.execute("SELECT id FROM sell_invoices WHERE id = %s", (invoice_id,))
            if not cursor.fetchone():
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="فاکتور یافت نشد")

            cursor.execute("DELETE FROM sell_invoice_items WHERE invoice_id = %s", (invoice_id,))
            cursor.execute("DELETE FROM sell_invoices WHERE id = %s", (invoice_id,))

    return {"message": "فاکتور با موفقیت حذف شد."}


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
                data.stock, 1 if data.is_genuine else 0, new_price,
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
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                UPDATE parts 
                SET stock = %s, last_updated_by = %s 
                WHERE id = %s
            """, (data.stock, current_user["username"], part_id))

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
