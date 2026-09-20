import hashlib
import logging
import hmac
import re
import secrets
import io
import os
import smtplib
from pathlib import Path
from uuid import uuid4
from email.message import EmailMessage
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi.responses import Response
from weasyprint import HTML

from fastapi import Cookie, Depends, FastAPI, File, HTTPException, Query, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, field_validator

from database import get_connection

logger = logging.getLogger("koreyadak.mail")

def _load_local_env():
    """Load a small .env file for local development without overriding real environment variables."""
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent / ".env",
        Path(__file__).resolve().parent.parent / ".env",
    ]
    seen = set()
    for path in candidates:
        path = path.resolve()
        if path in seen or not path.is_file():
            continue
        seen.add(path)
        try:
            for raw in path.read_text(encoding="utf-8").splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[7:].lstrip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if not key or key in os.environ:
                    continue
                if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}:
                    value = value[1:-1]
                os.environ[key] = value
        except OSError:
            continue

_load_local_env()

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
            # Users Table (kept backward-compatible with existing installations)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    email TEXT,
                    phone TEXT,
                    email_verified INTEGER NOT NULL DEFAULT 0,
                    role TEXT NOT NULL DEFAULT 'customer',
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
            """)

            # Safe migration for databases created by older versions.
            for statement in (
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS first_name TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_name TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS email TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone TEXT",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'customer'",
            ):
                cursor.execute(statement)

            # The original three admin accounts are kept as administrators.
            # Everyone else remains a normal customer. Matching is case-insensitive
            # and scoped to usernames so registration cannot accidentally gain admin access.
            cursor.execute("""
                UPDATE users
                SET role = CASE
                    WHEN LOWER(username) IN ('erfan', 'alireza', 'behnam') THEN 'admin'
                    ELSE COALESCE(NULLIF(role, ''), 'customer')
                END
            """)

            # Sessions Table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT
                );
            """)
            cursor.execute("ALTER TABLE sessions ADD COLUMN IF NOT EXISTS expires_at TEXT")

            # Email OTP verification records. Codes are stored only as hashes.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS email_verifications (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL,
                    code_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    verified_at TEXT,
                    used_at TEXT
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_email_verifications_email ON email_verifications(LOWER(email), created_at DESC);")

            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email ON users(email) WHERE email IS NOT NULL AND email <> '';")
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_phone ON users(phone) WHERE phone IS NOT NULL AND phone <> '';")

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
                    last_updated_by TEXT,
                    image_url TEXT,
                    description TEXT,
                    brand TEXT,
                    category TEXT,
                    specifications TEXT,
                    is_featured INTEGER NOT NULL DEFAULT 0,
                    home_order INTEGER NOT NULL DEFAULT 0
                );
            """)

            # Safe migration for existing databases.
            for statement in (
                "ALTER TABLE parts ADD COLUMN IF NOT EXISTS image_url TEXT",
                "ALTER TABLE parts ADD COLUMN IF NOT EXISTS description TEXT",
                "ALTER TABLE parts ADD COLUMN IF NOT EXISTS brand TEXT",
                "ALTER TABLE parts ADD COLUMN IF NOT EXISTS category TEXT",
                "ALTER TABLE parts ADD COLUMN IF NOT EXISTS specifications TEXT",
                "ALTER TABLE parts ADD COLUMN IF NOT EXISTS is_featured INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE parts ADD COLUMN IF NOT EXISTS home_order INTEGER NOT NULL DEFAULT 0",
            ):
                cursor.execute(statement)

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_parts_brand ON parts(brand)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_parts_category ON parts(category)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_parts_featured ON parts(is_featured, home_order)")

            # Persistent cart for authenticated users. Guest carts stay local and
            # are merged into this table after login.
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cart_items (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    part_id INTEGER NOT NULL REFERENCES parts(id) ON DELETE CASCADE,
                    quantity INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(user_id, part_id)
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_cart_user ON cart_items(user_id, updated_at DESC)")

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

MEDIA_ROOT = Path("media")
PART_MEDIA_ROOT = MEDIA_ROOT / "parts"
PART_MEDIA_ROOT.mkdir(parents=True, exist_ok=True)
app.mount("/media", StaticFiles(directory=str(MEDIA_ROOT)), name="media")

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


def _smtp_config():
    username = (os.getenv("GMAIL_ADDRESS") or os.getenv("SMTP_USERNAME") or "").strip()
    password = (os.getenv("GMAIL_APP_PASSWORD") or os.getenv("SMTP_PASSWORD") or "").replace(" ", "").strip()
    host = (os.getenv("SMTP_HOST") or "smtp.gmail.com").strip()
    from_address = (os.getenv("SMTP_FROM") or username).strip()
    try:
        port = int(os.getenv("SMTP_PORT") or ("465" if os.getenv("SMTP_USE_SSL", "").lower() in {"1", "true", "yes", "on"} else "587"))
    except ValueError:
        port = 587
    use_ssl = os.getenv("SMTP_USE_SSL", "").lower() in {"1", "true", "yes", "on"} or port == 465
    return username, password, host, port, use_ssl, from_address


def _send_email_message(message: EmailMessage):
    username, password, host, port, use_ssl, _ = _smtp_config()
    if not username:
        raise HTTPException(status_code=503, detail="GMAIL_ADDRESS یا SMTP_USERNAME روی سرور تنظیم نشده است.")
    if not password:
        raise HTTPException(status_code=503, detail="GMAIL_APP_PASSWORD یا SMTP_PASSWORD روی سرور تنظیم نشده است.")

    candidates = [(host, port, use_ssl)]
    # Gmail commonly works on 587/STARTTLS or 465/SSL. If the default Gmail
    # transport cannot connect, try the other standard transport automatically.
    if host == "smtp.gmail.com" and port == 587 and not use_ssl:
        candidates.append((host, 465, True))

    last_error = None
    for candidate_host, candidate_port, candidate_ssl in candidates:
        try:
            if candidate_ssl:
                with smtplib.SMTP_SSL(candidate_host, candidate_port, timeout=20) as smtp:
                    smtp.ehlo()
                    smtp.login(username, password)
                    smtp.send_message(message)
            else:
                with smtplib.SMTP(candidate_host, candidate_port, timeout=20) as smtp:
                    smtp.ehlo()
                    smtp.starttls()
                    smtp.ehlo()
                    smtp.login(username, password)
                    smtp.send_message(message)
            logger.info("Verification email sent successfully via %s:%s", candidate_host, candidate_port)
            return
        except smtplib.SMTPAuthenticationError as exc:
            logger.exception("SMTP authentication failed for %s", username)
            raise HTTPException(
                status_code=502,
                detail="احراز هویت Gmail انجام نشد. برای Gmail باید ۲مرحله‌ای فعال باشد و App Password وارد شود."
            ) from exc
        except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
            logger.exception("SMTP rejected sender/recipient")
            raise HTTPException(status_code=502, detail="سرور ایمیل فرستنده یا گیرنده را قبول نکرد.") from exc
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, TimeoutError, OSError, smtplib.SMTPException) as exc:
            last_error = exc
            logger.warning("SMTP attempt failed via %s:%s: %s", candidate_host, candidate_port, exc)
            continue

    logger.warning("All SMTP attempts failed: %s", last_error)
    raise HTTPException(status_code=502, detail="ارتباط با سرور ایمیل برقرار نشد. تنظیمات SMTP یا دسترسی شبکه سرور را بررسی کن.")


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

def _user_from_token(token: str) -> dict:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT u.id, u.username, u.first_name, u.last_name, u.email, u.phone,
                       u.email_verified, u.role, u.must_change_password, u.password_hash
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = %s
                  AND (s.expires_at IS NULL OR s.expires_at > %s)
            """, (token_hash, utc_now()))
            user = cursor.fetchone()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="جلسه ورود معتبر نیست."
        )
    return user


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> dict:
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="نیاز به ورود دارید."
        )
    return _user_from_token(credentials.credentials)


def get_page_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    page_token: Optional[str] = Cookie(default=None, alias="koreyadak_page_token"),
) -> dict:
    """Authenticate HTML page navigation using Authorization or the login page cookie."""
    token = credentials.credentials if credentials and credentials.credentials else page_token
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="نیاز به ورود دارید."
        )
    return _user_from_token(token)


def get_admin_page_user(current_user: dict = Depends(get_page_user)) -> dict:
    """Admin-only authentication for direct HTML page navigation."""
    if (current_user.get("role") or "customer") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="این حساب دسترسی به پنل مدیریت ندارد."
        )
    return current_user


def get_admin_user(current_user: dict = Depends(get_current_user)) -> dict:
    """Allows only administrator accounts to access management features."""
    if (current_user.get("role") or "customer") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="این حساب دسترسی به پنل مدیریت ندارد."
        )
    return current_user


# ------------------------------------------------------------------------------
# Pydantic Validation Models
# ------------------------------------------------------------------------------

class LoginRequest(BaseModel):
    # New frontend contract
    identifier: Optional[str] = None
    password: str
    remember_me: bool = False

    # Legacy frontend/backward compatibility
    username: Optional[str] = None

    def normalized_identifier(self) -> str:
        value = (self.identifier or self.username or "").strip()
        if not value:
            raise ValueError("نام کاربری یا ایمیل الزامی است.")
        return value


class RegisterRequest(BaseModel):
    first_name: str
    last_name: str
    username: str
    email: str
    phone: str
    password: str
    password_repeat: Optional[str] = None
    email_verified: bool = False  # legacy field; server no longer trusts it
    email_verification_id: Optional[int] = None
    terms_accepted: bool = True

    @field_validator("first_name", "last_name")
    @classmethod
    def validate_person_name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 80:
            raise ValueError("نام و نام خانوادگی معتبر نیست.")
        return v

    @field_validator("username")
    @classmethod
    def validate_register_username(cls, v: str) -> str:
        v = v.strip()
        if not USERNAME_RE.fullmatch(v):
            raise ValueError("نام کاربری باید 3 تا 32 کاراکتر باشد و با حرف انگلیسی شروع شود.")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", v):
            raise ValueError("ایمیل معتبر نیست.")
        if len(v) > 254:
            raise ValueError("ایمیل معتبر نیست.")
        return v

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: str) -> str:
        v = re.sub(r"[\s-]+", "", v)
        if not re.fullmatch(r"09\d{9}", v):
            raise ValueError("شماره موبایل باید به شکل 0912xxxxxxx باشد.")
        return v

    @field_validator("password")
    @classmethod
    def validate_register_password(cls, v: str) -> str:
        if not (8 <= len(v) <= 32):
            raise ValueError("رمز عبور باید بین 8 تا 32 کاراکتر باشد.")
        if not re.fullmatch(r"[A-Za-z0-9]+", v):
            raise ValueError("رمز عبور فقط می‌تواند شامل حروف انگلیسی و اعداد باشد.")
        if not PASSWORD_LETTER_RE.search(v) or not PASSWORD_DIGIT_RE.search(v):
            raise ValueError("رمز عبور باید حداقل یک حرف انگلیسی و یک عدد داشته باشد.")
        return v


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
    compatible_cars: str = ""
    stock: int = Field(default=0, ge=0, description="Stock cannot be negative")
    is_genuine: bool = False
    price: float = Field(default=0.0, ge=0.0, description="Price cannot be negative")
    image_url: Optional[str] = None
    description: Optional[str] = None
    brand: Optional[str] = None
    category: Optional[str] = None
    specifications: Optional[str] = None
    is_featured: bool = False
    home_order: int = 0


class PartUpdate(BaseModel):
    name: str
    part_number: str
    compatible_cars: str = ""
    stock: int = Field(default=0, ge=0)
    is_genuine: bool = False
    price: Optional[float] = None
    image_url: Optional[str] = None
    description: Optional[str] = None
    brand: Optional[str] = None
    category: Optional[str] = None
    specifications: Optional[str] = None
    is_featured: bool = False
    home_order: int = 0


class CartItemRequest(BaseModel):
    part_id: int
    quantity: int = Field(default=1, ge=1, le=99)


class CartMergeRequest(BaseModel):
    items: list[CartItemRequest] = []


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
async def serve_admin(current_user: dict = Depends(get_admin_page_user)):
    return FileResponse("admin.html")

@app.get("/admin/buy")
async def serve_buy(current_user: dict = Depends(get_admin_page_user)):
    return FileResponse("buy.html")

@app.get("/admin/sell")
async def serve_sell(current_user: dict = Depends(get_admin_page_user)):
    return FileResponse("sell.html")

@app.get("/admin/report")
async def serve_report(current_user: dict = Depends(get_admin_page_user)):
    return FileResponse("report.html")

@app.get("/order")
async def serve_order(current_user: dict = Depends(get_page_user)):
    return FileResponse("order.html")

@app.get("/login")
async def serve_login():
    return FileResponse("login.html")


# ------------------------------------------------------------------------------
# Routes: Authentication
# ------------------------------------------------------------------------------

@app.post("/api/auth/email/check")
def check_email(data: dict):
    """Validate a signup email, check uniqueness, and send a real Gmail OTP."""
    email = str(data.get("email") or "").strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
        raise HTTPException(status_code=422, detail="ایمیل معتبر نیست.")

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1 FROM users WHERE LOWER(email) = %s", (email,))
            if cursor.fetchone() is not None:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="این ایمیل قبلاً ثبت شده است.")

            now = datetime.now(timezone.utc)
            one_minute_ago = (now - timedelta(seconds=60)).isoformat()
            hour_ago = (now - timedelta(hours=1)).isoformat()
            cursor.execute(
                "SELECT COUNT(*) AS c FROM email_verifications WHERE LOWER(email) = %s AND created_at >= %s",
                (email, hour_ago),
            )
            if int(cursor.fetchone()["c"] or 0) >= 5:
                raise HTTPException(status_code=429, detail="تعداد درخواست‌های کد زیاد است. کمی بعد دوباره تلاش کن.")

            cursor.execute(
                "SELECT id FROM email_verifications WHERE LOWER(email) = %s AND created_at >= %s AND used_at IS NULL ORDER BY id DESC LIMIT 1",
                (email, one_minute_ago),
            )
            if cursor.fetchone() is not None:
                raise HTTPException(status_code=429, detail="کد قبلی هنوز تازه است؛ حدود یک دقیقه بعد دوباره درخواست بده.")

            username, _, _, _, _, from_address = _smtp_config()
            if not username:
                raise HTTPException(status_code=503, detail="GMAIL_ADDRESS یا SMTP_USERNAME روی سرور تنظیم نشده است.")

            code = f"{secrets.randbelow(1000000):06d}"
            code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
            expires_at = (now + timedelta(minutes=5)).isoformat()
            cursor.execute(
                "INSERT INTO email_verifications (email, code_hash, created_at, expires_at) VALUES (%s, %s, %s, %s) RETURNING id",
                (email, code_hash, now.isoformat(), expires_at),
            )
            verification_id = cursor.fetchone()["id"]

            msg = EmailMessage()
            msg["Subject"] = "کد تأیید ایمیل | کره یدک"
            msg["From"] = from_address or username
            msg["To"] = email
            msg.set_content(
                f"کد تأیید ایمیل کره یدک: {code}\n\n"
                "این کد تا ۵ دقیقه معتبر است. اگر این درخواست از طرف شما نبوده، این پیام را نادیده بگیرید."
            )

            try:
                _send_email_message(msg)
            except HTTPException:
                cursor.execute("DELETE FROM email_verifications WHERE id = %s", (verification_id,))
                raise

    return {"message": "کد تأیید به ایمیل ارسال شد.", "verification_id": verification_id, "expires_in": 300}


@app.post("/api/auth/email/verify-code")
def verify_email_code(data: dict):
    email = str(data.get("email") or "").strip().lower()
    code = str(data.get("code") or "").strip()
    verification_id = data.get("verification_id")

    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=422, detail="ایمیل معتبر نیست.")
    if not re.fullmatch(r"\d{6}", code):
        raise HTTPException(status_code=422, detail="کد تأیید باید ۶ رقمی باشد.")
    try:
        verification_id = int(verification_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="کد تأیید معتبر نیست.")

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, code_hash, expires_at, attempts, verified_at, used_at FROM email_verifications WHERE id = %s AND LOWER(email) = %s",
                (verification_id, email),
            )
            row = cursor.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="درخواست تأیید پیدا نشد. دوباره کد بگیر.")
            if row.get("used_at"):
                raise HTTPException(status_code=400, detail="این کد قبلاً استفاده شده است.")
            if row.get("verified_at"):
                return {"verified": True, "verification_id": verification_id}
            if datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc):
                raise HTTPException(status_code=400, detail="کد تأیید منقضی شده است. کد جدید بگیر.")
            if int(row.get("attempts") or 0) >= 5:
                raise HTTPException(status_code=429, detail="تعداد تلاش برای این کد تمام شده است. کد جدید بگیر.")

            expected = hashlib.sha256(code.encode("utf-8")).hexdigest()
            if not hmac.compare_digest(expected, row["code_hash"]):
                cursor.execute("UPDATE email_verifications SET attempts = attempts + 1 WHERE id = %s", (verification_id,))
                raise HTTPException(status_code=400, detail="کد تأیید اشتباه است.")

            cursor.execute(
                "UPDATE email_verifications SET verified_at = %s WHERE id = %s",
                (datetime.now(timezone.utc).isoformat(), verification_id),
            )

    return {"verified": True, "verification_id": verification_id}


@app.get("/api/auth/check-username")
def check_username(username: str = Query(default="")):
    username = username.strip()
    if not USERNAME_RE.fullmatch(username):
        raise HTTPException(status_code=422, detail="نام کاربری معتبر نیست.")
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1 FROM users WHERE LOWER(username) = LOWER(%s)", (username,))
            exists = cursor.fetchone() is not None
    return {"available": not exists}


@app.get("/api/auth/check-phone")
def check_phone(phone: str = Query(default="")):
    phone = re.sub(r"[\s-]+", "", phone)
    if not re.fullmatch(r"09\d{9}", phone):
        raise HTTPException(status_code=422, detail="شماره موبایل معتبر نیست.")
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1 FROM users WHERE phone = %s", (phone,))
            exists = cursor.fetchone() is not None
    return {"available": not exists}


@app.post("/api/auth/register")
def register(data: RegisterRequest):
    if not data.terms_accepted:
        raise HTTPException(status_code=400, detail="پذیرش قوانین الزامی است.")
    if data.password_repeat is not None and data.password != data.password_repeat:
        raise HTTPException(status_code=400, detail="تکرار رمز عبور یکسان نیست.")
    if not data.email_verification_id:
        raise HTTPException(status_code=400, detail="ابتدا ایمیل را با کد تأیید تأیید کن.")

    now = utc_now()
    password_hash = hash_password(data.password)

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT username, email, phone FROM users
                WHERE username = %s OR LOWER(email) = %s OR phone = %s
                """,
                (data.username, data.email, data.phone),
            )
            duplicate = cursor.fetchone()
            if duplicate:
                if duplicate.get("username") == data.username:
                    detail = "این نام کاربری قبلاً استفاده شده است."
                elif duplicate.get("email") == data.email:
                    detail = "این ایمیل قبلاً ثبت شده است."
                else:
                    detail = "این شماره موبایل قبلاً ثبت شده است."
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)

            cursor.execute(
                """
                SELECT id FROM email_verifications
                WHERE id = %s AND LOWER(email) = %s
                  AND verified_at IS NOT NULL AND used_at IS NULL
                  AND expires_at > %s
                """,
                (data.email_verification_id, data.email, now),
            )
            verification = cursor.fetchone()
            if verification is None:
                raise HTTPException(status_code=400, detail="تأیید ایمیل معتبر نیست یا منقضی شده است. دوباره کد بگیر.")

            cursor.execute(
                """
                INSERT INTO users (
                    username, password_hash, first_name, last_name, email, phone,
                    email_verified, role, must_change_password, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, username
                """,
                (
                    data.username, password_hash, data.first_name, data.last_name,
                    data.email, data.phone, 1, "customer", 0, now, now
                ),
            )
            user = cursor.fetchone()
            cursor.execute(
                "UPDATE email_verifications SET used_at = %s WHERE id = %s",
                (now, data.email_verification_id),
            )

    return {
        "message": "حساب با موفقیت ساخته شد.",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "first_name": data.first_name,
            "last_name": data.last_name,
            "email": data.email,
            "phone": data.phone,
            "role": "customer",
        },
    }


@app.post("/api/auth/login")
def login(data: LoginRequest, response: Response):
    identifier = (data.identifier or data.username or "").strip()
    if not identifier:
        raise HTTPException(status_code=422, detail="نام کاربری یا ایمیل الزامی است.")

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, username, first_name, last_name, email, phone,
                       email_verified, role, password_hash, must_change_password
                FROM users
                WHERE username = %s OR LOWER(email) = LOWER(%s)
                ORDER BY CASE WHEN username = %s THEN 0 ELSE 1 END
                LIMIT 1
                """,
                (identifier, identifier, identifier),
            )
            user = cursor.fetchone()

            if user is None or not verify_password(data.password, user["password_hash"]):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="نام کاربری/ایمیل یا رمز عبور اشتباه است."
                )

            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            if data.remember_me:
                expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
            else:
                expires_at = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()

            cursor.execute(
                """
                INSERT INTO sessions (user_id, token_hash, created_at, expires_at)
                VALUES (%s, %s, %s, %s)
                """,
                (user["id"], token_hash, utc_now(), expires_at),
            )

    response.set_cookie(
        key="koreyadak_page_token",
        value=raw_token,
        max_age=(30 * 24 * 60 * 60) if data.remember_me else (12 * 60 * 60),
        httponly=True,
        samesite="lax",
        secure=os.getenv("COOKIE_SECURE", "1") != "0",
        path="/",
    )

    return {
        "token": raw_token,
        "remember_me": data.remember_me,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "first_name": user.get("first_name"),
            "last_name": user.get("last_name"),
            "email": user.get("email"),
            "phone": user.get("phone"),
            "email_verified": bool(user.get("email_verified")),
            "role": user.get("role") or "customer",
            "must_change_password": bool(user["must_change_password"]),
        }
    }


@app.get("/api/auth/me")
def me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "first_name": current_user.get("first_name"),
        "last_name": current_user.get("last_name"),
        "email": current_user.get("email"),
        "phone": current_user.get("phone"),
        "email_verified": bool(current_user.get("email_verified")),
        "role": current_user.get("role") or "customer",
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
def get_sell_invoices(current_user: dict = Depends(get_admin_user)):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM sell_invoices ORDER BY id DESC")
            return cursor.fetchall()


@app.get("/api/invoices/sell/{invoice_id}")
def get_sell_invoice(
    invoice_id: int,
    current_user: dict = Depends(get_admin_user)
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
    current_user: dict = Depends(get_admin_user)
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
    current_user: dict = Depends(get_admin_user)
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
    current_user: dict = Depends(get_admin_user)
):
    is_paid = 1 if status_data.get("is_paid") else 0
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE sell_invoices SET is_paid = %s WHERE id = %s", (is_paid, invoice_id))

    return {"message": "وضعیت پرداخت تغییر کرد."}


@app.delete("/api/invoices/sell/{invoice_id}")
def delete_sell_invoice(
    invoice_id: int,
    current_user: dict = Depends(get_admin_user)
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
def get_buy_invoices(current_user: dict = Depends(get_admin_user)):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM buy_invoices ORDER BY id DESC")
            return cursor.fetchall()

@app.post("/api/invoices/buy")
def create_buy_invoice(
    data: BuyInvoiceCreate,
    current_user: dict = Depends(get_admin_user)
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
    current_user: dict = Depends(get_admin_user)
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
    current_user: dict = Depends(get_admin_user)
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
    current_user: dict = Depends(get_admin_user)
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

def _part_select_sql(alias: str = "") -> str:
    prefix = f"{alias}." if alias else ""
    return f"""
        {prefix}id, {prefix}part_number, {prefix}name, {prefix}compatible_cars,
        {prefix}stock, {prefix}is_genuine, {prefix}price, {prefix}price_updated_at,
        {prefix}last_updated_by, {prefix}image_url, {prefix}description,
        {prefix}brand, {prefix}category, {prefix}specifications,
        {prefix}is_featured, {prefix}home_order
    """


@app.get("/api/parts")
def get_parts(
    q: str = Query(default=""),
    car: str = Query(default=""),
    brand: str = Query(default=""),
    category: str = Query(default=""),
    in_stock: bool = Query(default=False),
    limit: int = Query(default=500, ge=1, le=1000),
    offset: int = Query(default=0, ge=0)
):
    conditions = []
    parameters = []

    if q.strip():
        for term in q.strip().split():
            search = f"%{term}%"
            conditions.append("""
                (
                    part_number ILIKE %s
                    OR name ILIKE %s
                    OR compatible_cars ILIKE %s
                    OR COALESCE(brand, '') ILIKE %s
                    OR COALESCE(category, '') ILIKE %s
                )
            """)
            parameters.extend([search, search, search, search, search])

    if car.strip():
        conditions.append("compatible_cars ILIKE %s")
        parameters.append(f"%{car.strip()}%")
    if brand.strip():
        conditions.append("brand ILIKE %s")
        parameters.append(f"%{brand.strip()}%")
    if category.strip():
        conditions.append("category ILIKE %s")
        parameters.append(f"%{category.strip()}%")
    if in_stock:
        conditions.append("stock > 0")

    query = f"SELECT {_part_select_sql()} FROM parts"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY is_featured DESC, home_order ASC, id ASC LIMIT %s OFFSET %s"
    parameters.extend([limit, offset])

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, parameters)
            return cursor.fetchall()


@app.get("/api/home-products")
def get_home_products(limit: int = Query(default=8, ge=1, le=12)):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                f"""
                SELECT {_part_select_sql()}
                FROM parts
                WHERE is_featured = 1 OR stock > 0
                ORDER BY is_featured DESC, home_order ASC, id DESC
                LIMIT %s
                """,
                (limit,)
            )
            return cursor.fetchall()


@app.get("/api/parts/{part_id}")
def get_part(part_id: int):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute(f"SELECT {_part_select_sql()} FROM parts WHERE id = %s", (part_id,))
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
def add_part(data: PartCreate, current_user: dict = Depends(get_admin_user)):
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
                INSERT INTO parts (
                    part_number, name, compatible_cars, stock, is_genuine, price,
                    price_updated_at, last_updated_by, image_url, description,
                    brand, category, specifications, is_featured, home_order
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                part_number, data.name.strip(), data.compatible_cars.strip(),
                data.stock, 1 if data.is_genuine else 0, data.price,
                now_str, current_user["username"], data.image_url, data.description,
                data.brand, data.category, data.specifications,
                1 if data.is_featured else 0, max(0, data.home_order)
            ))
            new_id = cursor.fetchone()["id"]
    return {"message": "قطعه جدید با موفقیت اضافه شد.", "id": new_id}


@app.put("/api/parts/{part_id}")
def update_part(part_id: int, data: PartUpdate, current_user: dict = Depends(get_admin_user)):
    part_number = data.part_number.strip()
    safe_stock = max(0, data.stock)
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT price, price_updated_at, image_url, description, brand, category,
                       specifications, is_featured, home_order
                FROM parts WHERE id = %s
            """, (part_id,))
            existing = cursor.fetchone()
            if existing is None:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="قطعه یافت نشد.")
            cursor.execute("SELECT id FROM parts WHERE part_number = %s AND id != %s", (part_number, part_id))
            if cursor.fetchone() is not None:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="این پارت نامبر متعلق به قطعه دیگری است.")

            new_price = data.price if data.price is not None else existing["price"]
            price_updated_at = utc_now() if float(new_price or 0) != float(existing["price"] or 0) else existing["price_updated_at"]
            image_url = data.image_url if data.image_url is not None else existing.get("image_url")
            description = data.description if data.description is not None else existing.get("description")
            brand = data.brand if data.brand is not None else existing.get("brand")
            category = data.category if data.category is not None else existing.get("category")
            specifications = data.specifications if data.specifications is not None else existing.get("specifications")

            cursor.execute("""
                UPDATE parts
                SET part_number=%s, name=%s, compatible_cars=%s, stock=%s, is_genuine=%s,
                    price=%s, price_updated_at=%s, last_updated_by=%s, image_url=%s,
                    description=%s, brand=%s, category=%s, specifications=%s,
                    is_featured=%s, home_order=%s
                WHERE id=%s
            """, (
                part_number, data.name.strip(), data.compatible_cars.strip(), safe_stock,
                1 if data.is_genuine else 0, new_price, price_updated_at, current_user["username"],
                image_url, description, brand, category, specifications,
                1 if data.is_featured else 0, max(0, data.home_order), part_id
            ))
    return {"message": "اطلاعات قطعه با موفقیت به‌روزرسانی شد."}


@app.patch("/api/parts/{part_id}/price")
def update_price(
    part_id: int,
    data: PriceUpdate,
    current_user: dict = Depends(get_admin_user)
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
    current_user: dict = Depends(get_admin_user)
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
    current_user: dict = Depends(get_admin_user)
):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM parts WHERE id = %s", (part_id,))
    return {"message": "قطعه با موفقیت حذف شد."}


@app.post("/api/parts/{part_id}/image")
async def upload_part_image(
    part_id: int,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_admin_user)
):
    allowed_types = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/avif": ".avif"}
    extension = allowed_types.get(file.content_type or "")
    if not extension:
        raise HTTPException(status_code=415, detail="فرمت تصویر مجاز نیست. فقط JPG، PNG، WEBP یا AVIF.")
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="حجم تصویر نباید بیشتر از ۵ مگابایت باشد.")

    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, image_url FROM parts WHERE id = %s", (part_id,))
            existing = cursor.fetchone()
            if existing is None:
                raise HTTPException(status_code=404, detail="قطعه یافت نشد.")

            filename = f"{part_id}-{uuid4().hex}{extension}"
            target = PART_MEDIA_ROOT / filename
            target.write_bytes(content)
            image_url = f"/media/parts/{filename}"
            cursor.execute(
                "UPDATE parts SET image_url=%s, last_updated_by=%s WHERE id=%s",
                (image_url, current_user["username"], part_id)
            )

    old_url = existing.get("image_url")
    if old_url and old_url.startswith("/media/parts/"):
        old_path = MEDIA_ROOT / old_url.removeprefix("/media/")
        try:
            if old_path != target and old_path.exists():
                old_path.unlink()
        except OSError:
            pass
    return {"message": "تصویر قطعه با موفقیت ذخیره شد.", "image_url": image_url}


def _serialize_cart_items(cursor, user_id: int):
    cursor.execute("""
        SELECT p.id, p.part_number, p.name, p.image_url, p.price, p.stock,
               ci.quantity, ci.updated_at
        FROM cart_items ci
        JOIN parts p ON p.id = ci.part_id
        WHERE ci.user_id = %s
        ORDER BY ci.updated_at DESC, ci.id DESC
    """, (user_id,))
    return [{**dict(row), "qty": int(row.get("quantity") or 1)} for row in cursor.fetchall()]


@app.get("/api/cart")
def get_cart(current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        with conn.cursor() as cursor:
            return {"items": _serialize_cart_items(cursor, current_user["id"])}


@app.post("/api/cart/merge")
def merge_cart(data: CartMergeRequest, current_user: dict = Depends(get_current_user)):
    now = utc_now()
    with get_db() as conn:
        with conn.cursor() as cursor:
            for item in data.items:
                cursor.execute("SELECT id FROM parts WHERE id=%s", (item.part_id,))
                if not cursor.fetchone():
                    continue
                cursor.execute("""
                    INSERT INTO cart_items (user_id, part_id, quantity, created_at, updated_at)
                    VALUES (%s,%s,%s,%s,%s)
                    ON CONFLICT (user_id, part_id)
                    DO UPDATE SET quantity=LEAST(99, cart_items.quantity + EXCLUDED.quantity), updated_at=EXCLUDED.updated_at
                """, (current_user["id"], item.part_id, min(99, item.quantity), now, now))
            return {"items": _serialize_cart_items(cursor, current_user["id"])}


@app.post("/api/cart/items")
def add_cart_item(data: CartItemRequest, current_user: dict = Depends(get_current_user)):
    now = utc_now()
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT id, stock FROM parts WHERE id=%s", (data.part_id,))
            part = cursor.fetchone()
            if not part:
                raise HTTPException(status_code=404, detail="قطعه یافت نشد.")
            cursor.execute("""
                INSERT INTO cart_items (user_id, part_id, quantity, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s)
                ON CONFLICT (user_id, part_id)
                DO UPDATE SET quantity=LEAST(99, cart_items.quantity + EXCLUDED.quantity), updated_at=EXCLUDED.updated_at
            """, (current_user["id"], data.part_id, min(99, data.quantity), now, now))
            return {"items": _serialize_cart_items(cursor, current_user["id"])}


@app.delete("/api/cart/items/{part_id}")
def delete_cart_item(part_id: int, current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM cart_items WHERE user_id=%s AND part_id=%s", (current_user["id"], part_id))
            return {"items": _serialize_cart_items(cursor, current_user["id"])}


@app.delete("/api/cart")
def clear_cart(current_user: dict = Depends(get_current_user)):
    with get_db() as conn:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM cart_items WHERE user_id=%s", (current_user["id"],))
    return {"items": []}

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
    current_user: dict = Depends(get_admin_user)
):
    """دریافت لیست داده‌های گزارش برای نمایش در جدول پیش‌نمایش فرانت‌اند"""
    return fetch_report_dataset(type, from_date, to_date, keyword)


@app.get("/api/reports/pdf")
def generate_report_pdf(
    type: str = Query(default="out_of_stock"),
    from_date: str = Query(default="", alias="from"),
    to_date: str = Query(default="", alias="to"),
    keyword: str = Query(default=""),
    current_user: dict = Depends(get_admin_user)
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
    current_user: dict = Depends(get_admin_user)
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
    current_user: dict = Depends(get_admin_user)
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
