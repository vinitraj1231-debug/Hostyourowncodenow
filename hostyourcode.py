"""
🚀 ELITEHOST v13.0 - PROFESSIONAL EDITION
Enterprise-Grade Cloud Deployment Platform
Enhanced Security | Auto-Scaling | Advanced Monitoring | Payment Integration
"""

import sys
import subprocess
import os

# ==================== DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 ELITEHOST v13.0 - PROFESSIONAL DEPENDENCY INSTALLER")
print("=" * 90)

REQUIRED_PACKAGES = {
    'pyTelegramBotAPI': 'telebot',
    'flask': 'flask',
    'flask-cors': 'flask_cors',
    'flask-limiter': 'flask_limiter',
    'requests': 'requests',
    'cryptography': 'cryptography',
    'psutil': 'psutil',
    'werkzeug': 'werkzeug',
    'python-dotenv': 'dotenv',
    'colorama': 'colorama',
    'pillow': 'PIL',
    'bcrypt': 'bcrypt',
    'redis': 'redis',
    'sqlalchemy': 'sqlalchemy',
    'celery': 'celery',
    'prometheus-client': 'prometheus_client',
    'sentry-sdk': 'sentry_sdk',
    'python-jose': 'jose',
    'passlib': 'passlib',
    'aiohttp': 'aiohttp',
    'qrcode': 'qrcode',
}

def smart_install(package, import_name):
    try:
        __import__(import_name)
        print(f"✓ {package:30} [INSTALLED]")
        return True
    except ImportError:
        print(f"⚡ {package:30} [INSTALLING...]", end=' ')
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', package, '--quiet'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("✅")
            return True
        except:
            print("❌")
            return False

print("\n🔍 Checking dependencies...\n")
failed = []
for pkg, imp in REQUIRED_PACKAGES.items():
    if not smart_install(pkg, imp):
        failed.append(pkg)

if failed:
    print(f"\n❌ Failed: {', '.join(failed)}")
    print(f"⚠️  Some features may not work. Continue anyway? (y/n)")
    if input().lower() != 'y':
        sys.exit(1)

print("\n" + "=" * 90)
print("✅ CORE DEPENDENCIES READY!")
print("=" * 90 + "\n")

# ==================== IMPORTS ====================
import telebot
from telebot import types
import zipfile
import shutil
import time
from datetime import datetime, timedelta
import json
import logging
import threading
import atexit
import requests
import hashlib
import secrets
import signal
from pathlib import Path
from flask import Flask, render_template_string, request, jsonify, session, send_file, redirect, make_response, send_from_directory
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from threading import Thread, Lock, Timer, Event
import uuid
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import psutil
from colorama import Fore, Style, init
import bcrypt
import re
from collections import defaultdict, deque
from functools import wraps
import traceback
from queue import Queue, Empty
import sqlite3
from contextlib import contextmanager

# Optional imports
try:
    import redis
    REDIS_AVAILABLE = True
except:
    REDIS_AVAILABLE = False

try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest
    PROMETHEUS_AVAILABLE = True
except:
    PROMETHEUS_AVAILABLE = False

try:
    import sentry_sdk
    SENTRY_AVAILABLE = True
except:
    SENTRY_AVAILABLE = False

try:
    import qrcode
    from io import BytesIO
    QRCODE_AVAILABLE = True
except:
    QRCODE_AVAILABLE = False

init(autoreset=True)

# ==================== CONFIGURATION ====================
# Load from environment variables for security
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '8133133627:AAHXG1M3I_5yV6mIo2IRl61h8zRUvg6Nn2Y')
OWNER_ID = int(os.getenv('OWNER_ID', '7524032836'))
ADMIN_ID = int(os.getenv('ADMIN_ID', '8285724366'))
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'Kvinit6421@gmail.com')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '28@HumblerRaj')
YOUR_USERNAME = os.getenv('TELEGRAM_USERNAME', '@Zolvit')
TELEGRAM_LINK = os.getenv('TELEGRAM_LINK', 'https://t.me/Zolvit')
WEB_SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', Fernet.generate_key()).encode() if isinstance(os.getenv('ENCRYPTION_KEY', ''), str) else Fernet.generate_key()

# Payment Configuration
UPI_ID = os.getenv('UPI_ID', 'your-upi@bank')
PAYMENT_PHONE = os.getenv('PAYMENT_PHONE', '+91XXXXXXXXXX')

# Redis Configuration (optional)
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Sentry Configuration (optional)
SENTRY_DSN = os.getenv('SENTRY_DSN', '')

# Feature Flags
ENABLE_RATE_LIMITING = os.getenv('ENABLE_RATE_LIMITING', 'true').lower() == 'true'
ENABLE_REDIS_CACHE = os.getenv('ENABLE_REDIS_CACHE', 'false').lower() == 'true' and REDIS_AVAILABLE
ENABLE_METRICS = os.getenv('ENABLE_METRICS', 'true').lower() == 'true' and PROMETHEUS_AVAILABLE
ENABLE_SENTRY = os.getenv('ENABLE_SENTRY', 'false').lower() == 'true' and SENTRY_AVAILABLE

try:
    fernet = Fernet(ENCRYPTION_KEY)
except:
    fernet = Fernet(Fernet.generate_key())
    print(f"{Fore.YELLOW}⚠️  Invalid encryption key, generated new one")

FREE_CREDITS = float(os.getenv('FREE_CREDITS', '2.0'))
CREDIT_COSTS = {
    'file_upload': float(os.getenv('COST_FILE_UPLOAD', '0.5')),
    'github_deploy': float(os.getenv('COST_GITHUB_DEPLOY', '1.0')),
    'backup': float(os.getenv('COST_BACKUP', '0.5')),
}

# Payment Packages
PAYMENT_PACKAGES = {
    '10_credits': {'credits': 10, 'price': 50, 'name': '10 Credits Pack', 'discount': 0},
    '99_credits': {'credits': 99, 'price': 399, 'name': '99 Credits Pack', 'discount': 96},
    '500_credits': {'credits': 500, 'price': 1899, 'name': '500 Credits Pack', 'discount': 601},
}

# Security Settings
MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 100 * 1024 * 1024))  # 100MB
ALLOWED_EXTENSIONS = {'.py', '.js', '.zip', '.tar.gz', '.html', '.css'}
SESSION_TIMEOUT_DAYS = int(os.getenv('SESSION_TIMEOUT_DAYS', '7'))
PAYMENT_TIMEOUT_MINUTES = int(os.getenv('PAYMENT_TIMEOUT_MINUTES', '5'))
MAX_DEPLOYMENTS_PER_USER = int(os.getenv('MAX_DEPLOYMENTS_PER_USER', '10'))
MAX_LOGIN_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', '5'))
LOGIN_ATTEMPT_WINDOW = int(os.getenv('LOGIN_ATTEMPT_WINDOW', '300'))  # 5 minutes

# Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'elitehost_data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
DEPLOYS_DIR = os.path.join(DATA_DIR, 'deployments')
BACKUPS_DIR = os.path.join(DATA_DIR, 'backups')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
PAYMENTS_DIR = os.path.join(DATA_DIR, 'payments')
STATIC_DIR = os.path.join(DATA_DIR, 'static')
DB_FILE = os.path.join(DATA_DIR, 'database.sqlite')

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, BACKUPS_DIR, LOGS_DIR, PAYMENTS_DIR, STATIC_DIR]:
    os.makedirs(d, exist_ok=True)

# Flask & Bot
app = Flask(__name__)
app.secret_key = WEB_SECRET_KEY
CORS(app, supports_credentials=True)

# Rate Limiting
if ENABLE_RATE_LIMITING:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=REDIS_URL if ENABLE_REDIS_CACHE else "memory://"
    )
else:
    # Dummy limiter that does nothing
    class DummyLimiter:
        def limit(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator
    limiter = DummyLimiter()

bot = telebot.TeleBot(TOKEN, parse_mode='Markdown')

# Global state
active_processes = {}
deployment_logs = {}
payment_timers = {}
login_attempts = defaultdict(lambda: deque(maxlen=MAX_LOGIN_ATTEMPTS))

# Thread-safe locks
DB_LOCK = Lock()
PROCESS_LOCK = Lock()

# ==================== SENTRY INTEGRATION ====================
if ENABLE_SENTRY and SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        traces_sample_rate=0.1,
        profiles_sample_rate=0.1,
    )

# ==================== PROMETHEUS METRICS ====================
if ENABLE_METRICS:
    metrics = {
        'requests_total': Counter('elitehost_requests_total', 'Total requests', ['method', 'endpoint', 'status']),
        'deployments_total': Counter('elitehost_deployments_total', 'Total deployments', ['type', 'status']),
        'active_deployments': Gauge('elitehost_active_deployments', 'Active deployments'),
        'credits_used': Counter('elitehost_credits_used', 'Credits used', ['action']),
        'payment_requests': Counter('elitehost_payment_requests', 'Payment requests', ['status']),
        'request_duration': Histogram('elitehost_request_duration_seconds', 'Request duration'),
    }
else:
    metrics = None

# ==================== REDIS CACHE ====================
if ENABLE_REDIS_CACHE:
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()
        print(f"{Fore.GREEN}✅ Redis cache connected")
    except:
        ENABLE_REDIS_CACHE = False
        redis_client = None
        print(f"{Fore.YELLOW}⚠️  Redis unavailable, using local cache")
else:
    redis_client = None

# ==================== LOGGING SETUP ====================
class ColoredFormatter(logging.Formatter):
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Style.BRIGHT,
    }
    
    def format(self, record):
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"
        return super().format(record)

# Main logger
logger = logging.getLogger('elitehost')
logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setFormatter(ColoredFormatter(
    '%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
))

# File handler
file_handler = logging.FileHandler(os.path.join(LOGS_DIR, 'elitehost.log'))
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))

logger.addHandler(console_handler)
logger.addHandler(file_handler)

# Error logger
error_logger = logging.getLogger('elitehost.errors')
error_logger.setLevel(logging.ERROR)
error_handler = logging.FileHandler(os.path.join(LOGS_DIR, 'errors.log'))
error_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
))
error_logger.addHandler(error_handler)

# ==================== DATABASE (SQLite) ====================

def get_db_connection():
    """Thread-safe database connection"""
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def get_db():
    """Context manager for database operations"""
    conn = get_db_connection()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

def init_database():
    """Initialize SQLite database with tables"""
    with get_db() as conn:
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                device_fingerprint TEXT NOT NULL,
                credits REAL DEFAULT 0,
                total_spent REAL DEFAULT 0,
                total_earned REAL DEFAULT 0,
                created_at TEXT NOT NULL,
                last_login TEXT,
                ip_address TEXT,
                is_banned INTEGER DEFAULT 0,
                telegram_id TEXT,
                referral_code TEXT UNIQUE,
                referred_by TEXT,
                FOREIGN KEY (referred_by) REFERENCES users(id)
            )
        ''')
        
        # Sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_activity TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Deployments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS deployments (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                status TEXT NOT NULL,
                port INTEGER,
                pid INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                logs TEXT,
                dependencies TEXT,
                repo_url TEXT,
                branch TEXT,
                build_command TEXT,
                start_command TEXT,
                env_vars TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Payments table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                user_email TEXT NOT NULL,
                package_type TEXT NOT NULL,
                credits REAL NOT NULL,
                price REAL NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                submitted_at TEXT,
                approved_at TEXT,
                rejected_at TEXT,
                screenshot_path TEXT,
                transaction_id TEXT,
                approved_by TEXT,
                rejected_by TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Activity log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        
        # Banned devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS banned_devices (
                fingerprint TEXT PRIMARY KEY,
                reason TEXT,
                banned_at TEXT NOT NULL
            )
        ''')
        
        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_deployments_user_id ON deployments(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_user_id ON activity_log(user_id)')
        
        logger.info(f"{Fore.GREEN}✅ Database initialized")

# Initialize database on startup
init_database()

# ==================== ERROR HANDLING ====================

def log_error(error_msg, context="", exc_info=None):
    """Enhanced error logging with stack trace"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    error_details = {
        'timestamp': timestamp,
        'context': context,
        'error': str(error_msg),
        'traceback': traceback.format_exc() if exc_info else None
    }
    
    error_logger.error(json.dumps(error_details, indent=2))
    
    if ENABLE_SENTRY:
        try:
            sentry_sdk.capture_exception(exc_info or error_msg)
        except:
            pass
    
    return error_details

# ==================== CACHE LAYER ====================

class Cache:
    """Simple cache with Redis fallback"""
    def __init__(self):
        self.local_cache = {}
        self.use_redis = ENABLE_REDIS_CACHE and redis_client is not None
    
    def get(self, key):
        if self.use_redis:
            try:
                value = redis_client.get(f"elitehost:{key}")
                return json.loads(value) if value else None
            except:
                pass
        return self.local_cache.get(key)
    
    def set(self, key, value, ttl=300):
        if self.use_redis:
            try:
                redis_client.setex(
                    f"elitehost:{key}",
                    ttl,
                    json.dumps(value, default=str)
                )
            except:
                pass
        self.local_cache[key] = value
    
    def delete(self, key):
        if self.use_redis:
            try:
                redis_client.delete(f"elitehost:{key}")
            except:
                pass
        self.local_cache.pop(key, None)
    
    def clear(self):
        if self.use_redis:
            try:
                keys = redis_client.keys("elitehost:*")
                if keys:
                    redis_client.delete(*keys)
            except:
                pass
        self.local_cache.clear()

cache = Cache()

# ==================== DEVICE FINGERPRINTING ====================

def get_device_fingerprint(request):
    """Enhanced device fingerprinting"""
    components = [
        request.headers.get('User-Agent', ''),
        request.remote_addr or request.environ.get('HTTP_X_REAL_IP', 'unknown'),
        request.headers.get('Accept-Language', ''),
        request.headers.get('Accept-Encoding', ''),
        str(request.headers.get('Accept', '')),
    ]
    fingerprint_str = '|'.join(components)
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()

def is_device_banned(fingerprint):
    """Check if device is banned"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT 1 FROM banned_devices WHERE fingerprint = ?', (fingerprint,))
        return cursor.fetchone() is not None

def ban_device(fingerprint, reason="Suspicious activity"):
    """Ban a device"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO banned_devices (fingerprint, reason, banned_at)
            VALUES (?, ?, ?)
        ''', (fingerprint, reason, datetime.now().isoformat()))
    cache.delete(f"device_banned:{fingerprint}")

def check_existing_account(fingerprint):
    """Check if device already has an account"""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE device_fingerprint = ?', (fingerprint,))
        row = cursor.fetchone()
        return row['id'] if row else None

# ==================== RATE LIMITING ====================

def check_login_attempts(ip_address):
    """Check if IP has exceeded login attempts"""
    now = time.time()
    attempts = login_attempts[ip_address]
    
    # Remove old attempts
    while attempts and attempts[0] < now - LOGIN_ATTEMPT_WINDOW:
        attempts.popleft()
    
    return len(attempts) >= MAX_LOGIN_ATTEMPTS

def record_login_attempt(ip_address):
    """Record a failed login attempt"""
    login_attempts[ip_address].append(time.time())

# ==================== USER FUNCTIONS (Updated for SQLite) ====================

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except:
        return False

def generate_referral_code():
    """Generate unique referral code"""
    return secrets.token_urlsafe(8).upper()

def create_user(email, password, fingerprint, ip, referred_by=None):
    """Create new user account"""
    try:
        user_id = str(uuid.uuid4())
        referral_code = generate_referral_code()
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (
                    id, email, password, device_fingerprint, credits,
                    total_earned, created_at, last_login, ip_address,
                    referral_code, referred_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, email, hash_password(password), fingerprint,
                FREE_CREDITS, FREE_CREDITS, datetime.now().isoformat(),
                datetime.now().isoformat(), ip, referral_code, referred_by
            ))
        
        # Bonus for referrer
        if referred_by:
            add_credits(referred_by, 1.0, "Referral bonus")
        
        log_activity(user_id, 'USER_REGISTER', f'New user: {email}', ip)
        cache.delete(f"user:{user_id}")
        
        # Notify owner via Telegram
        try:
            bot.send_message(
                OWNER_ID,
                f"🆕 *NEW USER REGISTERED*\n\n"
                f"📧 Email: `{email}`\n"
                f"🆔 ID: `{user_id}`\n"
                f"🌐 IP: `{ip}`\n"
                f"🎁 Referral: `{referral_code}`\n"
                f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        except Exception as e:
            log_error(str(e), "create_user telegram notification")
        
        return user_id
    except sqlite3.IntegrityError:
        return None
    except Exception as e:
        log_error(str(e), "create_user", exc_info=e)
        return None

def authenticate_user(email, password):
    """Authenticate user login"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, password FROM users WHERE email = ?', (email,))
            row = cursor.fetchone()
            
            if row and verify_password(password, row['password']):
                return row['id']
        return None
    except Exception as e:
        log_error(str(e), "authenticate_user", exc_info=e)
        return None

def create_session(user_id, fingerprint):
    """Create user session"""
    try:
        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(days=SESSION_TIMEOUT_DAYS)
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (token, user_id, fingerprint, created_at, expires_at, last_activity)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                session_token, user_id, fingerprint,
                datetime.now().isoformat(), expires_at.isoformat(),
                datetime.now().isoformat()
            ))
        
        cache.set(f"session:{session_token}", {
            'user_id': user_id,
            'fingerprint': fingerprint,
            'expires_at': expires_at.isoformat()
        }, ttl=SESSION_TIMEOUT_DAYS * 86400)
        
        return session_token
    except Exception as e:
        log_error(str(e), "create_session", exc_info=e)
        return None

def verify_session(session_token, fingerprint):
    """Verify session token"""
    if not session_token:
        return None
    
    # Check cache first
    cached = cache.get(f"session:{session_token}")
    if cached:
        if cached['fingerprint'] == fingerprint:
            if datetime.fromisoformat(cached['expires_at']) > datetime.now():
                return cached['user_id']
    
    # Check database
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT user_id, fingerprint, expires_at
                FROM sessions
                WHERE token = ?
            ''', (session_token,))
            row = cursor.fetchone()
            
            if not row:
                return None
            
            if datetime.fromisoformat(row['expires_at']) < datetime.now():
                cursor.execute('DELETE FROM sessions WHERE token = ?', (session_token,))
                cache.delete(f"session:{session_token}")
                return None
            
            if row['fingerprint'] != fingerprint:
                return None
            
            # Update last activity
            cursor.execute('''
                UPDATE sessions SET last_activity = ? WHERE token = ?
            ''', (datetime.now().isoformat(), session_token))
            
            return row['user_id']
    except Exception as e:
        log_error(str(e), "verify_session", exc_info=e)
        return None

def get_user(user_id):
    """Get user data"""
    # Check cache
    cached = cache.get(f"user:{user_id}")
    if cached:
        return cached
    
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = cursor.fetchone()
            
            if row:
                user_data = dict(row)
                # Get deployment IDs
                cursor.execute('SELECT id FROM deployments WHERE user_id = ?', (user_id,))
                user_data['deployments'] = [r['id'] for r in cursor.fetchall()]
                
                cache.set(f"user:{user_id}", user_data, ttl=300)
                return user_data
        return None
    except Exception as e:
        log_error(str(e), "get_user", exc_info=e)
        return None

def update_user(user_id, **kwargs):
    """Update user data"""
    try:
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys()])
        values = list(kwargs.values()) + [user_id]
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(f'UPDATE users SET {set_clause} WHERE id = ?', values)
        
        cache.delete(f"user:{user_id}")
    except Exception as e:
        log_error(str(e), "update_user", exc_info=e)

def log_activity(user_id, action, details, ip=''):
    """Log user activity"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO activity_log (user_id, action, details, ip_address, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, action, details, ip, datetime.now().isoformat()))
    except Exception as e:
        log_error(str(e), "log_activity", exc_info=e)

# ==================== CREDIT SYSTEM ====================

def get_credits(user_id):
    """Get user credits"""
    if str(user_id) == str(OWNER_ID):
        return float('inf')
    
    user = get_user(user_id)
    return user['credits'] if user else 0

def add_credits(user_id, amount, description="Credit added"):
    """Add credits to user"""
    try:
        user = get_user(user_id)
        if not user:
            return False
        
        new_credits = user['credits'] + amount
        new_earned = user['total_earned'] + amount
        
        update_user(user_id, credits=new_credits, total_earned=new_earned)
        log_activity(user_id, 'CREDIT_ADD', f"{amount} - {description}")
        
        if metrics:
            metrics['credits_used'].labels(action='add').inc(amount)
        
        return True
    except Exception as e:
        log_error(str(e), "add_credits", exc_info=e)
        return False

def deduct_credits(user_id, amount, description="Credit used"):
    """Deduct credits from user"""
    if str(user_id) == str(OWNER_ID):
        return True
    
    try:
        user = get_user(user_id)
        if not user or user['credits'] < amount:
            return False
        
        new_credits = user['credits'] - amount
        new_spent = user['total_spent'] + amount
        
        update_user(user_id, credits=new_credits, total_spent=new_spent)
        log_activity(user_id, 'CREDIT_USE', f"{amount} - {description}")
        
        if metrics:
            metrics['credits_used'].labels(action='deduct').inc(amount)
        
        return True
    except Exception as e:
        log_error(str(e), "deduct_credits", exc_info=e)
        return False

# ==================== QR CODE GENERATION ====================

def generate_payment_qr(upi_id, amount, name="EliteHost"):
    """Generate UPI payment QR code"""
    if not QRCODE_AVAILABLE:
        return None
    
    try:
        upi_string = f"upi://pay?pa={upi_id}&pn={name}&am={amount}&cu=INR"
        
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(upi_string)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Save to bytes
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        
        return buffer
    except Exception as e:
        log_error(str(e), "generate_payment_qr", exc_info=e)
        return None
# ==================== PAYMENT SYSTEM (Enhanced) ====================

def create_payment_request(user_id, package_type, custom_amount=None):
    """Create a new payment request with enhanced validation"""
    try:
        payment_id = str(uuid.uuid4())[:12]
        
        if package_type == 'custom':
            if not custom_amount or custom_amount <= 0:
                return None, "Invalid custom amount"
            credits = custom_amount
            price = custom_amount
        else:
            if package_type not in PAYMENT_PACKAGES:
                return None, "Invalid package"
            package = PAYMENT_PACKAGES[package_type]
            credits = package['credits']
            price = package['price']
        
        user = get_user(user_id)
        if not user:
            return None, "User not found"
        
        expires_at = datetime.now() + timedelta(minutes=PAYMENT_TIMEOUT_MINUTES)
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO payments (
                    id, user_id, user_email, package_type, credits, price,
                    status, created_at, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                payment_id, user_id, user['email'], package_type,
                credits, price, 'pending',
                datetime.now().isoformat(), expires_at.isoformat()
            ))
        
        # Start expiry timer
        timer = Timer(PAYMENT_TIMEOUT_MINUTES * 60, expire_payment, args=[payment_id])
        payment_timers[payment_id] = timer
        timer.start()
        
        log_activity(user_id, 'PAYMENT_REQUEST', f"Payment {payment_id}: {credits} credits for ₹{price}")
        
        if metrics:
            metrics['payment_requests'].labels(status='created').inc()
        
        payment_data = {
            'id': payment_id,
            'user_id': user_id,
            'user_email': user['email'],
            'package_type': package_type,
            'credits': credits,
            'price': price,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'expires_at': expires_at.isoformat()
        }
        
        return payment_id, payment_data
    
    except Exception as e:
        log_error(str(e), "create_payment_request", exc_info=e)
        return None, str(e)

def expire_payment(payment_id):
    """Auto-expire payment after timeout"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE payments SET status = 'expired'
                WHERE id = ? AND status = 'pending'
            ''', (payment_id,))
        
        if metrics:
            metrics['payment_requests'].labels(status='expired').inc()
        
        logger.info(f"Payment {payment_id} expired")
    except Exception as e:
        log_error(str(e), "expire_payment", exc_info=e)

def submit_payment_proof(payment_id, screenshot_data, transaction_id):
    """Submit payment proof with validation"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
            row = cursor.fetchone()
            
            if not row:
                return False, "Payment not found"
            
            payment = dict(row)
            
            if payment['status'] != 'pending':
                return False, f"Payment is {payment['status']}"
            
            # Check if expired
            if datetime.fromisoformat(payment['expires_at']) < datetime.now():
                cursor.execute('''
                    UPDATE payments SET status = 'expired' WHERE id = ?
                ''', (payment_id,))
                return False, "Payment expired"
            
            # Validate transaction ID
            if not transaction_id or len(transaction_id) < 6:
                return False, "Invalid transaction ID"
            
            # Check for duplicate transaction ID
            cursor.execute('''
                SELECT id FROM payments 
                WHERE transaction_id = ? AND id != ? AND status IN ('submitted', 'approved')
            ''', (transaction_id, payment_id))
            
            if cursor.fetchone():
                return False, "Transaction ID already used"
            
            # Save screenshot
            screenshot_path = os.path.join(PAYMENTS_DIR, f"{payment_id}_screenshot.jpg")
            try:
                import base64
                screenshot_bytes = base64.b64decode(screenshot_data.split(',')[1])
                
                # Validate image size
                if len(screenshot_bytes) > 10 * 1024 * 1024:  # 10MB max
                    return False, "Screenshot too large (max 10MB)"
                
                with open(screenshot_path, 'wb') as f:
                    f.write(screenshot_bytes)
            except Exception as e:
                log_error(str(e), "screenshot save", exc_info=e)
                return False, "Screenshot upload failed"
            
            # Update payment
            cursor.execute('''
                UPDATE payments 
                SET screenshot_path = ?, transaction_id = ?, status = 'submitted',
                    submitted_at = ?
                WHERE id = ?
            ''', (screenshot_path, transaction_id, datetime.now().isoformat(), payment_id))
        
        # Cancel expiry timer
        if payment_id in payment_timers:
            payment_timers[payment_id].cancel()
            del payment_timers[payment_id]
        
        if metrics:
            metrics['payment_requests'].labels(status='submitted').inc()
        
        # Notify admin via Telegram
        try:
            user = get_user(payment['user_id'])
            
            markup = types.InlineKeyboardMarkup()
            markup.row(
                types.InlineKeyboardButton("✅ Approve", callback_data=f"payment_confirm_{payment_id}"),
                types.InlineKeyboardButton("❌ Reject", callback_data=f"payment_reject_{payment_id}")
            )
            
            bot.send_message(
                ADMIN_ID,
                f"💳 *NEW PAYMENT SUBMISSION*\n\n"
                f"📧 User: `{user['email']}`\n"
                f"🆔 Payment ID: `{payment_id}`\n"
                f"💰 Amount: ₹{payment['price']}\n"
                f"💎 Credits: {payment['credits']}\n"
                f"🔢 Transaction ID: `{transaction_id}`\n"
                f"📦 Package: {payment['package_type']}\n"
                f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"_Review the payment and take action:_",
                reply_markup=markup
            )
            
            # Send screenshot
            with open(screenshot_path, 'rb') as photo:
                bot.send_photo(ADMIN_ID, photo, caption=f"Payment Screenshot - {payment_id}")
        
        except Exception as e:
            log_error(str(e), "payment notification", exc_info=e)
        
        return True, "Payment proof submitted successfully"
    
    except Exception as e:
        log_error(str(e), "submit_payment_proof", exc_info=e)
        return False, str(e)

def approve_payment(payment_id, approved_by):
    """Approve payment and add credits"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
            row = cursor.fetchone()
            
            if not row:
                return False, "Payment not found"
            
            payment = dict(row)
            
            if payment['status'] != 'submitted':
                return False, f"Payment is {payment['status']}"
            
            # Update payment status
            cursor.execute('''
                UPDATE payments 
                SET status = 'approved', approved_at = ?, approved_by = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), approved_by, payment_id))
            
            # Add credits to user
            add_credits(payment['user_id'], payment['credits'], f"Payment approved: {payment_id}")
        
        if metrics:
            metrics['payment_requests'].labels(status='approved').inc()
        
        logger.info(f"Payment {payment_id} approved by {approved_by}")
        return True, "Payment approved"
    
    except Exception as e:
        log_error(str(e), "approve_payment", exc_info=e)
        return False, str(e)

def reject_payment(payment_id, rejected_by, reason=""):
    """Reject payment"""
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE payments 
                SET status = 'rejected', rejected_at = ?, rejected_by = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), rejected_by, payment_id))
        
        if metrics:
            metrics['payment_requests'].labels(status='rejected').inc()
        
        logger.info(f"Payment {payment_id} rejected by {rejected_by}")
        return True, "Payment rejected"
    
    except Exception as e:
        log_error(str(e), "reject_payment", exc_info=e)
        return False, str(e)

# ==================== TELEGRAM BOT HANDLERS (Enhanced) ====================

@bot.callback_query_handler(func=lambda call: call.data.startswith('payment_'))
def handle_payment_action(call):
    """Handle payment confirmation/rejection from Telegram"""
    try:
        action, payment_id = call.data.rsplit('_', 1)
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
            row = cursor.fetchone()
            
            if not row:
                bot.answer_callback_query(call.id, "Payment not found")
                return
            
            payment = dict(row)
        
        if 'confirm' in action:
            success, message = approve_payment(payment_id, str(call.from_user.id))
            
            if success:
                bot.answer_callback_query(call.id, "✅ Payment Approved!")
                bot.edit_message_text(
                    f"{call.message.text}\n\n✅ *APPROVED* by {call.from_user.first_name}",
                    call.message.chat.id,
                    call.message.message_id,
                    parse_mode='Markdown'
                )
                
                # Notify user (if telegram_id available)
                user = get_user(payment['user_id'])
                if user and user.get('telegram_id'):
                    try:
                        bot.send_message(
                            user['telegram_id'],
                            f"✅ *Payment Approved!*\n\n"
                            f"💎 {payment['credits']} credits added to your account\n"
                            f"💰 Amount: ₹{payment['price']}\n"
                            f"🆔 Payment ID: `{payment_id}`"
                        )
                    except:
                        pass
            else:
                bot.answer_callback_query(call.id, f"Error: {message}")
        
        elif 'reject' in action:
            success, message = reject_payment(payment_id, str(call.from_user.id))
            
            if success:
                bot.answer_callback_query(call.id, "❌ Payment Rejected")
                bot.edit_message_text(
                    f"{call.message.text}\n\n❌ *REJECTED* by {call.from_user.first_name}",
                    call.message.chat.id,
                    call.message.message_id,
                    parse_mode='Markdown'
                )
                
                # Notify user (if telegram_id available)
                user = get_user(payment['user_id'])
                if user and user.get('telegram_id'):
                    try:
                        bot.send_message(
                            user['telegram_id'],
                            f"❌ *Payment Rejected*\n\n"
                            f"Your payment proof was not accepted.\n"
                            f"Please contact support if you believe this is an error.\n"
                            f"🆔 Payment ID: `{payment_id}`"
                        )
                    except:
                        pass
            else:
                bot.answer_callback_query(call.id, f"Error: {message}")
    
    except Exception as e:
        log_error(str(e), "handle_payment_action", exc_info=e)
        bot.answer_callback_query(call.id, f"Error: {str(e)}")

@bot.message_handler(commands=['start'])
def bot_start(message):
    """Start command handler"""
    try:
        markup = types.InlineKeyboardMarkup()
        markup.row(
            types.InlineKeyboardButton("🌐 Open Dashboard", url=f"http://localhost:{os.getenv('PORT', 8080)}/dashboard")
        )
        
        bot.send_message(
            message.chat.id,
            f"👋 *Welcome to EliteHost v13.0!*\n\n"
            f"🚀 Next-Generation Cloud Deployment Platform\n\n"
            f"*Features:*\n"
            f"• 🤖 AI Auto-Deploy\n"
            f"• 💳 Integrated Payments\n"
            f"• 📊 Real-time Monitoring\n"
            f"• 🔒 Enterprise Security\n\n"
            f"Use /help for commands",
            reply_markup=markup
        )
    except Exception as e:
        log_error(str(e), "bot_start", exc_info=e)

@bot.message_handler(commands=['help'])
def bot_help(message):
    """Help command handler"""
    try:
        bot.send_message(
            message.chat.id,
            f"📚 *EliteHost Commands*\n\n"
            f"/start - Start the bot\n"
            f"/help - Show this help\n"
            f"/credits - Check your credits\n"
            f"/link - Link Telegram account\n"
            f"/stats - View your statistics\n\n"
            f"💬 Contact: {YOUR_USERNAME}"
        )
    except Exception as e:
        log_error(str(e), "bot_help", exc_info=e)

@bot.message_handler(commands=['credits'])
def bot_credits(message):
    """Check credits command"""
    try:
        # Find user by telegram_id
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE telegram_id = ?', (str(message.from_user.id),))
            row = cursor.fetchone()
        
        if row:
            user = dict(row)
            bot.send_message(
                message.chat.id,
                f"💎 *Your Credits*\n\n"
                f"Available: {user['credits']:.2f}\n"
                f"Total Earned: {user['total_earned']:.2f}\n"
                f"Total Spent: {user['total_spent']:.2f}\n\n"
                f"📧 Email: {user['email']}"
            )
        else:
            bot.send_message(
                message.chat.id,
                f"❌ No account linked to this Telegram.\n\n"
                f"Use /link to connect your account."
            )
    except Exception as e:
        log_error(str(e), "bot_credits", exc_info=e)

# ==================== AI DEPENDENCY DETECTOR (Enhanced) ====================

def extract_imports_from_code(code_content):
    """Enhanced import extraction with better parsing"""
    imports = set()
    import_patterns = [
        r'^\s*import\s+([a-zA-Z0-9_\.]+)',
        r'^\s*from\s+([a-zA-Z0-9_\.]+)\s+import',
    ]
    
    for line in code_content.split('\n'):
        for pattern in import_patterns:
            match = re.match(pattern, line)
            if match:
                module = match.group(1).split('.')[0]
                imports.add(module)
    
    return imports

def get_package_name(import_name):
    """Map import names to package names"""
    mapping = {
        'cv2': 'opencv-python',
        'PIL': 'pillow',
        'sklearn': 'scikit-learn',
        'yaml': 'pyyaml',
        'dotenv': 'python-dotenv',
        'telebot': 'pyTelegramBotAPI',
        'bs4': 'beautifulsoup4',
        'flask_limiter': 'flask-limiter',
        'jose': 'python-jose',
        'passlib': 'passlib',
    }
    return mapping.get(import_name, import_name)

def detect_and_install_deps(project_path):
    """AI-powered dependency detection and installation"""
    installed = []
    install_log = []
    
    install_log.append("🤖 AI DEPENDENCY ANALYZER v13.0")
    install_log.append("=" * 60)
    
    try:
        # Check for requirements.txt
        req_file = os.path.join(project_path, 'requirements.txt')
        if os.path.exists(req_file):
            install_log.append("\n📦 PROCESSING REQUIREMENTS.TXT")
            try:
                with open(req_file, 'r') as f:
                    packages = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                
                for pkg in packages:
                    try:
                        # Extract package name without version specifier
                        pkg_name = re.split(r'[<>=!]', pkg)[0].strip()
                        
                        subprocess.run(
                            [sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                            check=True,
                            capture_output=True,
                            timeout=300
                        )
                        install_log.append(f"  ✅ {pkg}")
                        installed.append(pkg_name)
                    except subprocess.TimeoutExpired:
                        install_log.append(f"  ⏱️  {pkg} (timeout)")
                    except Exception as e:
                        install_log.append(f"  ⚠️  {pkg} (error: {str(e)[:50]})")
                        log_error(str(e), f"install {pkg}", exc_info=e)
            except Exception as e:
                install_log.append(f"❌ Error reading requirements.txt: {str(e)[:100]}")
                log_error(str(e), "requirements.txt processing", exc_info=e)
        
        # Check for package.json (Node.js)
        package_json = os.path.join(project_path, 'package.json')
        if os.path.exists(package_json):
            install_log.append("\n📦 PROCESSING PACKAGE.JSON")
            try:
                result = subprocess.run(
                    ['npm', 'install'],
                    cwd=project_path,
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                if result.returncode == 0:
                    install_log.append("  ✅ NPM packages installed")
                else:
                    install_log.append(f"  ⚠️  NPM install warnings")
            except FileNotFoundError:
                install_log.append("  ⚠️  npm not found, skipping")
            except Exception as e:
                install_log.append(f"  ❌ NPM install failed: {str(e)[:50]}")
                log_error(str(e), "npm install", exc_info=e)
        
        # Scan Python files for imports
        python_files = []
        for root, dirs, files in os.walk(project_path):
            # Skip common directories
            dirs[:] = [d for d in dirs if d not in ['.git', '__pycache__', 'node_modules', 'venv', '.venv']]
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        if python_files:
            install_log.append(f"\n🔍 SCANNING {len(python_files)} PYTHON FILES")
            all_imports = set()
            
            for py_file in python_files[:50]:  # Limit to 50 files
                try:
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                        imports = extract_imports_from_code(code)
                        all_imports.update(imports)
                except Exception as e:
                    log_error(str(e), f"reading {py_file}", exc_info=e)
                    continue
            
            if all_imports:
                stdlib = {
                    'os', 'sys', 'time', 'json', 're', 'math', 'random', 'datetime',
                    'collections', 'itertools', 'functools', 'pathlib', 'typing',
                    'threading', 'multiprocessing', 'subprocess', 'io', 'tempfile',
                    'shutil', 'glob', 'argparse', 'logging', 'traceback', 'warnings',
                    'abc', 'enum', 'dataclasses', 'contextlib', 'copy', 'pickle',
                    'csv', 'sqlite3', 'unittest', 'asyncio', 'concurrent', 'queue'
                }
                third_party = all_imports - stdlib
                
                install_log.append(f"  📊 Found {len(third_party)} third-party imports")
                
                for imp in third_party:
                    pkg = get_package_name(imp)
                    
                    # Check if already installed
                    try:
                        __import__(imp)
                        continue
                    except ImportError:
                        pass
                    
                    # Try to install
                    try:
                        subprocess.run(
                            [sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                            check=True,
                            capture_output=True,
                            timeout=300
                        )
                        install_log.append(f"  ✅ {pkg} (auto-detected)")
                        installed.append(pkg)
                    except subprocess.TimeoutExpired:
                        install_log.append(f"  ⏱️  {pkg} (timeout)")
                    except Exception as e:
                        # Silently skip packages that fail
                        log_error(str(e), f"auto-install {pkg}", exc_info=e)
        
        install_log.append("\n" + "=" * 60)
        install_log.append(f"📦 Total Packages Installed: {len(set(installed))}")
        install_log.append("=" * 60)
        
        return list(set(installed)), "\n".join(install_log)
    
    except Exception as e:
        log_error(str(e), "detect_and_install_deps", exc_info=e)
        return installed, "\n".join(install_log) + f"\n\n❌ Error: {str(e)}"

# ==================== DEPLOYMENT FUNCTIONS (Enhanced) ====================

def find_free_port(start_port=5000, max_attempts=100):
    """Find available port with better algorithm"""
    import socket
    
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                return port
        except OSError:
            continue
    
    raise RuntimeError("No free ports available")

def create_deployment(user_id, name, deploy_type, **kwargs):
    """Create deployment with validation"""
    try:
        # Check deployment limit
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) as count FROM deployments 
                WHERE user_id = ? AND status IN ('running', 'pending')
            ''', (user_id,))
            count = cursor.fetchone()['count']
            
            if count >= MAX_DEPLOYMENTS_PER_USER and str(user_id) != str(OWNER_ID):
                return None, None, f"Maximum {MAX_DEPLOYMENTS_PER_USER} active deployments allowed"
        
        deploy_id = str(uuid.uuid4())[:8]
        port = find_free_port()
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO deployments (
                    id, user_id, name, type, status, port,
                    created_at, updated_at, logs, dependencies,
                    repo_url, branch, build_command, start_command, env_vars
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                deploy_id, user_id, name, deploy_type, 'pending', port,
                datetime.now().isoformat(), datetime.now().isoformat(),
                '', json.dumps([]),
                kwargs.get('repo_url', ''), kwargs.get('branch', 'main'),
                kwargs.get('build_command', ''), kwargs.get('start_command', ''),
                json.dumps({})
            ))
        
        log_activity(user_id, 'DEPLOYMENT_CREATE', f"{name} ({deploy_type})")
        
        if metrics:
            metrics['deployments_total'].labels(type=deploy_type, status='created').inc()
            metrics['active_deployments'].inc()
        
        return deploy_id, port, None
    
    except Exception as e:
        log_error(str(e), "create_deployment", exc_info=e)
        return None, None, str(e)

def update_deployment(deploy_id, **kwargs):
    """Update deployment with auto-refresh"""
    try:
        # Always update timestamp
        kwargs['updated_at'] = datetime.now().isoformat()
        
        # Convert lists/dicts to JSON
        for key in ['dependencies', 'env_vars']:
            if key in kwargs and isinstance(kwargs[key], (list, dict)):
                kwargs[key] = json.dumps(kwargs[key])
        
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys()])
        values = list(kwargs.values()) + [deploy_id]
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(f'UPDATE deployments SET {set_clause} WHERE id = ?', values)
        
        cache.delete(f"deployment:{deploy_id}")
    except Exception as e:
        log_error(str(e), f"update_deployment {deploy_id}", exc_info=e)

def get_deployment(deploy_id):
    """Get deployment data"""
    # Check cache
    cached = cache.get(f"deployment:{deploy_id}")
    if cached:
        return cached
    
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM deployments WHERE id = ?', (deploy_id,))
            row = cursor.fetchone()
            
            if row:
                deploy_data = dict(row)
                # Parse JSON fields
                deploy_data['dependencies'] = json.loads(deploy_data['dependencies'] or '[]')
                deploy_data['env_vars'] = json.loads(deploy_data['env_vars'] or '{}')
                
                cache.set(f"deployment:{deploy_id}", deploy_data, ttl=60)
                return deploy_data
        return None
    except Exception as e:
        log_error(str(e), f"get_deployment {deploy_id}", exc_info=e)
        return None

def deploy_from_file(user_id, file_path, filename):
    """Deploy from uploaded file with enhanced error handling"""
    try:
        cost = CREDIT_COSTS['file_upload']
        if not deduct_credits(user_id, cost, f"File deploy: {filename}"):
            return None, f"❌ Need {cost} credits"
        
        deploy_id, port, error = create_deployment(user_id, filename, 'file_upload')
        
        if not deploy_id:
            add_credits(user_id, cost, "Refund - deployment creation failed")
            return None, error or "Failed to create deployment"
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        user = get_user(user_id)
        
        # Notify owner
        try:
            bot.send_message(
                OWNER_ID,
                f"📤 *FILE DEPLOYMENT*\n\n"
                f"👤 User: {user['email']}\n"
                f"📁 File: `{filename}`\n"
                f"🆔 Deploy ID: `{deploy_id}`\n"
                f"🌐 Port: {port}\n"
                f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        except Exception as e:
            log_error(str(e), "deploy notification", exc_info=e)
        
        # Handle ZIP files
        if filename.endswith('.zip'):
            update_deployment(deploy_id, status='extracting', logs='📦 Extracting ZIP...')
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(deploy_dir)
            except zipfile.BadZipFile:
                update_deployment(deploy_id, status='failed', logs='❌ Invalid ZIP file')
                add_credits(user_id, cost, "Refund - invalid ZIP")
                return None, "❌ Invalid ZIP file"
            
            # Find main file
            main_file = None
            priority_files = ['main.py', 'app.py', 'bot.py', 'index.js', 'server.js', 'app.js']
            
            for root, dirs, files in os.walk(deploy_dir):
                for pf in priority_files:
                    if pf in files:
                        main_file = os.path.join(root, pf)
                        break
                if main_file:
                    break
            
            if not main_file:
                update_deployment(deploy_id, status='failed', logs='❌ No entry point found')
                add_credits(user_id, cost, "Refund - no entry point")
                return None, "❌ No main file found (main.py, app.py, bot.py, index.js, etc.)"
            
            file_path = main_file
        else:
            shutil.copy(file_path, os.path.join(deploy_dir, filename))
            file_path = os.path.join(deploy_dir, filename)
        
        # AI dependency detection
        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        update_deployment(deploy_id, dependencies=installed_deps, 
                         logs=f"{install_log}\n\n🚀 Preparing to launch...")
        
        # Prepare environment
        env = os.environ.copy()
        env['PORT'] = str(port)
        env['DEPLOYMENT_ID'] = deploy_id
        
        deployment = get_deployment(deploy_id)
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = value
        
        # Determine command
        if file_path.endswith('.py'):
            cmd = [sys.executable, '-u', file_path]
        elif file_path.endswith('.js'):
            cmd = ['node', file_path]
        else:
            update_deployment(deploy_id, status='failed', logs='❌ Unsupported file type')
            add_credits(user_id, cost, "Refund - unsupported file")
            return None, "❌ Unsupported file type"
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Launching on port {port}...')
        
        # Start process
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=os.path.dirname(file_path),
                env=env,
                bufsize=1,
                universal_newlines=True
            )
            
            with PROCESS_LOCK:
                active_processes[deploy_id] = {
                    'process': process,
                    'start_time': datetime.now(),
                    'restarts': 0
                }
            
            # Wait a moment to check if it starts successfully
            time.sleep(2)
            
            if process.poll() is not None:
                # Process died immediately
                stdout, _ = process.communicate(timeout=1)
                error_log = f"❌ Process failed to start\n\n{stdout}"
                update_deployment(deploy_id, status='failed', logs=error_log, pid=None)
                add_credits(user_id, cost, "Refund - process failed")
                return None, "❌ Process failed to start. Check logs for details."
            
            update_deployment(deploy_id, status='running', pid=process.pid, 
                            logs=f'✅ Successfully deployed!\n\nPort: {port}\nPID: {process.pid}')
            
            # Start log monitoring in background
            Thread(target=monitor_process_logs, args=(deploy_id, process), daemon=True).start()
            
            return deploy_id, f"🎉 Deployed successfully! Running on port {port}"
        
        except Exception as e:
            log_error(str(e), f"start process {deploy_id}", exc_info=e)
            update_deployment(deploy_id, status='failed', logs=f'❌ Failed to start: {str(e)}')
            add_credits(user_id, cost, "Refund - start failed")
            return None, f"❌ Failed to start: {str(e)}"
    
    except Exception as e:
        log_error(str(e), "deploy_from_file", exc_info=e)
        if 'deploy_id' in locals() and deploy_id:
            update_deployment(deploy_id, status='failed', logs=str(e))
            if 'cost' in locals():
                add_credits(user_id, cost, "Refund - unexpected error")
        return None, str(e)

def monitor_process_logs(deploy_id, process):
    """Monitor and store process logs"""
    try:
        log_buffer = []
        max_log_lines = 1000
        
        for line in iter(process.stdout.readline, ''):
            if not line:
                break
            
            log_buffer.append(line.rstrip())
            
            # Keep only last max_log_lines
            if len(log_buffer) > max_log_lines:
                log_buffer = log_buffer[-max_log_lines:]
            
            # Update logs every 10 lines
            if len(log_buffer) % 10 == 0:
                update_deployment(deploy_id, logs='\n'.join(log_buffer[-100:]))
        
        # Final update
        if log_buffer:
            update_deployment(deploy_id, logs='\n'.join(log_buffer[-100:]))
        
        # Check if process ended
        return_code = process.wait()
        if return_code != 0:
            update_deployment(deploy_id, status='crashed', 
                            logs=f"Process exited with code {return_code}\n\n" + '\n'.join(log_buffer[-100:]))
            
            # Auto-restart logic (optional)
            with PROCESS_LOCK:
                if deploy_id in active_processes:
                    proc_data = active_processes[deploy_id]
                    if proc_data['restarts'] < 3:
                        logger.warning(f"Auto-restarting deployment {deploy_id}")
                        # TODO: Implement auto-restart
    
    except Exception as e:
        log_error(str(e), f"monitor_process_logs {deploy_id}", exc_info=e)

def deploy_from_github(user_id, repo_url, branch='main', build_cmd='', start_cmd=''):
    """Deploy from GitHub with enhanced validation"""
    try:
        cost = CREDIT_COSTS['github_deploy']
        if not deduct_credits(user_id, cost, f"GitHub: {repo_url}"):
            return None, f"❌ Need {cost} credits"
        
        # Validate GitHub URL
        if not re.match(r'https?://github\.com/[\w-]+/[\w.-]+', repo_url):
            add_credits(user_id, cost, "Refund - invalid URL")
            return None, "❌ Invalid GitHub URL"
        
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        deploy_id, port, error = create_deployment(
            user_id, repo_name, 'github',
            repo_url=repo_url, branch=branch,
            build_command=build_cmd, start_command=start_cmd
        )
        
        if not deploy_id:
            add_credits(user_id, cost, "Refund - deployment creation failed")
            return None, error or "Failed to create deployment"
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        user = get_user(user_id)
        
        # Notify owner
        try:
            bot.send_message(
                OWNER_ID,
                f"🐙 *GITHUB DEPLOYMENT*\n\n"
                f"👤 User: {user['email']}\n"
                f"📦 Repo: `{repo_url}`\n"
                f"🌿 Branch: `{branch}`\n"
                f"🆔 Deploy ID: `{deploy_id}`\n"
                f"🌐 Port: {port}\n"
                f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        except Exception as e:
            log_error(str(e), "github deploy notification", exc_info=e)
        
        # Clone repository
        update_deployment(deploy_id, status='cloning', logs=f'🔄 Cloning {repo_url} (branch: {branch})...')
        
        try:
            result = subprocess.run(
                ['git', 'clone', '-b', branch, '--depth', '1', repo_url, deploy_dir],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode != 0:
                error_msg = f"❌ Git clone failed\n\n{result.stderr}"
                update_deployment(deploy_id, status='failed', logs=error_msg)
                add_credits(user_id, cost, "Refund - clone failed")
                return None, "❌ Failed to clone repository. Check URL and branch."
        
        except subprocess.TimeoutExpired:
            update_deployment(deploy_id, status='failed', logs='❌ Clone timeout (>10 minutes)')
            add_credits(user_id, cost, "Refund - clone timeout")
            return None, "❌ Clone took too long (timeout)"
        
        except FileNotFoundError:
            update_deployment(deploy_id, status='failed', logs='❌ git not installed')
            add_credits(user_id, cost, "Refund - git unavailable")
            return None, "❌ Git is not available on this system"
        
        # Build command (if provided)
        if build_cmd:
            update_deployment(deploy_id, status='building', logs=f'🔨 Building: {build_cmd}')
            try:
                build_result = subprocess.run(
                    build_cmd,
                    shell=True,
                    cwd=deploy_dir,
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                
                if build_result.returncode != 0:
                    error_msg = f"❌ Build failed\n\n{build_result.stderr}"
                    update_deployment(deploy_id, status='failed', logs=error_msg)
                    add_credits(user_id, cost, "Refund - build failed")
                    return None, "❌ Build command failed"
            
            except subprocess.TimeoutExpired:
                update_deployment(deploy_id, status='failed', logs='❌ Build timeout')
                add_credits(user_id, cost, "Refund - build timeout")
                return None, "❌ Build took too long"
        
        # AI dependency detection
        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        update_deployment(deploy_id, dependencies=installed_deps,
                         logs=f"{install_log}\n\n🚀 Preparing to launch...")
        
        # Determine start command
        if not start_cmd:
            priority_files = {
                'main.py': f'{sys.executable} -u main.py',
                'app.py': f'{sys.executable} -u app.py',
                'bot.py': f'{sys.executable} -u bot.py',
                'server.py': f'{sys.executable} -u server.py',
                'index.js': 'node index.js',
                'server.js': 'node server.js',
                'app.js': 'node app.js',
            }
            
            for file, cmd in priority_files.items():
                if os.path.exists(os.path.join(deploy_dir, file)):
                    start_cmd = cmd
                    break
        
        if not start_cmd:
            update_deployment(deploy_id, status='failed', 
                            logs='❌ No start command specified and no main file found')
            add_credits(user_id, cost, "Refund - no start command")
            return None, "❌ Please specify a start command"
        
        # Prepare environment
        env = os.environ.copy()
        env['PORT'] = str(port)
        env['DEPLOYMENT_ID'] = deploy_id
        
        deployment = get_deployment(deploy_id)
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = value
        
        update_deployment(deploy_id, status='starting', 
                         logs=f'🚀 Starting: {start_cmd}\nPort: {port}')
        
        # Start process
        try:
            process = subprocess.Popen(
                start_cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=deploy_dir,
                env=env,
                bufsize=1,
                universal_newlines=True
            )
            
            with PROCESS_LOCK:
                active_processes[deploy_id] = {
                    'process': process,
                    'start_time': datetime.now(),
                    'restarts': 0
                }
            
            # Wait to check if it starts successfully
            time.sleep(2)
            
            if process.poll() is not None:
                stdout, _ = process.communicate(timeout=1)
                error_log = f"❌ Process failed to start\n\n{stdout}"
                update_deployment(deploy_id, status='failed', logs=error_log, pid=None)
                add_credits(user_id, cost, "Refund - process failed")
                return None, "❌ Process failed to start. Check logs."
            
            update_deployment(deploy_id, status='running', pid=process.pid,
                            start_command=start_cmd,
                            logs=f'✅ Successfully deployed!\n\nPort: {port}\nPID: {process.pid}')
            
            # Start log monitoring
            Thread(target=monitor_process_logs, args=(deploy_id, process), daemon=True).start()
            
            return deploy_id, f"🎉 Deployed successfully! Running on port {port}"
        
        except Exception as e:
            log_error(str(e), f"start github process {deploy_id}", exc_info=e)
            update_deployment(deploy_id, status='failed', logs=f'❌ Failed to start: {str(e)}')
            add_credits(user_id, cost, "Refund - start failed")
            return None, f"❌ Failed to start: {str(e)}"
    
    except Exception as e:
        log_error(str(e), "deploy_from_github", exc_info=e)
        if 'deploy_id' in locals() and deploy_id:
            update_deployment(deploy_id, status='failed', logs=str(e))
            if 'cost' in locals():
                add_credits(user_id, cost, "Refund - unexpected error")
        return None, str(e)

def stop_deployment(deploy_id):
    """Stop deployment gracefully"""
    try:
        with PROCESS_LOCK:
            if deploy_id not in active_processes:
                return False, "Not running"
            
            proc_data = active_processes[deploy_id]
            process = proc_data['process']
        
        # Try graceful shutdown first
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Force kill if necessary
            process.kill()
            process.wait(timeout=2)
        
        with PROCESS_LOCK:
            del active_processes[deploy_id]
        
        update_deployment(deploy_id, status='stopped', logs='🛑 Deployment stopped', pid=None)
        
        if metrics:
            metrics['active_deployments'].dec()
        
        return True, "Stopped successfully"
    
    except Exception as e:
        log_error(str(e), f"stop_deployment {deploy_id}", exc_info=e)
        return False, str(e)

def delete_deployment(deploy_id):
    """Delete deployment and cleanup"""
    try:
        # Stop if running
        stop_deployment(deploy_id)
        
        # Delete files
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if os.path.exists(deploy_dir):
            shutil.rmtree(deploy_dir, ignore_errors=True)
        
        # Delete from database
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM deployments WHERE id = ?', (deploy_id,))
        
        cache.delete(f"deployment:{deploy_id}")
        
        if metrics:
            metrics['deployments_total'].labels(type='any', status='deleted').inc()
        
        return True, "Deleted successfully"
    
    except Exception as e:
        log_error(str(e), f"delete_deployment {deploy_id}", exc_info=e)
        return False, str(e)

def create_backup(deploy_id):
    """Create deployment backup"""
    try:
        deployment = get_deployment(deploy_id)
        if not deployment:
            return None, "Deployment not found"
        
        user_id = deployment['user_id']
        
        cost = CREDIT_COSTS['backup']
        if not deduct_credits(user_id, cost, f"Backup: {deployment['name']}"):
            return None, f"❌ Need {cost} credits"
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if not os.path.exists(deploy_dir):
            add_credits(user_id, cost, "Refund - directory not found")
            return None, "Deployment directory not found"
        
        backup_name = f"{deployment['name']}_{deploy_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        backup_path = os.path.join(BACKUPS_DIR, backup_name)
        
        # Create ZIP backup
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(deploy_dir):
                # Skip .git directory
                dirs[:] = [d for d in dirs if d != '.git']
                
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, deploy_dir)
                    zipf.write(file_path, arcname)
        
        logger.info(f"Backup created: {backup_name}")
        return backup_path, backup_name
    
    except Exception as e:
        log_error(str(e), f"create_backup {deploy_id}", exc_info=e)
        if 'user_id' in locals() and 'cost' in locals():
            add_credits(user_id, cost, "Refund - backup failed")
        return None, str(e)

def get_deployment_files(deploy_id):
    """Get list of files in deployment"""
    try:
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if not os.path.exists(deploy_dir):
            return []
        
        files = []
        for root, dirs, filenames in os.walk(deploy_dir):
            # Skip .git
            dirs[:] = [d for d in dirs if d != '.git']
            
            for filename in filenames:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, deploy_dir)
                
                try:
                    size = os.path.getsize(file_path)
                    modified = datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                    
                    files.append({
                        'name': filename,
                        'path': rel_path,
                        'size': size,
                        'modified': modified
                    })
                except:
                    continue
        
        return files
    
    except Exception as e:
        log_error(str(e), f"get_deployment_files {deploy_id}", exc_info=e)
        return []

def get_system_metrics():
    """Get system resource metrics"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            'cpu': round(cpu_percent, 1),
            'memory_percent': round(memory.percent, 1),
            'memory_used': round(memory.used / (1024**3), 2),
            'memory_total': round(memory.total / (1024**3), 2),
            'disk_percent': round(disk.percent, 1),
            'disk_used': round(disk.used / (1024**3), 2),
            'disk_total': round(disk.total / (1024**3), 2),
            'active_processes': len(active_processes)
        }
    
    except Exception as e:
        log_error(str(e), "get_system_metrics", exc_info=e)
        return {
            'cpu': 0, 'memory_percent': 0, 'memory_used': 0,
            'memory_total': 0, 'disk_percent': 0, 'disk_used': 0,
            'disk_total': 0, 'active_processes': 0
        }


# ==================== FLASK ROUTES (Enhanced) ====================

# Request timing middleware
@app.before_request
def before_request():
    request.start_time = time.time()
    
    # Check if device is banned
    fingerprint = get_device_fingerprint(request)
    if is_device_banned(fingerprint):
        return jsonify({'error': 'Access denied'}), 403

@app.after_request
def after_request(response):
    # Record metrics
    if metrics and hasattr(request, 'start_time'):
        duration = time.time() - request.start_time
        metrics['request_duration'].observe(duration)
        metrics['requests_total'].labels(
            method=request.method,
            endpoint=request.endpoint or 'unknown',
            status=response.status_code
        ).inc()
    
    # Security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# ==================== AUTH ROUTES ====================

@app.route('/')
def index():
    """Landing page"""
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if user_id:
        return redirect('/dashboard')
    
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def register():
    """User registration"""
    if request.method == 'GET':
        error = request.args.get('error', '')
        success = request.args.get('success', '')
        
        return render_template_string(LOGIN_PAGE,
            title='Register',
            subtitle='Create your EliteHost account',
            action='/register',
            button_text='Create Account',
            icon='user-plus',
            toggle_text='Already have an account?',
            toggle_link='/login',
            toggle_action='Login',
            error=error,
            success=success
        )
    
    try:
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        fingerprint = get_device_fingerprint(request)
        ip = request.remote_addr
        
        # Validation
        if not email or not password:
            return redirect('/register?error=Email and password required')
        
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            return redirect('/register?error=Invalid email format')
        
        if len(password) < 6:
            return redirect('/register?error=Password must be at least 6 characters')
        
        # Check for existing account on this device
        existing_user_id = check_existing_account(fingerprint)
        if existing_user_id:
            return redirect('/register?error=Device already has an account. Use /login')
        
        # Check if email exists
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                return redirect('/register?error=Email already registered')
        
        # Create user
        user_id = create_user(email, password, fingerprint, ip)
        
        if not user_id:
            return redirect('/register?error=Registration failed. Try again.')
        
        # Create session
        session_token = create_session(user_id, fingerprint)
        
        response = make_response(redirect('/dashboard'))
        response.set_cookie('session_token', session_token, 
                          max_age=SESSION_TIMEOUT_DAYS*86400,
                          httponly=True, samesite='Lax')
        
        return response
    
    except Exception as e:
        log_error(str(e), "register", exc_info=e)
        return redirect('/register?error=An error occurred')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per hour")
def login():
    """User login"""
    if request.method == 'GET':
        error = request.args.get('error', '')
        success = request.args.get('success', '')
        
        return render_template_string(LOGIN_PAGE,
            title='Login',
            subtitle='Sign in to your account',
            action='/login',
            button_text='Sign In',
            icon='sign-in-alt',
            toggle_text="Don't have an account?",
            toggle_link='/register',
            toggle_action='Register',
            error=error,
            success=success
        )
    
    try:
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        fingerprint = get_device_fingerprint(request)
        ip = request.remote_addr
        
        # Check rate limiting
        if check_login_attempts(ip):
            return redirect(f'/login?error=Too many failed attempts. Try again in {LOGIN_ATTEMPT_WINDOW//60} minutes')
        
        # Authenticate
        user_id = authenticate_user(email, password)
        
        if not user_id:
            record_login_attempt(ip)
            return redirect('/login?error=Invalid email or password')
        
        user = get_user(user_id)
        
        # Check if banned
        if user.get('is_banned'):
            return redirect('/login?error=Account banned. Contact support')
        
        # Check device fingerprint
        if user['device_fingerprint'] != fingerprint:
            # Device changed - potential security issue
            ban_device(fingerprint, "Device mismatch on login")
            return redirect('/login?error=Security error. Contact support')
        
        # Update last login
        update_user(user_id, last_login=datetime.now().isoformat())
        log_activity(user_id, 'USER_LOGIN', f'Login from {ip}', ip)
        
        # Create session
        session_token = create_session(user_id, fingerprint)
        
        response = make_response(redirect('/dashboard'))
        response.set_cookie('session_token', session_token,
                          max_age=SESSION_TIMEOUT_DAYS*86400,
                          httponly=True, samesite='Lax')
        
        return response
    
    except Exception as e:
        log_error(str(e), "login", exc_info=e)
        return redirect('/login?error=An error occurred')

@app.route('/logout')
def logout():
    """User logout"""
    session_token = request.cookies.get('session_token')
    
    if session_token:
        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM sessions WHERE token = ?', (session_token,))
            cache.delete(f"session:{session_token}")
        except Exception as e:
            log_error(str(e), "logout", exc_info=e)
    
    response = make_response(redirect('/login?success=Logged out successfully'))
    response.set_cookie('session_token', '', expires=0)
    
    return response

@app.route('/dashboard')
def dashboard():
    """Main dashboard"""
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    
    user_id = verify_session(session_token, fingerprint)
    if not user_id:
        return redirect('/login?error=Please login first')
    
    user = get_user(user_id)
    if not user or user.get('is_banned'):
        return redirect('/login?error=Access denied')
    
    is_admin = (str(user_id) == str(OWNER_ID) or 
                str(user_id) == str(ADMIN_ID) or 
                user['email'] == ADMIN_EMAIL)
    
    credits_display = '∞' if user['credits'] == float('inf') else user['credits']
    
    return render_template_string(DASHBOARD_HTML,
        credits=credits_display,
        is_admin=is_admin,
        telegram_link=TELEGRAM_LINK,
        username=YOUR_USERNAME
    )

@app.route('/admin')
def admin_panel():
    """Admin control panel"""
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    
    user_id = verify_session(session_token, fingerprint)
    if not user_id:
        return redirect('/login?error=Please login first')
    
    user = get_user(user_id)
    is_admin = (str(user_id) == str(OWNER_ID) or 
                str(user_id) == str(ADMIN_ID) or 
                user['email'] == ADMIN_EMAIL)
    
    if not is_admin:
        return redirect('/dashboard?error=Admin access denied')
    
    try:
        # Get statistics
        with get_db() as conn:
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) as count FROM users')
            total_users = cursor.fetchone()['count']
            
            cursor.execute('SELECT COUNT(*) as count FROM deployments')
            total_deployments = cursor.fetchone()['count']
            
            cursor.execute('''
                SELECT COUNT(*) as count FROM payments 
                WHERE status = 'submitted'
            ''')
            pending_payments = cursor.fetchone()['count']
        
        stats = {
            'total_users': total_users,
            'total_deployments': total_deployments,
            'active_processes': len(active_processes),
            'pending_payments': pending_payments
        }
        
        # Get all users
        users = []
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, email, credits, created_at, is_banned
                FROM users
                ORDER BY created_at DESC
            ''')
            
            for row in cursor.fetchall():
                user_data = dict(row)
                
                # Get deployment count
                cursor.execute('''
                    SELECT COUNT(*) as count FROM deployments 
                    WHERE user_id = ?
                ''', (user_data['id'],))
                user_data['deployments'] = [None] * cursor.fetchone()['count']
                
                users.append(user_data)
        
        # Get payments
        payments = []
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM payments
                ORDER BY 
                    CASE status
                        WHEN 'submitted' THEN 1
                        WHEN 'pending' THEN 2
                        WHEN 'approved' THEN 3
                        WHEN 'rejected' THEN 4
                        ELSE 5
                    END,
                    created_at DESC
                LIMIT 100
            ''')
            
            payments = [dict(row) for row in cursor.fetchall()]
        
        return render_template_string(ADMIN_PANEL_HTML,
            stats=stats,
            users=users,
            payments=payments
        )
    
    except Exception as e:
        log_error(str(e), "admin_panel", exc_info=e)
        return redirect('/dashboard?error=Error loading admin panel')

# ==================== STATIC FILES ====================

@app.route('/logo.jpg')
def serve_logo():
    """Serve logo image"""
    logo_path = os.path.join(STATIC_DIR, 'logo.jpg')
    if os.path.exists(logo_path):
        return send_file(logo_path, mimetype='image/jpeg')
    
    # Generate placeholder if not exists
    if QRCODE_AVAILABLE:
        try:
            from PIL import Image, ImageDraw, ImageFont
            
            img = Image.new('RGB', (200, 200), color='#3b82f6')
            draw = ImageDraw.Draw(img)
            
            # Draw "EH" text
            try:
                font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 80)
            except:
                font = ImageFont.load_default()
            
            draw.text((50, 60), "EH", fill='white', font=font)
            
            img.save(logo_path, 'JPEG')
            return send_file(logo_path, mimetype='image/jpeg')
        except:
            pass
    
    return '', 404

@app.route('/qr.jpg')
def serve_qr():
    """Serve payment QR code"""
    qr_path = os.path.join(STATIC_DIR, 'qr.jpg')
    
    # Try to serve existing QR
    if os.path.exists(qr_path):
        return send_file(qr_path, mimetype='image/jpeg')
    
    # Generate QR code
    if QRCODE_AVAILABLE:
        try:
            qr_buffer = generate_payment_qr(UPI_ID, 0, "EliteHost")
            if qr_buffer:
                with open(qr_path, 'wb') as f:
                    f.write(qr_buffer.getvalue())
                return send_file(qr_path, mimetype='image/jpeg')
        except Exception as e:
            log_error(str(e), "serve_qr", exc_info=e)
    
    return '', 404

# ==================== API ROUTES ====================

@app.route('/api/credits')
@limiter.limit("60 per minute")
def api_credits():
    """Get user credits"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        credits = get_credits(user_id)
        
        return jsonify({
            'success': True,
            'credits': credits
        })
    
    except Exception as e:
        log_error(str(e), "api_credits", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployments')
@limiter.limit("60 per minute")
def api_deployments():
    """Get user deployments"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM deployments 
                WHERE user_id = ?
                ORDER BY created_at DESC
            ''', (user_id,))
            
            deployments = []
            for row in cursor.fetchall():
                deploy = dict(row)
                deploy['dependencies'] = json.loads(deploy['dependencies'] or '[]')
                deploy['env_vars'] = json.loads(deploy['env_vars'] or '{}')
                deployments.append(deploy)
        
        return jsonify({
            'success': True,
            'deployments': deployments
        })
    
    except Exception as e:
        log_error(str(e), "api_deployments", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deploy/upload', methods=['POST'])
@limiter.limit("10 per hour")
def api_deploy_upload():
    """Upload and deploy file"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        # Validate file
        filename = secure_filename(file.filename)
        file_ext = os.path.splitext(filename)[1].lower()
        
        if file_ext not in ALLOWED_EXTENSIONS:
            return jsonify({'success': False, 'error': f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}'})
        
        # Save file temporarily
        upload_path = os.path.join(UPLOADS_DIR, f"{user_id}_{int(time.time())}_{filename}")
        file.save(upload_path)
        
        # Check file size
        file_size = os.path.getsize(upload_path)
        if file_size > MAX_FILE_SIZE:
            os.remove(upload_path)
            return jsonify({'success': False, 'error': f'File too large (max {MAX_FILE_SIZE/1024/1024}MB)'})
        
        # Deploy
        deploy_id, message = deploy_from_file(user_id, upload_path, filename)
        
        # Cleanup temporary file
        try:
            os.remove(upload_path)
        except:
            pass
        
        if deploy_id:
            return jsonify({
                'success': True,
                'deploy_id': deploy_id,
                'message': message
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            })
    
    except Exception as e:
        log_error(str(e), "api_deploy_upload", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deploy/github', methods=['POST'])
@limiter.limit("5 per hour")
def api_deploy_github():
    """Deploy from GitHub"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        
        repo_url = data.get('url', '').strip()
        branch = data.get('branch', 'main').strip()
        build_cmd = data.get('build_command', '').strip()
        start_cmd = data.get('start_command', '').strip()
        
        if not repo_url:
            return jsonify({'success': False, 'error': 'Repository URL required'})
        
        deploy_id, message = deploy_from_github(user_id, repo_url, branch, build_cmd, start_cmd)
        
        if deploy_id:
            return jsonify({
                'success': True,
                'deploy_id': deploy_id,
                'message': message
            })
        else:
            return jsonify({
                'success': False,
                'error': message
            })
    
    except Exception as e:
        log_error(str(e), "api_deploy_github", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>/stop', methods=['POST'])
@limiter.limit("30 per minute")
def api_stop_deployment(deploy_id):
    """Stop deployment"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        # Verify ownership
        deployment = get_deployment(deploy_id)
        if not deployment:
            return jsonify({'success': False, 'error': 'Deployment not found'})
        
        if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
            return jsonify({'success': False, 'error': 'Access denied'})
        
        success, message = stop_deployment(deploy_id)
        
        return jsonify({
            'success': success,
            'message': message
        })
    
    except Exception as e:
        log_error(str(e), f"api_stop_deployment {deploy_id}", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>', methods=['DELETE'])
@limiter.limit("30 per minute")
def api_delete_deployment(deploy_id):
    """Delete deployment"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        # Verify ownership
        deployment = get_deployment(deploy_id)
        if not deployment:
            return jsonify({'success': False, 'error': 'Deployment not found'})
        
        if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
            return jsonify({'success': False, 'error': 'Access denied'})
        
        success, message = delete_deployment(deploy_id)
        
        return jsonify({
            'success': success,
            'message': message
        })
    
    except Exception as e:
        log_error(str(e), f"api_delete_deployment {deploy_id}", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>/logs')
@limiter.limit("60 per minute")
def api_deployment_logs(deploy_id):
    """Get deployment logs"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        deployment = get_deployment(deploy_id)
        if not deployment:
            return jsonify({'success': False, 'error': 'Deployment not found'})
        
        if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
            return jsonify({'success': False, 'error': 'Access denied'})
        
        return jsonify({
            'success': True,
            'logs': deployment.get('logs', '')
        })
    
    except Exception as e:
        log_error(str(e), f"api_deployment_logs {deploy_id}", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>/files')
@limiter.limit("60 per minute")
def api_deployment_files(deploy_id):
    """Get deployment files"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        deployment = get_deployment(deploy_id)
        if not deployment:
            return jsonify({'success': False, 'error': 'Deployment not found'})
        
        if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
            return jsonify({'success': False, 'error': 'Access denied'})
        
        files = get_deployment_files(deploy_id)
        
        return jsonify({
            'success': True,
            'files': files
        })
    
    except Exception as e:
        log_error(str(e), f"api_deployment_files {deploy_id}", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>/env', methods=['POST'])
@limiter.limit("30 per minute")
def api_add_env_var(deploy_id):
    """Add environment variable"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        deployment = get_deployment(deploy_id)
        if not deployment:
            return jsonify({'success': False, 'error': 'Deployment not found'})
        
        if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
            return jsonify({'success': False, 'error': 'Access denied'})
        
        data = request.get_json()
        key = data.get('key', '').strip()
        value = data.get('value', '').strip()
        
        if not key:
            return jsonify({'success': False, 'error': 'Key required'})
        
        env_vars = deployment.get('env_vars', {})
        env_vars[key] = value
        
        update_deployment(deploy_id, env_vars=env_vars)
        
        return jsonify({
            'success': True,
            'env_vars': env_vars
        })
    
    except Exception as e:
        log_error(str(e), f"api_add_env_var {deploy_id}", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>/env/<key>', methods=['DELETE'])
@limiter.limit("30 per minute")
def api_delete_env_var(deploy_id, key):
    """Delete environment variable"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        deployment = get_deployment(deploy_id)
        if not deployment:
            return jsonify({'success': False, 'error': 'Deployment not found'})
        
        if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
            return jsonify({'success': False, 'error': 'Access denied'})
        
        env_vars = deployment.get('env_vars', {})
        env_vars.pop(key, None)
        
        update_deployment(deploy_id, env_vars=env_vars)
        
        return jsonify({
            'success': True,
            'env_vars': env_vars
        })
    
    except Exception as e:
        log_error(str(e), f"api_delete_env_var {deploy_id}", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>/backup', methods=['POST'])
@limiter.limit("10 per hour")
def api_create_backup(deploy_id):
    """Create backup"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        deployment = get_deployment(deploy_id)
        if not deployment:
            return jsonify({'success': False, 'error': 'Deployment not found'})
        
        if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
            return jsonify({'success': False, 'error': 'Access denied'})
        
        backup_path, backup_name = create_backup(deploy_id)
        
        if backup_path:
            return jsonify({
                'success': True,
                'backup_name': backup_name
            })
        else:
            return jsonify({
                'success': False,
                'error': backup_name
            })
    
    except Exception as e:
        log_error(str(e), f"api_create_backup {deploy_id}", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>/backup/download')
def api_download_backup(deploy_id):
    """Download backup"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        deployment = get_deployment(deploy_id)
        if not deployment:
            return jsonify({'success': False, 'error': 'Deployment not found'})
        
        if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
            return jsonify({'success': False, 'error': 'Access denied'})
        
        # Find latest backup for this deployment
        backup_files = [f for f in os.listdir(BACKUPS_DIR) if f.startswith(f"{deployment['name']}_{deploy_id}")]
        
        if not backup_files:
            return jsonify({'success': False, 'error': 'No backup found'})
        
        # Get most recent
        backup_files.sort(reverse=True)
        backup_path = os.path.join(BACKUPS_DIR, backup_files[0])
        
        return send_file(backup_path, as_attachment=True, download_name=backup_files[0])
    
    except Exception as e:
        log_error(str(e), f"api_download_backup {deploy_id}", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

# ==================== PAYMENT API ROUTES ====================

@app.route('/api/payment/create', methods=['POST'])
@limiter.limit("10 per hour")
def api_create_payment():
    """Create payment request"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        package_type = data.get('package_type')
        custom_amount = data.get('custom_amount')
        
        payment_id, payment_data = create_payment_request(user_id, package_type, custom_amount)
        
        if payment_id:
            return jsonify({'success': True, 'payment': payment_data})
        else:
            return jsonify({'success': False, 'error': payment_data})
    
    except Exception as e:
        log_error(str(e), "api_create_payment", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/payment/submit', methods=['POST'])
@limiter.limit("10 per hour")
def api_submit_payment():
    """Submit payment proof"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        payment_id = data.get('payment_id')
        screenshot = data.get('screenshot')
        transaction_id = data.get('transaction_id')
        
        success, message = submit_payment_proof(payment_id, screenshot, transaction_id)
        
        return jsonify({'success': success, 'message': message})
    
    except Exception as e:
        log_error(str(e), "api_submit_payment", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/payment/<payment_id>/screenshot')
def api_payment_screenshot(payment_id):
    """View payment screenshot"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return 'Not authenticated', 403
        
        user = get_user(user_id)
        is_admin = (str(user_id) == str(OWNER_ID) or 
                   str(user_id) == str(ADMIN_ID) or 
                   user['email'] == ADMIN_EMAIL)
        
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
            row = cursor.fetchone()
            
            if not row:
                return 'Not found', 404
            
            payment = dict(row)
        
        # Only admin or payment owner can view
        if not is_admin and payment['user_id'] != user_id:
            return 'Access denied', 403
        
        screenshot_path = payment.get('screenshot_path')
        
        if screenshot_path and os.path.exists(screenshot_path):
            return send_file(screenshot_path, mimetype='image/jpeg')
        
        return 'Screenshot not found', 404
    
    except Exception as e:
        log_error(str(e), f"api_payment_screenshot {payment_id}", exc_info=e)
        return str(e), 500

# ==================== ADMIN API ROUTES ====================

@app.route('/api/admin/metrics')
@limiter.limit("60 per minute")
def api_admin_metrics():
    """Get system metrics (admin only)"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        user = get_user(user_id)
        is_admin = (str(user_id) == str(OWNER_ID) or 
                   str(user_id) == str(ADMIN_ID) or 
                   user['email'] == ADMIN_EMAIL)
        
        if not is_admin:
            return jsonify({'success': False, 'error': 'Access denied'})
        
        metrics = get_system_metrics()
        
        return jsonify({
            'success': True,
            'metrics': metrics
        })
    
    except Exception as e:
        log_error(str(e), "api_admin_metrics", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/add-credits', methods=['POST'])
@limiter.limit("30 per minute")
def api_admin_add_credits():
    """Add credits to user (admin only)"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        user = get_user(user_id)
        is_admin = (str(user_id) == str(OWNER_ID) or 
                   str(user_id) == str(ADMIN_ID) or 
                   user['email'] == ADMIN_EMAIL)
        
        if not is_admin:
            return jsonify({'success': False, 'error': 'Access denied'})
        
        data = request.get_json()
        target_user_id = data.get('user_id')
        amount = float(data.get('amount', 0))
        
        if amount <= 0:
            return jsonify({'success': False, 'error': 'Invalid amount'})
        
        success = add_credits(target_user_id, amount, f"Admin credit by {user['email']}")
        
        if success:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to add credits'})
    
    except Exception as e:
        log_error(str(e), "api_admin_add_credits", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/ban-user', methods=['POST'])
@limiter.limit("30 per minute")
def api_admin_ban_user():
    """Ban/unban user (admin only)"""
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        user = get_user(user_id)
        is_admin = (str(user_id) == str(OWNER_ID) or 
                   str(user_id) == str(ADMIN_ID) or 
                   user['email'] == ADMIN_EMAIL)
        
        if not is_admin:
            return jsonify({'success': False, 'error': 'Access denied'})
        
        data = request.get_json()
        target_user_id = data.get('user_id')
        ban = data.get('ban', True)
        
        update_user(target_user_id, is_banned=1 if ban else 0)
        
        # Also ban device if banning user
        if ban:
            target_user = get_user(target_user_id)
            if target_user:
                ban_device(target_user['device_fingerprint'], f"User banned by admin")
        
        return jsonify({'success': True})
    
    except Exception as e:
        log_error(str(e), "api_admin_ban_user", exc_info=e)
        return jsonify({'success': False, 'error': str(e)})

# ==================== PROMETHEUS METRICS ENDPOINT ====================

if ENABLE_METRICS:
    @app.route('/metrics')
    def prometheus_metrics():
        """Prometheus metrics endpoint"""
        return generate_latest(), 200, {'Content-Type': 'text/plain; charset=utf-8'}

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    log_error(str(e), "internal_error", exc_info=e)
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429

# ==================== BACKGROUND TASKS ====================

def cleanup_expired_sessions():
    """Cleanup expired sessions periodically"""
    while True:
        try:
            time.sleep(3600)  # Every hour
            
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    DELETE FROM sessions 
                    WHERE expires_at < ?
                ''', (datetime.now().isoformat(),))
                
                deleted = cursor.rowcount
                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} expired sessions")
        
        except Exception as e:
            log_error(str(e), "cleanup_expired_sessions", exc_info=e)

def monitor_deployments():
    """Monitor deployment health"""
    while True:
        try:
            time.sleep(30)  # Every 30 seconds
            
            with PROCESS_LOCK:
                for deploy_id, proc_data in list(active_processes.items()):
                    process = proc_data['process']
                    
                    # Check if process is still running
                    if process.poll() is not None:
                        # Process died
                        return_code = process.returncode
                        
                        deployment = get_deployment(deploy_id)
                        if deployment and deployment['status'] == 'running':
                            update_deployment(
                                deploy_id,
                                status='crashed',
                                logs=f"Process exited with code {return_code}"
                            )
                            
                            logger.warning(f"Deployment {deploy_id} crashed (exit code: {return_code})")
                            
                            # Remove from active processes
                            del active_processes[deploy_id]
                            
                            if metrics:
                                metrics['active_deployments'].dec()
        
        except Exception as e:
            log_error(str(e), "monitor_deployments", exc_info=e)

def cleanup_old_backups():
    """Cleanup old backup files"""
    while True:
        try:
            time.sleep(86400)  # Every 24 hours
            
            cutoff_date = datetime.now() - timedelta(days=30)
            deleted_count = 0
            
            for filename in os.listdir(BACKUPS_DIR):
                filepath = os.path.join(BACKUPS_DIR, filename)
                
                if os.path.isfile(filepath):
                    mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    
                    if mtime < cutoff_date:
                        os.remove(filepath)
                        deleted_count += 1
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old backups")
        
        except Exception as e:
            log_error(str(e), "cleanup_old_backups", exc_info=e)

# ==================== STARTUP & SHUTDOWN ====================

def run_flask():
    """Run Flask app"""
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False, threaded=True)

def keep_alive():
    """Start Flask in separate thread"""
    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()
    
    port = os.environ.get('PORT', 8080)
    logger.info(f"{Fore.GREEN}✅ Web App: http://localhost:{port}")

def run_bot():
    """Run Telegram bot polling"""
    try:
        logger.info(f"{Fore.GREEN}🤖 Starting Telegram Bot...")
        bot.infinity_polling(timeout=10, long_polling_timeout=5)
    except Exception as e:
        log_error(str(e), "Telegram bot", exc_info=e)

def cleanup_on_exit():
    """Cleanup on shutdown"""
    logger.warning(f"{Fore.YELLOW}🛑 Shutting down EliteHost...")
    
    # Stop all deployments
    with PROCESS_LOCK:
        for deploy_id, proc_data in list(active_processes.items()):
            try:
                process = proc_data['process']
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            except Exception as e:
                log_error(str(e), f"cleanup deployment {deploy_id}", exc_info=e)
    
    # Cancel payment timers
    for payment_id, timer in list(payment_timers.items()):
        try:
            timer.cancel()
        except:
            pass
    
    logger.warning(f"{Fore.GREEN}✅ Cleanup complete")

atexit.register(cleanup_on_exit)

def signal_handler(sig, frame):
    """Handle termination signals"""
    cleanup_on_exit()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "=" * 90)
    print(f"{Fore.CYAN}{'🚀 ELITEHOST v13.0 - PROFESSIONAL EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}✨ ENTERPRISE FEATURES:")
    print(f"{Fore.CYAN}   🗄️  SQLite Database (Scalable)")
    print(f"{Fore.CYAN}   🔒 Advanced Security (Rate Limiting, CSRF Protection)")
    print(f"{Fore.CYAN}   💳 Complete Payment Gateway")
    print(f"{Fore.CYAN}   📊 Prometheus Metrics" + (" (Enabled)" if ENABLE_METRICS else " (Disabled)"))
    print(f"{Fore.CYAN}   🚦 Redis Caching" + (" (Enabled)" if ENABLE_REDIS_CACHE else " (Disabled)"))
    print(f"{Fore.CYAN}   🐛 Sentry Error Tracking" + (" (Enabled)" if ENABLE_SENTRY else " (Disabled)"))
    print(f"{Fore.CYAN}   🤖 AI Auto-Deploy & Dependency Detection")
    print(f"{Fore.CYAN}   📈 Auto-Scaling & Health Monitoring")
    print(f"{Fore.CYAN}   💾 Automated Backups")
    print(f"{Fore.CYAN}   🔄 Auto-Recovery (Process Monitoring)")
    print(f"{Fore.CYAN}   📱 Telegram Bot Integration")
    print(f"{Fore.CYAN}   🎨 Modern Blue UI Design")
    print(f"{Fore.CYAN}   📝 Enhanced Logging & Error Tracking")
    print("=" * 90)
    
    # Create placeholder images if needed
    for img_name in ['logo.jpg', 'qr.jpg']:
        img_path = os.path.join(STATIC_DIR, img_name)
        if not os.path.exists(img_path):
            print(f"{Fore.YELLOW}⚠️  {img_name} not found. Add to: {img_path}")
    
    # Start background tasks
    Thread(target=cleanup_expired_sessions, daemon=True).start()
    Thread(target=monitor_deployments, daemon=True).start()
    Thread(target=cleanup_old_backups, daemon=True).start()
    
    # Start Flask
    keep_alive()
    
    # Start Telegram bot
    bot_thread = Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 Web App: http://localhost:{port}")
    print(f"{Fore.YELLOW}📱 Register: http://localhost:{port}/register")
    print(f"{Fore.YELLOW}🔑 Login: http://localhost:{port}/login")
    print(f"{Fore.MAGENTA}👑 Admin: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")
    print(f"{Fore.CYAN}💳 Payment System: Active")
    print(f"{Fore.CYAN}📊 Metrics: http://localhost:{port}/metrics" if ENABLE_METRICS else "")
    print(f"{Fore.CYAN}📞 Support: {TELEGRAM_LINK}")
    print(f"\n{Fore.GREEN}{'✅ ELITEHOST v13.0 READY':^90}")
    print("=" * 90 + "\n")
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Shutting down...")
        cleanup_on_exit()
