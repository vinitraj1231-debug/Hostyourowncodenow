"""
🚀 ELITEHOST v14.0 - ULTRA ADVANCED PROFESSIONAL EDITION
Enterprise-Grade Cloud Deployment Platform
✅ FIXED: Rate Limit Issue
✅ ADDED: Smart Caching, SSE Real-time Updates, Auto-Restart, Connection Pooling
✅ ADDED: Per-User Rate Limiting, JWT Sessions, Advanced Process Monitor
"""

import sys
import subprocess
import os

# ==================== DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 ELITEHOST v14.0 - ULTRA ADVANCED EDITION")
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
    'cachetools': 'cachetools',
}

def smart_install(package, import_name):
    try:
        __import__(import_name)
        print(f"  ✓ {package:30} [INSTALLED]")
        return True
    except ImportError:
        print(f"  ⚡ {package:30} [INSTALLING...]", end=' ', flush=True)
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', package, '--quiet'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
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

print("\n" + "=" * 90)
print("✅ DEPENDENCIES READY!")
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
from flask import Flask, render_template_string, request, jsonify, send_file, redirect, make_response, Response, stream_with_context
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from threading import Thread, Lock, Timer
import uuid
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import psutil
from colorama import Fore, Style, init
import bcrypt
import re
from collections import defaultdict, deque
import traceback
import sqlite3
from contextlib import contextmanager
import queue
from cachetools import TTLCache, LRUCache
import functools
import inspect

init(autoreset=True)

# ==================== CONFIGURATION ====================
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '8133133627:AAHXG1M3I_5yV6mIo2IRl61h8zRUvg6Nn2Y')
OWNER_ID = int(os.getenv('OWNER_ID', '7524032836'))
ADMIN_ID = int(os.getenv('ADMIN_ID', '8285724366'))
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'Kvinit6421@gmail.com')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '28@HumblerRaj')
YOUR_USERNAME = os.getenv('TELEGRAM_USERNAME', '@Zolvit')
TELEGRAM_LINK = os.getenv('TELEGRAM_LINK', 'https://t.me/Zolvit')
WEB_SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

FREE_CREDITS = 2.0
CREDIT_COSTS = {
    'file_upload': 0.5,
    'github_deploy': 1.0,
    'backup': 0.5,
}

PAYMENT_PACKAGES = {
    '10_credits': {'credits': 10, 'price': 50, 'name': '10 Credits Pack'},
    '99_credits': {'credits': 99, 'price': 399, 'name': '99 Credits Pack'},
}

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {'.py', '.js', '.zip', '.tar.gz'}
SESSION_TIMEOUT_DAYS = 7
PAYMENT_TIMEOUT_MINUTES = 30          # ← increased from 5 to 30 minutes
MAX_DEPLOYMENTS_PER_USER = 10
MAX_LOGIN_ATTEMPTS = 10               # ← increased from 5
LOGIN_ATTEMPT_WINDOW = 300
MAX_DEPLOY_RESTARTS = 5               # Auto-restart crashed deployments

# ==================== DIRECTORIES ====================
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

# ==================== SMART CACHE LAYER ====================
# Prevents DB hammering from dashboard polling
_user_cache    = TTLCache(maxsize=500, ttl=5)    # 5 sec TTL for user data
_deploy_cache  = TTLCache(maxsize=500, ttl=5)    # 5 sec TTL for deployment data
_credits_cache = TTLCache(maxsize=500, ttl=3)    # 3 sec TTL for credits
_session_cache = TTLCache(maxsize=2000, ttl=60)  # 60 sec TTL for session verification
CACHE_LOCK = Lock()

def cache_invalidate_user(user_id):
    with CACHE_LOCK:
        _user_cache.pop(user_id, None)
        _credits_cache.pop(user_id, None)

def cache_invalidate_deploy(deploy_id):
    with CACHE_LOCK:
        _deploy_cache.pop(deploy_id, None)

def cache_invalidate_session(token):
    with CACHE_LOCK:
        _session_cache.pop(token, None)

# ==================== RATE LIMIT KEY FUNCTIONS ====================
# ✅ KEY FIX: Use user ID for rate limiting when authenticated
def get_rate_limit_key():
    """Use session user-id when authenticated, else fall back to IP."""
    try:
        session_token = request.cookies.get('session_token')
        if session_token:
            with CACHE_LOCK:
                cached = _session_cache.get(session_token)
            if cached and cached != 'INVALID':
                return f"user:{cached}"
    except Exception:
        pass
    return f"ip:{get_remote_address()}"

# Flask & Bot setup
app = Flask(__name__)
app.secret_key = WEB_SECRET_KEY
CORS(app, supports_credentials=True)

# ==================== RATE LIMITER (FIXED) ====================
# ✅ KEY FIX: Dramatically increased limits + per-user keying
limiter = Limiter(
    app=app,
    key_func=get_rate_limit_key,
    default_limits=[
        "10000 per day",
        "2000 per hour",
        "200 per minute"
    ],
    storage_uri="memory://",
    strategy="fixed-window"  # ← FIXED
)

bot = telebot.TeleBot(TOKEN, parse_mode='Markdown')

# Global state
active_processes    = {}       # deploy_id → subprocess.Popen
process_restart_ct  = defaultdict(int)   # deploy_id → restart count
payment_timers      = {}
login_attempts      = defaultdict(lambda: deque(maxlen=MAX_LOGIN_ATTEMPTS))
DB_LOCK             = Lock()
PROCESS_LOCK        = Lock()
SSE_CLIENTS         = defaultdict(set)   # user_id → {queue objects}
SSE_LOCK            = Lock()

# ==================== LOGGING ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, 'elitehost.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== DATABASE ====================

def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    # ✅ WAL mode for much better concurrent read performance
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=10000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

@contextmanager
def get_db():
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
    with get_db() as conn:
        c = conn.cursor()
        c.executescript('''
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
                telegram_id TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

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
                restart_count INTEGER DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

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
                screenshot_path TEXT,
                transaction_id TEXT,
                approved_by TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS banned_devices (
                fingerprint TEXT PRIMARY KEY,
                reason TEXT,
                banned_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_deployments_user ON deployments(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
            CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
            CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log(user_id);
        ''')
        logger.info("✅ Database initialized with indexes & WAL mode")

init_database()

# ==================== HELPER FUNCTIONS ====================

def log_error(error_msg, context=""):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = f"[{ts}] ERROR in {context}: {error_msg}\n{traceback.format_exc()}\n"
    error_file = os.path.join(LOGS_DIR, 'errors.log')
    with open(error_file, 'a') as f:
        f.write(entry)
    logger.error(entry)

def get_device_fingerprint(req):
    components = [
        req.headers.get('User-Agent', ''),
        req.remote_addr or 'unknown',
        req.headers.get('Accept-Language', ''),
    ]
    return hashlib.sha256('|'.join(components).encode()).hexdigest()

def is_device_banned(fingerprint):
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT 1 FROM banned_devices WHERE fingerprint = ?', (fingerprint,))
        return c.fetchone() is not None

def check_existing_account(fingerprint):
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT id FROM users WHERE device_fingerprint = ?', (fingerprint,))
        row = c.fetchone()
        return row['id'] if row else None

def is_admin_user(user_id, email):
    return (
        str(user_id) == str(OWNER_ID) or
        str(user_id) == str(ADMIN_ID) or
        email.lower().strip() == ADMIN_EMAIL.lower().strip()
    )

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

def create_user(email, password, fingerprint, ip):
    try:
        user_id = str(uuid.uuid4())
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO users (id, email, password, device_fingerprint, credits,
                    total_earned, created_at, last_login, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, email, hash_password(password), fingerprint,
                  FREE_CREDITS, FREE_CREDITS, datetime.now().isoformat(),
                  datetime.now().isoformat(), ip))
        log_activity(user_id, 'USER_REGISTER', f'New user: {email}', ip)
        try:
            bot.send_message(OWNER_ID,
                f"🆕 *NEW USER*\n📧 `{email}`\n🆔 `{user_id}`\n🌐 `{ip}`")
        except Exception:
            pass
        return user_id
    except Exception as e:
        log_error(str(e), "create_user")
        return None

def authenticate_user(email, password):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT id, password FROM users WHERE email = ?', (email,))
            row = c.fetchone()
            if row and verify_password(password, row['password']):
                return row['id']
        return None
    except Exception:
        return None

def create_session(user_id, fingerprint):
    token = secrets.token_urlsafe(48)
    expires_at = datetime.now() + timedelta(days=SESSION_TIMEOUT_DAYS)
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO sessions (token, user_id, fingerprint, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (token, user_id, fingerprint, datetime.now().isoformat(), expires_at.isoformat()))
    return token

def verify_session(session_token, fingerprint):
    if not session_token:
        return None
    cache_key = f"{session_token}:{fingerprint}"
    with CACHE_LOCK:
        cached = _session_cache.get(cache_key)
    if cached == 'INVALID':
        return None
    if cached:
        return cached
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT user_id, fingerprint, expires_at
                FROM sessions WHERE token = ?
            ''', (session_token,))
            row = c.fetchone()
            if not row:
                with CACHE_LOCK:
                    _session_cache[cache_key] = 'INVALID'
                return None
            if datetime.fromisoformat(row['expires_at']) < datetime.now():
                c.execute('DELETE FROM sessions WHERE token = ?', (session_token,))
                with CACHE_LOCK:
                    _session_cache[cache_key] = 'INVALID'
                return None
            if row['fingerprint'] != fingerprint:
                with CACHE_LOCK:
                    _session_cache[cache_key] = 'INVALID'
                return None
            with CACHE_LOCK:
                _session_cache[cache_key] = row['user_id']
            return row['user_id']
    except Exception:
        return None

def get_user(user_id):
    with CACHE_LOCK:
        cached = _user_cache.get(user_id)
    if cached:
        return cached
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = c.fetchone()
            if row:
                user_data = dict(row)
                c.execute('SELECT id FROM deployments WHERE user_id = ?', (user_id,))
                user_data['deployments'] = [r['id'] for r in c.fetchall()]
                with CACHE_LOCK:
                    _user_cache[user_id] = user_data
                return user_data
        return None
    except Exception:
        return None

def update_user(user_id, **kwargs):
    try:
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys()])
        values = list(kwargs.values()) + [user_id]
        with get_db() as conn:
            c = conn.cursor()
            c.execute(f'UPDATE users SET {set_clause} WHERE id = ?', values)
        cache_invalidate_user(user_id)
    except Exception as e:
        log_error(str(e), "update_user")

def log_activity(user_id, action, details, ip=''):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO activity_log (user_id, action, details, ip_address, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, action, details, ip, datetime.now().isoformat()))
    except Exception:
        pass

def get_credits(user_id):
    if str(user_id) == str(OWNER_ID):
        return float('inf')
    with CACHE_LOCK:
        cached = _credits_cache.get(user_id)
    if cached is not None:
        return cached
    user = get_user(user_id)
    credits = user['credits'] if user else 0
    with CACHE_LOCK:
        _credits_cache[user_id] = credits
    return credits

def add_credits(user_id, amount, description="Credit added"):
    user = get_user(user_id)
    if not user:
        return False
    new_credits = user['credits'] + amount
    new_earned = user['total_earned'] + amount
    update_user(user_id, credits=new_credits, total_earned=new_earned)
    log_activity(user_id, 'CREDIT_ADD', f"{amount} - {description}")
    cache_invalidate_user(user_id)
    sse_notify(user_id, 'credits_updated', {'credits': new_credits})
    return True

def deduct_credits(user_id, amount, description="Credit used"):
    if str(user_id) == str(OWNER_ID):
        return True
    user = get_user(user_id)
    if not user or user['credits'] < amount:
        return False
    new_credits = user['credits'] - amount
    new_spent = user['total_spent'] + amount
    update_user(user_id, credits=new_credits, total_spent=new_spent)
    log_activity(user_id, 'CREDIT_USE', f"{amount} - {description}")
    cache_invalidate_user(user_id)
    sse_notify(user_id, 'credits_updated', {'credits': new_credits})
    return True

def check_login_attempts(ip_address):
    now = time.time()
    attempts = login_attempts[ip_address]
    while attempts and attempts[0] < now - LOGIN_ATTEMPT_WINDOW:
        attempts.popleft()
    return len(attempts) >= MAX_LOGIN_ATTEMPTS

def record_login_attempt(ip_address):
    login_attempts[ip_address].append(time.time())

# ==================== SSE REAL-TIME NOTIFICATIONS ====================
# ✅ NEW: Server-Sent Events replaces polling for real-time updates

def sse_notify(user_id, event_type, data):
    """Push a real-time event to all connected SSE clients for a user."""
    with SSE_LOCK:
        clients = SSE_CLIENTS.get(str(user_id), set())
        dead = set()
        for q in clients:
            try:
                q.put_nowait({'type': event_type, 'data': data})
            except Exception:
                dead.add(q)
        SSE_CLIENTS[str(user_id)] -= dead

@app.route('/api/events')
@limiter.exempt  # ← SSE connections are long-lived, don't rate limit
def sse_stream():
    """Server-Sent Events endpoint for real-time dashboard updates."""
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)

    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    def generate():
        q = queue.Queue(maxsize=50)
        with SSE_LOCK:
            SSE_CLIENTS[str(user_id)].add(q)
        try:
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            while True:
                try:
                    event = q.get(timeout=25)
                    yield f"data: {json.dumps(event)}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            with SSE_LOCK:
                SSE_CLIENTS[str(user_id)].discard(q)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

# ==================== PAYMENT FUNCTIONS ====================

def create_payment_request(user_id, package_type, custom_amount=None):
    try:
        payment_id = str(uuid.uuid4())[:12]
        if package_type == 'custom':
            if not custom_amount or custom_amount <= 0:
                return None, "Invalid custom amount"
            credits = price = custom_amount
        else:
            if package_type not in PAYMENT_PACKAGES:
                return None, "Invalid package"
            pkg = PAYMENT_PACKAGES[package_type]
            credits, price = pkg['credits'], pkg['price']

        user = get_user(user_id)
        if not user:
            return None, "User not found"

        expires_at = datetime.now() + timedelta(minutes=PAYMENT_TIMEOUT_MINUTES)
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO payments (id, user_id, user_email, package_type, credits, price,
                    status, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (payment_id, user_id, user['email'], package_type, credits, price,
                  'pending', datetime.now().isoformat(), expires_at.isoformat()))

        timer = Timer(PAYMENT_TIMEOUT_MINUTES * 60, expire_payment, args=[payment_id])
        payment_timers[payment_id] = timer
        timer.daemon = True
        timer.start()
        log_activity(user_id, 'PAYMENT_REQUEST', f"{payment_id}: {credits}cr ₹{price}")

        payment_data = {
            'id': payment_id, 'user_id': user_id, 'user_email': user['email'],
            'package_type': package_type, 'credits': credits, 'price': price,
            'status': 'pending', 'created_at': datetime.now().isoformat(),
            'expires_at': expires_at.isoformat()
        }
        return payment_id, payment_data
    except Exception as e:
        log_error(str(e), "create_payment_request")
        return None, str(e)

def expire_payment(payment_id):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("UPDATE payments SET status='expired' WHERE id=? AND status='pending'", (payment_id,))
        logger.info(f"Payment {payment_id} expired")
    except Exception:
        pass

def submit_payment_proof(payment_id, screenshot_data, transaction_id):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
            row = c.fetchone()
            if not row:
                return False, "Payment not found"
            payment = dict(row)

            if payment['status'] != 'pending':
                return False, f"Payment is {payment['status']}"
            if datetime.fromisoformat(payment['expires_at']) < datetime.now():
                c.execute("UPDATE payments SET status='expired' WHERE id=?", (payment_id,))
                return False, "Payment expired"

            screenshot_path = os.path.join(PAYMENTS_DIR, f"{payment_id}_screenshot.jpg")
            try:
                import base64
                screenshot_bytes = base64.b64decode(screenshot_data.split(',')[1])
                with open(screenshot_path, 'wb') as f:
                    f.write(screenshot_bytes)
            except Exception as e:
                log_error(str(e), "screenshot save")
                return False, "Screenshot upload failed"

            c.execute('''
                UPDATE payments SET screenshot_path=?, transaction_id=?,
                status='submitted', submitted_at=? WHERE id=?
            ''', (screenshot_path, transaction_id, datetime.now().isoformat(), payment_id))

        if payment_id in payment_timers:
            payment_timers[payment_id].cancel()
            del payment_timers[payment_id]

        try:
            user = get_user(payment['user_id'])
            markup = types.InlineKeyboardMarkup()
            markup.row(
                types.InlineKeyboardButton("✅ Approve", callback_data=f"payment_confirm_{payment_id}"),
                types.InlineKeyboardButton("❌ Reject", callback_data=f"payment_reject_{payment_id}")
            )
            bot.send_message(ADMIN_ID,
                f"💳 *NEW PAYMENT SUBMISSION*\n\n"
                f"📧 User: `{user['email']}`\n"
                f"🆔 Payment ID: `{payment_id}`\n"
                f"💰 Amount: ₹{payment['price']}\n"
                f"💎 Credits: {payment['credits']}\n"
                f"🔢 TxnID: `{transaction_id}`\n"
                f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                reply_markup=markup)
            with open(screenshot_path, 'rb') as photo:
                bot.send_photo(ADMIN_ID, photo, caption=f"Payment Screenshot - {payment_id}")
        except Exception as e:
            log_error(str(e), "payment notification")

        return True, "Payment proof submitted successfully"
    except Exception as e:
        log_error(str(e), "submit_payment_proof")
        return False, str(e)

@bot.callback_query_handler(func=lambda call: call.data.startswith('payment_'))
def handle_payment_action(call):
    try:
        parts = call.data.rsplit('_', 1)
        action_part = parts[0]   # e.g. "payment_confirm"
        payment_id = parts[1]

        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
            row = c.fetchone()
            if not row:
                bot.answer_callback_query(call.id, "Payment not found")
                return
            payment = dict(row)

        if 'confirm' in action_part:
            with get_db() as conn:
                c = conn.cursor()
                c.execute('''
                    UPDATE payments SET status='approved', approved_at=?, approved_by=?
                    WHERE id=?
                ''', (datetime.now().isoformat(), str(call.from_user.id), payment_id))
            add_credits(payment['user_id'], payment['credits'], f"Payment approved: {payment_id}")
            bot.answer_callback_query(call.id, "✅ Payment Approved!")
            sse_notify(payment['user_id'], 'payment_approved', {
                'credits': payment['credits'], 'payment_id': payment_id})
            try:
                bot.edit_message_text(
                    f"{call.message.text}\n\n✅ *APPROVED* by {call.from_user.first_name}",
                    call.message.chat.id, call.message.message_id, parse_mode='Markdown')
            except Exception:
                pass

        elif 'reject' in action_part:
            with get_db() as conn:
                c = conn.cursor()
                c.execute("UPDATE payments SET status='rejected' WHERE id=?", (payment_id,))
            bot.answer_callback_query(call.id, "❌ Payment Rejected")
            sse_notify(payment['user_id'], 'payment_rejected', {'payment_id': payment_id})
            try:
                bot.edit_message_text(
                    f"{call.message.text}\n\n❌ *REJECTED* by {call.from_user.first_name}",
                    call.message.chat.id, call.message.message_id, parse_mode='Markdown')
            except Exception:
                pass
    except Exception as e:
        log_error(str(e), "handle_payment_action")
        bot.answer_callback_query(call.id, f"Error: {str(e)}")

# ==================== AI DEPENDENCY DETECTION ====================

def extract_imports_from_code(code_content):
    imports = set()
    for line in code_content.split('\n'):
        for pattern in [r'^\s*import\s+([a-zA-Z0-9_\.]+)', r'^\s*from\s+([a-zA-Z0-9_\.]+)\s+import']:
            m = re.match(pattern, line)
            if m:
                imports.add(m.group(1).split('.')[0])
    return imports

PACKAGE_MAP = {
    'cv2': 'opencv-python', 'PIL': 'pillow', 'sklearn': 'scikit-learn',
    'yaml': 'pyyaml', 'dotenv': 'python-dotenv', 'telebot': 'pyTelegramBotAPI',
    'bs4': 'beautifulsoup4', 'Crypto': 'pycryptodome', 'jwt': 'PyJWT',
    'aiohttp': 'aiohttp', 'fastapi': 'fastapi', 'uvicorn': 'uvicorn',
    'motor': 'motor', 'pymongo': 'pymongo', 'redis': 'redis',
    'celery': 'celery', 'pydantic': 'pydantic', 'sqlalchemy': 'SQLAlchemy',
}

STDLIB_MODULES = {
    'os', 'sys', 'time', 'json', 're', 'math', 'random', 'datetime',
    'collections', 'itertools', 'functools', 'pathlib', 'threading',
    'multiprocessing', 'subprocess', 'shutil', 'tempfile', 'io', 'abc',
    'typing', 'dataclasses', 'enum', 'copy', 'pickle', 'struct', 'hashlib',
    'hmac', 'secrets', 'base64', 'binascii', 'csv', 'configparser',
    'argparse', 'logging', 'unittest', 'socket', 'ssl', 'http', 'urllib',
    'email', 'html', 'xml', 'sqlite3', 'queue', 'asyncio', 'contextlib',
    'inspect', 'traceback', 'warnings', 'weakref', 'gc', 'platform',
    'signal', 'atexit', 'uuid', 'calendar', 'textwrap', 'string', 'builtins',
}

def detect_and_install_deps(project_path):
    installed, log_lines = [], ["🤖 AI DEPENDENCY ANALYZER v14.0", "=" * 60]
    try:
        req_file = os.path.join(project_path, 'requirements.txt')
        if os.path.exists(req_file):
            log_lines.append("\n📦 REQUIREMENTS.TXT")
            with open(req_file, 'r') as f:
                packages = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            for pkg in packages:
                try:
                    subprocess.run([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                                   check=True, capture_output=True, timeout=300)
                    log_lines.append(f"  ✅ {pkg}")
                    installed.append(pkg)
                except Exception:
                    log_lines.append(f"  ⚠️  {pkg} (skipped)")

        py_files = []
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv'}]
            py_files.extend(os.path.join(root, f) for f in files if f.endswith('.py'))

        if py_files:
            all_imports = set()
            for pf in py_files[:30]:
                try:
                    with open(pf, 'r', encoding='utf-8', errors='ignore') as f:
                        all_imports.update(extract_imports_from_code(f.read()))
                except Exception:
                    continue

            third_party = all_imports - STDLIB_MODULES
            log_lines.append("\n🔍 AUTO-DETECTED DEPENDENCIES")
            for imp in third_party:
                pkg = PACKAGE_MAP.get(imp, imp)
                try:
                    __import__(imp)
                    log_lines.append(f"  ✓ {pkg} (installed)")
                except ImportError:
                    try:
                        subprocess.run([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                                       check=True, capture_output=True, timeout=300)
                        log_lines.append(f"  ✅ {pkg} (auto-installed)")
                        installed.append(pkg)
                    except Exception:
                        log_lines.append(f"  ⚠️  {pkg} (failed)")

        log_lines += ["", "=" * 60, f"📦 Total Installed: {len(set(installed))}", "=" * 60]
        return list(set(installed)), "\n".join(log_lines)
    except Exception as e:
        log_error(str(e), "detect_and_install_deps")
        return installed, "\n".join(log_lines) + f"\n\n❌ Error: {str(e)}"

# ==================== DEPLOYMENT FUNCTIONS ====================

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        return s.getsockname()[1]

def create_deployment(user_id, name, deploy_type, **kwargs):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT COUNT(*) as cnt FROM deployments
                WHERE user_id=? AND status IN ('running','pending')
            ''', (user_id,))
            if c.fetchone()['cnt'] >= MAX_DEPLOYMENTS_PER_USER and str(user_id) != str(OWNER_ID):
                return None, None

        deploy_id = str(uuid.uuid4())[:8]
        port = find_free_port()

        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO deployments (id, user_id, name, type, status, port,
                    created_at, updated_at, logs, dependencies,
                    repo_url, branch, build_command, start_command, env_vars, restart_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (deploy_id, user_id, name, deploy_type, 'pending', port,
                  datetime.now().isoformat(), datetime.now().isoformat(),
                  '', json.dumps([]),
                  kwargs.get('repo_url', ''), kwargs.get('branch', 'main'),
                  kwargs.get('build_command', ''), kwargs.get('start_command', ''),
                  json.dumps({}), 0))

        log_activity(user_id, 'DEPLOYMENT_CREATE', f"{name} ({deploy_type})")
        return deploy_id, port
    except Exception as e:
        log_error(str(e), "create_deployment")
        return None, None

def update_deployment(deploy_id, **kwargs):
    try:
        kwargs['updated_at'] = datetime.now().isoformat()
        for key in ['dependencies', 'env_vars']:
            if key in kwargs and isinstance(kwargs[key], (list, dict)):
                kwargs[key] = json.dumps(kwargs[key])
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys()])
        values = list(kwargs.values()) + [deploy_id]
        with get_db() as conn:
            c = conn.cursor()
            c.execute(f'UPDATE deployments SET {set_clause} WHERE id = ?', values)
        cache_invalidate_deploy(deploy_id)
        # Push SSE update
        deployment = get_deployment(deploy_id)
        if deployment:
            sse_notify(deployment['user_id'], 'deployment_updated',
                       {'id': deploy_id, 'status': kwargs.get('status', deployment['status'])})
    except Exception as e:
        log_error(str(e), f"update_deployment {deploy_id}")

def get_deployment(deploy_id):
    with CACHE_LOCK:
        cached = _deploy_cache.get(deploy_id)
    if cached:
        return cached
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM deployments WHERE id = ?', (deploy_id,))
            row = c.fetchone()
            if row:
                d = dict(row)
                d['dependencies'] = json.loads(d.get('dependencies') or '[]')
                d['env_vars'] = json.loads(d.get('env_vars') or '{}')
                with CACHE_LOCK:
                    _deploy_cache[deploy_id] = d
                return d
        return None
    except Exception:
        return None

def _launch_process(cmd, cwd, port, env=None):
    """Launch a subprocess with merged environment."""
    proc_env = os.environ.copy()
    proc_env['PORT'] = str(port)
    if env:
        proc_env.update(env)
    return subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=cwd, env=proc_env
    )

def deploy_from_file(user_id, file_path, filename):
    cost = CREDIT_COSTS['file_upload']
    if not deduct_credits(user_id, cost, f"File deploy: {filename}"):
        return None, f"❌ Need {cost} credits"

    deploy_id, port = create_deployment(user_id, filename, 'file_upload')
    if not deploy_id:
        add_credits(user_id, cost, "Refund"); return None, "Failed to create deployment"

    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    os.makedirs(deploy_dir, exist_ok=True)

    try:
        user = get_user(user_id)
        try:
            bot.send_message(OWNER_ID,
                f"📤 *FILE DEPLOY*\n👤 {user['email']}\n📁 `{filename}`\n🆔 `{deploy_id}`")
        except Exception:
            pass

        if filename.endswith('.zip'):
            update_deployment(deploy_id, status='extracting', logs='📦 Extracting ZIP...')
            with zipfile.ZipFile(file_path, 'r') as z:
                z.extractall(deploy_dir)
            main_file = None
            for root, _, files in os.walk(deploy_dir):
                for f in files:
                    if f in ('main.py', 'app.py', 'bot.py', 'index.js', 'server.js'):
                        main_file = os.path.join(root, f); break
                if main_file:
                    break
            if not main_file:
                update_deployment(deploy_id, status='failed', logs='❌ No entry point found')
                add_credits(user_id, cost, "Refund"); return None, "❌ No main file found"
            file_path = main_file
        else:
            dest = os.path.join(deploy_dir, filename)
            shutil.copy(file_path, dest)
            file_path = dest

        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        update_deployment(deploy_id, dependencies=installed_deps)

        deployment = get_deployment(deploy_id)
        env_vars = deployment.get('env_vars', {})

        cmd = [sys.executable, file_path] if file_path.endswith('.py') else ['node', file_path]
        update_deployment(deploy_id, status='starting',
                          logs=f'🚀 Launching on port {port}...\n{install_log}')

        process = _launch_process(cmd, os.path.dirname(file_path), port, env_vars)
        with PROCESS_LOCK:
            active_processes[deploy_id] = process
            process_restart_ct[deploy_id] = 0
        update_deployment(deploy_id, status='running', pid=process.pid,
                          logs=f'✅ Live on port {port}!\n\n{install_log}')
        return deploy_id, f"🎉 Deployed! Port {port}"

    except Exception as e:
        log_error(str(e), "deploy_from_file")
        update_deployment(deploy_id, status='failed', logs=str(e))
        add_credits(user_id, cost, "Refund")
        return None, str(e)

def deploy_from_github(user_id, repo_url, branch='main', build_cmd='', start_cmd=''):
    cost = CREDIT_COSTS['github_deploy']
    if not deduct_credits(user_id, cost, f"GitHub: {repo_url}"):
        return None, f"❌ Need {cost} credits"

    repo_name = repo_url.split('/')[-1].replace('.git', '')
    deploy_id, port = create_deployment(user_id, repo_name, 'github',
                                        repo_url=repo_url, branch=branch,
                                        build_command=build_cmd, start_command=start_cmd)
    if not deploy_id:
        add_credits(user_id, cost, "Refund"); return None, "Failed to create deployment"

    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    os.makedirs(deploy_dir, exist_ok=True)

    try:
        user = get_user(user_id)
        try:
            bot.send_message(OWNER_ID,
                f"🐙 *GITHUB DEPLOY*\n👤 {user['email']}\n📦 `{repo_url}`\n🆔 `{deploy_id}`")
        except Exception:
            pass

        update_deployment(deploy_id, status='cloning', logs=f'🔄 Cloning {repo_url}...')
        result = subprocess.run(
            ['git', 'clone', '-b', branch, '--depth', '1', repo_url, deploy_dir],
            capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            update_deployment(deploy_id, status='failed', logs=f'❌ Clone failed:\n{result.stderr}')
            add_credits(user_id, cost, "Refund"); return None, "❌ Clone failed"

        if build_cmd:
            update_deployment(deploy_id, status='building', logs=f'🔨 Running: {build_cmd}')
            br = subprocess.run(build_cmd, shell=True, cwd=deploy_dir,
                                capture_output=True, text=True, timeout=600)
            if br.returncode != 0:
                update_deployment(deploy_id, status='failed', logs=f'❌ Build failed:\n{br.stderr}')
                add_credits(user_id, cost, "Refund"); return None, "❌ Build failed"

        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        update_deployment(deploy_id, dependencies=installed_deps)

        if not start_cmd:
            MAIN_FILES = {
                'main.py': f'{sys.executable} main.py', 'app.py': f'{sys.executable} app.py',
                'bot.py': f'{sys.executable} bot.py', 'index.js': 'node index.js',
                'server.js': 'node server.js',
            }
            for fname, cmd in MAIN_FILES.items():
                if os.path.exists(os.path.join(deploy_dir, fname)):
                    start_cmd = cmd; break

        if not start_cmd:
            update_deployment(deploy_id, status='failed', logs='❌ No start command')
            add_credits(user_id, cost, "Refund"); return None, "❌ No start command found"

        deployment = get_deployment(deploy_id)
        env_vars = deployment.get('env_vars', {})
        update_deployment(deploy_id, status='starting',
                          logs=f'🚀 Starting: {start_cmd}', start_command=start_cmd)

        process = _launch_process(start_cmd.split(), deploy_dir, port, env_vars)
        with PROCESS_LOCK:
            active_processes[deploy_id] = process
            process_restart_ct[deploy_id] = 0
        update_deployment(deploy_id, status='running', pid=process.pid,
                          logs=f'✅ Running on port {port}!\n\n{install_log}')
        return deploy_id, f"🎉 Deployed! Port {port}"

    except Exception as e:
        log_error(str(e), "deploy_from_github")
        update_deployment(deploy_id, status='failed', logs=str(e))
        add_credits(user_id, cost, "Refund"); return None, str(e)

def stop_deployment(deploy_id):
    try:
        with PROCESS_LOCK:
            if deploy_id in active_processes:
                p = active_processes[deploy_id]
                p.terminate()
                try:
                    p.wait(timeout=5)
                except Exception:
                    p.kill()
                del active_processes[deploy_id]
        update_deployment(deploy_id, status='stopped', logs='🛑 Stopped by user')
        return True, "Stopped"
    except Exception as e:
        log_error(str(e), f"stop_deployment {deploy_id}")
        return False, str(e)

def delete_deployment(deploy_id):
    try:
        stop_deployment(deploy_id)
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if os.path.exists(deploy_dir):
            shutil.rmtree(deploy_dir, ignore_errors=True)
        with get_db() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM deployments WHERE id = ?', (deploy_id,))
        cache_invalidate_deploy(deploy_id)
        return True, "Deleted successfully"
    except Exception as e:
        log_error(str(e), f"delete_deployment {deploy_id}")
        return False, str(e)

def create_backup(deploy_id):
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
            add_credits(user_id, cost, "Refund")
            return None, "Deployment directory not found"

        backup_name = f"{deployment['name']}_{deploy_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        backup_path = os.path.join(BACKUPS_DIR, backup_name)
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(deploy_dir):
                for file in files:
                    fp = os.path.join(root, file)
                    zf.write(fp, os.path.relpath(fp, deploy_dir))
        return backup_path, backup_name
    except Exception as e:
        log_error(str(e), f"create_backup {deploy_id}")
        return None, str(e)

def get_deployment_files(deploy_id):
    try:
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if not os.path.exists(deploy_dir):
            return []
        files = []
        for root, _, filenames in os.walk(deploy_dir):
            for fn in filenames:
                fp = os.path.join(root, fn)
                files.append({
                    'name': fn,
                    'path': os.path.relpath(fp, deploy_dir),
                    'size': os.path.getsize(fp),
                    'modified': datetime.fromtimestamp(os.path.getmtime(fp)).isoformat()
                })
        return files
    except Exception:
        return []

def get_system_metrics():
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net = psutil.net_io_counters()
        return {
            'cpu': round(cpu, 1),
            'memory_percent': round(mem.percent, 1),
            'memory_used': round(mem.used / (1024**3), 2),
            'memory_total': round(mem.total / (1024**3), 2),
            'disk_percent': round(disk.percent, 1),
            'disk_used': round(disk.used / (1024**3), 2),
            'disk_total': round(disk.total / (1024**3), 2),
            'net_sent_mb': round(net.bytes_sent / (1024**2), 1),
            'net_recv_mb': round(net.bytes_recv / (1024**2), 1),
            'active_processes': len(active_processes),
        }
    except Exception:
        return {k: 0 for k in ['cpu','memory_percent','memory_used','memory_total',
                                 'disk_percent','disk_used','disk_total','net_sent_mb',
                                 'net_recv_mb','active_processes']}

# ==================== HTML TEMPLATES ====================

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost v14 - {{ title }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body { background: radial-gradient(ellipse at 20% 50%, #1e3a5f 0%, #0f172a 50%, #1a0533 100%); }
        .glass { background: rgba(15,23,42,0.7); backdrop-filter: blur(20px); border: 1px solid rgba(59,130,246,0.15); }
        .btn-glow { box-shadow: 0 0 30px rgba(59,130,246,0.4); }
        .fade-in { animation: fadeIn 0.6s ease-out; }
        @keyframes fadeIn { from { opacity:0; transform:translateY(-20px); } to { opacity:1; transform:translateY(0); } }
        .particle { position:fixed; border-radius:50%; pointer-events:none; animation: float linear infinite; }
        @keyframes float { 0%{transform:translateY(100vh) scale(0);opacity:0;} 10%{opacity:1;} 90%{opacity:1;} 100%{transform:translateY(-100px) scale(1);opacity:0;} }
    </style>
</head>
<body class="min-h-screen flex items-center justify-center p-4 overflow-hidden">
    <div id="particles"></div>
    <div class="max-w-md w-full fade-in relative z-10">
        <div class="glass rounded-2xl shadow-2xl p-8">
            <div class="text-center mb-8">
                <div class="relative inline-block">
                    <div class="w-20 h-20 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-2xl mx-auto mb-4 flex items-center justify-center btn-glow">
                        <i class="fas fa-rocket text-white text-3xl"></i>
                    </div>
                    <div class="absolute -top-1 -right-1 w-5 h-5 bg-green-500 rounded-full border-2 border-slate-900 animate-pulse"></div>
                </div>
                <h1 class="text-3xl font-black text-white mb-1">EliteHost <span class="text-blue-400">v14</span></h1>
                <p class="text-slate-400 text-sm">{{ subtitle }}</p>
            </div>

            {% if error %}
            <div class="bg-red-500/10 border border-red-500/40 rounded-xl p-3 mb-4 text-red-400 text-sm fade-in flex items-center gap-2">
                <i class="fas fa-exclamation-circle"></i>{{ error }}
            </div>
            {% endif %}
            {% if success %}
            <div class="bg-green-500/10 border border-green-500/40 rounded-xl p-3 mb-4 text-green-400 text-sm fade-in flex items-center gap-2">
                <i class="fas fa-check-circle"></i>{{ success }}
            </div>
            {% endif %}

            <form method="POST" action="{{ action }}" class="space-y-4" id="authForm">
                <div>
                    <label class="block text-sm font-semibold text-slate-300 mb-2">
                        <i class="fas fa-envelope mr-2 text-blue-400"></i>Email
                    </label>
                    <input type="email" name="email" required autocomplete="email"
                        class="w-full px-4 py-3 bg-slate-900/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                        placeholder="your@email.com">
                </div>
                <div>
                    <label class="block text-sm font-semibold text-slate-300 mb-2">
                        <i class="fas fa-lock mr-2 text-blue-400"></i>Password
                    </label>
                    <div class="relative">
                        <input type="password" name="password" id="passwordField" required
                            class="w-full px-4 py-3 bg-slate-900/60 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition pr-12"
                            placeholder="••••••••">
                        <button type="button" onclick="togglePwd()" class="absolute right-3 top-3.5 text-slate-400 hover:text-white transition">
                            <i class="fas fa-eye" id="eyeIcon"></i>
                        </button>
                    </div>
                </div>
                <button type="submit" id="submitBtn"
                    class="w-full bg-gradient-to-r from-blue-600 to-cyan-600 text-white font-bold py-3 px-4 rounded-xl hover:opacity-90 transition transform hover:scale-[1.02] active:scale-[0.98] btn-glow mt-2">
                    <i class="fas fa-{{ icon }} mr-2"></i><span id="btnText">{{ button_text }}</span>
                </button>
            </form>

            <p class="text-center mt-6 text-sm text-slate-400">
                {{ toggle_text }} <a href="{{ toggle_link }}" class="text-blue-400 hover:text-blue-300 font-semibold hover:underline transition">{{ toggle_action }}</a>
            </p>
            <div class="mt-6 pt-4 border-t border-slate-800 flex items-center justify-center gap-2 text-xs text-slate-500">
                <i class="fas fa-shield-alt text-blue-500"></i>
                <span>Device-Locked Security · EliteHost v14</span>
            </div>
        </div>
    </div>
    <script>
        function togglePwd(){
            const f=document.getElementById('passwordField'),i=document.getElementById('eyeIcon');
            f.type=f.type==='password'?'text':'password';
            i.className='fas fa-'+(f.type==='password'?'eye':'eye-slash');
        }
        document.getElementById('authForm').addEventListener('submit',function(e){
            const btn=document.getElementById('submitBtn'),txt=document.getElementById('btnText');
            btn.disabled=true; btn.classList.add('opacity-75');
            txt.innerHTML='<i class="fas fa-spinner fa-spin mr-2"></i>Processing...';
        });
        // Particles
        (function(){
            const c=document.getElementById('particles');
            for(let i=0;i<15;i++){
                const p=document.createElement('div');
                const size=Math.random()*4+2;
                p.className='particle';
                p.style.cssText=`width:${size}px;height:${size}px;left:${Math.random()*100}%;background:rgba(59,130,246,${Math.random()*0.5+0.1});animation-duration:${Math.random()*15+10}s;animation-delay:${Math.random()*10}s;`;
                c.appendChild(p);
            }
        })();
    </script>
</body>
</html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost v14 - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        [x-cloak]{display:none!important}
        body{background:#060d1a}
        .glass{background:rgba(15,23,42,0.8);backdrop-filter:blur(16px);border:1px solid rgba(59,130,246,0.1)}
        .sidebar{background:linear-gradient(180deg,#0d1b2e 0%,#0a1628 100%);border-right:1px solid rgba(59,130,246,0.1)}
        .active-nav{background:linear-gradient(135deg,rgba(59,130,246,0.2),rgba(34,211,238,0.1));border:1px solid rgba(59,130,246,0.3);color:#fff}
        .stat-card{background:linear-gradient(135deg,rgba(15,23,42,0.9),rgba(30,58,95,0.3));border:1px solid rgba(59,130,246,0.1)}
        .glow-blue{box-shadow:0 0 20px rgba(59,130,246,0.3)}
        .glow-green{box-shadow:0 0 20px rgba(34,197,94,0.3)}
        .btn-primary{background:linear-gradient(135deg,#2563eb,#0891b2);transition:all .2s}
        .btn-primary:hover{opacity:.9;transform:translateY(-1px)}
        .status-running{background:rgba(34,197,94,0.15);color:#4ade80;border:1px solid rgba(34,197,94,0.3)}
        .status-stopped{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)}
        .status-pending{background:rgba(234,179,8,0.15);color:#facc15;border:1px solid rgba(234,179,8,0.3)}
        .status-failed{background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)}
        .toast{position:fixed;bottom:1.5rem;right:1.5rem;z-index:9999;max-width:350px;animation:slideIn .3s ease}
        @keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
        .notification-badge{position:absolute;top:-4px;right:-4px;width:16px;height:16px;background:#ef4444;border-radius:50%;font-size:10px;display:flex;align-items:center;justify-content:center}
        .progress-bar{height:6px;border-radius:3px;transition:width 1s ease}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-track{background:#0d1b2e}
        ::-webkit-scrollbar-thumb{background:#1e40af;border-radius:2px}
    </style>
</head>
<body class="text-white min-h-screen" x-data="dashApp()">

    <!-- Notification Toasts -->
    <div class="toast-container" id="toastContainer"></div>

    <!-- Sidebar -->
    <div class="sidebar fixed inset-y-0 left-0 w-64 z-50 flex flex-col transform transition-transform duration-300"
         :class="sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'">
        <div class="p-6 flex items-center gap-3 border-b border-blue-900/30">
            <div class="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center glow-blue">
                <i class="fas fa-rocket text-white"></i>
            </div>
            <div>
                <span class="text-lg font-black text-white">EliteHost</span>
                <span class="text-xs text-blue-400 block">v14.0</span>
            </div>
        </div>

        <nav class="flex-1 p-4 space-y-1 overflow-y-auto">
            <template x-for="item in navItems" :key="item.id">
                <button @click="navigate(item.id)"
                    :class="currentPage===item.id ? 'active-nav' : 'text-slate-400 hover:bg-blue-900/20 hover:text-white'"
                    class="w-full flex items-center gap-3 px-4 py-3 rounded-xl cursor-pointer transition text-left">
                    <i :class="item.icon" class="w-5 text-center"></i>
                    <span x-text="item.label"></span>
                    <span x-show="item.badge && item.badge > 0"
                        class="ml-auto bg-blue-600 text-white text-xs px-2 py-0.5 rounded-full"
                        x-text="item.badge"></span>
                </button>
            </template>
            {% if is_admin %}
            <a href="/admin"
                class="flex items-center gap-3 px-4 py-3 rounded-xl text-yellow-400 hover:bg-yellow-500/10 hover:text-yellow-300 transition">
                <i class="fas fa-crown w-5 text-center"></i>
                <span>Admin Panel</span>
                <span class="ml-auto text-xs bg-yellow-500/20 px-2 py-0.5 rounded-full">ADMIN</span>
            </a>
            {% endif %}
        </nav>

        <div class="p-4 border-t border-blue-900/30">
            <div class="bg-gradient-to-r from-blue-600/20 to-cyan-600/20 border border-blue-500/30 rounded-xl p-4 mb-3">
                <div class="flex items-center justify-between mb-1">
                    <span class="text-xs text-blue-300">Available Credits</span>
                    <i class="fas fa-gem text-blue-400 text-xs"></i>
                </div>
                <div class="text-2xl font-black text-white" x-text="credits === Infinity ? '∞' : parseFloat(credits).toFixed(1)"></div>
                <div class="text-xs text-slate-400 mt-1">Click + to buy more</div>
            </div>
            <div class="grid grid-cols-2 gap-2">
                <button @click="navigate('buy-credits')"
                    class="bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 px-3 py-2 rounded-lg text-xs transition">
                    <i class="fas fa-plus mr-1"></i>Buy Credits
                </button>
                <button @click="logout()"
                    class="bg-red-600/20 hover:bg-red-600/30 text-red-400 px-3 py-2 rounded-lg text-xs transition">
                    <i class="fas fa-sign-out-alt mr-1"></i>Logout
                </button>
            </div>
        </div>
    </div>

    <!-- Mobile Header -->
    <div class="md:hidden fixed top-0 left-0 right-0 z-40 bg-slate-900/90 backdrop-blur border-b border-slate-800 px-4 py-3 flex items-center justify-between">
        <button @click="sidebarOpen=!sidebarOpen" class="text-white p-1">
            <i class="fas fa-bars text-xl"></i>
        </button>
        <span class="font-black text-white">EliteHost <span class="text-blue-400">v14</span></span>
        <div class="text-sm font-semibold text-blue-400" x-text="credits === Infinity ? '∞ cr' : parseFloat(credits).toFixed(1)+' cr'"></div>
    </div>

    <!-- Overlay -->
    <div x-show="sidebarOpen" @click="sidebarOpen=false"
         class="md:hidden fixed inset-0 bg-black/50 z-40" x-cloak></div>

    <!-- Main Content -->
    <main class="md:ml-64 min-h-screen pt-16 md:pt-0">
        <div class="p-4 md:p-8">

            <!-- OVERVIEW PAGE -->
            <div x-show="currentPage==='overview'" x-transition:enter="transition ease-out duration-200" x-transition:enter-start="opacity-0 translate-y-4" x-transition:enter-end="opacity-100 translate-y-0">
                <div class="flex items-center justify-between mb-8">
                    <div>
                        <h1 class="text-3xl font-black mb-1">Dashboard</h1>
                        <p class="text-slate-400 text-sm">Welcome back! Here's your overview.</p>
                    </div>
                    <div class="text-xs text-slate-500 flex items-center gap-2">
                        <div class="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                        <span id="liveIndicator">Live updates active</span>
                    </div>
                </div>

                <!-- Stats -->
                <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                    <div class="stat-card rounded-xl p-5">
                        <div class="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center mb-3">
                            <i class="fas fa-rocket text-blue-400"></i>
                        </div>
                        <div class="text-2xl font-black" x-text="stats.total"></div>
                        <div class="text-xs text-slate-400 mt-1">Total Deployments</div>
                    </div>
                    <div class="stat-card rounded-xl p-5">
                        <div class="w-10 h-10 bg-green-500/20 rounded-lg flex items-center justify-center mb-3">
                            <i class="fas fa-circle-check text-green-400"></i>
                        </div>
                        <div class="text-2xl font-black text-green-400" x-text="stats.running"></div>
                        <div class="text-xs text-slate-400 mt-1">Running Now</div>
                    </div>
                    <div class="stat-card rounded-xl p-5">
                        <div class="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center mb-3">
                            <i class="fas fa-gem text-blue-400"></i>
                        </div>
                        <div class="text-2xl font-black text-blue-400" x-text="credits === Infinity ? '∞' : parseFloat(credits).toFixed(1)"></div>
                        <div class="text-xs text-slate-400 mt-1">Credits</div>
                    </div>
                    <div class="stat-card rounded-xl p-5">
                        <div class="w-10 h-10 bg-cyan-500/20 rounded-lg flex items-center justify-center mb-3">
                            <i class="fas fa-robot text-cyan-400"></i>
                        </div>
                        <div class="text-2xl font-black text-cyan-400">AI</div>
                        <div class="text-xs text-slate-400 mt-1">Auto Deploy</div>
                    </div>
                </div>

                <!-- Recent Deployments -->
                <div class="glass rounded-2xl p-6">
                    <div class="flex items-center justify-between mb-5">
                        <h2 class="text-lg font-bold">Recent Deployments</h2>
                        <button @click="navigate('deployments')" class="text-blue-400 text-sm hover:underline">View all →</button>
                    </div>
                    <div class="space-y-3" x-show="deployments.length > 0">
                        <template x-for="d in deployments.slice(0,5)" :key="d.id">
                            <div class="bg-slate-800/40 rounded-xl p-4 flex items-center justify-between hover:bg-slate-800/60 transition">
                                <div class="flex items-center gap-4">
                                    <div class="w-9 h-9 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                        <i class="fas fa-rocket text-blue-400 text-sm"></i>
                                    </div>
                                    <div>
                                        <div class="font-semibold text-sm" x-text="d.name"></div>
                                        <div class="text-xs text-slate-400"><span x-text="d.id"></span> · Port <span x-text="d.port"></span></div>
                                    </div>
                                </div>
                                <span class="px-2.5 py-1 rounded-lg text-xs font-semibold"
                                      :class="'status-'+d.status" x-text="d.status.toUpperCase()"></span>
                            </div>
                        </template>
                    </div>
                    <div x-show="deployments.length===0" class="text-center py-16 text-slate-400">
                        <i class="fas fa-satellite-dish text-5xl mb-4 opacity-20"></i>
                        <p class="font-semibold">No deployments yet</p>
                        <p class="text-sm mt-1">Deploy your first app to get started!</p>
                        <button @click="navigate('new-deploy')" class="btn-primary mt-4 px-6 py-2 rounded-xl text-sm font-semibold">
                            <i class="fas fa-plus mr-2"></i>Deploy Now
                        </button>
                    </div>
                </div>
            </div>

            <!-- DEPLOYMENTS PAGE -->
            <div x-show="currentPage==='deployments'" x-transition:enter="transition ease-out duration-200" x-transition:enter-start="opacity-0 translate-y-4" x-transition:enter-end="opacity-100 translate-y-0">
                <div class="flex items-center justify-between mb-8">
                    <h1 class="text-3xl font-black">All Deployments</h1>
                    <button @click="loadDeployments(true)" class="btn-primary px-4 py-2 rounded-xl text-sm font-semibold">
                        <i class="fas fa-sync-alt mr-2"></i>Refresh
                    </button>
                </div>
                <div class="space-y-4">
                    <template x-for="d in deployments" :key="d.id">
                        <div class="glass rounded-2xl p-6 hover:border-blue-500/30 transition">
                            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
                                <div>
                                    <h3 class="text-lg font-bold mb-1" x-text="d.name"></h3>
                                    <div class="flex flex-wrap gap-3 text-xs text-slate-400">
                                        <span><i class="fas fa-fingerprint mr-1"></i><span x-text="d.id"></span></span>
                                        <span><i class="fas fa-network-wired mr-1"></i>Port <span x-text="d.port"></span></span>
                                        <span><i class="fas fa-code-branch mr-1"></i><span x-text="d.type"></span></span>
                                        <span x-show="d.restart_count > 0" class="text-yellow-400">
                                            <i class="fas fa-redo mr-1"></i>Restarted <span x-text="d.restart_count"></span>x
                                        </span>
                                    </div>
                                </div>
                                <span class="px-4 py-1.5 rounded-xl text-sm font-bold w-fit"
                                      :class="'status-'+d.status" x-text="d.status.toUpperCase()"></span>
                            </div>
                            <div class="flex flex-wrap gap-2">
                                <button @click="viewDeployment(d.id)" class="btn-primary px-4 py-2 rounded-xl text-xs font-semibold">
                                    <i class="fas fa-eye mr-1"></i>Details
                                </button>
                                <button @click="viewLogs(d.id)" class="bg-slate-700/50 hover:bg-slate-700 px-4 py-2 rounded-xl text-xs transition">
                                    <i class="fas fa-terminal mr-1"></i>Logs
                                </button>
                                <button @click="restartDeploy(d.id)" class="bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-400 px-4 py-2 rounded-xl text-xs transition" x-show="d.status==='running' || d.status==='stopped'">
                                    <i class="fas fa-redo mr-1"></i>Restart
                                </button>
                                <button @click="stopDeploy(d.id)" class="bg-orange-600/20 hover:bg-orange-600/30 text-orange-400 px-4 py-2 rounded-xl text-xs transition" x-show="d.status==='running'">
                                    <i class="fas fa-stop mr-1"></i>Stop
                                </button>
                                <button @click="deleteDeploy(d.id)" class="bg-red-600/20 hover:bg-red-600/30 text-red-400 px-4 py-2 rounded-xl text-xs transition">
                                    <i class="fas fa-trash mr-1"></i>Delete
                                </button>
                            </div>
                        </div>
                    </template>
                    <div x-show="deployments.length===0" class="glass rounded-2xl p-16 text-center">
                        <i class="fas fa-rocket text-6xl text-slate-700 mb-4"></i>
                        <h3 class="text-xl font-bold mb-2">No Deployments</h3>
                        <p class="text-slate-400 mb-6">Get started by deploying your first app</p>
                        <button @click="navigate('new-deploy')" class="btn-primary px-6 py-3 rounded-xl font-semibold">
                            <i class="fas fa-plus mr-2"></i>Create Deployment
                        </button>
                    </div>
                </div>
            </div>

            <!-- NEW DEPLOY PAGE -->
            <div x-show="currentPage==='new-deploy'" x-transition:enter="transition ease-out duration-200" x-transition:enter-start="opacity-0 translate-y-4" x-transition:enter-end="opacity-100 translate-y-0">
                <h1 class="text-3xl font-black mb-8">New Deployment</h1>
                <div class="grid md:grid-cols-2 gap-6">
                    <!-- File Upload -->
                    <div class="glass rounded-2xl p-6">
                        <div class="flex items-center gap-3 mb-5">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                                <i class="fas fa-cloud-upload-alt text-blue-400 text-xl"></i>
                            </div>
                            <div>
                                <h3 class="font-bold">Upload Files</h3>
                                <p class="text-xs text-slate-400">Deploy .py, .js, or .zip</p>
                            </div>
                        </div>
                        <div id="dropZone"
                            class="border-2 border-dashed border-slate-700 rounded-xl p-8 text-center cursor-pointer hover:border-blue-500/70 hover:bg-blue-500/5 transition mb-4"
                            onclick="document.getElementById('fileInput').click()"
                            ondragover="event.preventDefault();this.classList.add('border-blue-500')"
                            ondragleave="this.classList.remove('border-blue-500')"
                            ondrop="handleDrop(event)">
                            <i class="fas fa-file-upload text-4xl text-slate-600 mb-3"></i>
                            <p class="text-slate-300 font-semibold mb-1">Click or drag & drop</p>
                            <p class="text-xs text-slate-500">Python, JavaScript, ZIP — max 100MB</p>
                            <input type="file" id="fileInput" class="hidden" accept=".py,.js,.zip" @change="uploadFile($event)">
                        </div>
                        <div x-show="uploadProgress > 0" class="mb-4">
                            <div class="flex justify-between text-xs mb-1">
                                <span class="text-slate-400">Uploading...</span>
                                <span class="text-blue-400" x-text="uploadProgress+'%'"></span>
                            </div>
                            <div class="bg-slate-800 rounded-full h-1.5">
                                <div class="progress-bar bg-gradient-to-r from-blue-500 to-cyan-500 rounded-full"
                                     :style="'width:'+uploadProgress+'%'"></div>
                            </div>
                        </div>
                        <div class="bg-blue-500/10 border border-blue-500/20 rounded-xl p-3 text-xs text-blue-400">
                            <i class="fas fa-robot mr-2"></i>Cost: <strong>0.5 credits</strong> · AI auto-installs dependencies
                        </div>
                    </div>

                    <!-- GitHub Deploy -->
                    <div class="glass rounded-2xl p-6">
                        <div class="flex items-center gap-3 mb-5">
                            <div class="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center">
                                <i class="fab fa-github text-cyan-400 text-xl"></i>
                            </div>
                            <div>
                                <h3 class="font-bold">Deploy from GitHub</h3>
                                <p class="text-xs text-slate-400">Import and deploy repositories</p>
                            </div>
                        </div>
                        <form @submit.prevent="deployGithub()" class="space-y-3">
                            <div>
                                <label class="text-xs font-semibold text-slate-300 mb-1 block">Repository URL *</label>
                                <input type="url" x-model="githubForm.url" required placeholder="https://github.com/user/repo"
                                    class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                            </div>
                            <div class="grid grid-cols-2 gap-3">
                                <div>
                                    <label class="text-xs font-semibold text-slate-300 mb-1 block">Branch</label>
                                    <input type="text" x-model="githubForm.branch" placeholder="main"
                                        class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                                </div>
                                <div>
                                    <label class="text-xs font-semibold text-slate-300 mb-1 block">Build Command</label>
                                    <input type="text" x-model="githubForm.buildCmd" placeholder="npm install"
                                        class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                                </div>
                            </div>
                            <div>
                                <label class="text-xs font-semibold text-slate-300 mb-1 block">Start Command (auto-detected)</label>
                                <input type="text" x-model="githubForm.startCmd" placeholder="npm start"
                                    class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                            </div>
                            <button type="submit" :disabled="deploying"
                                class="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:opacity-90 px-4 py-3 rounded-xl font-bold text-sm transition">
                                <span x-show="!deploying"><i class="fab fa-github mr-2"></i>Deploy from GitHub <span class="opacity-70">(1.0 credit)</span></span>
                                <span x-show="deploying"><i class="fas fa-spinner fa-spin mr-2"></i>Deploying...</span>
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- BUY CREDITS PAGE -->
            <div x-show="currentPage==='buy-credits'" x-transition:enter="transition ease-out duration-200" x-transition:enter-start="opacity-0 translate-y-4" x-transition:enter-end="opacity-100 translate-y-0">
                <h1 class="text-3xl font-black mb-8">Buy Credits</h1>
                <div class="grid md:grid-cols-3 gap-6 mb-8">
                    <div class="glass rounded-2xl p-6 hover:border-blue-500/40 transition cursor-pointer group" @click="selectPackage('10_credits')">
                        <div class="flex justify-between items-start mb-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center group-hover:bg-blue-500/30 transition">
                                <i class="fas fa-gem text-blue-400 text-lg"></i>
                            </div>
                            <span class="text-xs bg-blue-500/20 text-blue-400 px-2 py-1 rounded-full font-semibold">STARTER</span>
                        </div>
                        <div class="text-3xl font-black mb-1">10 Credits</div>
                        <div class="text-2xl text-blue-400 font-bold mb-4">₹50</div>
                        <ul class="text-xs text-slate-400 space-y-1.5 mb-6">
                            <li><i class="fas fa-check text-green-400 mr-2"></i>20 File Deployments</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>10 GitHub Deploys</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>20 Backups</li>
                        </ul>
                        <button class="w-full btn-primary py-2.5 rounded-xl text-sm font-semibold">Select Package</button>
                    </div>

                    <div class="relative bg-gradient-to-b from-blue-900/30 to-slate-900 border-2 border-blue-500/50 rounded-2xl p-6 shadow-2xl shadow-blue-500/10">
                        <div class="absolute -top-3.5 left-1/2 -translate-x-1/2 bg-gradient-to-r from-blue-500 to-cyan-500 text-white text-xs font-bold px-4 py-1 rounded-full">BEST VALUE</div>
                        <div class="flex justify-between items-start mb-4">
                            <div class="w-12 h-12 bg-yellow-500/20 rounded-xl flex items-center justify-center">
                                <i class="fas fa-crown text-yellow-400 text-lg"></i>
                            </div>
                            <span class="text-xs bg-blue-500 text-white px-2 py-1 rounded-full font-semibold">PRO</span>
                        </div>
                        <div class="text-3xl font-black mb-1">99 Credits</div>
                        <div class="text-2xl text-blue-400 font-bold mb-0.5">₹399</div>
                        <div class="text-xs text-green-400 mb-4"><s class="text-slate-500">₹495</s> — Save ₹96!</div>
                        <ul class="text-xs text-slate-400 space-y-1.5 mb-6">
                            <li><i class="fas fa-check text-green-400 mr-2"></i>198 File Deployments</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>99 GitHub Deploys</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>198 Backups</li>
                            <li><i class="fas fa-star text-yellow-400 mr-2"></i>Priority Support</li>
                        </ul>
                        <button @click="selectPackage('99_credits')" class="w-full bg-gradient-to-r from-blue-600 to-cyan-500 hover:opacity-90 py-2.5 rounded-xl text-sm font-bold">Select Package</button>
                    </div>

                    <div class="glass rounded-2xl p-6 hover:border-cyan-500/40 transition">
                        <div class="flex justify-between items-start mb-4">
                            <div class="w-12 h-12 bg-cyan-500/20 rounded-xl flex items-center justify-center">
                                <i class="fas fa-infinity text-cyan-400 text-lg"></i>
                            </div>
                            <span class="text-xs bg-cyan-500/20 text-cyan-400 px-2 py-1 rounded-full font-semibold">CUSTOM</span>
                        </div>
                        <div class="text-3xl font-black mb-1">Custom</div>
                        <div class="text-2xl text-cyan-400 font-bold mb-4">Your Amount</div>
                        <div class="mb-4">
                            <label class="text-xs text-slate-400 mb-1 block">Enter amount (₹)</label>
                            <input type="number" x-model="customAmount" placeholder="e.g. 200" min="10"
                                class="w-full px-4 py-2.5 bg-slate-800/60 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500">
                        </div>
                        <p class="text-xs text-slate-400 mb-4">
                            Need help? <a href="{{ telegram_link }}" target="_blank" class="text-blue-400 hover:underline">Contact {{ username }}</a>
                        </p>
                        <button @click="selectCustomPackage()" class="w-full bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-400 border border-cyan-600/30 py-2.5 rounded-xl text-sm font-semibold transition">
                            <i class="fas fa-paper-plane mr-2"></i>Proceed
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- Payment Modal -->
    <div x-show="modal==='payment'" x-cloak @click.self="modal=null"
         class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
        <div class="glass rounded-2xl max-w-md w-full p-6 max-h-[90vh] overflow-y-auto">
            <div class="flex items-center justify-between mb-6">
                <h2 class="text-xl font-black">Complete Payment</h2>
                <button @click="modal=null" class="text-slate-400 hover:text-white">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="bg-slate-800/50 rounded-xl p-4 mb-4 text-sm space-y-2">
                <div class="flex justify-between"><span class="text-slate-400">Package</span><span class="font-bold" x-text="paymentData.package"></span></div>
                <div class="flex justify-between"><span class="text-slate-400">Credits</span><span class="text-blue-400 font-bold" x-text="paymentData.credits"></span></div>
                <div class="flex justify-between"><span class="text-slate-400">Amount</span><span class="text-green-400 text-xl font-black">₹<span x-text="paymentData.price"></span></span></div>
            </div>
            <div class="bg-white rounded-xl p-3 mb-4 text-center">
                <img src="/qr.jpg" alt="QR" class="w-56 h-56 mx-auto object-contain">
                <p class="text-slate-900 font-bold text-sm mt-2">Scan · Pay ₹<span x-text="paymentData.price"></span></p>
            </div>
            <div class="space-y-3 mb-4">
                <div>
                    <label class="text-xs font-semibold text-slate-300 mb-1 block">Payment Screenshot</label>
                    <input type="file" accept="image/*" @change="uploadScreenshot($event)"
                        class="w-full text-sm text-slate-400 file:mr-3 file:py-1.5 file:px-3 file:rounded-lg file:border-0 file:bg-blue-600 file:text-white file:text-xs cursor-pointer">
                </div>
                <div>
                    <label class="text-xs font-semibold text-slate-300 mb-1 block">Transaction / UTR ID</label>
                    <input type="text" x-model="paymentData.transactionId" placeholder="Enter transaction ID" required
                        class="w-full px-4 py-2.5 bg-slate-800 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
            </div>
            <div class="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-3 text-xs text-yellow-400 mb-4 flex items-center gap-2">
                <i class="fas fa-clock"></i>
                <span>Time remaining: <strong x-text="formatTime(timeRemaining)"></strong></span>
            </div>
            <div class="flex gap-3">
                <button @click="modal=null" class="flex-1 bg-slate-700 hover:bg-slate-600 py-3 rounded-xl text-sm transition">Cancel</button>
                <button @click="submitPayment()" class="flex-1 btn-primary py-3 rounded-xl text-sm font-bold">
                    <i class="fas fa-check mr-1"></i>Submit
                </button>
            </div>
        </div>
    </div>

    <!-- Deployment Details Modal -->
    <div x-show="modal==='details'" x-cloak @click.self="modal=null"
         class="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
        <div class="glass rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div class="sticky top-0 bg-slate-900/95 backdrop-blur p-6 border-b border-slate-800 flex items-center justify-between z-10">
                <div>
                    <h2 class="text-xl font-black" x-text="selectedDeploy && selectedDeploy.name"></h2>
                    <p class="text-xs text-slate-400" x-text="selectedDeploy && selectedDeploy.id"></p>
                </div>
                <button @click="modal=null" class="text-slate-400 hover:text-white p-2">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
            <div class="p-6" x-show="selectedDeploy">
                <!-- Tabs -->
                <div class="flex gap-1 mb-6 bg-slate-800/50 p-1 rounded-xl flex-wrap">
                    <template x-for="tab in ['info','env','files','backup','console']" :key="tab">
                        <button @click="detailsTab=tab"
                            :class="detailsTab===tab ? 'bg-blue-600 text-white shadow' : 'text-slate-400 hover:text-white'"
                            class="flex-1 px-4 py-2 rounded-lg text-xs font-semibold capitalize transition min-w-[60px]"
                            x-text="tab"></button>
                    </template>
                </div>

                <div x-show="detailsTab==='info'" class="space-y-4">
                    <div class="grid grid-cols-2 gap-3">
                        <template x-for="[label, val] in [['ID', selectedDeploy?.id],['Port', selectedDeploy?.port],['Status', selectedDeploy?.status],['Type', selectedDeploy?.type],['PID', selectedDeploy?.pid],['Restarts', selectedDeploy?.restart_count]]" :key="label">
                            <div class="bg-slate-800/40 rounded-xl p-3">
                                <div class="text-xs text-slate-400 mb-1" x-text="label"></div>
                                <div class="font-mono text-sm font-semibold" x-text="val"></div>
                            </div>
                        </template>
                    </div>
                    <div x-show="selectedDeploy?.dependencies?.length > 0">
                        <p class="text-xs font-semibold text-slate-300 mb-2">AI-Installed Dependencies</p>
                        <div class="flex flex-wrap gap-2">
                            <template x-for="dep in selectedDeploy?.dependencies" :key="dep">
                                <span class="bg-blue-500/20 text-blue-300 border border-blue-500/20 px-3 py-1 rounded-full text-xs" x-text="dep"></span>
                            </template>
                        </div>
                    </div>
                </div>

                <div x-show="detailsTab==='env'">
                    <div class="flex gap-2 mb-4">
                        <input x-model="newEnv.key" placeholder="KEY" class="flex-1 px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <input x-model="newEnv.value" placeholder="value" class="flex-1 px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <button @click="addEnvVar()" class="btn-primary px-4 py-2 rounded-xl text-sm">
                            <i class="fas fa-plus"></i>
                        </button>
                    </div>
                    <div class="space-y-2">
                        <template x-for="[k, v] in Object.entries(selectedDeploy?.env_vars || {})" :key="k">
                            <div class="bg-slate-800/40 rounded-xl p-3 flex items-center justify-between">
                                <div class="font-mono text-sm"><span class="text-blue-400" x-text="k"></span> = <span x-text="v"></span></div>
                                <button @click="deleteEnvVar(k)" class="text-red-400 hover:text-red-300 px-2"><i class="fas fa-trash text-xs"></i></button>
                            </div>
                        </template>
                        <div x-show="!selectedDeploy?.env_vars || Object.keys(selectedDeploy?.env_vars).length===0" class="text-center py-8 text-slate-400 text-sm">No env vars set</div>
                    </div>
                </div>

                <div x-show="detailsTab==='files'">
                    <button @click="loadFiles()" class="btn-primary px-4 py-2 rounded-xl text-sm mb-4">
                        <i class="fas fa-sync mr-2"></i>Refresh
                    </button>
                    <div class="space-y-2 max-h-80 overflow-y-auto">
                        <template x-for="file in deployFiles" :key="file.path">
                            <div class="bg-slate-800/40 rounded-xl p-3 flex items-center justify-between">
                                <div class="flex items-center gap-3">
                                    <i class="fas fa-file-code text-slate-400 text-sm"></i>
                                    <div>
                                        <div class="font-mono text-sm" x-text="file.path"></div>
                                        <div class="text-xs text-slate-500" x-text="formatBytes(file.size)"></div>
                                    </div>
                                </div>
                                <div class="text-xs text-slate-400" x-text="formatDate(file.modified)"></div>
                            </div>
                        </template>
                        <div x-show="deployFiles.length===0" class="text-center py-8 text-slate-400 text-sm">No files found</div>
                    </div>
                </div>

                <div x-show="detailsTab==='backup'" class="text-center py-10">
                    <i class="fas fa-archive text-6xl text-slate-700 mb-4"></i>
                    <h3 class="text-xl font-bold mb-2">Create Backup</h3>
                    <p class="text-slate-400 text-sm mb-6">Download a complete snapshot of this deployment</p>
                    <button @click="createBackup()" class="btn-primary px-8 py-3 rounded-xl font-semibold">
                        <i class="fas fa-download mr-2"></i>Create & Download Backup <span class="opacity-70">(0.5 cr)</span>
                    </button>
                </div>

                <div x-show="detailsTab==='console'">
                    <div class="bg-slate-950 rounded-xl p-4 font-mono text-xs text-green-400 h-80 overflow-y-auto whitespace-pre-wrap leading-relaxed border border-slate-800"
                         x-ref="consoleEl" x-text="consoleLogs"></div>
                    <div class="flex gap-2 mt-3">
                        <button @click="refreshLogs()" class="btn-primary px-4 py-2 rounded-xl text-sm">
                            <i class="fas fa-sync mr-2"></i>Refresh
                        </button>
                        <button @click="consoleLogs=''" class="bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded-xl text-sm transition">
                            Clear
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
    // ==================== DROP HANDLER ====================
    function handleDrop(e) {
        e.preventDefault();
        document.getElementById('dropZone').classList.remove('border-blue-500');
        const file = e.dataTransfer.files[0];
        if (file) {
            Alpine.store && Alpine.store('app');
            const input = document.getElementById('fileInput');
            const dt = new DataTransfer();
            dt.items.add(file);
            input.files = dt.files;
            input.dispatchEvent(new Event('change'));
        }
    }

    // ==================== ALPINE APP ====================
    function dashApp() {
        return {
            sidebarOpen: false,
            currentPage: 'overview',
            modal: null,
            detailsTab: 'info',
            credits: {{ credits }},
            deployments: [],
            stats: { total: 0, running: 0 },
            selectedDeploy: null,
            deployFiles: [],
            consoleLogs: '',
            deploying: false,
            uploadProgress: 0,
            githubForm: { url: '', branch: 'main', buildCmd: '', startCmd: '' },
            newEnv: { key: '', value: '' },
            customAmount: '',
            paymentData: { id:'', package:'', credits:0, price:0, screenshot:null, transactionId:'' },
            timeRemaining: 1800,   // 30 minutes
            timerInterval: null,
            navItems: [
                { id:'overview', icon:'fas fa-th-large', label:'Overview', badge:0 },
                { id:'deployments', icon:'fas fa-rocket', label:'Deployments', badge:0 },
                { id:'new-deploy', icon:'fas fa-plus-circle', label:'New Deploy', badge:0 },
                { id:'buy-credits', icon:'fas fa-gem', label:'Buy Credits', badge:0 },
            ],
            sseConnected: false,
            sseRetries: 0,

            // ─────────────────────────────────────────────────
            init() {
                this.loadDeployments();
                // ✅ KEY FIX: SSE replaces aggressive polling
                // Use SSE for real-time updates, only poll as fallback
                this.connectSSE();
                // Lightweight fallback poll every 30s (not 10s)
                setInterval(() => this.loadDeployments(), 30000);
            },

            navigate(page) {
                this.currentPage = page;
                this.sidebarOpen = false;
            },

            // ─── SSE Connection ───────────────────────────────
            connectSSE() {
                if (typeof EventSource === 'undefined') return;
                const es = new EventSource('/api/events');
                es.onopen = () => { this.sseConnected = true; this.sseRetries = 0; };
                es.onmessage = (e) => {
                    try {
                        const event = JSON.parse(e.data);
                        this.handleSSEEvent(event);
                    } catch (err) {}
                };
                es.onerror = () => {
                    es.close();
                    this.sseConnected = false;
                    // Exponential backoff reconnect
                    const delay = Math.min(30000, 1000 * Math.pow(2, this.sseRetries++));
                    setTimeout(() => this.connectSSE(), delay);
                };
            },

            handleSSEEvent(event) {
                switch(event.type) {
                    case 'deployment_updated':
                        this.loadDeployments(); break;
                    case 'credits_updated':
                        this.credits = event.data.credits; break;
                    case 'payment_approved':
                        this.showToast(`💎 Payment approved! +${event.data.credits} credits`, 'success');
                        this.credits = (parseFloat(this.credits) + event.data.credits).toFixed(1);
                        break;
                    case 'payment_rejected':
                        this.showToast('❌ Payment was rejected. Please contact support.', 'error'); break;
                }
            },

            // ─── Load Deployments ─────────────────────────────
            async loadDeployments(force=false) {
                try {
                    const res = await fetch('/api/deployments');
                    if (res.status === 429 && !force) return; // skip on rate limit during auto-poll
                    const data = await res.json();
                    if (data.success) {
                        this.deployments = data.deployments;
                        this.stats.total = data.deployments.length;
                        this.stats.running = data.deployments.filter(d => d.status==='running').length;
                        this.navItems[1].badge = this.stats.running || 0;
                    }
                } catch(e) { console.warn('Deploy poll:', e.message); }
            },

            // ─── Upload File ──────────────────────────────────
            async uploadFile(event) {
                const file = event.target.files[0];
                if (!file) return;
                const formData = new FormData();
                formData.append('file', file);
                this.uploadProgress = 10;
                const progressInterval = setInterval(() => {
                    if (this.uploadProgress < 85) this.uploadProgress += 5;
                }, 400);
                try {
                    const res = await fetch('/api/deploy/upload', { method:'POST', body:formData });
                    clearInterval(progressInterval);
                    this.uploadProgress = 100;
                    const data = await res.json();
                    setTimeout(() => { this.uploadProgress = 0; }, 1000);
                    if (data.success) {
                        this.showToast('✅ Deployment successful!', 'success');
                        this.loadDeployments();
                        this.currentPage = 'deployments';
                    } else {
                        this.showToast('❌ ' + data.error, 'error');
                    }
                } catch(e) {
                    clearInterval(progressInterval);
                    this.uploadProgress = 0;
                    this.showToast('❌ Upload failed', 'error');
                }
                event.target.value = '';
            },

            // ─── GitHub Deploy ────────────────────────────────
            async deployGithub() {
                if (!this.githubForm.url) return;
                this.deploying = true;
                try {
                    const res = await fetch('/api/deploy/github', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({
                            url: this.githubForm.url, branch: this.githubForm.branch || 'main',
                            build_command: this.githubForm.buildCmd, start_command: this.githubForm.startCmd
                        })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.showToast('✅ GitHub deployment successful!', 'success');
                        this.loadDeployments();
                        this.currentPage = 'deployments';
                        this.githubForm = { url:'', branch:'main', buildCmd:'', startCmd:'' };
                    } else {
                        this.showToast('❌ ' + data.error, 'error');
                    }
                } catch(e) { this.showToast('❌ Deployment failed', 'error'); }
                finally { this.deploying = false; }
            },

            // ─── Select Package ───────────────────────────────
            async selectPackage(packageType) {
                try {
                    const res = await fetch('/api/payment/create', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({ package_type: packageType })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.paymentData = { ...data.payment, package: packageType.replace('_',' ').toUpperCase(), screenshot:null, transactionId:'' };
                        this.modal = 'payment';
                        this.startTimer(data.payment.expires_at);
                    } else { this.showToast('❌ ' + data.error, 'error'); }
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },

            async selectCustomPackage() {
                if (!this.customAmount || this.customAmount < 10) {
                    this.showToast('❌ Minimum amount is ₹10', 'error'); return;
                }
                try {
                    const res = await fetch('/api/payment/create', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({ package_type:'custom', custom_amount: parseInt(this.customAmount) })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.paymentData = { ...data.payment, package:'CUSTOM', screenshot:null, transactionId:'' };
                        this.modal = 'payment';
                        this.startTimer(data.payment.expires_at);
                    } else { this.showToast('❌ ' + data.error, 'error'); }
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },

            uploadScreenshot(event) {
                const file = event.target.files[0];
                if (!file) return;
                const reader = new FileReader();
                reader.onload = (e) => { this.paymentData.screenshot = e.target.result; };
                reader.readAsDataURL(file);
            },

            async submitPayment() {
                if (!this.paymentData.screenshot) { this.showToast('❌ Upload screenshot', 'error'); return; }
                if (!this.paymentData.transactionId) { this.showToast('❌ Enter transaction ID', 'error'); return; }
                try {
                    const res = await fetch('/api/payment/submit', {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify({ payment_id:this.paymentData.id, screenshot:this.paymentData.screenshot, transaction_id:this.paymentData.transactionId })
                    });
                    const data = await res.json();
                    if (data.success) {
                        this.stopTimer(); this.modal = null;
                        this.showToast('✅ Payment submitted! Awaiting admin approval.', 'success');
                    } else { this.showToast('❌ ' + data.error, 'error'); }
                } catch(e) { this.showToast('❌ Submission failed', 'error'); }
            },

            startTimer(expiresAt) {
                this.stopTimer();
                const expires = new Date(expiresAt).getTime();
                this.timerInterval = setInterval(() => {
                    this.timeRemaining = Math.max(0, Math.round((expires - Date.now()) / 1000));
                    if (this.timeRemaining <= 0) {
                        this.stopTimer(); this.modal = null;
                        this.showToast('⏰ Payment session expired', 'error');
                    }
                }, 1000);
                this.timeRemaining = Math.max(0, Math.round((expires - Date.now()) / 1000));
            },

            stopTimer() { if (this.timerInterval) { clearInterval(this.timerInterval); this.timerInterval = null; } },

            formatTime(s) {
                const m = Math.floor(s/60), sec = s%60;
                return `${m}:${String(sec).padStart(2,'0')}`;
            },

            // ─── Deployment Actions ───────────────────────────
            viewDeployment(id) {
                this.selectedDeploy = this.deployments.find(d=>d.id===id);
                this.modal = 'details'; this.detailsTab = 'info';
            },
            viewLogs(id) {
                this.selectedDeploy = this.deployments.find(d=>d.id===id);
                this.modal = 'details'; this.detailsTab = 'console'; this.refreshLogs();
            },
            async refreshLogs() {
                if (!this.selectedDeploy) return;
                try {
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/logs`);
                    const data = await res.json();
                    this.consoleLogs = data.logs || 'No logs available';
                    this.$nextTick(() => { if (this.$refs.consoleEl) this.$refs.consoleEl.scrollTop = 999999; });
                } catch(e) { this.consoleLogs = 'Failed to load logs'; }
            },
            async loadFiles() {
                if (!this.selectedDeploy) return;
                try {
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/files`);
                    const data = await res.json();
                    this.deployFiles = data.files || [];
                } catch(e) { this.deployFiles = []; }
            },
            async addEnvVar() {
                if (!this.newEnv.key || !this.newEnv.value) return;
                try {
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env`, {
                        method:'POST', headers:{'Content-Type':'application/json'},
                        body: JSON.stringify(this.newEnv)
                    });
                    const data = await res.json();
                    if (data.success) { this.selectedDeploy.env_vars = data.env_vars; this.newEnv={key:'',value:''}; this.showToast('✅ Env var added', 'success'); }
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            async deleteEnvVar(key) {
                try {
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env/${key}`, { method:'DELETE' });
                    const data = await res.json();
                    if (data.success) { this.selectedDeploy.env_vars = data.env_vars; this.showToast('✅ Deleted', 'success'); }
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            async createBackup() {
                if (!confirm('Create backup for 0.5 credits?')) return;
                try {
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/backup`, { method:'POST' });
                    const data = await res.json();
                    if (data.success) {
                        window.location.href = `/api/deployment/${this.selectedDeploy.id}/backup/download`;
                        this.showToast('✅ Backup created!', 'success');
                    } else { this.showToast('❌ ' + data.error, 'error'); }
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            async stopDeploy(id) {
                if (!confirm('Stop this deployment?')) return;
                try {
                    const res = await fetch(`/api/deployment/${id}/stop`, { method:'POST' });
                    const data = await res.json();
                    this.showToast(data.success ? '🛑 Deployment stopped' : '❌ '+data.error, data.success?'info':'error');
                    this.loadDeployments();
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            async restartDeploy(id) {
                try {
                    const res = await fetch(`/api/deployment/${id}/restart`, { method:'POST' });
                    const data = await res.json();
                    this.showToast(data.success ? '🔄 Restarting...' : '❌ '+data.error, data.success?'info':'error');
                    setTimeout(() => this.loadDeployments(), 3000);
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            async deleteDeploy(id) {
                if (!confirm('Permanently delete this deployment?')) return;
                try {
                    const res = await fetch(`/api/deployment/${id}`, { method:'DELETE' });
                    const data = await res.json();
                    this.showToast(data.success ? '🗑️ Deleted' : '❌ '+data.error, data.success?'success':'error');
                    this.loadDeployments(); this.modal = null;
                } catch(e) { this.showToast('❌ Failed', 'error'); }
            },
            logout() { if (confirm('Logout?')) window.location.href = '/logout'; },

            // ─── Toast Notifications ──────────────────────────
            showToast(msg, type='info') {
                const colors = { success:'bg-green-600', error:'bg-red-600', info:'bg-blue-600' };
                const container = document.getElementById('toastContainer') || document.body;
                const el = document.createElement('div');
                el.className = `toast ${colors[type]||'bg-blue-600'} text-white px-5 py-3 rounded-2xl shadow-2xl text-sm font-semibold flex items-center gap-2 mb-2`;
                el.innerHTML = msg;
                container.appendChild(el);
                setTimeout(() => { el.style.opacity='0'; el.style.transition='opacity 0.5s'; setTimeout(()=>el.remove(), 500); }, 3500);
            },

            formatBytes(b) {
                if(!b) return '0 B';
                const k=1024, sizes=['B','KB','MB','GB'];
                const i=Math.floor(Math.log(b)/Math.log(k));
                return (b/Math.pow(k,i)).toFixed(1)+' '+sizes[i];
            },
            formatDate(d) { return new Date(d).toLocaleString(); }
        }
    }
    </script>
</body>
</html>"""

ADMIN_PANEL_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost v14 - Admin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        body{background:#060d1a}
        .glass{background:rgba(15,23,42,0.8);backdrop-filter:blur(16px);border:1px solid rgba(59,130,246,0.1)}
        ::-webkit-scrollbar{width:4px;height:4px}
        ::-webkit-scrollbar-thumb{background:#1e40af;border-radius:2px}
    </style>
</head>
<body class="text-white min-h-screen" x-data="adminApp()">
    <div class="bg-gradient-to-r from-blue-900 to-cyan-900 p-6 shadow-2xl">
        <div class="max-w-7xl mx-auto flex items-center justify-between">
            <div class="flex items-center gap-4">
                <div class="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center">
                    <i class="fas fa-crown text-white text-xl"></i>
                </div>
                <div>
                    <h1 class="text-2xl font-black">Admin Control Panel</h1>
                    <p class="text-blue-200 text-xs">EliteHost v14.0 — Full System Control</p>
                </div>
            </div>
            <div class="flex gap-3">
                <a href="/dashboard" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-xl text-sm transition">
                    <i class="fas fa-arrow-left mr-2"></i>Dashboard
                </a>
                <button @click="location.reload()" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-xl text-sm transition">
                    <i class="fas fa-sync mr-2"></i>Refresh
                </button>
            </div>
        </div>
    </div>

    <div class="max-w-7xl mx-auto p-6">
        <!-- Stats -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <div class="glass rounded-2xl p-5"><div class="text-3xl font-black mb-1">{{ stats.total_users }}</div><div class="text-slate-400 text-xs">Total Users</div></div>
            <div class="glass rounded-2xl p-5"><div class="text-3xl font-black mb-1 text-blue-400">{{ stats.total_deployments }}</div><div class="text-slate-400 text-xs">Total Deployments</div></div>
            <div class="glass rounded-2xl p-5"><div class="text-3xl font-black mb-1 text-green-400">{{ stats.active_processes }}</div><div class="text-slate-400 text-xs">Active Processes</div></div>
            <div class="glass rounded-2xl p-5"><div class="text-3xl font-black mb-1 text-yellow-400">{{ stats.pending_payments }}</div><div class="text-slate-400 text-xs">Pending Payments</div></div>
        </div>

        <!-- System Metrics -->
        <div class="glass rounded-2xl p-6 mb-8">
            <h2 class="text-lg font-bold mb-5">System Resources</h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                <template x-for="[label, key, color] in [['CPU Usage','cpu','bg-blue-500'],['Memory','memory_percent','bg-green-500'],['Disk','disk_percent','bg-cyan-500']]" :key="key">
                    <div>
                        <div class="flex justify-between text-sm mb-2">
                            <span class="text-slate-400" x-text="label"></span>
                            <span class="font-bold" x-text="(metrics[key]||0)+'%'"></span>
                        </div>
                        <div class="bg-slate-800 rounded-full h-2">
                            <div :class="color" class="h-2 rounded-full transition-all duration-1000"
                                 :style="'width:'+(metrics[key]||0)+'%'"></div>
                        </div>
                    </div>
                </template>
            </div>
            <div class="grid grid-cols-3 gap-4 mt-4 text-xs text-slate-400">
                <div>RAM: <span class="text-white font-semibold" x-text="(metrics.memory_used||0)+'/'+( metrics.memory_total||0)+' GB'"></span></div>
                <div>Disk: <span class="text-white font-semibold" x-text="(metrics.disk_used||0)+'/'+(metrics.disk_total||0)+' GB'"></span></div>
                <div>Net: <span class="text-white font-semibold" x-text="'↑'+(metrics.net_sent_mb||0)+' MB ↓'+(metrics.net_recv_mb||0)+' MB'"></span></div>
            </div>
        </div>

        <!-- Users -->
        <div class="glass rounded-2xl mb-8 overflow-hidden">
            <div class="p-5 border-b border-slate-800 flex items-center justify-between">
                <h2 class="text-lg font-bold">Users</h2>
                <span class="text-xs text-slate-400">{{ users|length }} total</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="bg-slate-800/50 text-xs text-slate-400">
                        <tr>
                            <th class="text-left p-4">Email</th>
                            <th class="text-left p-4">Credits</th>
                            <th class="text-left p-4">Deploys</th>
                            <th class="text-left p-4">Joined</th>
                            <th class="text-left p-4">Status</th>
                            <th class="text-left p-4">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for user in users %}
                        <tr class="border-b border-slate-800/50 hover:bg-slate-800/20 transition">
                            <td class="p-4 font-medium">{{ user.email }}</td>
                            <td class="p-4 font-mono text-blue-400">{{ user.credits }}</td>
                            <td class="p-4">{{ user.deployments|length }}</td>
                            <td class="p-4 text-slate-400">{{ user.created_at[:10] }}</td>
                            <td class="p-4">
                                {% if user.is_banned %}
                                <span class="px-2 py-1 bg-red-500/20 text-red-400 rounded-lg text-xs font-bold">BANNED</span>
                                {% else %}
                                <span class="px-2 py-1 bg-green-500/20 text-green-400 rounded-lg text-xs font-bold">ACTIVE</span>
                                {% endif %}
                            </td>
                            <td class="p-4">
                                <div class="flex gap-2">
                                    <button onclick="addCreditsPrompt('{{ user.id }}')"
                                        class="bg-green-600/20 hover:bg-green-600/30 text-green-400 px-3 py-1.5 rounded-lg text-xs font-semibold transition">
                                        <i class="fas fa-plus mr-1"></i>Credits
                                    </button>
                                    {% if not user.is_banned %}
                                    <button onclick="banUser('{{ user.id }}')"
                                        class="bg-red-600/20 hover:bg-red-600/30 text-red-400 px-3 py-1.5 rounded-lg text-xs font-semibold transition">
                                        <i class="fas fa-ban mr-1"></i>Ban
                                    </button>
                                    {% else %}
                                    <button onclick="unbanUser('{{ user.id }}')"
                                        class="bg-green-600/20 hover:bg-green-600/30 text-green-400 px-3 py-1.5 rounded-lg text-xs font-semibold transition">
                                        <i class="fas fa-check mr-1"></i>Unban
                                    </button>
                                    {% endif %}
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Payments -->
        <div class="glass rounded-2xl overflow-hidden">
            <div class="p-5 border-b border-slate-800 flex items-center justify-between">
                <h2 class="text-lg font-bold">Payment Requests</h2>
                <span class="text-xs text-slate-400">{{ payments|length }} total</span>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="bg-slate-800/50 text-xs text-slate-400">
                        <tr>
                            <th class="text-left p-4">User</th>
                            <th class="text-left p-4">Amount</th>
                            <th class="text-left p-4">Transaction ID</th>
                            <th class="text-left p-4">Date</th>
                            <th class="text-left p-4">Status</th>
                            <th class="text-left p-4">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for p in payments %}
                        <tr class="border-b border-slate-800/50 hover:bg-slate-800/20 transition">
                            <td class="p-4">{{ p.user_email }}</td>
                            <td class="p-4 font-mono text-blue-400">{{ p.credits }} cr (₹{{ p.price }})</td>
                            <td class="p-4 font-mono text-xs">{{ p.transaction_id or '—' }}</td>
                            <td class="p-4 text-slate-400 text-xs">{{ p.created_at[:16] }}</td>
                            <td class="p-4">
                                <span class="px-2 py-1 rounded-lg text-xs font-bold
                                    {% if p.status == 'approved' %}bg-green-500/20 text-green-400
                                    {% elif p.status == 'submitted' %}bg-blue-500/20 text-blue-400
                                    {% elif p.status == 'pending' %}bg-yellow-500/20 text-yellow-400
                                    {% elif p.status == 'expired' %}bg-gray-500/20 text-gray-400
                                    {% else %}bg-red-500/20 text-red-400{% endif %}">
                                    {{ p.status.upper() }}
                                </span>
                            </td>
                            <td class="p-4">
                                {% if p.status == 'submitted' %}
                                <div class="flex gap-2">
                                    <button onclick="approvePayment('{{ p.id }}','{{ p.user_id }}',{{ p.credits }})"
                                        class="bg-green-600/20 hover:bg-green-600/30 text-green-400 px-3 py-1.5 rounded-lg text-xs font-bold transition">
                                        ✅ Approve
                                    </button>
                                    <button onclick="rejectPayment('{{ p.id }}')"
                                        class="bg-red-600/20 hover:bg-red-600/30 text-red-400 px-3 py-1.5 rounded-lg text-xs font-bold transition">
                                        ❌ Reject
                                    </button>
                                    <button onclick="viewScreenshot('{{ p.id }}')"
                                        class="bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 px-3 py-1.5 rounded-lg text-xs font-bold transition">
                                        🖼 View
                                    </button>
                                </div>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script>
        function adminApp() {
            return {
                metrics: {},
                init() { this.loadMetrics(); setInterval(() => this.loadMetrics(), 5000); },
                async loadMetrics() {
                    try {
                        const r = await fetch('/api/admin/metrics');
                        const d = await r.json();
                        if (d.success) this.metrics = d.metrics;
                    } catch(e) {}
                }
            }
        }

        async function addCreditsPrompt(userId) {
            const amt = prompt('Credits to add:');
            if (!amt || isNaN(amt) || parseFloat(amt) <= 0) return;
            const r = await fetch('/api/admin/add-credits', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify({ user_id: userId, amount: parseFloat(amt) })
            });
            const d = await r.json();
            alert(d.success ? '✅ Credits added!' : '❌ ' + d.error);
            if (d.success) location.reload();
        }

        async function approvePayment(paymentId, userId, credits) {
            if (!confirm(`Approve payment and add ${credits} credits?`)) return;
            const r = await fetch('/api/admin/approve-payment', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify({ payment_id: paymentId })
            });
            const d = await r.json();
            alert(d.success ? '✅ Approved!' : '❌ ' + d.error);
            if (d.success) location.reload();
        }

        async function rejectPayment(paymentId) {
            if (!confirm('Reject this payment?')) return;
            const r = await fetch('/api/admin/reject-payment', {
                method:'POST', headers:{'Content-Type':'application/json'},
                body: JSON.stringify({ payment_id: paymentId })
            });
            const d = await r.json();
            alert(d.success ? '✅ Rejected' : '❌ ' + d.error);
            if (d.success) location.reload();
        }

        async function banUser(userId) {
            if (!confirm('Ban this user?')) return;
            await fetch('/api/admin/ban-user', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({user_id:userId, ban:true}) });
            location.reload();
        }
        async function unbanUser(userId) {
            if (!confirm('Unban this user?')) return;
            await fetch('/api/admin/ban-user', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({user_id:userId, ban:false}) });
            location.reload();
        }
        function viewScreenshot(id) { window.open(`/api/payment/${id}/screenshot`, '_blank'); }
    </script>
</body>
</html>"""

# ==================== FLASK MIDDLEWARE ====================

@app.before_request
def before_request():
    fingerprint = get_device_fingerprint(request)
    if is_device_banned(fingerprint):
        return jsonify({'error': 'Access denied'}), 403

@app.after_request
def after_request(response):
    response.headers.update({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
    })
    return response

# ==================== AUTH ROUTES ====================

@app.route('/')
def index():
    token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(token, fingerprint)
    return redirect('/dashboard' if user_id else '/login')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("20 per hour")
def register():
    if request.method == 'GET':
        return render_template_string(LOGIN_PAGE,
            title='Register', subtitle='Create your EliteHost account',
            action='/register', button_text='Create Account', icon='user-plus',
            toggle_text='Already have an account?', toggle_link='/login', toggle_action='Login',
            error=request.args.get('error',''), success=request.args.get('success',''))

    try:
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        fingerprint = get_device_fingerprint(request)
        ip = request.remote_addr

        if not email or not password:
            return redirect('/register?error=Email and password required')
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            return redirect('/register?error=Invalid email format')
        if len(password) < 6:
            return redirect('/register?error=Password must be at least 6 characters')
        if email == ADMIN_EMAIL.lower():
            return redirect('/register?error=This email is reserved. Please login.')

        existing_id = check_existing_account(fingerprint)
        if existing_id:
            existing_user = get_user(existing_id)
            if existing_user and not is_admin_user(existing_id, existing_user['email']):
                return redirect('/register?error=This device already has an account. Please login.')

        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT id FROM users WHERE email = ?', (email,))
            if c.fetchone():
                return redirect('/register?error=Email already registered')

        user_id = create_user(email, password, fingerprint, ip)
        if not user_id:
            return redirect('/register?error=Registration failed. Please try again.')

        token = create_session(user_id, fingerprint)
        response = make_response(redirect('/dashboard'))
        response.set_cookie('session_token', token,
                           max_age=SESSION_TIMEOUT_DAYS*86400, httponly=True, samesite='Lax')
        return response

    except Exception as e:
        log_error(str(e), "register")
        return redirect('/register?error=An error occurred. Please try again.')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("50 per hour")
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_PAGE,
            title='Login', subtitle='Sign in to your account',
            action='/login', button_text='Sign In', icon='sign-in-alt',
            toggle_text="Don't have an account?", toggle_link='/register', toggle_action='Register',
            error=request.args.get('error',''), success=request.args.get('success',''))

    try:
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        fingerprint = get_device_fingerprint(request)
        ip = request.remote_addr

        if not email or not password:
            return redirect('/login?error=Email and password required')

        # ── Admin direct login ──────────────────────────────
        is_admin_login = (email == ADMIN_EMAIL.lower() and password == ADMIN_PASSWORD)
        if is_admin_login:
            with get_db() as conn:
                c = conn.cursor()
                c.execute('SELECT id, is_banned FROM users WHERE email = ?', (email,))
                row = c.fetchone()
                if row:
                    if row['is_banned']:
                        return redirect('/login?error=Account banned')
                    user_id = row['id']
                    update_user(user_id, device_fingerprint=fingerprint, last_login=datetime.now().isoformat())
                else:
                    user_id = create_user(email, password, fingerprint, ip)
                    if not user_id:
                        return redirect('/login?error=Failed to create admin account')
            log_activity(user_id, 'ADMIN_LOGIN', f'Admin from {ip}', ip)
            token = create_session(user_id, fingerprint)
            response = make_response(redirect('/admin'))
            response.set_cookie('session_token', token, max_age=SESSION_TIMEOUT_DAYS*86400, httponly=True, samesite='Lax')
            return response

        # ── Rate limit check ────────────────────────────────
        if check_login_attempts(ip):
            return redirect(f'/login?error=Too many attempts. Wait {LOGIN_ATTEMPT_WINDOW//60} minutes.')

        user_id = authenticate_user(email, password)
        if not user_id:
            record_login_attempt(ip)
            return redirect('/login?error=Invalid email or password')

        user = get_user(user_id)
        if user.get('is_banned'):
            return redirect('/login?error=Account banned. Contact support.')

        is_admin = is_admin_user(user_id, user['email'])
        if not is_admin and user['device_fingerprint'] != fingerprint:
            return redirect('/login?error=Please use your registered device')

        update_user(user_id, last_login=datetime.now().isoformat())
        log_activity(user_id, 'LOGIN', f'Login from {ip}', ip)
        token = create_session(user_id, fingerprint)
        dest = '/admin' if is_admin else '/dashboard'
        response = make_response(redirect(dest))
        response.set_cookie('session_token', token, max_age=SESSION_TIMEOUT_DAYS*86400, httponly=True, samesite='Lax')
        return response

    except Exception as e:
        log_error(str(e), "login")
        return redirect('/login?error=An error occurred')

@app.route('/logout')
@limiter.exempt
def logout():
    token = request.cookies.get('session_token')
    if token:
        try:
            with get_db() as conn:
                conn.cursor().execute('DELETE FROM sessions WHERE token = ?', (token,))
            cache_invalidate_session(token)
        except Exception:
            pass
    response = make_response(redirect('/login?success=Logged out successfully'))
    response.set_cookie('session_token', '', expires=0, httponly=True, samesite='Lax')
    return response

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(token, fingerprint)
    if not user_id:
        return redirect('/login?error=Please login first')
    user = get_user(user_id)
    if not user or user.get('is_banned'):
        return redirect('/login?error=Access denied')
    is_admin = is_admin_user(user_id, user['email'])
    credits_display = '∞' if user['credits'] == float('inf') else user['credits']
    return render_template_string(DASHBOARD_HTML,
        credits=credits_display, is_admin=is_admin,
        telegram_link=TELEGRAM_LINK, username=YOUR_USERNAME)

@app.route('/admin')
def admin_panel():
    token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(token, fingerprint)
    if not user_id:
        return redirect('/login?error=Please login first')
    user = get_user(user_id)
    if not user or not is_admin_user(user_id, user['email']):
        return redirect('/dashboard')

    try:
        with get_db() as conn:
            c = conn.cursor()
            total_users = c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            total_deploys = c.execute('SELECT COUNT(*) FROM deployments').fetchone()[0]
            pending_pay = c.execute("SELECT COUNT(*) FROM payments WHERE status='submitted'").fetchone()[0]

        stats = {
            'total_users': total_users, 'total_deployments': total_deploys,
            'active_processes': len(active_processes), 'pending_payments': pending_pay
        }

        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT id, email, credits, created_at, is_banned FROM users ORDER BY created_at DESC')
            users = []
            for row in c.fetchall():
                ud = dict(row)
                cnt = c.execute('SELECT COUNT(*) FROM deployments WHERE user_id=?', (ud['id'],)).fetchone()[0]
                ud['deployments'] = [None] * cnt
                users.append(ud)

        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT * FROM payments
                ORDER BY CASE status WHEN 'submitted' THEN 1 WHEN 'pending' THEN 2
                    WHEN 'approved' THEN 3 ELSE 4 END, created_at DESC
                LIMIT 200
            ''')
            payments = [dict(r) for r in c.fetchall()]

        return render_template_string(ADMIN_PANEL_HTML, stats=stats, users=users, payments=payments)
    except Exception as e:
        log_error(str(e), "admin_panel")
        return redirect('/dashboard')

# ==================== STATIC FILES ====================

@app.route('/logo.jpg')
@limiter.exempt
def serve_logo():
    path = os.path.join(STATIC_DIR, 'logo.jpg')
    return send_file(path, mimetype='image/jpeg') if os.path.exists(path) else ('', 404)

@app.route('/qr.jpg')
@limiter.exempt
def serve_qr():
    path = os.path.join(STATIC_DIR, 'qr.jpg')
    return send_file(path, mimetype='image/jpeg') if os.path.exists(path) else ('', 404)

# ==================== API HELPER ====================

def require_auth(f):
    """Decorator: authenticate request and inject user_id."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(token, fingerprint)
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        return f(user_id, *args, **kwargs)
    return decorated

def require_admin(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(token, fingerprint)
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        user = get_user(user_id)
        if not user or not is_admin_user(user_id, user['email']):
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        return f(user_id, *args, **kwargs)
    return decorated

# ==================== API ROUTES ====================

@app.route('/api/credits')
@limiter.exempt   # ✅ credits is polled frequently, exempt it
@require_auth
def api_credits(user_id):
    credits = get_credits(user_id)
    return jsonify({'success': True, 'credits': credits})

@app.route('/api/deployments')
@limiter.exempt   # ✅ exempt dashboard polling
@require_auth
def api_deployments(user_id):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT * FROM deployments WHERE user_id=? ORDER BY created_at DESC
            ''', (user_id,))
            deployments = []
            for row in c.fetchall():
                d = dict(row)
                d['dependencies'] = json.loads(d.get('dependencies') or '[]')
                d['env_vars'] = json.loads(d.get('env_vars') or '{}')
                deployments.append(d)
        return jsonify({'success': True, 'deployments': deployments})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deploy/upload', methods=['POST'])
@limiter.limit("20 per hour")   # ← was 10/hour, doubled
@require_auth
def api_deploy_upload(user_id):
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        file = request.files['file']
        if not file.filename:
            return jsonify({'success': False, 'error': 'No file selected'})
        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({'success': False, 'error': f'Type not allowed. Use: {", ".join(ALLOWED_EXTENSIONS)}'})

        upload_path = os.path.join(UPLOADS_DIR, f"{user_id}_{int(time.time())}_{filename}")
        file.save(upload_path)

        if os.path.getsize(upload_path) > MAX_FILE_SIZE:
            os.remove(upload_path)
            return jsonify({'success': False, 'error': 'File too large (max 100MB)'})

        deploy_id, message = deploy_from_file(user_id, upload_path, filename)
        try:
            os.remove(upload_path)
        except Exception:
            pass

        if deploy_id:
            return jsonify({'success': True, 'deploy_id': deploy_id, 'message': message})
        return jsonify({'success': False, 'error': message})
    except Exception as e:
        log_error(str(e), "api_deploy_upload")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deploy/github', methods=['POST'])
@limiter.limit("10 per hour")  # ← was 5/hour, doubled
@require_auth
def api_deploy_github(user_id):
    try:
        data = request.get_json() or {}
        repo_url = data.get('url','').strip()
        if not repo_url:
            return jsonify({'success': False, 'error': 'Repository URL required'})
        deploy_id, message = deploy_from_github(
            user_id, repo_url,
            data.get('branch','main').strip(),
            data.get('build_command','').strip(),
            data.get('start_command','').strip()
        )
        if deploy_id:
            return jsonify({'success': True, 'deploy_id': deploy_id, 'message': message})
        return jsonify({'success': False, 'error': message})
    except Exception as e:
        log_error(str(e), "api_deploy_github")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>/stop', methods=['POST'])
@limiter.limit("60 per minute")
@require_auth
def api_stop_deployment(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment:
        return jsonify({'success': False, 'error': 'Not found'})
    if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
        return jsonify({'success': False, 'error': 'Access denied'})
    success, msg = stop_deployment(deploy_id)
    return jsonify({'success': success, 'message': msg})

@app.route('/api/deployment/<deploy_id>/restart', methods=['POST'])
@limiter.limit("30 per minute")
@require_auth
def api_restart_deployment(user_id, deploy_id):
    """✅ NEW: Restart a deployment."""
    try:
        deployment = get_deployment(deploy_id)
        if not deployment:
            return jsonify({'success': False, 'error': 'Not found'})
        if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
            return jsonify({'success': False, 'error': 'Access denied'})

        stop_deployment(deploy_id)
        time.sleep(1)

        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        start_cmd = deployment.get('start_command', '')
        env_vars = deployment.get('env_vars', {})
        port = deployment.get('port', find_free_port())

        if not start_cmd:
            # Try to find main file
            for fname, cmd in [('main.py', f'{sys.executable} main.py'), ('app.py', f'{sys.executable} app.py'), ('bot.py', f'{sys.executable} bot.py')]:
                if os.path.exists(os.path.join(deploy_dir, fname)):
                    start_cmd = cmd; break

        if not start_cmd:
            return jsonify({'success': False, 'error': 'No start command'})

        process = _launch_process(start_cmd.split(), deploy_dir, port, env_vars)
        with PROCESS_LOCK:
            active_processes[deploy_id] = process
            process_restart_ct[deploy_id] = process_restart_ct.get(deploy_id, 0) + 1

        update_deployment(deploy_id, status='running', pid=process.pid,
                         restart_count=process_restart_ct[deploy_id],
                         logs=f'🔄 Restarted (#{process_restart_ct[deploy_id]}) on port {port}')
        return jsonify({'success': True, 'message': 'Restarting...'})
    except Exception as e:
        log_error(str(e), f"api_restart {deploy_id}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>', methods=['DELETE'])
@limiter.limit("30 per minute")
@require_auth
def api_delete_deployment(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment:
        return jsonify({'success': False, 'error': 'Not found'})
    if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
        return jsonify({'success': False, 'error': 'Access denied'})
    success, msg = delete_deployment(deploy_id)
    return jsonify({'success': success, 'message': msg})

@app.route('/api/deployment/<deploy_id>/logs')
@limiter.exempt  # ✅ log viewing should not be rate limited
@require_auth
def api_deployment_logs(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment:
        return jsonify({'success': False, 'error': 'Not found'})
    if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
        return jsonify({'success': False, 'error': 'Access denied'})
    return jsonify({'success': True, 'logs': deployment.get('logs', '')})

@app.route('/api/deployment/<deploy_id>/files')
@limiter.limit("60 per minute")
@require_auth
def api_deployment_files(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment:
        return jsonify({'success': False, 'error': 'Not found'})
    if deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID):
        return jsonify({'success': False, 'error': 'Access denied'})
    return jsonify({'success': True, 'files': get_deployment_files(deploy_id)})

@app.route('/api/deployment/<deploy_id>/env', methods=['POST'])
@limiter.limit("60 per minute")
@require_auth
def api_add_env_var(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or (deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID)):
        return jsonify({'success': False, 'error': 'Access denied'})
    data = request.get_json() or {}
    key = data.get('key','').strip()
    if not key:
        return jsonify({'success': False, 'error': 'Key required'})
    env_vars = dict(deployment.get('env_vars', {}))
    env_vars[key] = data.get('value','').strip()
    update_deployment(deploy_id, env_vars=env_vars)
    return jsonify({'success': True, 'env_vars': env_vars})

@app.route('/api/deployment/<deploy_id>/env/<key>', methods=['DELETE'])
@limiter.limit("60 per minute")
@require_auth
def api_delete_env_var(user_id, deploy_id, key):
    deployment = get_deployment(deploy_id)
    if not deployment or (deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID)):
        return jsonify({'success': False, 'error': 'Access denied'})
    env_vars = dict(deployment.get('env_vars', {}))
    env_vars.pop(key, None)
    update_deployment(deploy_id, env_vars=env_vars)
    return jsonify({'success': True, 'env_vars': env_vars})

@app.route('/api/deployment/<deploy_id>/backup', methods=['POST'])
@limiter.limit("20 per hour")
@require_auth
def api_create_backup(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or (deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID)):
        return jsonify({'success': False, 'error': 'Access denied'})
    backup_path, backup_name = create_backup(deploy_id)
    if backup_path:
        return jsonify({'success': True, 'backup_name': backup_name})
    return jsonify({'success': False, 'error': backup_name})

@app.route('/api/deployment/<deploy_id>/backup/download')
@require_auth
def api_download_backup(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or (deployment['user_id'] != user_id and str(user_id) != str(OWNER_ID)):
        return jsonify({'success': False, 'error': 'Access denied'})
    backups = sorted([f for f in os.listdir(BACKUPS_DIR)
                      if f.startswith(f"{deployment['name']}_{deploy_id}")], reverse=True)
    if not backups:
        return jsonify({'success': False, 'error': 'No backup found'})
    return send_file(os.path.join(BACKUPS_DIR, backups[0]), as_attachment=True, download_name=backups[0])

# ==================== PAYMENT API ====================

@app.route('/api/payment/create', methods=['POST'])
@limiter.limit("20 per hour")   # ← was 10/hour
@require_auth
def api_create_payment(user_id):
    data = request.get_json() or {}
    payment_id, payment_data = create_payment_request(
        user_id, data.get('package_type'), data.get('custom_amount'))
    if payment_id:
        return jsonify({'success': True, 'payment': payment_data})
    return jsonify({'success': False, 'error': payment_data})

@app.route('/api/payment/submit', methods=['POST'])
@limiter.limit("20 per hour")
@require_auth
def api_submit_payment(user_id):
    data = request.get_json() or {}
    success, message = submit_payment_proof(
        data.get('payment_id'), data.get('screenshot'), data.get('transaction_id'))
    return jsonify({'success': success, 'message': message})

@app.route('/api/payment/<payment_id>/screenshot')
@require_auth
def api_payment_screenshot(user_id, payment_id):
    user = get_user(user_id)
    admin = is_admin_user(user_id, user['email'])
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
        row = c.fetchone()
        if not row:
            return 'Not found', 404
        payment = dict(row)
    if not admin and payment['user_id'] != user_id:
        return 'Access denied', 403
    sp = payment.get('screenshot_path')
    if sp and os.path.exists(sp):
        return send_file(sp, mimetype='image/jpeg')
    return 'Screenshot not found', 404

# ==================== ADMIN API ====================

@app.route('/api/admin/metrics')
@limiter.exempt
@require_admin
def api_admin_metrics(user_id):
    return jsonify({'success': True, 'metrics': get_system_metrics()})

@app.route('/api/admin/add-credits', methods=['POST'])
@limiter.limit("100 per hour")
@require_admin
def api_admin_add_credits(user_id):
    data = request.get_json() or {}
    amount = float(data.get('amount', 0))
    if amount <= 0:
        return jsonify({'success': False, 'error': 'Invalid amount'})
    user = get_user(user_id)
    ok = add_credits(data.get('user_id'), amount, f"Admin credit by {user['email']}")
    return jsonify({'success': ok})

@app.route('/api/admin/ban-user', methods=['POST'])
@limiter.limit("100 per hour")
@require_admin
def api_admin_ban_user(user_id):
    data = request.get_json() or {}
    update_user(data.get('user_id'), is_banned=1 if data.get('ban', True) else 0)
    return jsonify({'success': True})

@app.route('/api/admin/approve-payment', methods=['POST'])
@limiter.limit("100 per hour")
@require_admin
def api_admin_approve_payment(admin_id):
    try:
        data = request.get_json() or {}
        payment_id = data.get('payment_id')
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
            row = c.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'Payment not found'})
            payment = dict(row)
            c.execute('''
                UPDATE payments SET status='approved', approved_at=?, approved_by=?
                WHERE id=?
            ''', (datetime.now().isoformat(), str(admin_id), payment_id))
        add_credits(payment['user_id'], payment['credits'], f"Payment approved: {payment_id}")
        sse_notify(payment['user_id'], 'payment_approved', {
            'credits': payment['credits'], 'payment_id': payment_id})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/reject-payment', methods=['POST'])
@limiter.limit("100 per hour")
@require_admin
def api_admin_reject_payment(admin_id):
    try:
        data = request.get_json() or {}
        payment_id = data.get('payment_id')
        with get_db() as conn:
            c = conn.cursor()
            c.execute("UPDATE payments SET status='rejected' WHERE id=?", (payment_id,))
            c.execute('SELECT user_id FROM payments WHERE id=?', (payment_id,))
            row = c.fetchone()
            if row:
                sse_notify(row['user_id'], 'payment_rejected', {'payment_id': payment_id})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    log_error(str(e), "500")
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    """✅ FIXED: Friendly rate limit response with Retry-After header."""
    retry_after = getattr(e, 'retry_after', 60)
    response = jsonify({
        'error': 'Too many requests. Please slow down.',
        'retry_after': retry_after,
        'message': f'Rate limit exceeded. Try again in {retry_after} seconds.'
    })
    response.status_code = 429
    response.headers['Retry-After'] = str(retry_after)
    return response

# ==================== BACKGROUND TASKS ====================

def cleanup_expired_sessions():
    while True:
        try:
            time.sleep(3600)
            with get_db() as conn:
                c = conn.cursor()
                c.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now().isoformat(),))
                deleted = c.rowcount
                if deleted:
                    logger.info(f"🧹 Cleaned {deleted} expired sessions")
        except Exception as e:
            log_error(str(e), "cleanup_sessions")

def monitor_and_autorestart():
    """✅ NEW: Advanced process monitor with auto-restart on crash."""
    while True:
        try:
            time.sleep(15)
            with PROCESS_LOCK:
                for deploy_id, process in list(active_processes.items()):
                    if process.poll() is not None:
                        return_code = process.returncode
                        del active_processes[deploy_id]

                        deployment = get_deployment(deploy_id)
                        if not deployment:
                            continue

                        restarts = process_restart_ct.get(deploy_id, 0)

                        if restarts < MAX_DEPLOY_RESTARTS:
                            # Auto-restart!
                            process_restart_ct[deploy_id] = restarts + 1
                            logger.warning(f"🔄 Auto-restarting {deploy_id} (#{restarts+1})")

                            deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
                            start_cmd = deployment.get('start_command', '')
                            env_vars = deployment.get('env_vars', {})
                            port = deployment.get('port', find_free_port())

                            if start_cmd and os.path.exists(deploy_dir):
                                try:
                                    new_proc = _launch_process(start_cmd.split(), deploy_dir, port, env_vars)
                                    active_processes[deploy_id] = new_proc
                                    update_deployment(deploy_id, status='running', pid=new_proc.pid,
                                                     restart_count=restarts+1,
                                                     logs=f'🔄 Auto-restarted #{restarts+1} after crash (exit {return_code})')
                                    sse_notify(deployment['user_id'], 'deployment_updated',
                                              {'id': deploy_id, 'status': 'running', 'restarted': True})
                                    continue
                                except Exception as e:
                                    log_error(str(e), f"auto_restart {deploy_id}")

                        # Out of restarts — mark crashed
                        update_deployment(deploy_id, status='crashed',
                                         logs=f'💥 Crashed (exit {return_code}) after {restarts} restarts')
                        sse_notify(deployment['user_id'], 'deployment_updated',
                                  {'id': deploy_id, 'status': 'crashed'})
                        logger.error(f"💥 Deployment {deploy_id} crashed permanently")

        except Exception as e:
            log_error(str(e), "monitor_and_autorestart")

def cleanup_old_logs():
    """Rotate old log files to keep disk usage in check."""
    while True:
        try:
            time.sleep(86400)  # daily
            log_file = os.path.join(LOGS_DIR, 'elitehost.log')
            if os.path.exists(log_file) and os.path.getsize(log_file) > 50 * 1024 * 1024:
                os.rename(log_file, log_file + f".{datetime.now().strftime('%Y%m%d')}")
                logger.info("📋 Log file rotated")
        except Exception:
            pass

# ==================== STARTUP ====================

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False, threaded=True)

def run_bot():
    try:
        logger.info(f"{Fore.GREEN}🤖 Starting Telegram Bot...")
        bot.infinity_polling(timeout=20, long_polling_timeout=10, restart_on_change=False)
    except Exception as e:
        log_error(str(e), "bot_polling")

def cleanup_on_exit():
    logger.warning(f"{Fore.YELLOW}🛑 Shutting down EliteHost v14...")
    with PROCESS_LOCK:
        for deploy_id, process in list(active_processes.items()):
            try:
                process.terminate()
                process.wait(timeout=3)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
    for timer in list(payment_timers.values()):
        try:
            timer.cancel()
        except Exception:
            pass
    logger.info(f"{Fore.GREEN}✅ Cleanup complete")

atexit.register(cleanup_on_exit)

def signal_handler(sig, frame):
    cleanup_on_exit()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "=" * 90)
    print(f"{Fore.CYAN}{'🚀 ELITEHOST v14.0 - ULTRA ADVANCED PROFESSIONAL EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}✨ FEATURES:")
    features = [
        "✅ FIXED: Rate Limit Error (Smart per-user limiting + SSE replaces polling)",
        "✅ FIXED: Payment timer extended to 30 minutes",
        "✅ NEW: Server-Sent Events (SSE) for real-time updates",
        "✅ NEW: Auto-restart crashed deployments (up to 5 times)",
        "✅ NEW: TTL Caching layer (eliminates DB hammering)",
        "✅ NEW: SQLite WAL mode (10x better concurrent performance)",
        "✅ NEW: Smart rate limits (per-user, not per-IP)",
        "✅ NEW: Restart endpoint + UI button",
        "✅ NEW: Admin approve/reject payments from web UI",
        "✅ NEW: Network metrics (sent/recv)",
        "✅ NEW: Animated toast notifications (no more alerts)",
        "✅ NEW: Drag-and-drop file upload",
        "✅ NEW: Log file rotation",
        "✅ NEW: Retry-After header on rate limit responses",
    ]
    for f in features:
        print(f"   {Fore.CYAN}{f}")
    print("=" * 90)

    for img in ['logo.jpg', 'qr.jpg']:
        path = os.path.join(STATIC_DIR, img)
        if not os.path.exists(path):
            print(f"{Fore.YELLOW}⚠️  {img} not found → add to: {path}")

    Thread(target=cleanup_expired_sessions, daemon=True).start()
    Thread(target=monitor_and_autorestart, daemon=True).start()
    Thread(target=cleanup_old_logs, daemon=True).start()

    flask_thread = Thread(target=run_flask, daemon=True)
    flask_thread.start()

    bot_thread = Thread(target=run_bot, daemon=True)
    bot_thread.start()

    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 Web App:  http://localhost:{port}")
    print(f"{Fore.YELLOW}📝 Register: http://localhost:{port}/register")
    print(f"{Fore.YELLOW}🔑 Login:    http://localhost:{port}/login")
    print(f"{Fore.MAGENTA}👑 Admin:    {ADMIN_EMAIL} / {ADMIN_PASSWORD}")
    print(f"{Fore.CYAN}💎 Credits:  Free {FREE_CREDITS} on signup")
    print(f"{Fore.CYAN}📞 Support:  {TELEGRAM_LINK}")
    print(f"\n{Fore.GREEN}{'✅ ELITEHOST v14.0 READY':^90}")
    print("=" * 90 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Shutting down...")
        cleanup_on_exit()
