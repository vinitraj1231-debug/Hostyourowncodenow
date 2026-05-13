import bcrypt
import uuid
import secrets
import logging
from datetime import datetime, timedelta
from app.db import get_db
from app.config import FREE_CREDITS, SESSION_TIMEOUT_DAYS, OWNER_ID, ADMIN_ID, ADMIN_EMAIL
from app.utils import log_error

logger = logging.getLogger(__name__)

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

def create_session(user_id, fingerprint, ip, user_agent):
    token = secrets.token_urlsafe(48)
    now = datetime.now().isoformat()
    expires_at = (datetime.now() + timedelta(days=SESSION_TIMEOUT_DAYS)).isoformat()
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO sessions (token, user_id, fingerprint, created_at, expires_at, last_activity, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (token, user_id, fingerprint, now, expires_at, now, ip, user_agent))
    return token

def verify_session(session_token, fingerprint):
    if not session_token:
        return None
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT user_id, fingerprint, expires_at
                FROM sessions WHERE token = ?
            ''', (session_token,))
            row = c.fetchone()
            if not row:
                return None
            if datetime.fromisoformat(row['expires_at']) < datetime.now():
                c.execute('DELETE FROM sessions WHERE token = ?', (session_token,))
                return None
            if row['fingerprint'] != fingerprint:
                # Security: Log fingerprint mismatch but don't invalidate session immediately
                # to allow switching between mobile/desktop modes or minor browser updates.
                from app.security.audit import audit_log
                audit_log("SESSION_FINGERPRINT_CHANGE", "INFO", f"Fingerprint changed for token {session_token[:10]}...", user_id=row['user_id'])
                # Update fingerprint to the new one
                c.execute('UPDATE sessions SET fingerprint = ? WHERE token = ?', (fingerprint, session_token))

            # Update last activity
            c.execute('UPDATE sessions SET last_activity = ? WHERE token = ?',
                     (datetime.now().isoformat(), session_token))

            return row['user_id']
    except Exception:
        return None

def logout_other_sessions(user_id, current_token):
    with get_db() as conn:
        conn.cursor().execute('DELETE FROM sessions WHERE user_id = ? AND token != ?', (user_id, current_token))

def get_active_sessions(user_id):
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT token, created_at, last_activity, ip_address, user_agent FROM sessions WHERE user_id = ?', (user_id,))
        return [dict(row) for row in c.fetchall()]

def revoke_session(user_id, token):
    with get_db() as conn:
        conn.cursor().execute('DELETE FROM sessions WHERE user_id = ? AND token = ?', (user_id, token))

def is_admin_user(user_id, email):
    return (
        str(user_id) == str(OWNER_ID) or
        str(user_id) == str(ADMIN_ID) or
        (ADMIN_EMAIL and email.lower().strip() == ADMIN_EMAIL.lower().strip())
    )

def get_user(user_id):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            row = c.fetchone()
            if row:
                user_data = dict(row)
                c.execute('SELECT id FROM deployments WHERE user_id = ?', (user_id,))
                user_data['deployments'] = [r['id'] for r in c.fetchall()]
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
    except Exception as e:
        log_error(str(e), "update_user")

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
