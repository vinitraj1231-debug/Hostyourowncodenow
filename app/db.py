import sqlite3
import logging
from contextlib import contextmanager
from app.config import DB_FILE

logger = logging.getLogger(__name__)

def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
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
                telegram_id TEXT,
                two_fa_enabled INTEGER DEFAULT 0,
                two_fa_secret TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_activity TEXT,
                ip_address TEXT,
                user_agent TEXT,
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

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_deployments_user ON deployments(user_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
            CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
            CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log(user_id);
        ''')
        logger.info("✅ Database initialized")
