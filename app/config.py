import os
import secrets
from cryptography.fernet import Fernet

# ==================== CONFIGURATION ====================
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
OWNER_ID = int(os.getenv('OWNER_ID', '0'))
ADMIN_ID = int(os.getenv('ADMIN_ID', '0'))
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'Kvinit6421@gmail.com')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', '28@Humbler')
RAJ_ADMIN_USER = os.getenv('RAJ_ADMIN_USER', 'Raj')
RAJ_ADMIN_PASS = os.getenv('RAJ_ADMIN_PASS', '28@RajPapa')
YOUR_USERNAME = os.getenv('TELEGRAM_USERNAME', '@zolvid')
TELEGRAM_LINK = os.getenv('TELEGRAM_LINK', 'https://t.me/zolvid')
WEB_SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
ENCRYPTION_KEY = os.getenv('ENCRYPTION_KEY', Fernet.generate_key().decode())
if isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

FREE_CREDITS = 0.0 # Handled by trial system
TRIAL_DURATION_HOURS = 3
REFERRAL_COMMISSION_PERCENT = 30
CREDIT_COSTS = {
    'file_upload': 1.0,
    'github_deploy': 2.0,
    'zip_deploy': 2.0,
    'raw_deploy': 1.0,
    'backup': 0.5,
}

PAYMENT_PACKAGES = {
    '10_credits': {'credits': 10, 'price': 50, 'name': '10 Credits Pack'},
    '99_credits': {'credits': 99, 'price': 399, 'name': '99 Credits Pack'},
}

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {'.py', '.js', '.zip', '.tar.gz'}
SESSION_TIMEOUT_DAYS = 7
PAYMENT_TIMEOUT_MINUTES = 30
MAX_DEPLOYMENTS_PER_USER = 10
MAX_LOGIN_ATTEMPTS = 10
LOGIN_ATTEMPT_WINDOW = 300
MAX_DEPLOY_RESTARTS = 5

# ==================== DIRECTORIES ====================
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
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

def get_rate_limit_key():
    """Use session user-id when authenticated, else fall back to IP."""
    from flask import request
    try:
        session_token = request.cookies.get('session_token')
        if session_token:
            from app.services.user_service import verify_session
            from app.utils import get_device_fingerprint
            user_id = verify_session(session_token, get_device_fingerprint(request))
            if user_id:
                return f"user:{user_id}"
    except Exception:
        pass
    from flask_limiter.util import get_remote_address
    return f"ip:{get_remote_address()}"
