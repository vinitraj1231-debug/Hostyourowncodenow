import secrets
from app.db import get_db
from app.bot import bot
from app.security.audit import audit_log

def generate_two_fa_secret(user_id):
    secret = secrets.token_hex(16)
    with get_db() as conn:
        conn.cursor().execute('UPDATE users SET two_fa_secret = ? WHERE id = ?', (secret, user_id))
    return secret

def send_two_fa_code(user_id, telegram_id):
    if not telegram_id:
        return None

    code = secrets.token_hex(3).upper() # 6 char code
    # In a real app, you'd store this in Redis or a DB with TTL
    # For now, let's just use it as a simple example
    try:
        bot.send_message(telegram_id, f"🔐 Your EliteHost login code: `{code}`\nIf you didn't request this, please change your password immediately.")
        return code
    except Exception:
        return None

def verify_two_fa_code(user_id, input_code, actual_code):
    return input_code == actual_code
