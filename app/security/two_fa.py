import secrets
from app.services.json_db import db
from app.bot import bot
from app.security.audit import audit_log

def generate_two_fa_secret(user_id):
    secret = secrets.token_hex(16)
    db.users.update({'id': user_id}, {'two_fa_secret': secret})
    return secret

def send_two_fa_code(user_id, telegram_id):
    if not telegram_id:
        return None

    code = secrets.token_hex(3).upper() # 6 char code
    try:
        bot.send_message(telegram_id, f"🔐 Your EliteHost login code: `{code}`\nIf you didn't request this, please change your password immediately.")
        return code
    except Exception:
        return None

def verify_two_fa_code(user_id, input_code, actual_code):
    return input_code == actual_code
