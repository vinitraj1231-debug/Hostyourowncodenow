import logging
from datetime import datetime
from app.db import get_db
from app.services.user_service import get_user, update_user
from app.config import OWNER_ID, FREE_CREDITS

logger = logging.getLogger(__name__)

def get_credits(user_id):
    if str(user_id) == str(OWNER_ID):
        return float('inf')
    user = get_user(user_id)
    return user['credits'] if user else 0

def add_credits(user_id, amount, description="Credit added"):
    user = get_user(user_id)
    if not user:
        return False
    new_credits = user['credits'] + amount
    new_earned = user['total_earned'] + amount
    update_user(user_id, credits=new_credits, total_earned=new_earned)
    log_activity(user_id, 'CREDIT_ADD', f"{amount} - {description}")
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
    return True

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
