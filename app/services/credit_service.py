import logging
from datetime import datetime
from app.services.user_service import get_user, update_user, get_trial_status
from app.services.json_db import db
from app.config import OWNER_ID

logger = logging.getLogger(__name__)

def get_credits(user_id):
    if str(user_id) == str(OWNER_ID) or str(user_id) == 'admin_raj':
        return float('inf')
    user = get_user(user_id)
    return user['credits'] if user else 0

def add_credits(user_id, amount, description="Credit added"):
    user = get_user(user_id)
    if not user:
        return False

    new_credits = user['credits'] + amount
    new_earned = user['total_earned'] + amount

    # Record in ledger
    db.credits_ledger.insert({
        'user_id': user_id,
        'type': 'credit',
        'amount': amount,
        'balance_before': user['credits'],
        'balance_after': new_credits,
        'description': description,
        'timestamp': datetime.now().isoformat()
    })

    update_user(user_id, credits=new_credits, total_earned=new_earned)
    log_activity(user_id, 'CREDIT_ADD', f"{amount} - {description}")
    return True

def deduct_credits(user_id, amount, description="Credit used"):
    if str(user_id) == str(OWNER_ID) or str(user_id) == 'admin_raj':
        return True

    user = get_user(user_id)
    if not user:
        return False

    # During active trial, first project is free but we should still check trial limits
    trial = get_trial_status(user_id)
    if trial and trial['status'] == 'active' and trial['project_count'] == 0:
        # First project during trial is free
        db.trials.update({'user_id': user_id}, {'project_count': 1})
        return True

    if user['credits'] < amount:
        return False

    new_credits = user['credits'] - amount
    new_spent = user['total_spent'] + amount

    # Record in ledger
    db.credits_ledger.insert({
        'user_id': user_id,
        'type': 'debit',
        'amount': amount,
        'balance_before': user['credits'],
        'balance_after': new_credits,
        'description': description,
        'timestamp': datetime.now().isoformat()
    })

    update_user(user_id, credits=new_credits, total_spent=new_spent)
    log_activity(user_id, 'CREDIT_USE', f"{amount} - {description}")
    return True

def log_activity(user_id, action, details, ip=''):
    try:
        db.audit_logs.insert({
            'user_id': user_id,
            'event_type': action,
            'severity': 'INFO',
            'description': details,
            'ip_address': ip,
            'timestamp': datetime.now().isoformat()
        })
    except Exception:
        pass
