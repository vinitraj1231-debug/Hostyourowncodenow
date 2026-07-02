import uuid
import secrets
import logging
import hashlib
from datetime import datetime, timedelta
from app.services.json_db import db
from app.config import SESSION_TIMEOUT_DAYS, OWNER_ID, ADMIN_ID, ADMIN_EMAIL, TRIAL_DURATION_HOURS

logger = logging.getLogger(__name__)

import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except:
        return False

def create_user(email, password, fingerprint, ip, referred_by=None):
    try:
        user_id = str(uuid.uuid4())
        my_referral_code = hashlib.md5(email.encode()).hexdigest()[:8].upper()

        user = {
            'id': user_id,
            'email': email.lower(),
            'password': hash_password(password),
            'device_fingerprint': fingerprint,
            'referral_code': my_referral_code,
            'referred_by': referred_by,
            'credits': 0.0,
            'total_spent': 0.0,
            'total_earned': 0.0,
            'is_banned': False,
            'is_admin': False,
            'created_at': datetime.now().isoformat(),
            'last_login': datetime.now().isoformat(),
            'ip_address': ip,
            'telegram_id': None,
            'two_fa_enabled': 0
        }

        db.users.insert(user)

        # Initialize wallet
        db.wallets.insert({
            'user_id': user_id,
            'balance': 0.0,
            'total_earned': 0.0,
            'total_withdrawn': 0.0,
            'pending_withdrawals': 0.0
        })

        # Initialize trial
        db.trials.insert({
            'user_id': user_id,
            'status': 'active',
            'start_time': datetime.now().isoformat(),
            'end_time': (datetime.now() + timedelta(hours=TRIAL_DURATION_HOURS)).isoformat(),
            'project_count': 0
        })

        return user_id
    except Exception as e:
        logger.error(f"create_user error: {str(e)}")
        return None

def authenticate_user(email, password):
    user = db.users.find_one(email=email.lower())
    if user and verify_password(password, user['password']):
        return user['id']
    return None

def create_session(user_id, fingerprint, ip, user_agent):
    token = secrets.token_urlsafe(48)
    now = datetime.now().isoformat()
    expires_at = (datetime.now() + timedelta(days=SESSION_TIMEOUT_DAYS)).isoformat()

    db.sessions.insert({
        'token': token,
        'user_id': user_id,
        'fingerprint': fingerprint,
        'created_at': now,
        'expires_at': expires_at,
        'last_activity': now,
        'ip_address': ip,
        'user_agent': user_agent
    })
    return token

def verify_session(session_token, fingerprint):
    if not session_token:
        return None
    session = db.sessions.find_one(token=session_token)
    if not session:
        return None

    if datetime.fromisoformat(session['expires_at']) < datetime.now():
        db.sessions.delete(token=session_token)
        return None

    # Update fingerprint if changed
    if session['fingerprint'] != fingerprint:
        db.sessions.update({'token': session_token}, {'fingerprint': fingerprint})

    db.sessions.update({'token': session_token}, {'last_activity': datetime.now().isoformat()})
    return session['user_id']

def get_user(user_id):
    user = db.users.find_one(id=user_id)
    if user:
        deploys = db.deployments.find(user_id=user_id)
        user['deployments'] = [d['id'] for d in deploys]
    return user

def update_user(user_id, **kwargs):
    db.users.update({'id': user_id}, kwargs)

def is_admin_user(user_id, email):
    # Special admin user
    if user_id == 'admin_raj':
        return True

    user = db.users.find_one(id=user_id)
    if user and user.get('is_admin'):
        return True

    return (
        str(user_id) == str(OWNER_ID) or
        str(user_id) == str(ADMIN_ID) or
        (ADMIN_EMAIL and email.lower().strip() == ADMIN_EMAIL.lower().strip())
    )

def get_trial_status(user_id):
    trial = db.trials.find_one(user_id=user_id)
    if not trial:
        return None

    if trial['status'] == 'active':
        end_time = datetime.fromisoformat(trial['end_time'])
        if datetime.now() > end_time:
            db.trials.update({'user_id': user_id}, {'status': 'expired'})
            trial = db.trials.find_one(user_id=user_id)

    return trial

def add_referral_commission(user_id, amount):
    user = db.users.find_one(id=user_id)
    if not user or not user.get('referred_by'):
        return

    referrer = db.users.find_one(referral_code=user['referred_by'])
    if not referrer:
        return

    commission = amount * 0.30

    # Update referrer wallet
    wallet = db.wallets.find_one(user_id=referrer['id'])
    db.wallets.update({'user_id': referrer['id']}, {
        'balance': wallet['balance'] + commission,
        'total_earned': wallet['total_earned'] + commission
    })

    # Log commission
    db.commissions.insert({
        'referrer_id': referrer['id'],
        'referee_id': user_id,
        'amount': commission,
        'base_amount': amount,
        'timestamp': datetime.now().isoformat()
    })

def is_device_banned(fingerprint):
    # For JSON DB, we'll use settings or a dedicated banned_devices table
    # Let's check settings for now or create a dedicated JSON table if needed
    # Actually I added audit_logs, I can add banned_devices too if I want,
    # but let's just use a simple check in a "blacklist" setting for now
    blacklist = db.settings.find_one(key='banned_devices')
    if blacklist and fingerprint in blacklist.get('list', []):
        return True
    return False

def check_existing_account(fingerprint):
    user = db.users.find_one(device_fingerprint=fingerprint)
    return user['id'] if user else None

def get_active_sessions(user_id):
    return db.sessions.find(user_id=user_id)

def revoke_session(user_id, token):
    db.sessions.delete(user_id=user_id, token=token)
