from datetime import datetime
from app.services.json_db import db
from app.services.user_service import get_user

def get_wallet(user_id):
    wallet = db.wallets.find_one(user_id=user_id)
    if not wallet:
        wallet = db.wallets.insert({
            'user_id': user_id,
            'balance': 0.0,
            'total_earned': 0.0,
            'total_withdrawn': 0.0,
            'pending_withdrawals': 0.0
        })
    return wallet

def request_withdrawal(user_id, amount, method, note=''):
    wallet = get_wallet(user_id)
    if wallet['balance'] < amount:
        return False, "Insufficient balance"

    import random
    withdrawal_id = f"WD-{datetime.now().strftime('%y%m%d')}-{random.randint(1000, 9999)}"

    withdrawal = {
        'id': withdrawal_id,
        'user_id': user_id,
        'amount': amount,
        'method': method,
        'note': note,
        'status': 'pending',
        'created_at': datetime.now().isoformat()
    }

    db.withdrawals.insert(withdrawal)

    # Lock balance
    db.wallets.update({'user_id': user_id}, {
        'balance': wallet['balance'] - amount,
        'pending_withdrawals': wallet['pending_withdrawals'] + amount
    })

    return True, withdrawal_id

def get_withdrawal_history(user_id):
    return db.withdrawals.find(user_id=user_id)

def create_ticket(user_id, subject, category, message):
    ticket_id = f"TKT-{random_id()}"
    ticket = {
        'id': ticket_id,
        'user_id': user_id,
        'subject': subject,
        'category': category,
        'status': 'open',
        'priority': 'medium',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    db.tickets.insert(ticket)

    db.messages.insert({
        'ticket_id': ticket_id,
        'sender_id': user_id,
        'message': message,
        'is_admin': False,
        'timestamp': datetime.now().isoformat()
    })
    return ticket_id

def random_id():
    import string
    import random
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def get_referral_stats(user_id):
    user = get_user(user_id)
    referrals = db.users.find(referred_by=user['referral_code'])
    commissions = db.commissions.find(referrer_id=user_id)

    return {
        'referral_code': user['referral_code'],
        'count': len(referrals),
        'commissions_count': len(commissions),
        'total_earned': sum(c['amount'] for c in commissions)
    }
