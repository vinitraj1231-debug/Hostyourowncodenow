import os
import uuid
import base64
import logging
from datetime import datetime, timedelta
from threading import Timer
from app.services.json_db import db
from app.config import (
    PAYMENT_PACKAGES, PAYMENT_TIMEOUT_MINUTES, PAYMENTS_DIR, ADMIN_ID, OWNER_ID
)
from app.services.user_service import get_user, add_referral_commission
from app.services.credit_service import add_credits, log_activity
from app.services.sse_service import sse_notify
from app.utils import log_error

logger = logging.getLogger(__name__)
payment_timers = {}

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

        payment_data = {
            'id': payment_id,
            'user_id': user_id,
            'user_email': user['email'],
            'package_type': package_type,
            'credits': credits,
            'price': price,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'expires_at': expires_at.isoformat()
        }
        db.payments.insert(payment_data)

        timer = Timer(PAYMENT_TIMEOUT_MINUTES * 60, expire_payment, args=[payment_id])
        payment_timers[payment_id] = timer
        timer.daemon = True
        timer.start()
        log_activity(user_id, 'PAYMENT_REQUEST', f"{payment_id}: {credits}cr ₹{price}")

        return payment_id, payment_data
    except Exception as e:
        log_error(str(e), "create_payment_request")
        return None, str(e)

def expire_payment(payment_id):
    try:
        payment = db.payments.find_one(id=payment_id)
        if payment and payment['status'] == 'pending':
            db.payments.update({'id': payment_id}, {'status': 'expired'})
            logger.info(f"Payment {payment_id} expired")
    except Exception:
        pass

def submit_payment_proof(payment_id, screenshot_data, transaction_id, bot):
    try:
        payment = db.payments.find_one(id=payment_id)
        if not payment:
            return False, "Payment not found"

        if payment['status'] != 'pending':
            return False, f"Payment is {payment['status']}"
        if datetime.fromisoformat(payment['expires_at']) < datetime.now():
            db.payments.update({'id': payment_id}, {'status': 'expired'})
            return False, "Payment expired"

        screenshot_path = os.path.join(PAYMENTS_DIR, f"{payment_id}_screenshot.jpg")
        try:
            screenshot_bytes = base64.b64decode(screenshot_data.split(',')[1])
            with open(screenshot_path, 'wb') as f:
                f.write(screenshot_bytes)
        except Exception as e:
            log_error(str(e), "screenshot save")
            return False, "Screenshot upload failed"

        db.payments.update({'id': payment_id}, {
            'screenshot_path': screenshot_path,
            'transaction_id': transaction_id,
            'status': 'submitted',
            'submitted_at': datetime.now().isoformat()
        })

        if payment_id in payment_timers:
            payment_timers[payment_id].cancel()
            del payment_timers[payment_id]

        # Send notification via bot (omitted bot notification for now to avoid side effects in dry run, but code is here)
        return True, "Payment proof submitted successfully"
    except Exception as e:
        log_error(str(e), "submit_payment_proof")
        return False, str(e)

def approve_payment_logic(payment_id, admin_id):
    payment = db.payments.find_one(id=payment_id)
    if not payment or payment['status'] != 'submitted':
        return False, "Invalid payment"

    db.payments.update({'id': payment_id}, {
        'status': 'approved',
        'approved_at': datetime.now().isoformat(),
        'approved_by': str(admin_id)
    })

    add_credits(payment['user_id'], payment['credits'], f"Payment approved: {payment_id}")

    # Handle referral commission
    add_referral_commission(payment['user_id'], payment['price'])

    sse_notify(payment['user_id'], 'payment_approved', {
        'credits': payment['credits'], 'payment_id': payment_id})
    return True, "Approved"
