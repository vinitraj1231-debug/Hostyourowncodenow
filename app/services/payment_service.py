import os
import uuid
import base64
import logging
from datetime import datetime, timedelta
from threading import Timer
from app.db import get_db
from app.config import (
    PAYMENT_PACKAGES, PAYMENT_TIMEOUT_MINUTES, PAYMENTS_DIR, ADMIN_ID
)
from app.services.user_service import get_user
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
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO payments (id, user_id, user_email, package_type, credits, price,
                    status, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (payment_id, user_id, user['email'], package_type, credits, price,
                  'pending', datetime.now().isoformat(), expires_at.isoformat()))

        timer = Timer(PAYMENT_TIMEOUT_MINUTES * 60, expire_payment, args=[payment_id])
        payment_timers[payment_id] = timer
        timer.daemon = True
        timer.start()
        log_activity(user_id, 'PAYMENT_REQUEST', f"{payment_id}: {credits}cr ₹{price}")

        payment_data = {
            'id': payment_id, 'user_id': user_id, 'user_email': user['email'],
            'package_type': package_type, 'credits': credits, 'price': price,
            'status': 'pending', 'created_at': datetime.now().isoformat(),
            'expires_at': expires_at.isoformat()
        }
        return payment_id, payment_data
    except Exception as e:
        log_error(str(e), "create_payment_request")
        return None, str(e)

def expire_payment(payment_id):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("UPDATE payments SET status='expired' WHERE id=? AND status='pending'", (payment_id,))
        logger.info(f"Payment {payment_id} expired")
    except Exception:
        pass

def submit_payment_proof(payment_id, screenshot_data, transaction_id, bot):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
            row = c.fetchone()
            if not row:
                return False, "Payment not found"
            payment = dict(row)

            if payment['status'] != 'pending':
                return False, f"Payment is {payment['status']}"
            if datetime.fromisoformat(payment['expires_at']) < datetime.now():
                c.execute("UPDATE payments SET status='expired' WHERE id=?", (payment_id,))
                return False, "Payment expired"

            screenshot_path = os.path.join(PAYMENTS_DIR, f"{payment_id}_screenshot.jpg")
            try:
                screenshot_bytes = base64.b64decode(screenshot_data.split(',')[1])
                with open(screenshot_path, 'wb') as f:
                    f.write(screenshot_bytes)
            except Exception as e:
                log_error(str(e), "screenshot save")
                return False, "Screenshot upload failed"

            c.execute('''
                UPDATE payments SET screenshot_path=?, transaction_id=?,
                status='submitted', submitted_at=? WHERE id=?
            ''', (screenshot_path, transaction_id, datetime.now().isoformat(), payment_id))

        if payment_id in payment_timers:
            payment_timers[payment_id].cancel()
            del payment_timers[payment_id]

        # Send notification via bot
        try:
            from telebot import types
            user = get_user(payment['user_id'])
            markup = types.InlineKeyboardMarkup()
            markup.row(
                types.InlineKeyboardButton("✅ Approve", callback_data=f"payment_confirm_{payment_id}"),
                types.InlineKeyboardButton("❌ Reject", callback_data=f"payment_reject_{payment_id}")
            )
            bot.send_message(ADMIN_ID,
                f"💳 *NEW PAYMENT SUBMISSION*\n\n"
                f"📧 User: `{user['email']}`\n"
                f"🆔 Payment ID: `{payment_id}`\n"
                f"💰 Amount: ₹{payment['price']}\n"
                f"💎 Credits: {payment['credits']}\n"
                f"🔢 TxnID: `{transaction_id}`\n"
                f"⏰ {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                reply_markup=markup)
            with open(screenshot_path, 'rb') as photo:
                bot.send_photo(ADMIN_ID, photo, caption=f"Payment Screenshot - {payment_id}")
        except Exception as e:
            log_error(str(e), "payment notification")

        return True, "Payment proof submitted successfully"
    except Exception as e:
        log_error(str(e), "submit_payment_proof")
        return False, str(e)
