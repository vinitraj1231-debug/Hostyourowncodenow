import telebot
from telebot import types
from datetime import datetime
from app.config import TOKEN, ADMIN_ID
from app.services.json_db import db
from app.services.credit_service import add_credits
from app.services.sse_service import sse_notify
from app.utils import log_error

bot = telebot.TeleBot(TOKEN, parse_mode='Markdown') if TOKEN else None

def bot_handler(bot_instance):
    @bot_instance.callback_query_handler(func=lambda call: call.data.startswith('payment_'))
    def handle_payment_action(call):
        try:
            parts = call.data.rsplit('_', 1)
            action_part = parts[0]
            payment_id = parts[1]

            payment = db.payments.find_one(id=payment_id)
            if not payment:
                bot_instance.answer_callback_query(call.id, "Payment not found")
                return

            if 'confirm' in action_part:
                db.payments.update({'id': payment_id}, {
                    'status': 'approved',
                    'approved_at': datetime.now().isoformat(),
                    'approved_by': str(call.from_user.id)
                })
                add_credits(payment['user_id'], payment['credits'], f"Payment approved: {payment_id}")
                bot_instance.answer_callback_query(call.id, "✅ Payment Approved!")
                sse_notify(payment['user_id'], 'payment_approved', {
                    'credits': payment['credits'], 'payment_id': payment_id})
                try:
                    bot_instance.edit_message_text(
                        f"{call.message.text}\n\n✅ *APPROVED* by {call.from_user.first_name}",
                        call.message.chat.id, call.message.message_id, parse_mode='Markdown')
                except Exception:
                    pass

            elif 'reject' in action_part:
                db.payments.update({'id': payment_id}, {'status': 'rejected'})
                bot_instance.answer_callback_query(call.id, "❌ Payment Rejected")
                sse_notify(payment['user_id'], 'payment_rejected', {'payment_id': payment_id})
                try:
                    bot_instance.edit_message_text(
                        f"{call.message.text}\n\n❌ *REJECTED* by {call.from_user.first_name}",
                        call.message.chat.id, call.message.message_id, parse_mode='Markdown')
                except Exception:
                    pass
        except Exception as e:
            log_error(str(e), "handle_payment_action")
            bot_instance.answer_callback_query(call.id, f"Error: {str(e)}")

if bot:
    bot_handler(bot)

def run_bot():
    if not bot:
        print("⚠️ Bot token not set. Bot will not start.")
        return
    try:
        bot.infinity_polling(timeout=20, long_polling_timeout=10, restart_on_change=False)
    except Exception as e:
        log_error(str(e), "bot_polling")
