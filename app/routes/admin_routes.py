from flask import Blueprint, request, redirect, render_template_string, jsonify, send_file
from app.routes.auth_middleware import require_admin
from app.services.user_service import get_user, update_user, is_admin_user
from app.services.credit_service import add_credits
from app.services.deployment_service import get_system_metrics, active_processes
from app.services.sse_service import sse_notify
from app.services.json_db import db
from app.services.payment_service import approve_payment_logic
from app.templates import ADMIN_PANEL_HTML
import os
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/raj')
@require_admin
def admin_panel(user_id):
    try:
        users = db.users.all()
        deploys = db.deployments.all()
        payments = db.payments.all()
        withdrawals = db.withdrawals.all()
        tickets = db.tickets.all()

        pending_pay = len([p for p in payments if p['status'] == 'submitted'])
        pending_withdraw = len([w for w in withdrawals if w['status'] == 'pending'])

        stats = {
            'total_users': len(users),
            'total_deployments': len(deploys),
            'active_processes': len(active_processes),
            'pending_payments': pending_pay,
            'pending_withdrawals': pending_withdraw,
            'open_tickets': len([t for t in tickets if t['status'] == 'open'])
        }

        # Sort payments: submitted first, then by date
        payments.sort(key=lambda x: (0 if x['status'] == 'submitted' else 1, x['created_at']), reverse=False)

        return render_template_string(ADMIN_PANEL_HTML,
                                     stats=stats,
                                     users=users,
                                     payments=payments,
                                     withdrawals=withdrawals,
                                     tickets=tickets)
    except Exception as e:
        from app.utils import log_error
        log_error(str(e), "admin_panel")
        return redirect('/dashboard')

@admin_bp.route('/api/admin/metrics')
@require_admin
def api_admin_metrics(user_id):
    return jsonify({'success': True, 'metrics': get_system_metrics()})

@admin_bp.route('/api/admin/add-credits', methods=['POST'])
@require_admin
def api_admin_add_credits(admin_id):
    data = request.get_json() or {}
    amount = float(data.get('amount', 0))
    user = get_user(admin_id)
    ok = add_credits(data.get('user_id'), amount, f"Admin credit by {user['email']}")
    return jsonify({'success': ok})

@admin_bp.route('/api/admin/approve-payment', methods=['POST'])
@require_admin
def api_admin_approve_payment(admin_id):
    data = request.get_json() or {}
    success, msg = approve_payment_logic(data.get('payment_id'), admin_id)
    return jsonify({'success': success, 'error' if not success else 'message': msg})

@admin_bp.route('/api/admin/reject-payment', methods=['POST'])
@require_admin
def api_admin_reject_payment(admin_id):
    data = request.get_json() or {}
    payment_id = data.get('payment_id')
    db.payments.update({'id': payment_id}, {'status': 'rejected'})
    return jsonify({'success': True})

@admin_bp.route('/api/admin/withdrawal/<withdrawal_id>/<action>', methods=['POST'])
@require_admin
def api_admin_withdrawal_action(admin_id, withdrawal_id, action):
    w = db.withdrawals.find_one(id=withdrawal_id)
    if not w: return jsonify({'success': False, 'error': 'Not found'})

    if action == 'approve':
        db.withdrawals.update({'id': withdrawal_id}, {'status': 'approved'})
    elif action == 'paid':
        db.withdrawals.update({'id': withdrawal_id}, {'status': 'paid'})
        wallet = db.wallets.find_one(user_id=w['user_id'])
        db.wallets.update({'user_id': w['user_id']}, {
            'pending_withdrawals': wallet['pending_withdrawals'] - w['amount'],
            'total_withdrawn': wallet['total_withdrawn'] + w['amount']
        })
    elif action == 'reject':
        db.withdrawals.update({'id': withdrawal_id}, {'status': 'rejected'})
        wallet = db.wallets.find_one(user_id=w['user_id'])
        db.wallets.update({'user_id': w['user_id']}, {
            'balance': wallet['balance'] + w['amount'],
            'pending_withdrawals': wallet['pending_withdrawals'] - w['amount']
        })
    return jsonify({'success': True})

@admin_bp.route('/api/admin/ban-user', methods=['POST'])
@require_admin
def api_admin_ban_user(admin_id):
    data = request.get_json() or {}
    update_user(data.get('user_id'), is_banned=1 if data.get('ban', True) else 0)
    return jsonify({'success': True})
