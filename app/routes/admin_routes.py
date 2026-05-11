from flask import Blueprint, request, redirect, render_template_string, jsonify, send_file
from app.routes.auth_middleware import require_admin
from app.services.user_service import get_user, update_user, is_admin_user
from app.services.credit_service import add_credits
from app.services.deployment_service import get_system_metrics, active_processes
from app.services.sse_service import sse_notify
from app.db import get_db
from app.templates import ADMIN_PANEL_HTML
import os
from datetime import datetime

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin')
@require_admin
def admin_panel(user_id):
    try:
        with get_db() as conn:
            c = conn.cursor()
            total_users = c.execute('SELECT COUNT(*) FROM users').fetchone()[0]
            total_deploys = c.execute('SELECT COUNT(*) FROM deployments').fetchone()[0]
            pending_pay = c.execute("SELECT COUNT(*) FROM payments WHERE status='submitted'").fetchone()[0]

        stats = {
            'total_users': total_users, 'total_deployments': total_deploys,
            'active_processes': len(active_processes), 'pending_payments': pending_pay
        }

        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT id, email, credits, created_at, is_banned FROM users ORDER BY created_at DESC')
            users = []
            for row in c.fetchall():
                ud = dict(row)
                cnt = c.execute('SELECT COUNT(*) FROM deployments WHERE user_id=?', (ud['id'],)).fetchone()[0]
                ud['deployments'] = [None] * cnt
                users.append(ud)

        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT * FROM payments
                ORDER BY CASE status WHEN 'submitted' THEN 1 WHEN 'pending' THEN 2
                    WHEN 'approved' THEN 3 ELSE 4 END, created_at DESC
                LIMIT 200
            ''')
            payments = [dict(r) for r in c.fetchall()]

        return render_template_string(ADMIN_PANEL_HTML, stats=stats, users=users, payments=payments)
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
    try:
        data = request.get_json() or {}
        payment_id = data.get('payment_id')
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM payments WHERE id = ?', (payment_id,))
            row = c.fetchone()
            if not row:
                return jsonify({'success': False, 'error': 'Payment not found'})
            payment = dict(row)
            c.execute('''
                UPDATE payments SET status='approved', approved_at=?, approved_by=?
                WHERE id=?
            ''', (datetime.now().isoformat(), str(admin_id), payment_id))
        add_credits(payment['user_id'], payment['credits'], f"Payment approved: {payment_id}")
        sse_notify(payment['user_id'], 'payment_approved', {
            'credits': payment['credits'], 'payment_id': payment_id})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@admin_bp.route('/api/admin/ban-user', methods=['POST'])
@require_admin
def api_admin_ban_user(admin_id):
    data = request.get_json() or {}
    update_user(data.get('user_id'), is_banned=1 if data.get('ban', True) else 0)
    return jsonify({'success': True})
