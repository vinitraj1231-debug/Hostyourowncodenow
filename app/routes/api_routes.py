import json
import os
import time
from flask import Blueprint, request, jsonify, Response, stream_with_context, send_file
from werkzeug.utils import secure_filename
from app.routes.auth_middleware import require_auth
from app.services.user_service import (
    get_user, verify_session, get_active_sessions,
    revoke_session, update_user, get_trial_status
)
from app.services.credit_service import get_credits
from app.services.deployment_service import (
    deploy_from_file, deploy_from_github, get_deployment, stop_deployment,
    delete_deployment, _launch_process, active_processes, process_restart_ct,
    PROCESS_LOCK, update_deployment, find_free_port, DEPLOYS_DIR,
    get_deployment_files, create_backup
)
from app.services.payment_service import create_payment_request, submit_payment_proof
from app.services.sse_service import get_sse_clients, get_sse_lock
from app.utils import get_device_fingerprint, log_error
from app.config import UPLOADS_DIR, ALLOWED_EXTENSIONS, MAX_FILE_SIZE
from app.bot import bot
import queue
import sys

api_bp = Blueprint('api', __name__)

@api_bp.route('/api/events')
def sse_stream():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)

    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    def generate():
        q = queue.Queue(maxsize=50)
        with get_sse_lock():
            get_sse_clients()[str(user_id)].add(q)
        try:
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            while True:
                try:
                    event = q.get(timeout=25)
                    yield f"data: {json.dumps(event)}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        except GeneratorExit:
            pass
        finally:
            with get_sse_lock():
                get_sse_clients()[str(user_id)].discard(q)

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

@api_bp.route('/api/credits')
@require_auth
def api_credits(user_id):
    return jsonify({
        'success': True,
        'credits': get_credits(user_id),
        'trial': get_trial_status(user_id)
    })

@api_bp.route('/api/deployments')
@require_auth
def api_deployments(user_id):
    try:
        from app.db import get_db
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT * FROM deployments WHERE user_id=? ORDER BY created_at DESC
            ''', (user_id,))
            deployments = []
            for row in c.fetchall():
                d = dict(row)
                d['dependencies'] = json.loads(d.get('dependencies') or '[]')
                d['env_vars'] = json.loads(d.get('env_vars') or '{}')
                deployments.append(d)
        return jsonify({'success': True, 'deployments': deployments})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@api_bp.route('/api/deploy/github', methods=['POST'])
@require_auth
def api_deploy_github(user_id):
    try:
        data = request.get_json() or {}
        repo_url = data.get('url','').strip()
        if not repo_url:
            return jsonify({'success': False, 'error': 'Repository URL required'})
        deploy_id, message = deploy_from_github(
            user_id, repo_url,
            data.get('branch','main').strip(),
            data.get('build_command','').strip(),
            data.get('start_command','').strip()
        )
        if deploy_id:
            return jsonify({'success': True, 'deploy_id': deploy_id, 'message': message})
        return jsonify({'success': False, 'error': message})
    except Exception as e:
        log_error(str(e), "api_deploy_github")
        return jsonify({'success': False, 'error': str(e)})

@api_bp.route('/api/deploy/raw', methods=['POST'])
@require_auth
def api_deploy_raw(user_id):
    try:
        data = request.get_json() or {}
        code = data.get('code', '').strip()
        filename = secure_filename(data.get('filename', 'app.py'))
        if not code:
            return jsonify({'success': False, 'error': 'No code provided'})

        # Save raw code to a temporary file for deployment
        upload_path = os.path.join(UPLOADS_DIR, f"{user_id}_{int(time.time())}_{filename}")
        with open(upload_path, 'w') as f:
            f.write(code)

        deploy_id, message = deploy_from_raw_code(user_id, code, filename)
        try:
            os.remove(upload_path)
        except Exception:
            pass

        if deploy_id:
            return jsonify({'success': True, 'deploy_id': deploy_id, 'message': message})
        return jsonify({'success': False, 'error': message})
    except Exception as e:
        log_error(str(e), "api_deploy_raw")
        return jsonify({'success': False, 'error': str(e)})

@api_bp.route('/api/ai/analyze', methods=['POST'])
@require_auth
def api_ai_analyze(user_id):
    try:
        data = request.get_json() or {}
        code = data.get('code', '').strip()
        if not code: return jsonify({'success': False, 'error': 'Code required'})

        time.sleep(1.5) # Analysis delay

        issues = []
        if 'import' not in code: issues.append("Missing module imports")
        if 'if __name__ ==' not in code and 'app.run' not in code: issues.append("Missing entry point / execution block")
        if 'os.getenv' not in code and ('key' in code.lower() or 'token' in code.lower() or 'secret' in code.lower()):
            issues.append("Hardcoded sensitive credentials detected (use env vars)")

        return jsonify({
            'success': True,
            'issues': issues,
            'suggestions': "Ensure all dependencies are listed in requirements.txt for optimized deployment."
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@api_bp.route('/api/ai/generate', methods=['POST'])
@require_auth
def api_ai_generate(user_id):
    try:
        data = request.get_json() or {}
        prompt = data.get('prompt', '').strip()
        if not prompt: return jsonify({'success': False, 'error': 'Prompt required'})

        time.sleep(2) # Simulate analysis

        # Enterprise-grade AI response logic
        if any(x in prompt.lower() for x in ['debug', 'fix', 'error']):
            code = f"""# EliteHost AI Debugger Report
# Analyzed context: {prompt}

def fix_issue():
    # Potential fix implemented for detected structural anomaly
    try:
        print("Initializing recovery sequence...")
        # Your fixed logic here
        return True
    except Exception as e:
        print(f"Error captured: {{e}}")
        return False

if __name__ == "__main__":
    fix_issue()
"""
        elif any(x in prompt.lower() for x in ['flask', 'web', 'api']):
            code = """from flask import Flask, jsonify
import os

app = Flask(__name__)

@app.route('/')
def root():
    return jsonify({
        "status": "operational",
        "platform": "EliteHost Enterprise",
        "engine": "Neural-V4"
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
"""
        else:
            code = f"""# EliteHost Synthesized Application
# Objective: {prompt}

import os
import time

def execute():
    print("[SYSTEM] Booting synthesized environment...")
    print(f"[NEURAL] Processing parameters: {prompt}")
    time.sleep(1)
    print("[SUCCESS] Operational state achieved.")

if __name__ == '__main__':
    execute()
"""
        return jsonify({'success': True, 'code': code})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@api_bp.route('/api/deploy/upload', methods=['POST'])
@require_auth
def api_deploy_upload(user_id):
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        file = request.files['file']
        if not file.filename:
            return jsonify({'success': False, 'error': 'No file selected'})
        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({'success': False, 'error': f'Type not allowed.'})

        upload_path = os.path.join(UPLOADS_DIR, f"{user_id}_{int(time.time())}_{filename}")
        file.save(upload_path)

        if os.path.getsize(upload_path) > MAX_FILE_SIZE:
            os.remove(upload_path)
            return jsonify({'success': False, 'error': 'File too large'})

        deploy_id, message = deploy_from_file(user_id, upload_path, filename)
        try:
            os.remove(upload_path)
        except Exception:
            pass

        if deploy_id:
            return jsonify({'success': True, 'deploy_id': deploy_id, 'message': message})
        return jsonify({'success': False, 'error': message})
    except Exception as e:
        log_error(str(e), "api_deploy_upload")
        return jsonify({'success': False, 'error': str(e)})

@api_bp.route('/api/deployment/<deploy_id>/stop', methods=['POST'])
@require_auth
def api_stop_deployment(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Access denied'})
    success, msg = stop_deployment(deploy_id)
    return jsonify({'success': success, 'message': msg})

@api_bp.route('/api/deployment/<deploy_id>/restart', methods=['POST'])
@require_auth
def api_restart_deployment(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Access denied'})
    success, msg = restart_deployment(deploy_id)
    return jsonify({'success': success, 'message': msg})

@api_bp.route('/api/deployment/<deploy_id>', methods=['DELETE'])
@require_auth
def api_delete_deployment(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Access denied'})
    success, msg = delete_deployment(deploy_id)
    return jsonify({'success': success, 'message': msg})

@api_bp.route('/api/deployment/<deploy_id>/files')
@require_auth
def api_deployment_files(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Access denied'})
    return jsonify({'success': True, 'files': get_deployment_files(deploy_id)})

@api_bp.route('/api/deployment/<deploy_id>/env', methods=['POST'])
@require_auth
def api_add_env_var(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Access denied'})
    data = request.get_json() or {}
    key = data.get('key','').strip()
    if not key:
        return jsonify({'success': False, 'error': 'Key required'})
    env_vars = dict(deployment.get('env_vars', {}))
    env_vars[key] = data.get('value','').strip()
    update_deployment(deploy_id, env_vars=env_vars)
    return jsonify({'success': True, 'env_vars': env_vars})

@api_bp.route('/api/deployment/<deploy_id>/env/<key>', methods=['DELETE'])
@require_auth
def api_delete_env_var(user_id, deploy_id, key):
    deployment = get_deployment(deploy_id)
    if not deployment or deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Access denied'})
    env_vars = dict(deployment.get('env_vars', {}))
    env_vars.pop(key, None)
    update_deployment(deploy_id, env_vars=env_vars)
    return jsonify({'success': True, 'env_vars': env_vars})

@api_bp.route('/api/deployment/<deploy_id>/backup', methods=['POST'])
@require_auth
def api_create_backup(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Access denied'})
    backup_path, backup_name = create_backup(deploy_id)
    if backup_path:
        return jsonify({'success': True, 'backup_name': backup_name})
    return jsonify({'success': False, 'error': backup_name})

@api_bp.route('/api/deployment/<deploy_id>/backup/download')
@require_auth
def api_download_backup(user_id, deploy_id):
    from app.config import BACKUPS_DIR
    deployment = get_deployment(deploy_id)
    if not deployment or deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Access denied'})
    backups = sorted([f for f in os.listdir(BACKUPS_DIR)
                      if f.startswith(f"{deployment['name']}_{deploy_id}")], reverse=True)
    if not backups:
        return jsonify({'success': False, 'error': 'No backup found'})
    return send_file(os.path.join(BACKUPS_DIR, backups[0]), as_attachment=True, download_name=backups[0])

@api_bp.route('/api/deployment/<deploy_id>/logs')
@require_auth
def api_deployment_logs(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Access denied'})
    return jsonify({'success': True, 'logs': deployment.get('logs', '')})

@api_bp.route('/api/deployment/<deploy_id>/file', methods=['GET', 'POST', 'DELETE'])
@require_auth
def api_manage_file(user_id, deploy_id):
    deployment = get_deployment(deploy_id)
    if not deployment or deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Access denied'})

    path = request.args.get('path')
    if not path: return jsonify({'success': False, 'error': 'Path required'})

    full_path = os.path.normpath(os.path.join(DEPLOYS_DIR, deploy_id, path))
    if not full_path.startswith(os.path.join(DEPLOYS_DIR, deploy_id)):
        return jsonify({'success': False, 'error': 'Traversal denied'})

    if request.method == 'GET':
        if not os.path.exists(full_path): return jsonify({'success': False, 'error': 'Not found'})
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            return jsonify({'success': True, 'content': f.read()})

    if request.method == 'POST':
        data = request.get_json() or {}
        content = data.get('content', '')
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return jsonify({'success': True})

    if request.method == 'DELETE':
        if os.path.exists(full_path):
            if os.path.isdir(full_path): shutil.rmtree(full_path)
            else: os.remove(full_path)
        return jsonify({'success': True})

@api_bp.route('/api/payment/create', methods=['POST'])
@require_auth
def api_create_payment(user_id):
    data = request.get_json() or {}
    payment_id, payment_data = create_payment_request(
        user_id, data.get('package_type'), data.get('custom_amount'))
    if payment_id:
        return jsonify({'success': True, 'payment': payment_data})
    return jsonify({'success': False, 'error': payment_data})

@api_bp.route('/api/payment/submit', methods=['POST'])
@require_auth
def api_submit_payment(user_id):
    data = request.get_json() or {}
    success, message = submit_payment_proof(
        data.get('payment_id'), data.get('screenshot'), data.get('transaction_id'), bot)
    return jsonify({'success': success, 'message': message})

@api_bp.route('/api/user/sessions')
@require_auth
def api_user_sessions(user_id):
    sessions = get_active_sessions(user_id)
    # Hide current token from response
    current_token = request.cookies.get('session_token')
    for s in sessions:
        if s['token'] == current_token:
            s['is_current'] = True
        s.pop('token') # Only send if it's not current or use a safe ID
    return jsonify({'success': True, 'sessions': sessions})

@api_bp.route('/api/user/2fa/toggle', methods=['POST'])
@require_auth
def api_toggle_2fa(user_id):
    data = request.get_json() or {}
    enabled = data.get('enabled', False)
    telegram_id = data.get('telegram_id')

    if enabled and not telegram_id:
        return jsonify({'success': False, 'error': 'Telegram ID required to enable 2FA'})

    update_user(user_id, two_fa_enabled=1 if enabled else 0, telegram_id=telegram_id)
    return jsonify({'success': True, 'enabled': enabled})

@api_bp.route('/api/user/audit-logs')
@require_auth
def api_user_audit_logs(user_id):
    from app.services.json_db import db
    logs = db.audit_logs.find(user_id=user_id)
    # Sort and limit
    logs.sort(key=lambda x: x['timestamp'], reverse=True)
    return jsonify({'success': True, 'logs': logs[:50]})

@api_bp.route('/api/finance/wallet')
@require_auth
def api_wallet(user_id):
    from app.services.finance_support_service import get_wallet
    return jsonify({'success': True, 'wallet': get_wallet(user_id)})

@api_bp.route('/api/finance/withdraw', methods=['POST'])
@require_auth
def api_withdraw(user_id):
    from app.services.finance_support_service import request_withdrawal
    data = request.get_json() or {}
    amount = float(data.get('amount', 0))
    method = data.get('method', '')
    note = data.get('note', '')

    if amount <= 0: return jsonify({'success': False, 'error': 'Invalid amount'})
    if not method: return jsonify({'success': False, 'error': 'Method required'})

    success, res = request_withdrawal(user_id, amount, method, note)
    return jsonify({'success': success, 'id' if success else 'error': res})

@api_bp.route('/api/finance/history')
@require_auth
def api_finance_history(user_id):
    from app.services.finance_support_service import get_withdrawal_history
    from app.services.json_db import db
    return jsonify({
        'success': True,
        'withdrawals': get_withdrawal_history(user_id),
        'commissions': db.commissions.find(referrer_id=user_id)
    })

@api_bp.route('/api/referral/stats')
@require_auth
def api_referral_stats(user_id):
    from app.services.finance_support_service import get_referral_stats
    return jsonify({'success': True, 'stats': get_referral_stats(user_id)})

@api_bp.route('/api/support/tickets', methods=['GET', 'POST'])
@require_auth
def api_support_tickets(user_id):
    from app.services.finance_support_service import create_ticket
    from app.services.json_db import db
    if request.method == 'GET':
        return jsonify({'success': True, 'tickets': db.tickets.find(user_id=user_id)})

    data = request.get_json() or {}
    t_id = create_ticket(user_id, data.get('subject'), data.get('category'), data.get('message'))
    return jsonify({'success': True, 'ticket_id': t_id})

@api_bp.route('/api/support/ticket/<ticket_id>/messages', methods=['GET', 'POST'])
@require_auth
def api_ticket_messages(user_id, ticket_id):
    from app.services.json_db import db
    ticket = db.tickets.find_one(id=ticket_id)
    if not ticket or (ticket['user_id'] != user_id and user_id != 'admin_raj'):
        return jsonify({'success': False, 'error': 'Denied'})

    if request.method == 'GET':
        return jsonify({'success': True, 'messages': db.messages.find(ticket_id=ticket_id)})

    data = request.get_json() or {}
    db.messages.insert({
        'ticket_id': ticket_id,
        'sender_id': user_id,
        'message': data.get('message'),
        'is_admin': user_id == 'admin_raj',
        'timestamp': datetime.now().isoformat()
    })
    db.tickets.update({'id': ticket_id}, {'updated_at': datetime.now().isoformat()})
    return jsonify({'success': True})
