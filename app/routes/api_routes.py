import json
import os
import time
from flask import Blueprint, request, jsonify, Response, stream_with_context, send_file
from werkzeug.utils import secure_filename
from app.routes.auth_middleware import require_auth
from app.services.user_service import (
    get_user, verify_session, get_active_sessions,
    revoke_session, update_user
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
    return jsonify({'success': True, 'credits': get_credits(user_id)})

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
    try:
        deployment = get_deployment(deploy_id)
        if not deployment or deployment['user_id'] != user_id:
            return jsonify({'success': False, 'error': 'Access denied'})

        stop_deployment(deploy_id)
        time.sleep(1)

        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        start_cmd = deployment.get('start_command', '')
        env_vars = deployment.get('env_vars', {})
        port = deployment.get('port', find_free_port())

        if not start_cmd:
            for fname, cmd in [('main.py', f'{sys.executable} main.py'), ('app.py', f'{sys.executable} app.py'), ('bot.py', f'{sys.executable} bot.py')]:
                if os.path.exists(os.path.join(deploy_dir, fname)):
                    start_cmd = cmd; break

        if not start_cmd:
            return jsonify({'success': False, 'error': 'No start command'})

        process = _launch_process(start_cmd.split(), deploy_dir, port, env_vars, project_path=deploy_dir, deploy_id=deploy_id)
        with PROCESS_LOCK:
            active_processes[deploy_id] = process
            process_restart_ct[deploy_id] = process_restart_ct.get(deploy_id, 0) + 1

        update_deployment(deploy_id, status='running', pid=process.pid,
                         restart_count=process_restart_ct[deploy_id],
                         logs=f'🔄 Restarted (#{process_restart_ct[deploy_id]})')
        return jsonify({'success': True, 'message': 'Restarting...'})
    except Exception as e:
        log_error(str(e), f"api_restart {deploy_id}")
        return jsonify({'success': False, 'error': str(e)})

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
    from app.db import get_db
    with get_db() as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 50', (user_id,))
        logs = [dict(row) for row in c.fetchall()]
    return jsonify({'success': True, 'logs': logs})
