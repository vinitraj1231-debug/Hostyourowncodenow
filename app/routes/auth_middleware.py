import functools
from flask import request, jsonify
from app.services.user_service import verify_session, get_user, is_admin_user
from app.utils import get_device_fingerprint

def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(token, fingerprint)
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        return f(user_id, *args, **kwargs)
    return decorated

def require_admin(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(token, fingerprint)
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'}), 401
        user = get_user(user_id)
        if not user or not is_admin_user(user_id, user['email']):
            return jsonify({'success': False, 'error': 'Access denied'}), 403
        return f(user_id, *args, **kwargs)
    return decorated
