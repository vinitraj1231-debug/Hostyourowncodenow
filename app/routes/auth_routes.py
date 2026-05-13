import re
from datetime import datetime
from flask import Blueprint, request, redirect, make_response, render_template_string, session
from app.services.user_service import (
    check_existing_account, create_user, authenticate_user,
    create_session, update_user, get_user, is_admin_user
)
from app.utils import get_device_fingerprint, log_error
from app.templates import LOGIN_PAGE
from app.config import (
    SESSION_TIMEOUT_DAYS, ADMIN_EMAIL, ADMIN_PASSWORD
)
from app.services.credit_service import log_activity

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string(LOGIN_PAGE,
            title='Register', subtitle='Create your EliteHost account',
            action='/register', button_text='Create Account', icon='user-plus',
            toggle_text='Already have an account?', toggle_link='/login', toggle_action='Login',
            error=request.args.get('error',''), success=request.args.get('success',''))

    try:
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        fingerprint = get_device_fingerprint(request)
        ip = request.remote_addr

        if not email or not password:
            return redirect('/register?error=Email and password required')
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            return redirect('/register?error=Invalid email format')
        if len(password) < 6:
            return redirect('/register?error=Password must be at least 6 characters')

        user_id = create_user(email, password, fingerprint, ip)
        if not user_id:
            return redirect('/register?error=Registration failed. Email might already be taken.')

        token = create_session(user_id, fingerprint, ip, request.headers.get('User-Agent'))

        from app.security.audit import log_security_event
        log_security_event(request, "USER_REGISTER", "INFO", f"New user registered: {email}", user_id=user_id)

        response = make_response(redirect('/dashboard'))
        response.set_cookie('session_token', token,
                           max_age=SESSION_TIMEOUT_DAYS*86400, httponly=True, samesite='Lax')
        return response

    except Exception as e:
        log_error(str(e), "register")
        return redirect('/register?error=An error occurred.')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_PAGE,
            title='Login', subtitle='Sign in to your account',
            action='/login', button_text='Sign In', icon='sign-in-alt',
            toggle_text="Don't have an account?", toggle_link='/register', toggle_action='Register',
            error=request.args.get('error',''), success=request.args.get('success',''))

    try:
        email = request.form.get('email','').strip().lower()
        password = request.form.get('password','')
        fingerprint = get_device_fingerprint(request)
        ip = request.remote_addr

        if not email or not password:
            return redirect('/login?error=Email and password required')

        is_admin_login = (ADMIN_EMAIL and email == ADMIN_EMAIL.lower() and password == ADMIN_PASSWORD)

        user_id = authenticate_user(email, password)
        if not user_id and not is_admin_login:
            return redirect('/login?error=Invalid email or password')

        if is_admin_login and not user_id:
            # Create admin user if not exists
            user_id = create_user(email, password, fingerprint, ip)

        user = get_user(user_id)
        if user.get('is_banned'):
            from app.security.audit import log_security_event
            log_security_event(request, "BANNED_LOGIN_ATTEMPT", "WARNING", f"Banned user {email} tried to login")
            return redirect('/login?error=Account banned.')

        # Check for 2FA
        if user.get('two_fa_enabled') and user.get('telegram_id'):
            from app.security.two_fa import send_two_fa_code
            code = send_two_fa_code(user_id, user['telegram_id'])
            if code:
                session['pending_2fa_user'] = user_id
                session['2fa_code'] = code
                return redirect('/login/2fa')

        update_user(user_id, last_login=datetime.now().isoformat())
        log_activity(user_id, 'LOGIN', f'Login from {ip}', ip)

        from app.security.audit import log_security_event
        log_security_event(request, "USER_LOGIN", "INFO", f"User logged in: {email}", user_id=user_id)

        token = create_session(user_id, fingerprint, ip, request.headers.get('User-Agent'))

        is_admin = is_admin_user(user_id, user['email'])
        dest = '/admin' if is_admin else '/dashboard'

        response = make_response(redirect(dest))
        response.set_cookie('session_token', token, max_age=SESSION_TIMEOUT_DAYS*86400, httponly=True, samesite='Lax')
        return response

    except Exception as e:
        log_error(str(e), "login")
        return redirect('/login?error=An error occurred')

@auth_bp.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    user_id = session.get('pending_2fa_user')
    if not user_id:
        return redirect('/login')

    if request.method == 'GET':
        return render_template_string(LOGIN_PAGE,
            title='2FA Verification', subtitle='Enter the code sent to your Telegram',
            action='/login/2fa', button_text='Verify', icon='shield-alt',
            toggle_text="Didn't receive a code?", toggle_link='/login', toggle_action='Retry',
            error=request.args.get('error',''))

    input_code = request.form.get('password','').strip().upper()
    actual_code = session.get('2fa_code')

    if input_code == actual_code:
        user = get_user(user_id)
        fingerprint = get_device_fingerprint(request)
        ip = request.remote_addr

        session.pop('pending_2fa_user', None)
        session.pop('2fa_code', None)

        update_user(user_id, last_login=datetime.now().isoformat())
        log_activity(user_id, 'LOGIN_2FA', f'Login via 2FA from {ip}', ip)

        from app.security.audit import log_security_event
        log_security_event(request, "USER_LOGIN_2FA", "INFO", f"User logged in via 2FA: {user['email']}", user_id=user_id)

        token = create_session(user_id, fingerprint, ip, request.headers.get('User-Agent'))

        is_admin = is_admin_user(user_id, user['email'])
        dest = '/admin' if is_admin else '/dashboard'

        response = make_response(redirect(dest))
        response.set_cookie('session_token', token, max_age=SESSION_TIMEOUT_DAYS*86400, httponly=True, samesite='Lax')
        return response
    else:
        from app.security.audit import log_security_event
        log_security_event(request, "INVALID_2FA_ATTEMPT", "WARNING", f"Invalid 2FA code for user_id {user_id}", user_id=user_id)
        return redirect('/login/2fa?error=Invalid code')

@auth_bp.route('/logout')
def logout():
    token = request.cookies.get('session_token')
    if token:
        from app.db import get_db
        with get_db() as conn:
            conn.cursor().execute('DELETE FROM sessions WHERE token = ?', (token,))
    response = make_response(redirect('/login?success=Logged out successfully'))
    response.set_cookie('session_token', '', expires=0, httponly=True, samesite='Lax')
    return response
