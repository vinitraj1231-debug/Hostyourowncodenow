from flask import Blueprint, request, redirect, render_template_string
from app.routes.auth_middleware import require_auth
from app.services.user_service import get_user, is_admin_user, verify_session
from app.utils import get_device_fingerprint
from app.templates import DASHBOARD_HTML, LANDING_PAGE_HTML
from app.config import TELEGRAM_LINK, YOUR_USERNAME

dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
def index():
    return render_template_string(LANDING_PAGE_HTML)

@dashboard_bp.route('/dashboard')
@require_auth
def dashboard(user_id):
    user = get_user(user_id)
    if not user or user.get('is_banned'):
        return redirect('/login?error=Access denied')
    is_admin = is_admin_user(user_id, user['email'])
    credits_display = '∞' if user['credits'] == float('inf') else user['credits']
    return render_template_string(DASHBOARD_HTML,
        credits=credits_display, is_admin=is_admin,
        telegram_link=TELEGRAM_LINK, username=YOUR_USERNAME)
