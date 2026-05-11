from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.config import WEB_SECRET_KEY, get_rate_limit_key
from app.db import init_database
from app.utils import get_device_fingerprint
from app.services.user_service import is_device_banned

def create_app():
    app = Flask(__name__)
    app.secret_key = WEB_SECRET_KEY
    CORS(app, supports_credentials=True)

    # Initialize Limiter
    limiter = Limiter(
        key_func=get_rate_limit_key,
        app=app,
        default_limits=["10000 per day", "2000 per hour", "200 per minute"],
        storage_uri="memory://",
        strategy="fixed-window"
    )

    # Initialize Database
    init_database()

    # Register Blueprints
    from app.routes.auth_routes import auth_bp
    from app.routes.dashboard_routes import dashboard_bp
    from app.routes.admin_routes import admin_bp
    from app.routes.api_routes import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)

    @app.before_request
    def before_request():
        fingerprint = get_device_fingerprint(request)
        if is_device_banned(fingerprint):
            return jsonify({'error': 'Access denied'}), 403

    @app.after_request
    def after_request(response):
        response.headers.update({
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin',
        })
        return response

    return app
