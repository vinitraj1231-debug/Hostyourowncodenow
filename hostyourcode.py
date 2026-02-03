"""
🚀 ELITEHOST v12.0 - PAYMENT GATEWAY EDITION
Next-Generation Cloud Deployment Platform
Payment System | Blue Theme | Logo Support | Advanced Features
"""

import sys
import subprocess
import os

# ==================== DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 ELITEHOST v12.0 - DEPENDENCY INSTALLER")
print("=" * 90)

REQUIRED_PACKAGES = {
    'pyTelegramBotAPI': 'telebot',
    'flask': 'flask',
    'flask-cors': 'flask_cors',
    'requests': 'requests',
    'cryptography': 'cryptography',
    'psutil': 'psutil',
    'werkzeug': 'werkzeug',
    'python-dotenv': 'dotenv',
    'colorama': 'colorama',
    'pillow': 'PIL',
    'bcrypt': 'bcrypt'
}

def smart_install(package, import_name):
    try:
        __import__(import_name)
        print(f"✓ {package:30} [INSTALLED]")
        return True
    except ImportError:
        print(f"⚡ {package:30} [INSTALLING...]", end=' ')
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', package, '--quiet'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            print("✅")
            return True
        except:
            print("❌")
            return False

print("\n🔍 Checking dependencies...\n")
failed = []
for pkg, imp in REQUIRED_PACKAGES.items():
    if not smart_install(pkg, imp):
        failed.append(pkg)

if failed:
    print(f"\n❌ Failed: {', '.join(failed)}")
    sys.exit(1)

print("\n" + "=" * 90)
print("✅ ALL DEPENDENCIES READY!")
print("=" * 90 + "\n")

# ==================== IMPORTS ====================
import telebot
from telebot import types
import zipfile
import shutil
import time
from datetime import datetime, timedelta
import json
import logging
import threading
import atexit
import requests
import hashlib
import secrets
import signal
from pathlib import Path
from flask import Flask, render_template_string, request, jsonify, session, send_file, redirect, make_response, send_from_directory
from flask_cors import CORS
from threading import Thread, Lock, Timer
import uuid
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import psutil
from colorama import Fore, Style, init
import bcrypt
import re

init(autoreset=True)

# ==================== CONFIGURATION ====================
TOKEN = '8133133627:AAHXG1M3I_5yV6mIo2IRl61h8zRUvg6Nn2Y'
OWNER_ID = 7524032836
ADMIN_ID = 8285724366
ADMIN_EMAIL = 'Kvinit6421@gmail.com'
ADMIN_PASSWORD = '28@HumblerRaj'
YOUR_USERNAME = '@Zolvit'
TELEGRAM_LINK = 'https://t.me/Zolvit'
WEB_SECRET_KEY = secrets.token_hex(32)
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

FREE_CREDITS = 2.0
CREDIT_COSTS = {
    'file_upload': 0.5,
    'github_deploy': 1.0,
    'backup': 0.5,
}

# Payment Packages
PAYMENT_PACKAGES = {
    '10_credits': {'credits': 10, 'price': 50, 'name': '10 Credits Pack'},
    '99_credits': {'credits': 99, 'price': 399, 'name': '99 Credits Pack'},
}

# Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'elitehost_data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
DEPLOYS_DIR = os.path.join(DATA_DIR, 'deployments')
BACKUPS_DIR = os.path.join(DATA_DIR, 'backups')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
PAYMENTS_DIR = os.path.join(DATA_DIR, 'payments')
STATIC_DIR = os.path.join(DATA_DIR, 'static')
DB_FILE = os.path.join(DATA_DIR, 'database.json')

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, BACKUPS_DIR, LOGS_DIR, PAYMENTS_DIR, STATIC_DIR]:
    os.makedirs(d, exist_ok=True)

# Flask & Bot
app = Flask(__name__)
app.secret_key = WEB_SECRET_KEY
CORS(app)
bot = telebot.TeleBot(TOKEN, parse_mode='Markdown')

# Global state
active_processes = {}
deployment_logs = {}
payment_timers = {}
DB_LOCK = Lock()

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, 'bot.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== ERROR LOGGER ====================
def log_error(error_msg, context=""):
    """Log errors to file and console"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    error_log = f"[{timestamp}] ERROR in {context}: {error_msg}\n"
    
    error_file = os.path.join(LOGS_DIR, 'errors.log')
    with open(error_file, 'a') as f:
        f.write(error_log)
    
    logger.error(f"{Fore.RED}{error_log}")
    return error_log

# ==================== DATABASE FUNCTIONS ====================

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            log_error(str(e), "load_db")
    return {
        'users': {},
        'sessions': {},
        'deployments': {},
        'payments': {},
        'activity': [],
        'banned_devices': []
    }

def save_db(db):
    with DB_LOCK:
        try:
            db_copy = db.copy()
            if 'banned_devices' in db_copy and isinstance(db_copy['banned_devices'], set):
                db_copy['banned_devices'] = list(db_copy['banned_devices'])
            
            with open(DB_FILE, 'w') as f:
                json.dump(db_copy, f, indent=2, default=str)
        except Exception as e:
            log_error(str(e), "save_db")

db = load_db()
if isinstance(db.get('banned_devices'), list):
    db['banned_devices'] = set(db['banned_devices'])
else:
    db['banned_devices'] = set()

if 'payments' not in db:
    db['payments'] = {}

# ==================== DEVICE FINGERPRINTING ====================

def get_device_fingerprint(request):
    user_agent = request.headers.get('User-Agent', '')
    ip = request.remote_addr or request.environ.get('HTTP_X_REAL_IP', 'unknown')
    accept_lang = request.headers.get('Accept-Language', '')
    fingerprint_str = f"{user_agent}|{ip}|{accept_lang}"
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()

def is_device_banned(fingerprint):
    return fingerprint in db.get('banned_devices', set())

def check_existing_account(fingerprint):
    for user_id, user_data in db['users'].items():
        if user_data.get('device_fingerprint') == fingerprint:
            return user_id
    return None

# ==================== USER FUNCTIONS ====================

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_user(email, password, fingerprint, ip):
    user_id = str(uuid.uuid4())
    
    db['users'][user_id] = {
        'email': email,
        'password': hash_password(password),
        'device_fingerprint': fingerprint,
        'credits': FREE_CREDITS,
        'total_spent': 0,
        'total_earned': FREE_CREDITS,
        'deployments': [],
        'created_at': datetime.now().isoformat(),
        'last_login': datetime.now().isoformat(),
        'ip_address': ip,
        'is_banned': False,
        'telegram_id': None
    }
    
    log_activity(user_id, 'USER_REGISTER', f'New user: {email}', ip)
    save_db(db)
    
    # Notify owner via Telegram
    try:
        bot.send_message(
            OWNER_ID,
            f"🆕 *NEW USER REGISTERED*\n\n"
            f"📧 Email: `{email}`\n"
            f"🆔 ID: `{user_id}`\n"
            f"🌐 IP: `{ip}`\n"
            f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
    except Exception as e:
        log_error(str(e), "create_user telegram notification")
    
    return user_id

def authenticate_user(email, password):
    for user_id, user_data in db['users'].items():
        if user_data['email'] == email:
            if verify_password(password, user_data['password']):
                return user_id
    return None

def create_session(user_id, fingerprint):
    session_token = secrets.token_urlsafe(32)
    db['sessions'][session_token] = {
        'user_id': user_id,
        'fingerprint': fingerprint,
        'created_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(days=7)).isoformat()
    }
    save_db(db)
    return session_token

def verify_session(session_token, fingerprint):
    if session_token not in db['sessions']:
        return None
    session_data = db['sessions'][session_token]
    if datetime.fromisoformat(session_data['expires_at']) < datetime.now():
        del db['sessions'][session_token]
        save_db(db)
        return None
    if session_data['fingerprint'] != fingerprint:
        return None
    return session_data['user_id']

def get_user(user_id):
    return db['users'].get(user_id)

def update_user(user_id, **kwargs):
    if user_id in db['users']:
        db['users'][user_id].update(kwargs)
        save_db(db)

def log_activity(user_id, action, details, ip=''):
    db['activity'].append({
        'user_id': user_id,
        'action': action,
        'details': details,
        'ip': ip,
        'timestamp': datetime.now().isoformat()
    })
    save_db(db)

# ==================== CREDIT SYSTEM ====================

def get_credits(user_id):
    if user_id == str(OWNER_ID):
        return float('inf')
    user = get_user(user_id)
    return user['credits'] if user else 0

def add_credits(user_id, amount, description="Credit added"):
    user = get_user(user_id)
    if not user:
        return False
    user['credits'] += amount
    user['total_earned'] += amount
    update_user(user_id, credits=user['credits'], total_earned=user['total_earned'])
    log_activity(user_id, 'CREDIT_ADD', f"{amount} - {description}")
    return True

def deduct_credits(user_id, amount, description="Credit used"):
    if user_id == str(OWNER_ID):
        return True
    user = get_user(user_id)
    if not user or user['credits'] < amount:
        return False
    user['credits'] -= amount
    user['total_spent'] += amount
    update_user(user_id, credits=user['credits'], total_spent=user['total_spent'])
    log_activity(user_id, 'CREDIT_USE', f"{amount} - {description}")
    return True

# ==================== PAYMENT SYSTEM ====================

def create_payment_request(user_id, package_type, custom_amount=None):
    """Create a new payment request"""
    try:
        payment_id = str(uuid.uuid4())[:12]
        
        if package_type == 'custom':
            if not custom_amount or custom_amount <= 0:
                return None, "Invalid custom amount"
            credits = custom_amount
            price = custom_amount  # Custom pricing
        else:
            if package_type not in PAYMENT_PACKAGES:
                return None, "Invalid package"
            package = PAYMENT_PACKAGES[package_type]
            credits = package['credits']
            price = package['price']
        
        user = get_user(user_id)
        if not user:
            return None, "User not found"
        
        payment_data = {
            'id': payment_id,
            'user_id': user_id,
            'user_email': user['email'],
            'package_type': package_type,
            'credits': credits,
            'price': price,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'expires_at': (datetime.now() + timedelta(minutes=5)).isoformat(),
            'screenshot': None,
            'transaction_id': None
        }
        
        db['payments'][payment_id] = payment_data
        save_db(db)
        
        # Start 5-minute timer
        timer = Timer(300, expire_payment, args=[payment_id])
        payment_timers[payment_id] = timer
        timer.start()
        
        log_activity(user_id, 'PAYMENT_REQUEST', f"Payment {payment_id}: {credits} credits for ₹{price}")
        
        return payment_id, payment_data
    
    except Exception as e:
        log_error(str(e), "create_payment_request")
        return None, str(e)

def expire_payment(payment_id):
    """Auto-expire payment after 5 minutes"""
    try:
        if payment_id in db['payments']:
            if db['payments'][payment_id]['status'] == 'pending':
                db['payments'][payment_id]['status'] = 'expired'
                save_db(db)
                logger.info(f"Payment {payment_id} expired")
    except Exception as e:
        log_error(str(e), "expire_payment")

def submit_payment_proof(payment_id, screenshot_data, transaction_id):
    """Submit payment proof"""
    try:
        if payment_id not in db['payments']:
            return False, "Payment not found"
        
        payment = db['payments'][payment_id]
        
        if payment['status'] != 'pending':
            return False, f"Payment is {payment['status']}"
        
        # Check if expired
        if datetime.fromisoformat(payment['expires_at']) < datetime.now():
            payment['status'] = 'expired'
            save_db(db)
            return False, "Payment expired"
        
        # Save screenshot
        screenshot_path = os.path.join(PAYMENTS_DIR, f"{payment_id}_screenshot.jpg")
        try:
            import base64
            screenshot_bytes = base64.b64decode(screenshot_data.split(',')[1])
            with open(screenshot_path, 'wb') as f:
                f.write(screenshot_bytes)
        except Exception as e:
            log_error(str(e), "screenshot save")
            return False, "Screenshot upload failed"
        
        payment['screenshot'] = screenshot_path
        payment['transaction_id'] = transaction_id
        payment['status'] = 'submitted'
        payment['submitted_at'] = datetime.now().isoformat()
        save_db(db)
        
        # Cancel expiry timer
        if payment_id in payment_timers:
            payment_timers[payment_id].cancel()
            del payment_timers[payment_id]
        
        # Notify admin via Telegram
        try:
            user = get_user(payment['user_id'])
            
            markup = types.InlineKeyboardMarkup()
            markup.row(
                types.InlineKeyboardButton("✅ Confirm", callback_data=f"payment_confirm_{payment_id}"),
                types.InlineKeyboardButton("❌ Reject", callback_data=f"payment_reject_{payment_id}")
            )
            
            bot.send_message(
                ADMIN_ID,
                f"💳 *NEW PAYMENT SUBMISSION*\n\n"
                f"📧 User: `{user['email']}`\n"
                f"🆔 Payment ID: `{payment_id}`\n"
                f"💰 Amount: ₹{payment['price']}\n"
                f"💎 Credits: {payment['credits']}\n"
                f"🔢 Transaction ID: `{transaction_id}`\n"
                f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                f"_Review the payment and take action:_",
                reply_markup=markup
            )
            
            # Send screenshot
            with open(screenshot_path, 'rb') as photo:
                bot.send_photo(ADMIN_ID, photo, caption=f"Payment Screenshot - {payment_id}")
        
        except Exception as e:
            log_error(str(e), "payment notification")
        
        return True, "Payment proof submitted successfully"
    
    except Exception as e:
        log_error(str(e), "submit_payment_proof")
        return False, str(e)

# ==================== TELEGRAM BOT HANDLERS ====================

@bot.callback_query_handler(func=lambda call: call.data.startswith('payment_'))
def handle_payment_action(call):
    """Handle payment confirmation/rejection from Telegram"""
    try:
        action, payment_id = call.data.rsplit('_', 1)
        
        if payment_id not in db['payments']:
            bot.answer_callback_query(call.id, "Payment not found")
            return
        
        payment = db['payments'][payment_id]
        
        if 'confirm' in action:
            # Approve payment
            payment['status'] = 'approved'
            payment['approved_at'] = datetime.now().isoformat()
            payment['approved_by'] = str(call.from_user.id)
            
            # Add credits to user
            add_credits(payment['user_id'], payment['credits'], f"Payment approved: {payment_id}")
            
            save_db(db)
            
            bot.answer_callback_query(call.id, "✅ Payment Approved!")
            bot.edit_message_text(
                f"{call.message.text}\n\n✅ *APPROVED* by {call.from_user.first_name}",
                call.message.chat.id,
                call.message.message_id,
                parse_mode='Markdown'
            )
            
            # Notify user
            user = get_user(payment['user_id'])
            logger.info(f"Payment {payment_id} approved - {payment['credits']} credits added to {user['email']}")
        
        elif 'reject' in action:
            # Reject payment
            payment['status'] = 'rejected'
            payment['rejected_at'] = datetime.now().isoformat()
            payment['rejected_by'] = str(call.from_user.id)
            
            save_db(db)
            
            bot.answer_callback_query(call.id, "❌ Payment Rejected")
            bot.edit_message_text(
                f"{call.message.text}\n\n❌ *REJECTED* by {call.from_user.first_name}",
                call.message.chat.id,
                call.message.message_id,
                parse_mode='Markdown'
            )
            
            user = get_user(payment['user_id'])
            logger.info(f"Payment {payment_id} rejected for {user['email']}")
    
    except Exception as e:
        log_error(str(e), "handle_payment_action")
        bot.answer_callback_query(call.id, f"Error: {str(e)}")

# ==================== AI DEPENDENCY DETECTOR ====================

def extract_imports_from_code(code_content):
    imports = set()
    import_patterns = [
        r'^\s*import\s+([a-zA-Z0-9_\.]+)',
        r'^\s*from\s+([a-zA-Z0-9_\.]+)\s+import',
    ]
    for line in code_content.split('\n'):
        for pattern in import_patterns:
            match = re.match(pattern, line)
            if match:
                module = match.group(1).split('.')[0]
                imports.add(module)
    return imports

def get_package_name(import_name):
    mapping = {
        'cv2': 'opencv-python',
        'PIL': 'pillow',
        'sklearn': 'scikit-learn',
        'yaml': 'pyyaml',
        'dotenv': 'python-dotenv',
        'telebot': 'pyTelegramBotAPI',
        'bs4': 'beautifulsoup4',
    }
    return mapping.get(import_name, import_name)

def detect_and_install_deps(project_path):
    installed = []
    install_log = []
    
    install_log.append("🤖 AI DEPENDENCY ANALYZER v12.0")
    install_log.append("=" * 60)
    
    try:
        req_file = os.path.join(project_path, 'requirements.txt')
        if os.path.exists(req_file):
            install_log.append("\n📦 PYTHON REQUIREMENTS.TXT DETECTED")
            try:
                with open(req_file, 'r') as f:
                    packages = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                for pkg in packages:
                    try:
                        subprocess.run(
                            [sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                            check=True,
                            capture_output=True,
                            timeout=300
                        )
                        install_log.append(f"  ✅ {pkg}")
                        installed.append(pkg)
                    except Exception as e:
                        install_log.append(f"  ⚠️  {pkg} (skipped: {str(e)[:50]})")
                        log_error(str(e), f"install {pkg}")
            except Exception as e:
                install_log.append(f"❌ Error: {str(e)[:100]}")
                log_error(str(e), "requirements.txt processing")
        
        python_files = []
        for root, dirs, files in os.walk(project_path):
            for file in files:
                if file.endswith('.py'):
                    python_files.append(os.path.join(root, file))
        
        if python_files:
            all_imports = set()
            for py_file in python_files[:20]:
                try:
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                        imports = extract_imports_from_code(code)
                        all_imports.update(imports)
                except Exception as e:
                    log_error(str(e), f"reading {py_file}")
                    continue
            
            if all_imports:
                stdlib = {'os', 'sys', 'time', 'json', 're', 'math', 'random', 'datetime'}
                third_party = all_imports - stdlib
                
                for imp in third_party:
                    pkg = get_package_name(imp)
                    try:
                        __import__(imp)
                    except ImportError:
                        try:
                            subprocess.run(
                                [sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                                check=True,
                                capture_output=True,
                                timeout=300
                            )
                            install_log.append(f"  ✅ {pkg} (auto-installed)")
                            installed.append(pkg)
                        except Exception as e:
                            log_error(str(e), f"auto-install {pkg}")
                            pass
        
        install_log.append("\n" + "=" * 60)
        install_log.append(f"📦 Total Packages Installed: {len(installed)}")
        install_log.append("=" * 60)
        
        return installed, "\n".join(install_log)
    
    except Exception as e:
        log_error(str(e), "detect_and_install_deps")
        return installed, "\n".join(install_log) + f"\n\n❌ Error: {str(e)}"

# ==================== DEPLOYMENT FUNCTIONS ====================

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port

def create_deployment(user_id, name, deploy_type, **kwargs):
    try:
        deploy_id = str(uuid.uuid4())[:8]
        port = find_free_port()
        
        deployment = {
            'id': deploy_id,
            'user_id': user_id,
            'name': name,
            'type': deploy_type,
            'status': 'pending',
            'port': port,
            'pid': None,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'logs': '',
            'dependencies': [],
            'repo_url': kwargs.get('repo_url', ''),
            'branch': kwargs.get('branch', 'main'),
            'build_command': kwargs.get('build_command', ''),
            'start_command': kwargs.get('start_command', ''),
            'env_vars': {},
            'files': []
        }
        
        db['deployments'][deploy_id] = deployment
        
        user = get_user(user_id)
        if user:
            user['deployments'].append(deploy_id)
            update_user(user_id, deployments=user['deployments'])
        
        log_activity(user_id, 'DEPLOYMENT_CREATE', f"{name} ({deploy_type})")
        save_db(db)
        
        return deploy_id, port
    
    except Exception as e:
        log_error(str(e), "create_deployment")
        return None, None

def update_deployment(deploy_id, **kwargs):
    try:
        if deploy_id in db['deployments']:
            db['deployments'][deploy_id].update(kwargs)
            db['deployments'][deploy_id]['updated_at'] = datetime.now().isoformat()
            save_db(db)
    except Exception as e:
        log_error(str(e), f"update_deployment {deploy_id}")

def deploy_from_file(user_id, file_path, filename):
    try:
        cost = CREDIT_COSTS['file_upload']
        if not deduct_credits(user_id, cost, f"File deploy: {filename}"):
            return None, f"❌ Need {cost} credits"
        
        deploy_id, port = create_deployment(user_id, filename, 'file_upload')
        
        if not deploy_id:
            add_credits(user_id, cost, "Refund")
            return None, "Failed to create deployment"
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        user = get_user(user_id)
        
        # Notify owner
        try:
            bot.send_message(
                OWNER_ID,
                f"📤 *FILE DEPLOYMENT*\n\n"
                f"👤 User: {user['email']}\n"
                f"📁 File: `{filename}`\n"
                f"🆔 Deploy ID: `{deploy_id}`\n"
                f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        except Exception as e:
            log_error(str(e), "deploy notification")
        
        if filename.endswith('.zip'):
            update_deployment(deploy_id, status='extracting', logs='📦 Extracting ZIP...')
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(deploy_dir)
            
            main_file = None
            for root, dirs, files in os.walk(deploy_dir):
                for file in files:
                    if file in ['main.py', 'app.py', 'bot.py', 'index.js', 'server.js']:
                        main_file = os.path.join(root, file)
                        break
                if main_file:
                    break
            
            if not main_file:
                update_deployment(deploy_id, status='failed', logs='❌ No entry point')
                add_credits(user_id, cost, "Refund")
                return None, "❌ No main file found"
            
            file_path = main_file
        else:
            shutil.copy(file_path, os.path.join(deploy_dir, filename))
            file_path = os.path.join(deploy_dir, filename)
        
        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        update_deployment(deploy_id, dependencies=installed_deps)
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        deployment = db['deployments'][deploy_id]
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = value
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Launching on port {port}...')
        
        if file_path.endswith('.py'):
            cmd = [sys.executable, file_path]
        elif file_path.endswith('.js'):
            cmd = ['node', file_path]
        else:
            cmd = [sys.executable, file_path]
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.dirname(file_path),
            env=env
        )
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, status='running', pid=process.pid, logs=f'✅ Live on port {port}!')
        
        return deploy_id, f"🎉 Deployed! Port {port}"
    
    except Exception as e:
        log_error(str(e), "deploy_from_file")
        if 'deploy_id' in locals() and deploy_id:
            update_deployment(deploy_id, status='failed', logs=str(e))
            add_credits(user_id, cost, "Refund")
        return None, str(e)

def deploy_from_github(user_id, repo_url, branch='main', build_cmd='', start_cmd=''):
    try:
        cost = CREDIT_COSTS['github_deploy']
        if not deduct_credits(user_id, cost, f"GitHub: {repo_url}"):
            return None, f"❌ Need {cost} credits"
        
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        deploy_id, port = create_deployment(user_id, repo_name, 'github', 
                                           repo_url=repo_url, branch=branch,
                                           build_command=build_cmd, start_command=start_cmd)
        
        if not deploy_id:
            add_credits(user_id, cost, "Refund")
            return None, "Failed to create deployment"
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        user = get_user(user_id)
        
        # Notify owner
        try:
            bot.send_message(
                OWNER_ID,
                f"🐙 *GITHUB DEPLOYMENT*\n\n"
                f"👤 User: {user['email']}\n"
                f"📦 Repo: `{repo_url}`\n"
                f"🌿 Branch: `{branch}`\n"
                f"🆔 Deploy ID: `{deploy_id}`\n"
                f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )
        except Exception as e:
            log_error(str(e), "github deploy notification")
        
        update_deployment(deploy_id, status='cloning', logs=f'🔄 Cloning {repo_url}...')
        
        result = subprocess.run(
            ['git', 'clone', '-b', branch, '--depth', '1', repo_url, deploy_dir],
            capture_output=True,
            text=True,
            timeout=600
        )
        
        if result.returncode != 0:
            update_deployment(deploy_id, status='failed', logs='❌ Clone failed')
            add_credits(user_id, cost, "Refund")
            return None, "❌ Clone failed"
        
        if build_cmd:
            update_deployment(deploy_id, status='building', logs=f'🔨 Running: {build_cmd}')
            build_result = subprocess.run(
                build_cmd,
                shell=True,
                cwd=deploy_dir,
                capture_output=True,
                text=True,
                timeout=600
            )
            if build_result.returncode != 0:
                update_deployment(deploy_id, status='failed', logs=f'❌ Build failed: {build_result.stderr}')
                add_credits(user_id, cost, "Refund")
                return None, "❌ Build failed"
        
        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        update_deployment(deploy_id, dependencies=installed_deps)
        
        if not start_cmd:
            main_files = {
                'main.py': f'{sys.executable} main.py',
                'app.py': f'{sys.executable} app.py',
                'bot.py': f'{sys.executable} bot.py',
                'index.js': 'node index.js',
                'server.js': 'node server.js',
            }
            
            for file, cmd in main_files.items():
                if os.path.exists(os.path.join(deploy_dir, file)):
                    start_cmd = cmd
                    break
        
        if not start_cmd:
            update_deployment(deploy_id, status='failed', logs='❌ No start command')
            add_credits(user_id, cost, "Refund")
            return None, "❌ No start command found"
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Starting: {start_cmd}')
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        deployment = db['deployments'][deploy_id]
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = value
        
        process = subprocess.Popen(
            start_cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=deploy_dir,
            env=env
        )
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, status='running', pid=process.pid, 
                         logs=f'✅ Running on port {port}!', start_command=start_cmd)
        
        return deploy_id, f"🎉 Deployed! Port {port}"
    
    except Exception as e:
        log_error(str(e), "deploy_from_github")
        if 'deploy_id' in locals() and deploy_id:
            update_deployment(deploy_id, status='failed', logs=str(e))
            add_credits(user_id, cost, "Refund")
        return None, str(e)

def stop_deployment(deploy_id):
    try:
        if deploy_id in active_processes:
            process = active_processes[deploy_id]
            process.terminate()
            try:
                process.wait(timeout=5)
            except:
                process.kill()
            del active_processes[deploy_id]
            update_deployment(deploy_id, status='stopped', logs='🛑 Stopped')
            return True, "Stopped"
        return False, "Not running"
    except Exception as e:
        log_error(str(e), f"stop_deployment {deploy_id}")
        return False, str(e)

def create_backup(deploy_id):
    try:
        if deploy_id not in db['deployments']:
            return None, "Deployment not found"
        
        deployment = db['deployments'][deploy_id]
        user_id = deployment['user_id']
        
        cost = CREDIT_COSTS['backup']
        if not deduct_credits(user_id, cost, f"Backup: {deployment['name']}"):
            return None, f"❌ Need {cost} credits"
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if not os.path.exists(deploy_dir):
            add_credits(user_id, cost, "Refund")
            return None, "Deployment directory not found"
        
        backup_name = f"{deployment['name']}_{deploy_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        backup_path = os.path.join(BACKUPS_DIR, backup_name)
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(deploy_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, deploy_dir)
                    zipf.write(file_path, arcname)
        
        return backup_path, backup_name
    
    except Exception as e:
        log_error(str(e), f"create_backup {deploy_id}")
        if 'user_id' in locals() and 'cost' in locals():
            add_credits(user_id, cost, "Refund")
        return None, str(e)

def get_deployment_files(deploy_id):
    try:
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if not os.path.exists(deploy_dir):
            return []
        
        files = []
        for root, dirs, filenames in os.walk(deploy_dir):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                rel_path = os.path.relpath(file_path, deploy_dir)
                size = os.path.getsize(file_path)
                files.append({
                    'name': filename,
                    'path': rel_path,
                    'size': size,
                    'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                })
        
        return files
    except Exception as e:
        log_error(str(e), f"get_deployment_files {deploy_id}")
        return []

def get_system_metrics():
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return {
            'cpu': cpu_percent,
            'memory_percent': memory.percent,
            'memory_used': memory.used / (1024**3),
            'memory_total': memory.total / (1024**3),
            'disk_percent': disk.percent,
            'disk_used': disk.used / (1024**3),
            'disk_total': disk.total / (1024**3)
        }
    except Exception as e:
        log_error(str(e), "get_system_metrics")
        return {}

# ==================== HTML TEMPLATES ====================

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost - {{ title }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        primary: '#3b82f6',
                        dark: '#0f172a',
                    }
                }
            }
        }
    </script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
</head>
<body class="bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 min-h-screen flex items-center justify-center p-4">
    <div class="max-w-md w-full">
        <div class="bg-slate-800/50 backdrop-blur-xl rounded-2xl shadow-2xl border border-slate-700/50 p-8">
            <div class="text-center mb-8">
                <img src="/logo.jpg" alt="EliteHost Logo" class="w-16 h-16 mx-auto mb-4 rounded-xl">
                <h1 class="text-3xl font-bold text-white mb-2">EliteHost</h1>
                <p class="text-slate-400 text-sm">{{ subtitle }}</p>
            </div>
            
            {% if error %}
            <div class="bg-red-500/10 border border-red-500/50 rounded-lg p-3 mb-4 text-red-400 text-sm">
                <i class="fas fa-exclamation-circle mr-2"></i>{{ error }}
            </div>
            {% endif %}
            
            {% if success %}
            <div class="bg-green-500/10 border border-green-500/50 rounded-lg p-3 mb-4 text-green-400 text-sm">
                <i class="fas fa-check-circle mr-2"></i>{{ success }}
            </div>
            {% endif %}
            
            <div class="bg-blue-500/10 border border-blue-500/50 rounded-lg p-3 mb-6 text-blue-400 text-xs">
                <i class="fas fa-shield-alt mr-2"></i>
                <strong>Secure Authentication:</strong> One account per device
            </div>
            
            <form method="POST" action="{{ action }}" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium text-slate-300 mb-2">
                        <i class="fas fa-envelope mr-2"></i>Email Address
                    </label>
                    <input type="email" name="email" required
                        class="w-full px-4 py-3 bg-slate-900/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition">
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-slate-300 mb-2">
                        <i class="fas fa-lock mr-2"></i>Password
                    </label>
                    <input type="password" name="password" required
                        class="w-full px-4 py-3 bg-slate-900/50 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition">
                </div>
                
                <button type="submit" 
                    class="w-full bg-gradient-to-r from-blue-600 to-blue-700 text-white font-bold py-3 px-4 rounded-lg hover:from-blue-700 hover:to-blue-800 transition transform hover:scale-105 active:scale-95">
                    <i class="fas fa-{{ icon }} mr-2"></i>{{ button_text }}
                </button>
            </form>
            
            <div class="text-center mt-6 text-sm text-slate-400">
                {{ toggle_text }} <a href="{{ toggle_link }}" class="text-blue-400 hover:text-blue-300 font-semibold">{{ toggle_action }}</a>
            </div>
        </div>
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        primary: '#3b82f6',
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-slate-950 text-white" x-data="dashboardApp()">
    <!-- Sidebar -->
    <div class="fixed inset-y-0 left-0 w-64 bg-slate-900 border-r border-slate-800 z-50 transform transition-transform duration-300"
         :class="sidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'">
        <div class="p-6">
            <div class="flex items-center gap-3 mb-8">
                <img src="/logo.jpg" alt="Logo" class="w-10 h-10 rounded-lg">
                <span class="text-xl font-bold">EliteHost</span>
            </div>
            
            <nav class="space-y-1">
                <button @click="sidebarOpen = false" 
                        class="md:hidden w-full flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-slate-800 cursor-pointer transition text-slate-400 hover:text-white mb-2 group">
                    <i class="fas fa-times w-5"></i>
                    <span>Close Menu</span>
                </button>
                <div class="h-px bg-slate-800 mx-4 mb-2 md:hidden"></div>
                
                <a @click="currentPage = 'overview'; sidebarOpen = false" :class="currentPage === 'overview' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-th-large w-5"></i>
                    <span>Overview</span>
                </a>
                <a @click="currentPage = 'deployments'; sidebarOpen = false" :class="currentPage === 'deployments' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-rocket w-5"></i>
                    <span>Deployments</span>
                </a>
                <a @click="currentPage = 'new-deploy'; sidebarOpen = false" :class="currentPage === 'new-deploy' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-plus-circle w-5"></i>
                    <span>New Deploy</span>
                </a>
                <a @click="currentPage = 'buy-credits'; sidebarOpen = false" :class="currentPage === 'buy-credits' ? 'bg-blue-600' : 'hover:bg-slate-800'"
                   class="flex items-center gap-3 px-4 py-3 rounded-lg cursor-pointer transition">
                    <i class="fas fa-gem w-5"></i>
                    <span>Buy Credits</span>
                </a>
                {% if is_admin %}
                <a href="/admin" class="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-slate-800 cursor-pointer transition">
                    <i class="fas fa-crown w-5 text-yellow-500"></i>
                    <span>Admin Panel</span>
                </a>
                {% endif %}
            </nav>
        </div>
        
        <div class="absolute bottom-0 left-0 right-0 p-6 border-t border-slate-800">
            <div class="bg-gradient-to-r from-blue-600 to-blue-700 rounded-lg p-4 mb-4">
                <div class="flex items-center justify-between mb-2">
                    <span class="text-sm font-semibold">Credits</span>
                    <i class="fas fa-gem"></i>
                </div>
                <div class="text-2xl font-bold" x-text="credits"></div>
            </div>
            <button @click="logout()" class="w-full bg-red-600/20 hover:bg-red-600/30 text-red-400 px-4 py-2 rounded-lg transition">
                <i class="fas fa-sign-out-alt mr-2"></i>Logout
            </button>
        </div>
    </div>
    
    <!-- Mobile Header -->
    <div class="md:hidden fixed top-0 left-0 right-0 bg-slate-900 border-b border-slate-800 p-4 z-40 flex items-center justify-between">
        <button @click="sidebarOpen = !sidebarOpen" class="text-white">
            <i class="fas fa-bars text-xl"></i>
        </button>
        <img src="/logo.jpg" alt="Logo" class="w-8 h-8 rounded-lg">
        <div class="w-6"></div>
    </div>
    
    <!-- Main Content -->
    <div class="md:ml-64 min-h-screen">
        <div class="p-4 md:p-8 mt-16 md:mt-0">
            <!-- Overview Page -->
            <div x-show="currentPage === 'overview'" x-transition>
                <h1 class="text-3xl font-bold mb-8">Dashboard Overview</h1>
                
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-rocket text-blue-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1" x-text="stats.total"></div>
                        <div class="text-slate-400 text-sm">Total Deployments</div>
                    </div>
                    
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-check-circle text-green-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1 text-green-400" x-text="stats.running"></div>
                        <div class="text-slate-400 text-sm">Active Now</div>
                    </div>
                    
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-gem text-blue-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1 text-blue-400" x-text="credits"></div>
                        <div class="text-slate-400 text-sm">Available Credits</div>
                    </div>
                    
                    <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-cyan-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-robot text-cyan-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1">AI</div>
                        <div class="text-slate-400 text-sm">Auto Deploy</div>
                    </div>
                </div>
                
                <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                    <h2 class="text-xl font-bold mb-4">Recent Deployments</h2>
                    <div class="space-y-3" x-show="deployments.length > 0">
                        <template x-for="deploy in deployments.slice(0, 5)" :key="deploy.id">
                            <div class="bg-slate-800/50 rounded-lg p-4 flex items-center justify-between">
                                <div class="flex items-center gap-4">
                                    <div class="w-10 h-10 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                        <i class="fas fa-rocket text-blue-400"></i>
                                    </div>
                                    <div>
                                        <div class="font-semibold" x-text="deploy.name"></div>
                                        <div class="text-sm text-slate-400">
                                            <span x-text="deploy.id"></span> • Port <span x-text="deploy.port"></span>
                                        </div>
                                    </div>
                                </div>
                                <span class="px-3 py-1 rounded-full text-xs font-semibold"
                                      :class="{
                                          'bg-green-500/20 text-green-400': deploy.status === 'running',
                                          'bg-yellow-500/20 text-yellow-400': deploy.status === 'pending',
                                          'bg-red-500/20 text-red-400': deploy.status === 'stopped'
                                      }"
                                      x-text="deploy.status"></span>
                            </div>
                        </template>
                    </div>
                    <div x-show="deployments.length === 0" class="text-center py-12 text-slate-400">
                        <i class="fas fa-inbox text-5xl mb-4 opacity-20"></i>
                        <p>No deployments yet</p>
                    </div>
                </div>
            </div>
            
            <!-- Deployments Page -->
            <div x-show="currentPage === 'deployments'" x-transition>
                <div class="flex items-center justify-between mb-8">
                    <h1 class="text-3xl font-bold">All Deployments</h1>
                    <button @click="loadDeployments()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition">
                        <i class="fas fa-sync-alt mr-2"></i>Refresh
                    </button>
                </div>
                
                <div class="grid gap-4">
                    <template x-for="deploy in deployments" :key="deploy.id">
                        <div class="bg-slate-900 rounded-xl border border-slate-800 p-6">
                            <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
                                <div>
                                    <h3 class="text-xl font-bold mb-2" x-text="deploy.name"></h3>
                                    <div class="flex flex-wrap gap-3 text-sm text-slate-400">
                                        <span><i class="fas fa-fingerprint mr-1"></i><span x-text="deploy.id"></span></span>
                                        <span><i class="fas fa-network-wired mr-1"></i>Port <span x-text="deploy.port"></span></span>
                                        <span><i class="fas fa-code-branch mr-1"></i><span x-text="deploy.type"></span></span>
                                    </div>
                                </div>
                                <span class="px-4 py-2 rounded-lg text-sm font-semibold w-fit"
                                      :class="{
                                          'bg-green-500/20 text-green-400': deploy.status === 'running',
                                          'bg-yellow-500/20 text-yellow-400': deploy.status === 'pending',
                                          'bg-red-500/20 text-red-400': deploy.status === 'stopped'
                                      }"
                                      x-text="deploy.status.toUpperCase()"></span>
                            </div>
                            
                            <div class="flex flex-wrap gap-2">
                                <button @click="viewDeployment(deploy.id)" 
                                    class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm transition">
                                    <i class="fas fa-eye mr-2"></i>View Details
                                </button>
                                <button @click="viewLogs(deploy.id)" 
                                    class="bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded-lg text-sm transition">
                                    <i class="fas fa-terminal mr-2"></i>Logs
                                </button>
                                <button @click="stopDeploy(deploy.id)" 
                                    class="bg-orange-600 hover:bg-orange-700 px-4 py-2 rounded-lg text-sm transition">
                                    <i class="fas fa-stop mr-2"></i>Stop
                                </button>
                                <button @click="deleteDeploy(deploy.id)" 
                                    class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg text-sm transition">
                                    <i class="fas fa-trash mr-2"></i>Delete
                                </button>
                            </div>
                        </div>
                    </template>
                </div>
                
                <div x-show="deployments.length === 0" class="bg-slate-900 rounded-xl border border-slate-800 p-12 text-center">
                    <i class="fas fa-rocket text-6xl text-slate-700 mb-4"></i>
                    <h3 class="text-xl font-bold mb-2">No Deployments Yet</h3>
                    <p class="text-slate-400 mb-4">Get started by deploying your first app</p>
                    <button @click="currentPage = 'new-deploy'" class="bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-lg transition">
                        <i class="fas fa-plus mr-2"></i>Create Deployment
                    </button>
                </div>
            </div>
            
            <!-- New Deploy Page -->
            <div x-show="currentPage === 'new-deploy'" x-transition>
                <h1 class="text-3xl font-bold mb-8">New Deployment</h1>
                
                <div class="grid md:grid-cols-2 gap-6">
                    <!-- File Upload -->
                    <div class="bg-slate-900 rounded-xl border border-slate-800 p-6">
                        <div class="flex items-center gap-3 mb-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-cloud-upload-alt text-blue-400 text-xl"></i>
                            </div>
                            <div>
                                <h3 class="text-lg font-bold">Upload Files</h3>
                                <p class="text-sm text-slate-400">Deploy .py, .js, or .zip files</p>
                            </div>
                        </div>
                        
                        <div class="border-2 border-dashed border-slate-700 rounded-xl p-8 text-center mb-4 cursor-pointer hover:border-blue-500 transition"
                             onclick="document.getElementById('fileInput').click()">
                            <i class="fas fa-file-upload text-4xl text-slate-600 mb-3"></i>
                            <p class="text-slate-400 mb-2">Click to upload or drag and drop</p>
                            <p class="text-xs text-slate-500">Python, JavaScript, ZIP (max 100MB)</p>
                            <input type="file" id="fileInput" class="hidden" accept=".py,.js,.zip" @change="uploadFile($event)">
                        </div>
                        
                        <div class="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3 text-sm text-blue-400">
                            <i class="fas fa-info-circle mr-2"></i>Cost: 0.5 credits • AI auto-installs dependencies
                        </div>
                    </div>
                    
                    <!-- GitHub Deploy -->
                    <div class="bg-slate-900 rounded-xl border border-slate-800 p-6">
                        <div class="flex items-center gap-3 mb-4">
                            <div class="w-12 h-12 bg-cyan-500/20 rounded-lg flex items-center justify-center">
                                <i class="fab fa-github text-cyan-400 text-xl"></i>
                            </div>
                            <div>
                                <h3 class="text-lg font-bold">Deploy from GitHub</h3>
                                <p class="text-sm text-slate-400">Import and deploy repositories</p>
                            </div>
                        </div>
                        
                        <form @submit.prevent="deployGithub()" class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-slate-300 mb-2">Repository URL</label>
                                <input type="url" x-model="githubForm.url" required
                                    class="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    placeholder="https://github.com/user/repo">
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium text-slate-300 mb-2">Branch</label>
                                <input type="text" x-model="githubForm.branch"
                                    class="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    placeholder="main">
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium text-slate-300 mb-2">Build Command (Optional)</label>
                                <input type="text" x-model="githubForm.buildCmd"
                                    class="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    placeholder="npm install">
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium text-slate-300 mb-2">Start Command (Optional)</label>
                                <input type="text" x-model="githubForm.startCmd"
                                    class="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    placeholder="npm start">
                            </div>
                            
                            <button type="submit" class="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 px-4 py-3 rounded-lg font-semibold transition">
                                <i class="fab fa-github mr-2"></i>Deploy from GitHub (1.0 credit)
                            </button>
                        </form>
                        
                        <div class="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3 text-sm text-blue-400 mt-4">
                            <i class="fas fa-robot mr-2"></i>AI auto-detects language and installs dependencies
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Buy Credits Page -->
            <div x-show="currentPage === 'buy-credits'" x-transition>
                <h1 class="text-3xl font-bold mb-8">Buy Credits</h1>
                
                <div class="grid md:grid-cols-3 gap-6 mb-8">
                    <!-- 10 Credits Pack -->
                    <div class="bg-slate-900 rounded-xl border-2 border-slate-800 hover:border-blue-500 p-6 transition cursor-pointer"
                         @click="selectPackage('10_credits')">
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-gem text-blue-400 text-xl"></i>
                            </div>
                            <span class="bg-blue-500/20 text-blue-400 px-3 py-1 rounded-full text-xs font-semibold">Starter</span>
                        </div>
                        <div class="text-3xl font-bold mb-2">10 Credits</div>
                        <div class="text-2xl text-blue-400 font-bold mb-4">₹50</div>
                        <ul class="text-sm text-slate-400 space-y-2 mb-6">
                            <li><i class="fas fa-check text-green-400 mr-2"></i>20 File Deployments</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>10 GitHub Deployments</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>20 Backups</li>
                        </ul>
                        <button class="w-full bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg transition">
                            <i class="fas fa-shopping-cart mr-2"></i>Select Package
                        </button>
                    </div>
                    
                    <!-- 99 Credits Pack -->
                    <div class="bg-slate-900 rounded-xl border-2 border-blue-500 p-6 relative">
                        <div class="absolute -top-3 left-1/2 transform -translate-x-1/2 bg-blue-500 text-white px-4 py-1 rounded-full text-xs font-bold">
                            BEST VALUE
                        </div>
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-crown text-yellow-400 text-xl"></i>
                            </div>
                            <span class="bg-blue-500 text-white px-3 py-1 rounded-full text-xs font-semibold">Pro</span>
                        </div>
                        <div class="text-3xl font-bold mb-2">99 Credits</div>
                        <div class="text-2xl text-blue-400 font-bold mb-1">₹399</div>
                        <div class="text-xs text-green-400 mb-4"><del class="text-slate-500">₹495</del> Save ₹96</div>
                        <ul class="text-sm text-slate-400 space-y-2 mb-6">
                            <li><i class="fas fa-check text-green-400 mr-2"></i>198 File Deployments</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>99 GitHub Deployments</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>198 Backups</li>
                            <li><i class="fas fa-star text-yellow-400 mr-2"></i>Priority Support</li>
                        </ul>
                        <button @click="selectPackage('99_credits')" 
                                class="w-full bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 px-4 py-2 rounded-lg transition font-semibold">
                            <i class="fas fa-shopping-cart mr-2"></i>Select Package
                        </button>
                    </div>
                    
                    <!-- Custom Amount -->
                    <div class="bg-slate-900 rounded-xl border-2 border-slate-800 hover:border-blue-500 p-6 transition">
                        <div class="flex items-center justify-between mb-4">
                            <div class="w-12 h-12 bg-cyan-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-infinity text-cyan-400 text-xl"></i>
                            </div>
                            <span class="bg-cyan-500/20 text-cyan-400 px-3 py-1 rounded-full text-xs font-semibold">Custom</span>
                        </div>
                        <div class="text-3xl font-bold mb-2">Custom</div>
                        <div class="text-2xl text-cyan-400 font-bold mb-4">Your Choice</div>
                        <input type="number" x-model="customAmount" placeholder="Enter amount" min="1"
                               class="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white mb-4">
                        <p class="text-sm text-slate-400 mb-6">
                            <i class="fas fa-info-circle mr-2"></i>Need help? <a href="{{ telegram_link }}" target="_blank" class="text-blue-400 hover:underline">Contact {{ username }}</a>
                        </p>
                        <button @click="selectCustomPackage()" 
                                class="w-full bg-cyan-600 hover:bg-cyan-700 px-4 py-2 rounded-lg transition">
                            <i class="fas fa-comments mr-2"></i>Contact for Custom
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Payment Modal -->
    <div x-show="modal === 'payment'" x-cloak class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" @click.self="modal = null">
        <div class="bg-slate-900 rounded-2xl border border-slate-800 max-w-md w-full p-6">
            <div class="text-center mb-6">
                <h2 class="text-2xl font-bold mb-2">Complete Payment</h2>
                <p class="text-slate-400 text-sm">Scan QR code and submit proof</p>
            </div>
            
            <div class="bg-slate-800/50 rounded-lg p-4 mb-6">
                <div class="flex items-center justify-between mb-4">
                    <span class="text-slate-400">Package:</span>
                    <span class="font-semibold" x-text="paymentData.package"></span>
                </div>
                <div class="flex items-center justify-between mb-4">
                    <span class="text-slate-400">Credits:</span>
                    <span class="font-semibold text-blue-400" x-text="paymentData.credits"></span>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-slate-400">Amount:</span>
                    <span class="text-2xl font-bold text-green-400">₹<span x-text="paymentData.price"></span></span>
                </div>
            </div>
            
            <div class="bg-white rounded-lg p-4 mb-6 text-center">
                <img src="/qr.jpg" alt="Payment QR Code" class="w-64 h-64 mx-auto">
                <p class="text-slate-900 font-semibold mt-2">Scan to Pay ₹<span x-text="paymentData.price"></span></p>
            </div>
            
            <div class="mb-4">
                <label class="block text-sm font-medium text-slate-300 mb-2">Upload Screenshot</label>
                <input type="file" accept="image/*" @change="uploadScreenshot($event)" 
                       class="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white">
            </div>
            
            <div class="mb-6">
                <label class="block text-sm font-medium text-slate-300 mb-2">Transaction ID</label>
                <input type="text" x-model="paymentData.transactionId" placeholder="Enter transaction/UTR ID" required
                       class="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-lg text-white">
            </div>
            
            <div class="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 text-sm text-yellow-400 mb-6">
                <i class="fas fa-clock mr-2"></i>
                <span>Time remaining: </span>
                <span class="font-bold" x-text="formatTime(timeRemaining)"></span>
            </div>
            
            <div class="flex gap-3">
                <button @click="modal = null" class="flex-1 bg-slate-700 hover:bg-slate-600 px-4 py-3 rounded-lg transition">
                    Cancel
                </button>
                <button @click="submitPayment()" class="flex-1 bg-blue-600 hover:bg-blue-700 px-4 py-3 rounded-lg transition font-semibold">
                    <i class="fas fa-check mr-2"></i>Submit
                </button>
            </div>
        </div>
    </div>
    
    <!-- Deployment Details Modal -->
    <div x-show="modal === 'details'" x-cloak class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4" @click.self="modal = null">
        <div class="bg-slate-900 rounded-2xl border border-slate-800 max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div class="p-6 border-b border-slate-800 flex items-center justify-between sticky top-0 bg-slate-900 z-10">
                <h2 class="text-2xl font-bold">Deployment Details</h2>
                <button @click="modal = null" class="text-slate-400 hover:text-white">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
            
            <div class="p-6" x-show="selectedDeploy">
                <div class="flex gap-2 mb-6 border-b border-slate-800">
                    <button @click="detailsTab = 'info'" 
                        :class="detailsTab === 'info' ? 'border-blue-500 text-white' : 'border-transparent text-slate-400'"
                        class="px-4 py-2 border-b-2 transition">Info</button>
                    <button @click="detailsTab = 'env'" 
                        :class="detailsTab === 'env' ? 'border-blue-500 text-white' : 'border-transparent text-slate-400'"
                        class="px-4 py-2 border-b-2 transition">Environment</button>
                    <button @click="detailsTab = 'files'" 
                        :class="detailsTab === 'files' ? 'border-blue-500 text-white' : 'border-transparent text-slate-400'"
                        class="px-4 py-2 border-b-2 transition">Files</button>
                    <button @click="detailsTab = 'backup'" 
                        :class="detailsTab === 'backup' ? 'border-blue-500 text-white' : 'border-transparent text-slate-400'"
                        class="px-4 py-2 border-b-2 transition">Backup</button>
                    <button @click="detailsTab = 'console'"
                        :class="detailsTab === 'console' ? 'border-blue-500 text-white' : 'border-transparent text-slate-400'"
                        class="px-4 py-2 border-b-2 transition">Console</button>
                </div>
                
                <div x-show="detailsTab === 'info'" class="space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div class="bg-slate-800/50 rounded-lg p-4">
                            <div class="text-sm text-slate-400 mb-1">Deployment ID</div>
                            <div class="font-mono" x-text="selectedDeploy.id"></div>
                        </div>
                        <div class="bg-slate-800/50 rounded-lg p-4">
                            <div class="text-sm text-slate-400 mb-1">Port</div>
                            <div class="font-mono" x-text="selectedDeploy.port"></div>
                        </div>
                        <div class="bg-slate-800/50 rounded-lg p-4">
                            <div class="text-sm text-slate-400 mb-1">Status</div>
                            <div class="font-mono" x-text="selectedDeploy.status"></div>
                        </div>
                        <div class="bg-slate-800/50 rounded-lg p-4">
                            <div class="text-sm text-slate-400 mb-1">Type</div>
                            <div class="font-mono" x-text="selectedDeploy.type"></div>
                        </div>
                    </div>
                    
                    <div x-show="selectedDeploy.dependencies && selectedDeploy.dependencies.length > 0">
                        <div class="text-sm font-semibold text-slate-300 mb-2">AI Installed Dependencies</div>
                        <div class="bg-slate-800/50 rounded-lg p-4">
                            <template x-for="dep in selectedDeploy.dependencies" :key="dep">
                                <span class="inline-block bg-blue-500/20 text-blue-300 px-3 py-1 rounded-full text-xs mr-2 mb-2" x-text="dep"></span>
                            </template>
                        </div>
                    </div>
                </div>
                
                <div x-show="detailsTab === 'env'">
                    <div class="mb-4">
                        <div class="flex gap-2 mb-4">
                            <input type="text" x-model="newEnv.key" placeholder="KEY" 
                                class="flex-1 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white">
                            <input type="text" x-model="newEnv.value" placeholder="value" 
                                class="flex-1 px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white">
                            <button @click="addEnvVar()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg">
                                <i class="fas fa-plus"></i>
                            </button>
                        </div>
                    </div>
                    
                    <div class="space-y-2">
                        <template x-for="(value, key) in selectedDeploy.env_vars" :key="key">
                            <div class="bg-slate-800/50 rounded-lg p-3 flex items-center justify-between">
                                <div class="font-mono text-sm">
                                    <span class="text-blue-400" x-text="key"></span> = <span x-text="value"></span>
                                </div>
                                <button @click="deleteEnvVar(key)" class="text-red-400 hover:text-red-300">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </template>
                        <div x-show="!selectedDeploy.env_vars || Object.keys(selectedDeploy.env_vars).length === 0" 
                            class="text-center py-8 text-slate-400">
                            No environment variables set
                        </div>
                    </div>
                </div>
                
                <div x-show="detailsTab === 'files'">
                    <button @click="loadFiles()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg mb-4">
                        <i class="fas fa-sync mr-2"></i>Refresh Files
                    </button>
                    
                    <div class="space-y-2">
                        <template x-for="file in deployFiles" :key="file.path">
                            <div class="bg-slate-800/50 rounded-lg p-3 flex items-center justify-between">
                                <div class="flex items-center gap-3">
                                    <i class="fas fa-file-code text-slate-400"></i>
                                    <div>
                                        <div class="font-mono text-sm" x-text="file.path"></div>
                                        <div class="text-xs text-slate-500" x-text="formatBytes(file.size)"></div>
                                    </div>
                                </div>
                                <div class="text-xs text-slate-400" x-text="formatDate(file.modified)"></div>
                            </div>
                        </template>
                        <div x-show="deployFiles.length === 0" class="text-center py-8 text-slate-400">
                            No files found
                        </div>
                    </div>
                </div>
                
                <div x-show="detailsTab === 'backup'">
                    <div class="text-center py-8">
                        <i class="fas fa-archive text-6xl text-slate-700 mb-4"></i>
                        <h3 class="text-xl font-bold mb-2">Create Backup</h3>
                        <p class="text-slate-400 mb-6">Download a complete snapshot of this deployment</p>
                        <button @click="createBackup()" class="bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-lg">
                            <i class="fas fa-download mr-2"></i>Create & Download Backup (0.5 credits)
                        </button>
                    </div>
                </div>
                
                <div x-show="detailsTab === 'console'">
                    <div class="bg-slate-950 rounded-lg p-4 font-mono text-sm text-green-400 h-96 overflow-y-auto whitespace-pre-wrap" 
                         x-ref="console" x-text="consoleLogs"></div>
                    <button @click="refreshLogs()" class="mt-4 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg">
                        <i class="fas fa-sync mr-2"></i>Refresh Logs
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function dashboardApp() {
            return {
                sidebarOpen: false,
                currentPage: 'overview',
                modal: null,
                detailsTab: 'info',
                credits: {{ credits }},
                deployments: [],
                stats: {
                    total: 0,
                    running: 0
                },
                selectedDeploy: null,
                deployFiles: [],
                consoleLogs: '',
                githubForm: {
                    url: '',
                    branch: 'main',
                    buildCmd: '',
                    startCmd: ''
                },
                newEnv: {
                    key: '',
                    value: ''
                },
                customAmount: '',
                paymentData: {
                    id: '',
                    package: '',
                    credits: 0,
                    price: 0,
                    screenshot: null,
                    transactionId: ''
                },
                timeRemaining: 300,
                timerInterval: null,
                
                init() {
                    this.loadDeployments();
                    setInterval(() => this.loadDeployments(), 10000);
                    setInterval(() => this.updateCredits(), 15000);
                },
                
                async loadDeployments() {
                    const res = await fetch('/api/deployments');
                    const data = await res.json();
                    if (data.success) {
                        this.deployments = data.deployments;
                        this.stats.total = data.deployments.length;
                        this.stats.running = data.deployments.filter(d => d.status === 'running').length;
                    }
                },
                
                async updateCredits() {
                    const res = await fetch('/api/credits');
                    const data = await res.json();
                    if (data.success) {
                        this.credits = data.credits === Infinity ? '∞' : data.credits.toFixed(1);
                    }
                },
                
                async uploadFile(event) {
                    const file = event.target.files[0];
                    if (!file) return;
                    
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    this.showNotification('🤖 Uploading and deploying...', 'info');
                    
                    const res = await fetch('/api/deploy/upload', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        this.showNotification('✅ Deployment successful!', 'success');
                        this.loadDeployments();
                        this.updateCredits();
                        this.currentPage = 'deployments';
                    } else {
                        this.showNotification('❌ ' + data.error, 'error');
                    }
                },
                
                async deployGithub() {
                    if (!this.githubForm.url) return;
                    
                    this.showNotification('🤖 Cloning and deploying...', 'info');
                    
                    const res = await fetch('/api/deploy/github', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            url: this.githubForm.url,
                            branch: this.githubForm.branch || 'main',
                            build_command: this.githubForm.buildCmd,
                            start_command: this.githubForm.startCmd
                        })
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        this.showNotification('✅ GitHub deployment successful!', 'success');
                        this.loadDeployments();
                        this.updateCredits();
                        this.currentPage = 'deployments';
                        this.githubForm = { url: '', branch: 'main', buildCmd: '', startCmd: '' };
                    } else {
                        this.showNotification('❌ ' + data.error, 'error');
                    }
                },
                
                async selectPackage(packageType) {
                    const res = await fetch('/api/payment/create', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ package_type: packageType })
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        this.paymentData = data.payment;
                        this.paymentData.package = packageType.replace('_', ' ').toUpperCase();
                        this.modal = 'payment';
                        this.startTimer();
                    } else {
                        this.showNotification('❌ ' + data.error, 'error');
                    }
                },
                
                async selectCustomPackage() {
                    if (!this.customAmount || this.customAmount <= 0) {
                        this.showNotification('❌ Enter valid amount', 'error');
                        return;
}
                    
                    const res = await fetch('/api/payment/create', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({ 
                            package_type: 'custom',
                            custom_amount: parseInt(this.customAmount)
                        })
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        this.paymentData = data.payment;
                        this.paymentData.package = 'CUSTOM';
                        this.modal = 'payment';
                        this.startTimer();
                    } else {
                        this.showNotification('❌ ' + data.error, 'error');
                    }
                },
                
                uploadScreenshot(event) {
                    const file = event.target.files[0];
                    if (!file) return;
                    
                    const reader = new FileReader();
                    reader.onload = (e) => {
                        this.paymentData.screenshot = e.target.result;
                    };
                    reader.readAsDataURL(file);
                },
                
                async submitPayment() {
                    if (!this.paymentData.screenshot) {
                        this.showNotification('❌ Upload screenshot', 'error');
                        return;
                    }
                    
                    if (!this.paymentData.transactionId) {
                        this.showNotification('❌ Enter transaction ID', 'error');
                        return;
                    }
                    
                    const res = await fetch('/api/payment/submit', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            payment_id: this.paymentData.id,
                            screenshot: this.paymentData.screenshot,
                            transaction_id: this.paymentData.transactionId
                        })
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        this.stopTimer();
                        this.modal = null;
                        this.showNotification('✅ Payment submitted! Waiting for approval...', 'success');
                    } else {
                        this.showNotification('❌ ' + data.error, 'error');
                    }
                },
                
                startTimer() {
                    this.timeRemaining = 300;
                    this.timerInterval = setInterval(() => {
                        this.timeRemaining--;
                        if (this.timeRemaining <= 0) {
                            this.stopTimer();
                            this.modal = null;
                            this.showNotification('❌ Payment expired', 'error');
                        }
                    }, 1000);
                },
                
                stopTimer() {
                    if (this.timerInterval) {
                        clearInterval(this.timerInterval);
                        this.timerInterval = null;
                    }
                },
                
                formatTime(seconds) {
                    const mins = Math.floor(seconds / 60);
                    const secs = seconds % 60;
                    return `${mins}:${secs.toString().padStart(2, '0')}`;
                },
                
                async viewDeployment(id) {
                    this.selectedDeploy = this.deployments.find(d => d.id === id);
                    this.modal = 'details';
                    this.detailsTab = 'info';
                },
                
                async viewLogs(id) {
                    this.selectedDeploy = this.deployments.find(d => d.id === id);
                    this.modal = 'details';
                    this.detailsTab = 'console';
                    this.refreshLogs();
                },
                
                async refreshLogs() {
                    if (!this.selectedDeploy) return;
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/logs`);
                    const data = await res.json();
                    this.consoleLogs = data.logs || 'No logs available';
                    this.$nextTick(() => {
                        if (this.$refs.console) {
                            this.$refs.console.scrollTop = this.$refs.console.scrollHeight;
                        }
                    });
                },
                
                async loadFiles() {
                    if (!this.selectedDeploy) return;
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/files`);
                    const data = await res.json();
                    this.deployFiles = data.files || [];
                },
                
                async addEnvVar() {
                    if (!this.newEnv.key || !this.newEnv.value) return;
                    
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({
                            key: this.newEnv.key,
                            value: this.newEnv.value
                        })
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        this.selectedDeploy.env_vars = data.env_vars;
                        this.newEnv = { key: '', value: '' };
                        this.showNotification('✅ Environment variable added', 'success');
                    }
                },
                
                async deleteEnvVar(key) {
                    if (!confirm(`Delete ${key}?`)) return;
                    
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env/${key}`, {
                        method: 'DELETE'
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        this.selectedDeploy.env_vars = data.env_vars;
                        this.showNotification('✅ Environment variable deleted', 'success');
                    }
                },
                
                async createBackup() {
                    if (!confirm('Create backup for 0.5 credits?')) return;
                    
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/backup`, {
                        method: 'POST'
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        window.location.href = `/api/deployment/${this.selectedDeploy.id}/backup/download`;
                        this.showNotification('✅ Backup created!', 'success');
                        this.updateCredits();
                    } else {
                        this.showNotification('❌ ' + data.error, 'error');
                    }
                },
                
                async stopDeploy(id) {
                    if (!confirm('Stop this deployment?')) return;
                    
                    const res = await fetch(`/api/deployment/${id}/stop`, { method: 'POST' });
                    const data = await res.json();
                    
                    this.showNotification(data.success ? '✅ Stopped' : '❌ Failed', data.success ? 'success' : 'error');
                    this.loadDeployments();
                },
                
                async deleteDeploy(id) {
                    if (!confirm('Delete this deployment permanently?')) return;
                    
                    const res = await fetch(`/api/deployment/${id}`, { method: 'DELETE' });
                    const data = await res.json();
                    
                    this.showNotification(data.success ? '✅ Deleted' : '❌ Failed', data.success ? 'success' : 'error');
                    this.loadDeployments();
                    this.modal = null;
                },
                
                logout() {
                    if (confirm('Logout from EliteHost?')) {
                        window.location.href = '/logout';
                    }
                },
                
                showNotification(message, type) {
                    alert(message);
                },
                
                formatBytes(bytes) {
                    if (bytes === 0) return '0 B';
                    const k = 1024;
                    const sizes = ['B', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
                },
                
                formatDate(date) {
                    return new Date(date).toLocaleString();
                }
            }
        }
    </script>
    <style>
        [x-cloak] { display: none !important; }
    </style>
</body>
</html>
"""

ADMIN_PANEL_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost - Admin Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
</head>
<body class="bg-slate-950 text-white" x-data="adminApp()">
    <div class="min-h-screen">
        <!-- Header -->
        <div class="bg-gradient-to-r from-blue-600 to-cyan-600 p-6 shadow-2xl">
            <div class="max-w-7xl mx-auto">
                <div class="flex items-center justify-between">
                    <div class="flex items-center gap-4">
                        <img src="/logo.jpg" alt="Logo" class="w-12 h-12 rounded-xl">
                        <div>
                            <h1 class="text-3xl font-bold mb-1">
                                <i class="fas fa-crown mr-2"></i>Admin Control Panel
                            </h1>
                            <p class="text-blue-100">System Management & Monitoring</p>
                        </div>
                    </div>
                    <div class="flex gap-3">
                        <a href="/dashboard" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-lg transition">
                            <i class="fas fa-arrow-left mr-2"></i>Dashboard
                        </a>
                        <button @click="location.reload()" class="bg-white/20 hover:bg-white/30 px-4 py-2 rounded-lg transition">
                            <i class="fas fa-sync mr-2"></i>Refresh
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="max-w-7xl mx-auto p-6">
            <!-- Stats Grid -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                            <i class="fas fa-users text-blue-400 text-xl"></i>
                        </div>
                    </div>
                    <div class="text-3xl font-bold mb-1">{{ stats.total_users }}</div>
                    <div class="text-slate-400 text-sm">Total Users</div>
                </div>
                
                <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                            <i class="fas fa-rocket text-green-400 text-xl"></i>
                        </div>
                    </div>
                    <div class="text-3xl font-bold mb-1">{{ stats.total_deployments }}</div>
                    <div class="text-slate-400 text-sm">Deployments</div>
                </div>
                
                <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-cyan-500/20 rounded-lg flex items-center justify-center">
                            <i class="fas fa-server text-cyan-400 text-xl"></i>
                        </div>
                    </div>
                    <div class="text-3xl font-bold mb-1">{{ stats.active_processes }}</div>
                    <div class="text-slate-400 text-sm">Active Now</div>
                </div>
                
                <div class="bg-slate-900 rounded-xl p-6 border border-slate-800">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                            <i class="fas fa-dollar-sign text-yellow-400 text-xl"></i>
                        </div>
                    </div>
                    <div class="text-3xl font-bold mb-1">{{ stats.pending_payments }}</div>
                    <div class="text-slate-400 text-sm">Pending Payments</div>
                </div>
            </div>
            
            <!-- System Metrics -->
            <div class="bg-slate-900 rounded-xl p-6 border border-slate-800 mb-8">
                <h2 class="text-xl font-bold mb-4">System Resources</h2>
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div>
                        <div class="flex items-center justify-between mb-2">
                            <span class="text-sm text-slate-400">CPU Usage</span>
                            <span class="text-sm font-semibold" x-text="metrics.cpu + '%'"></span>
                        </div>
                        <div class="w-full bg-slate-800 rounded-full h-2">
                            <div class="bg-blue-500 h-2 rounded-full transition-all" :style="`width: ${metrics.cpu}%`"></div>
                        </div>
                    </div>
                    
                    <div>
                        <div class="flex items-center justify-between mb-2">
                            <span class="text-sm text-slate-400">Memory</span>
                            <span class="text-sm font-semibold" x-text="metrics.memory_percent + '%'"></span>
                        </div>
                        <div class="w-full bg-slate-800 rounded-full h-2">
                            <div class="bg-green-500 h-2 rounded-full transition-all" :style="`width: ${metrics.memory_percent}%`"></div>
                        </div>
                    </div>
                    
                    <div>
                        <div class="flex items-center justify-between mb-2">
                            <span class="text-sm text-slate-400">Disk</span>
                            <span class="text-sm font-semibold" x-text="metrics.disk_percent + '%'"></span>
                        </div>
                        <div class="w-full bg-slate-800 rounded-full h-2">
                            <div class="bg-cyan-500 h-2 rounded-full transition-all" :style="`width: ${metrics.disk_percent}%`"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Users Table -->
            <div class="bg-slate-900 rounded-xl border border-slate-800 mb-8">
                <div class="p-6 border-b border-slate-800">
                    <h2 class="text-xl font-bold">All Users</h2>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-slate-800/50">
                            <tr>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Email</th>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Credits</th>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Deployments</th>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Joined</th>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Status</th>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for user in users %}
                            <tr class="border-b border-slate-800 hover:bg-slate-800/30">
                                <td class="p-4 text-sm">{{ user.email }}</td>
                                <td class="p-4 text-sm font-mono">{{ user.credits }}</td>
                                <td class="p-4 text-sm">{{ user.deployments|length }}</td>
                                <td class="p-4 text-sm text-slate-400">{{ user.created_at[:10] }}</td>
                                <td class="p-4">
                                    {% if user.is_banned %}
                                    <span class="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-xs font-semibold">Banned</span>
                                    {% else %}
                                    <span class="px-3 py-1 bg-green-500/20 text-green-400 rounded-full text-xs font-semibold">Active</span>
                                    {% endif %}
                                </td>
                                <td class="p-4">
                                    <div class="flex gap-2">
                                        <button onclick="addCreditsPrompt('{{ user.id }}')" 
                                            class="bg-green-600 hover:bg-green-700 px-3 py-1 rounded text-xs transition">
                                            <i class="fas fa-plus mr-1"></i>Credits
                                        </button>
                                        {% if not user.is_banned %}
                                        <button onclick="banUser('{{ user.id }}')" 
                                            class="bg-red-600 hover:bg-red-700 px-3 py-1 rounded text-xs transition">
                                            <i class="fas fa-ban mr-1"></i>Ban
                                        </button>
                                        {% else %}
                                        <button onclick="unbanUser('{{ user.id }}')" 
                                            class="bg-green-600 hover:bg-green-700 px-3 py-1 rounded text-xs transition">
                                            <i class="fas fa-check mr-1"></i>Unban
                                        </button>
                                        {% endif %}
                                    </div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <!-- Payments Table -->
            <div class="bg-slate-900 rounded-xl border border-slate-800">
                <div class="p-6 border-b border-slate-800">
                    <h2 class="text-xl font-bold">Payment Requests</h2>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-slate-800/50">
                            <tr>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">User</th>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Amount</th>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Transaction ID</th>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Date</th>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Status</th>
                                <th class="text-left p-4 text-sm font-semibold text-slate-300">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for payment in payments %}
                            <tr class="border-b border-slate-800 hover:bg-slate-800/30">
                                <td class="p-4 text-sm">{{ payment.user_email }}</td>
                                <td class="p-4 text-sm font-mono">{{ payment.credits }} credits (₹{{ payment.price }})</td>
                                <td class="p-4 text-sm font-mono text-blue-400">{{ payment.transaction_id or 'N/A' }}</td>
                                <td class="p-4 text-sm text-slate-400">{{ payment.created_at[:16] }}</td>
                                <td class="p-4">
                                    <span class="px-3 py-1 rounded-full text-xs font-semibold
                                        {% if payment.status == 'approved' %}bg-green-500/20 text-green-400
                                        {% elif payment.status == 'submitted' %}bg-blue-500/20 text-blue-400
                                        {% elif payment.status == 'pending' %}bg-yellow-500/20 text-yellow-400
                                        {% elif payment.status == 'expired' %}bg-gray-500/20 text-gray-400
                                        {% else %}bg-red-500/20 text-red-400{% endif %}">
                                        {{ payment.status }}
                                    </span>
                                </td>
                                <td class="p-4">
                                    {% if payment.status == 'submitted' %}
                                    <div class="flex gap-2">
                                        <button onclick="viewScreenshot('{{ payment.id }}')" 
                                            class="bg-blue-600 hover:bg-blue-700 px-3 py-1 rounded text-xs transition">
                                            <i class="fas fa-image mr-1"></i>View
                                        </button>
                                    </div>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function adminApp() {
            return {
                metrics: {
                    cpu: 0,
                    memory_percent: 0,
                    disk_percent: 0
                },
                
                init() {
                    this.loadMetrics();
                    setInterval(() => this.loadMetrics(), 5000);
                },
                
                async loadMetrics() {
                    const res = await fetch('/api/admin/metrics');
                    const data = await res.json();
                    if (data.success) {
                        this.metrics = data.metrics;
                    }
                }
            }
        }
        
        async function addCreditsPrompt(userId) {
            const amount = prompt('Enter amount of credits to add:');
            if (!amount || isNaN(amount)) return;
            
            const res = await fetch('/api/admin/add-credits', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({user_id: userId, amount: parseFloat(amount)})
            });
            
            const data = await res.json();
            alert(data.success ? '✅ Credits added!' : '❌ ' + data.error);
            location.reload();
        }
        
        async function banUser(userId) {
            if (!confirm('Ban this user?')) return;
            
            const res = await fetch('/api/admin/ban-user', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({user_id: userId, ban: true})
            });
            
            const data = await res.json();
            alert(data.success ? '✅ User banned' : '❌ ' + data.error);
            location.reload();
        }
        
        async function unbanUser(userId) {
            if (!confirm('Unban this user?')) return;
            
            const res = await fetch('/api/admin/ban-user', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({user_id: userId, ban: false})
            });
            
            const data = await res.json();
            alert(data.success ? '✅ User unbanned' : '❌ ' + data.error);
            location.reload();
        }
        
        function viewScreenshot(paymentId) {
            window.open(`/api/payment/${paymentId}/screenshot`, '_blank');
        }
    </script>
</body>
</html>
"""

# ==================== FLASK ROUTES CONTINUED ====================

@app.route('/logo.jpg')
def serve_logo():
    logo_path = os.path.join(STATIC_DIR, 'logo.jpg')
    if os.path.exists(logo_path):
        return send_file(logo_path, mimetype='image/jpeg')
    # Return a placeholder if logo doesn't exist
    return '', 404

@app.route('/qr.jpg')
def serve_qr():
    qr_path = os.path.join(STATIC_DIR, 'qr.jpg')
    if os.path.exists(qr_path):
        return send_file(qr_path, mimetype='image/jpeg')
    return '', 404

@app.route('/api/payment/create', methods=['POST'])
def api_create_payment():
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        package_type = data.get('package_type')
        custom_amount = data.get('custom_amount')
        
        payment_id, payment_data = create_payment_request(user_id, package_type, custom_amount)
        
        if payment_id:
            return jsonify({'success': True, 'payment': payment_data})
        else:
            return jsonify({'success': False, 'error': payment_data})
    
    except Exception as e:
        log_error(str(e), "api_create_payment")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/payment/submit', methods=['POST'])
def api_submit_payment():
    try:
        session_token = request.cookies.get('session_token')
        fingerprint = get_device_fingerprint(request)
        user_id = verify_session(session_token, fingerprint)
        
        if not user_id:
            return jsonify({'success': False, 'error': 'Not authenticated'})
        
        data = request.get_json()
        payment_id = data.get('payment_id')
        screenshot = data.get('screenshot')
        transaction_id = data.get('transaction_id')
        
        success, message = submit_payment_proof(payment_id, screenshot, transaction_id)
        
        return jsonify({'success': success, 'message': message})
    
    except Exception as e:
        log_error(str(e), "api_submit_payment")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/payment/<payment_id>/screenshot')
def api_payment_screenshot(payment_id):
    try:
        if payment_id not in db['payments']:
            return 'Not found', 404
        
        payment = db['payments'][payment_id]
        screenshot_path = payment.get('screenshot')
        
        if screenshot_path and os.path.exists(screenshot_path):
            return send_file(screenshot_path, mimetype='image/jpeg')
        
        return 'Screenshot not found', 404
    
    except Exception as e:
        log_error(str(e), f"api_payment_screenshot {payment_id}")
        return str(e), 500

# Update other routes to pass telegram_link and username
@app.route('/dashboard')
def dashboard():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    
    user_id = verify_session(session_token, fingerprint)
    if not user_id:
        return redirect('/login?error=Please login first')
    
    user = get_user(user_id)
    if not user or user.get('is_banned'):
        return redirect('/login?error=Access denied')
    
    is_admin = str(user_id) == str(OWNER_ID) or str(user_id) == str(ADMIN_ID) or user['email'] == ADMIN_EMAIL
    
    return render_template_string(DASHBOARD_HTML,
        credits=user['credits'] if user['credits'] != float('inf') else '∞',
        is_admin=is_admin,
        telegram_link=TELEGRAM_LINK,
        username=YOUR_USERNAME
    )

@app.route('/admin')
def admin_panel():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    
    user_id = verify_session(session_token, fingerprint)
    if not user_id:
        return redirect('/login?error=Please login first')
    
    user = get_user(user_id)
    is_admin = str(user_id) == str(OWNER_ID) or str(user_id) == str(ADMIN_ID) or user['email'] == ADMIN_EMAIL
    
    if not is_admin:
        return redirect('/dashboard?error=Admin access denied')
    
    stats = {
        'total_users': len(db['users']),
        'total_deployments': len(db['deployments']),
        'active_processes': len(active_processes),
        'pending_payments': len([p for p in db.get('payments', {}).values() if p.get('status') == 'submitted'])
    }
    
    users = []
    for uid, user_data in db['users'].items():
        users.append({
            'id': uid,
            'email': user_data['email'],
            'credits': user_data['credits'],
            'deployments': user_data.get('deployments', []),
            'created_at': user_data['created_at'],
            'is_banned': user_data.get('is_banned', False)
        })
    
    payments = []
    for pid, payment_data in db.get('payments', {}).items():
        puser = get_user(payment_data['user_id'])
        payments.append({
            'id': pid,
            'user_id': payment_data['user_id'],
            'user_email': puser['email'] if puser else 'Unknown',
            'credits': payment_data.get('credits', 0),
            'price': payment_data.get('price', 0),
            'transaction_id': payment_data.get('transaction_id', ''),
            'status': payment_data['status'],
            'created_at': payment_data['created_at']
        })
    
    # Sort by submitted first
    payments.sort(key=lambda x: (x['status'] != 'submitted', x['created_at']), reverse=True)
    
    return render_template_string(ADMIN_PANEL_HTML,
        stats=stats,
        users=users,
        payments=payments
    )

# Rest of Flask routes remain same...
[Previous Flask routes from lines 831-1086 remain exactly the same]

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

def keep_alive():
    t = Thread(target=run_flask, daemon=True)
    t.start()
    logger.info(f"{Fore.GREEN}✅ Web App: http://localhost:{os.environ.get('PORT', 8080)}")

def run_bot():
    """Run Telegram bot polling"""
    try:
        logger.info(f"{Fore.GREEN}🤖 Starting Telegram Bot...")
        bot.infinity_polling(timeout=10, long_polling_timeout=5)
    except Exception as e:
        log_error(str(e), "Telegram bot")

def cleanup_on_exit():
    logger.warning(f"{Fore.YELLOW}🛑 Shutting down...")
    for deploy_id, process in list(active_processes.items()):
        try:
            process.terminate()
            process.wait(timeout=3)
        except:
            try:
                process.kill()
            except:
                pass
    
    for payment_id, timer in list(payment_timers.items()):
        try:
            timer.cancel()
        except:
            pass
    
    logger.warning(f"{Fore.GREEN}✅ Cleanup complete")

atexit.register(cleanup_on_exit)

def signal_handler(sig, frame):
    cleanup_on_exit()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "=" * 90)
    print(f"{Fore.CYAN}{'🚀 ELITEHOST v12.0 - PAYMENT GATEWAY EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}✨ NEW FEATURES v12.0:")
    print(f"{Fore.CYAN}   💳 Complete Payment Gateway System")
    print(f"{Fore.CYAN}   🎨 Blue Color Theme")
    print(f"{Fore.CYAN}   🖼️  Logo Support (logo.jpg)")
    print(f"{Fore.CYAN}   💎 Buy Credits: 10=₹50, 99=₹399, Custom")
    print(f"{Fore.CYAN}   📸 QR Code Payment (qr.jpg)")
    print(f"{Fore.CYAN}   ⏱️  5-Minute Payment Timer")
    print(f"{Fore.CYAN}   ✅ Admin Confirmation via Telegram")
    print(f"{Fore.CYAN}   🔔 Real-time Notifications")
    print(f"{Fore.CYAN}   📱 Mobile-Friendly Design")
    print(f"{Fore.CYAN}   🛡️  Advanced Security")
    print(f"{Fore.CYAN}   📊 Enhanced Error Logging")
    print("=" * 90)
    
    # Create placeholder images if they don't exist
    for img_name in ['logo.jpg', 'qr.jpg']:
        img_path = os.path.join(STATIC_DIR, img_name)
        if not os.path.exists(img_path):
            print(f"{Fore.YELLOW}⚠️  {img_name} not found. Please add it to: {img_path}")
    
    keep_alive()
    
    # Start bot in separate thread
    bot_thread = Thread(target=run_bot, daemon=True)
    bot_thread.start()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 Web App: http://localhost:{port}")
    print(f"{Fore.YELLOW}📱 Register: http://localhost:{port}/register")
    print(f"{Fore.YELLOW}🔑 Login: http://localhost:{port}/login")
    print(f"{Fore.MAGENTA}👑 Admin: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")
    print(f"{Fore.CYAN}💳 Payment System: Active")
    print(f"{Fore.CYAN}📞 Support: {TELEGRAM_LINK}")
    print(f"\n{Fore.GREEN}{'✅ ELITEHOST v12.0 READY':^90}")
    print("=" * 90 + "\n")
    
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
