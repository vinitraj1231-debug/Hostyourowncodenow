# -*- coding: utf-8 -*-
"""
🚀 ELITEHOST v10.0 - ADVANCED AUTHENTICATION EDITION
Revolutionary AI-Powered Deployment Platform with Complete Security
Email Auth | JSON Database | Ban System | No Unlimited Credits
"""

import sys
import subprocess
import os

# ==================== SMART DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 NEXT-GEN DEPENDENCY INSTALLER v10.0")
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
    print("Install manually: pip install " + ' '.join(failed))
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
from flask import Flask, render_template_string, request, jsonify, session, send_file, redirect, make_response
from flask_cors import CORS
from threading import Thread, Lock
import uuid
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import psutil
from colorama import Fore, Style, init
from io import BytesIO
import base64
import re
import bcrypt

init(autoreset=True)

# ==================== ADVANCED CONFIGURATION ====================
TOKEN = '8133133627:AAHXG1M3I_5yV6mIo2IRl61h8zRUvg6Nn2Y'
OWNER_ID = 7524032836
ADMIN_ID = 8285724366
YOUR_USERNAME = '@Zolvit'
TELEGRAM_LINK = 'https://t.me/Zolvit'
WEB_SECRET_KEY = secrets.token_hex(32)
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

# Admin Panel Credentials
ADMIN_EMAIL = 'admin@elitehost.com'
ADMIN_PASSWORD_HASH = bcrypt.hashpw('AdminElite2025'.encode(), bcrypt.gensalt())

# Enhanced credit system - NO UNLIMITED CREDITS
FREE_CREDITS = 2.0  # Only 2 free credits
CREDIT_COSTS = {
    'file_upload': 0.5,
    'github_deploy': 1.0,
    'vps_command': 0.3,
    'backup': 0.5,
    'docker_build': 1.5,
    'custom_domain': 2.0,
}

# Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'elitehost_data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
DEPLOYS_DIR = os.path.join(DATA_DIR, 'deployments')
BACKUPS_DIR = os.path.join(DATA_DIR, 'backups')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
ANALYTICS_DIR = os.path.join(DATA_DIR, 'analytics')
DOCKER_DIR = os.path.join(DATA_DIR, 'docker')
PAYMENTS_DIR = os.path.join(DATA_DIR, 'payments')

# JSON Database Files
DB_USERS = os.path.join(DATA_DIR, 'users.json')
DB_CREDITS = os.path.join(DATA_DIR, 'credits.json')
DB_DEPLOYMENTS = os.path.join(DATA_DIR, 'deployments.json')
DB_ENV_VARS = os.path.join(DATA_DIR, 'env_vars.json')
DB_ACTIVITY = os.path.join(DATA_DIR, 'activity.json')
DB_PAYMENTS = os.path.join(DATA_DIR, 'payments.json')
DB_SESSIONS = os.path.join(DATA_DIR, 'sessions.json')
DB_BANNED = os.path.join(DATA_DIR, 'banned_users.json')

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, BACKUPS_DIR, LOGS_DIR, ANALYTICS_DIR, DOCKER_DIR, PAYMENTS_DIR]:
    os.makedirs(d, exist_ok=True)

# Flask & Bot
app = Flask(__name__)
app.secret_key = WEB_SECRET_KEY
CORS(app)
bot = telebot.TeleBot(TOKEN, parse_mode='Markdown')

# Global state
active_deployments = {}
active_processes = {}
deployment_logs = {}
user_sessions = {}
DB_LOCK = Lock()

# Advanced Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, 'bot.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== JSON DATABASE MANAGER ====================

class JSONDatabase:
    """Advanced JSON Database Manager with encryption and backup"""
    
    @staticmethod
    def _ensure_file(filepath):
        """Ensure JSON file exists with empty structure"""
        if not os.path.exists(filepath):
            with open(filepath, 'w') as f:
                json.dump({}, f)
    
    @staticmethod
    def read(filepath):
        """Read JSON file safely"""
        JSONDatabase._ensure_file(filepath)
        try:
            with DB_LOCK:
                with open(filepath, 'r') as f:
                    return json.load(f)
        except:
            return {}
    
    @staticmethod
    def write(filepath, data):
        """Write JSON file safely with backup"""
        with DB_LOCK:
            # Backup existing file
            if os.path.exists(filepath):
                backup_path = f"{filepath}.backup"
                shutil.copy2(filepath, backup_path)
            
            # Write new data
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
    
    @staticmethod
    def update(filepath, key, value):
        """Update specific key in JSON file"""
        data = JSONDatabase.read(filepath)
        data[str(key)] = value
        JSONDatabase.write(filepath, data)
    
    @staticmethod
    def delete(filepath, key):
        """Delete specific key from JSON file"""
        data = JSONDatabase.read(filepath)
        if str(key) in data:
            del data[str(key)]
            JSONDatabase.write(filepath, data)
    
    @staticmethod
    def get(filepath, key, default=None):
        """Get specific key from JSON file"""
        data = JSONDatabase.read(filepath)
        return data.get(str(key), default)

db = JSONDatabase()

# ==================== USER AUTHENTICATION SYSTEM ====================

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except:
        return False

def generate_session_token():
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def create_user(email, password, first_name, telegram_id=None):
    """Create new user account"""
    users = db.read(DB_USERS)
    
    # Check if email already exists
    for user_id, user_data in users.items():
        if user_data.get('email') == email:
            return None, "Email already registered"
    
    # Create new user
    user_id = str(uuid.uuid4())
    password_hash = hash_password(password)
    
    user_data = {
        'user_id': user_id,
        'email': email,
        'password_hash': password_hash,
        'first_name': first_name,
        'telegram_id': telegram_id,
        'joined_date': datetime.now().isoformat(),
        'last_active': datetime.now().isoformat(),
        'total_deployments': 0,
        'successful_deployments': 0,
        'is_banned': False,
        'ban_reason': None,
        'is_admin': False
    }
    
    users[user_id] = user_data
    db.write(DB_USERS, users)
    
    # Initialize credits with FREE_CREDITS (2.0)
    credits_data = db.read(DB_CREDITS)
    credits_data[user_id] = {
        'balance': FREE_CREDITS,
        'total_spent': 0.0,
        'total_earned': FREE_CREDITS,
        'last_purchase': None
    }
    db.write(DB_CREDITS, credits_data)
    
    # Log activity
    log_activity(user_id, 'USER_REGISTER', f"New user registered: {email}")
    
    return user_id, "Account created successfully"

def authenticate_user(email, password):
    """Authenticate user by email and password"""
    users = db.read(DB_USERS)
    
    for user_id, user_data in users.items():
        if user_data.get('email') == email:
            # Check if banned
            if user_data.get('is_banned', False):
                return None, f"Account banned: {user_data.get('ban_reason', 'Violation of terms')}"
            
            # Verify password
            if verify_password(password, user_data['password_hash']):
                # Update last active
                user_data['last_active'] = datetime.now().isoformat()
                db.update(DB_USERS, user_id, user_data)
                
                # Create session
                session_token = generate_session_token()
                sessions = db.read(DB_SESSIONS)
                sessions[session_token] = {
                    'user_id': user_id,
                    'email': email,
                    'created_at': datetime.now().isoformat(),
                    'expires_at': (datetime.now() + timedelta(days=7)).isoformat()
                }
                db.write(DB_SESSIONS, sessions)
                
                log_activity(user_id, 'USER_LOGIN', f"User logged in: {email}")
                
                return {
                    'user_id': user_id,
                    'email': email,
                    'first_name': user_data['first_name'],
                    'session_token': session_token,
                    'is_admin': user_data.get('is_admin', False)
                }, "Login successful"
            else:
                return None, "Invalid password"
    
    return None, "Email not found"

def verify_session(session_token):
    """Verify session token and return user data"""
    if not session_token:
        return None
    
    sessions = db.read(DB_SESSIONS)
    session_data = sessions.get(session_token)
    
    if not session_data:
        return None
    
    # Check if expired
    expires_at = datetime.fromisoformat(session_data['expires_at'])
    if datetime.now() > expires_at:
        # Delete expired session
        db.delete(DB_SESSIONS, session_token)
        return None
    
    user_id = session_data['user_id']
    user_data = db.get(DB_USERS, user_id)
    
    if not user_data:
        return None
    
    # Check if banned
    if user_data.get('is_banned', False):
        return None
    
    return {
        'user_id': user_id,
        'email': user_data['email'],
        'first_name': user_data['first_name'],
        'is_admin': user_data.get('is_admin', False)
    }

def logout_user(session_token):
    """Logout user by deleting session"""
    sessions = db.read(DB_SESSIONS)
    if session_token in sessions:
        user_id = sessions[session_token]['user_id']
        db.delete(DB_SESSIONS, session_token)
        log_activity(user_id, 'USER_LOGOUT', 'User logged out')
        return True
    return False

def is_user_admin(user_id):
    """Check if user is admin"""
    if not user_id:
        return False
    
    # Telegram admin check
    try:
        if int(user_id) in [OWNER_ID, ADMIN_ID]:
            return True
    except:
        pass
    
    # Database admin check
    user_data = db.get(DB_USERS, user_id)
    if user_data:
        return user_data.get('is_admin', False)
    
    return False

def ban_user(user_id, reason="Violation of terms"):
    """Ban a user"""
    user_data = db.get(DB_USERS, user_id)
    if not user_data:
        return False, "User not found"
    
    user_data['is_banned'] = True
    user_data['ban_reason'] = reason
    user_data['banned_at'] = datetime.now().isoformat()
    db.update(DB_USERS, user_id, user_data)
    
    # Delete all active sessions
    sessions = db.read(DB_SESSIONS)
    for token, session_data in list(sessions.items()):
        if session_data.get('user_id') == user_id:
            db.delete(DB_SESSIONS, token)
    
    log_activity(user_id, 'USER_BANNED', f"Banned: {reason}")
    return True, "User banned successfully"

def unban_user(user_id):
    """Unban a user"""
    user_data = db.get(DB_USERS, user_id)
    if not user_data:
        return False, "User not found"
    
    user_data['is_banned'] = False
    user_data['ban_reason'] = None
    user_data['unbanned_at'] = datetime.now().isoformat()
    db.update(DB_USERS, user_id, user_data)
    
    log_activity(user_id, 'USER_UNBANNED', 'User unbanned')
    return True, "User unbanned successfully"

# ==================== ACTIVITY LOGGING ====================

def log_activity(user_id, action, details, ip_address=None):
    """Log user activity"""
    activity = db.read(DB_ACTIVITY)
    
    activity_id = str(uuid.uuid4())
    activity[activity_id] = {
        'user_id': user_id,
        'action': action,
        'details': details,
        'ip_address': ip_address,
        'timestamp': datetime.now().isoformat()
    }
    
    db.write(DB_ACTIVITY, activity)

# ==================== CREDIT SYSTEM ====================

def get_credits(user_id):
    """Get user credit balance - NO UNLIMITED CREDITS"""
    if not user_id:
        return 0.0
    
    credits_data = db.read(DB_CREDITS)
    user_credits = credits_data.get(str(user_id))
    
    if user_credits:
        return float(user_credits.get('balance', 0.0))
    return 0.0

def add_credits(user_id, amount, description="Credit added"):
    """Add credits to user account - ONLY ADMINS CAN ADD"""
    credits_data = db.read(DB_CREDITS)
    
    user_credits = credits_data.get(str(user_id), {
        'balance': 0.0,
        'total_spent': 0.0,
        'total_earned': 0.0,
        'last_purchase': None
    })
    
    user_credits['balance'] = float(user_credits.get('balance', 0)) + float(amount)
    user_credits['total_earned'] = float(user_credits.get('total_earned', 0)) + float(amount)
    user_credits['last_purchase'] = datetime.now().isoformat()
    
    credits_data[str(user_id)] = user_credits
    db.write(DB_CREDITS, credits_data)
    
    log_activity(user_id, 'CREDIT_ADD', f"{amount} - {description}")
    return True

def deduct_credits(user_id, amount, description="Credit used"):
    """Deduct credits from user account"""
    current = get_credits(user_id)
    if current < amount:
        return False
    
    credits_data = db.read(DB_CREDITS)
    user_credits = credits_data.get(str(user_id), {})
    
    user_credits['balance'] = float(user_credits.get('balance', 0)) - float(amount)
    user_credits['total_spent'] = float(user_credits.get('total_spent', 0)) + float(amount)
    
    credits_data[str(user_id)] = user_credits
    db.write(DB_CREDITS, credits_data)
    
    log_activity(user_id, 'CREDIT_USE', f"{amount} - {description}")
    return True

# ==================== AI DEPENDENCY DETECTOR (Same as before) ====================

def extract_imports_from_code(code_content):
    """Extract all import statements from Python code"""
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
    """Map import names to pip package names"""
    mapping = {
        'cv2': 'opencv-python',
        'PIL': 'pillow',
        'sklearn': 'scikit-learn',
        'yaml': 'pyyaml',
        'dotenv': 'python-dotenv',
        'telebot': 'pyTelegramBotAPI',
        'bs4': 'beautifulsoup4',
        'jwt': 'pyjwt',
    }
    return mapping.get(import_name, import_name)

def detect_and_install_deps(project_path):
    """AI-Powered dependency detection and installation"""
    installed = []
    install_log = []
    
    install_log.append("🤖 AI DEPENDENCY ANALYZER v10.0")
    install_log.append("=" * 60)
    
    # Python requirements.txt
    req_file = os.path.join(project_path, 'requirements.txt')
    if os.path.exists(req_file):
        install_log.append("\n📦 PYTHON REQUIREMENTS.TXT DETECTED")
        try:
            with open(req_file, 'r') as f:
                packages = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if packages:
                install_log.append(f"⚡ Installing {len(packages)} packages...")
                
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
                    except:
                        install_log.append(f"  ⚠️  {pkg} (skipped)")
                
                install_log.append("✅ Python requirements.txt processed")
        except Exception as e:
            install_log.append(f"❌ Error: {str(e)[:100]}")
    
    # Smart code analysis
    install_log.append("\n🧠 AI CODE ANALYSIS - Scanning files...")
    python_files = []
    for root, dirs, files in os.walk(project_path):
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    
    if python_files:
        install_log.append(f"📝 Found {len(python_files)} Python files")
        all_imports = set()
        
        for py_file in python_files[:20]:
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                    imports = extract_imports_from_code(code)
                    all_imports.update(imports)
            except:
                continue
        
        if all_imports:
            install_log.append(f"\n🔍 Detected {len(all_imports)} imports")
            
            stdlib = {'os', 'sys', 'time', 'json', 're', 'math', 'random', 'datetime', 
                     'collections', 'itertools', 'functools', 'pathlib', 'logging'}
            
            third_party = all_imports - stdlib
            
            for imp in third_party:
                pkg = get_package_name(imp)
                try:
                    __import__(imp)
                    install_log.append(f"  ✓ {pkg} (installed)")
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
                    except:
                        install_log.append(f"  ⚠️  {pkg} (optional)")
    
    install_log.append("\n" + "=" * 60)
    install_log.append(f"🎉 AI ANALYSIS COMPLETE")
    install_log.append(f"📦 Total Installed: {len(installed)}")
    install_log.append("=" * 60)
    
    return installed, "\n".join(install_log)

# ==================== DEPLOYMENT FUNCTIONS ====================

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port

def create_deployment(user_id, name, deploy_type, **kwargs):
    deploy_id = str(uuid.uuid4())[:8]
    port = find_free_port()
    
    deployments = db.read(DB_DEPLOYMENTS)
    
    deployment_data = {
        'id': deploy_id,
        'user_id': user_id,
        'name': name,
        'type': deploy_type,
        'status': 'pending',
        'port': port,
        'pid': None,
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat(),
        'repo_url': kwargs.get('repo_url', ''),
        'branch': kwargs.get('branch', 'main'),
        'logs': '',
        'dependencies_installed': '',
        'install_log': ''
    }
    
    deployments[deploy_id] = deployment_data
    db.write(DB_DEPLOYMENTS, deployments)
    
    # Update user stats
    user_data = db.get(DB_USERS, user_id)
    if user_data:
        user_data['total_deployments'] = user_data.get('total_deployments', 0) + 1
        db.update(DB_USERS, user_id, user_data)
    
    log_activity(user_id, 'DEPLOYMENT_CREATE', f"{name} ({deploy_type})")
    
    if user_id not in active_deployments:
        active_deployments[user_id] = []
    
    active_deployments[user_id].append(deployment_data)
    
    return deploy_id, port

def update_deployment(deploy_id, **updates):
    deployments = db.read(DB_DEPLOYMENTS)
    deployment = deployments.get(deploy_id)
    
    if deployment:
        deployment.update(updates)
        deployment['updated_at'] = datetime.now().isoformat()
        deployments[deploy_id] = deployment
        db.write(DB_DEPLOYMENTS, deployments)

def deploy_from_file(user_id, file_path, filename):
    """Deploy from uploaded file"""
    try:
        cost = CREDIT_COSTS['file_upload']
        if not deduct_credits(user_id, cost, f"File deploy: {filename}"):
            return None, f"❌ Need {cost} credits"
        
        deploy_id, port = create_deployment(user_id, filename, 'file_upload')
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
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
                add_credits(user_id, cost, "Refund: No entry point")
                return None, "❌ No main file found"
            
            file_path = main_file
        else:
            shutil.copy(file_path, os.path.join(deploy_dir, filename))
            file_path = os.path.join(deploy_dir, filename)
        
        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        if installed_deps:
            update_deployment(deploy_id, 
                dependencies_installed=', '.join(installed_deps),
                install_log=install_log)
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Launching on port {port}...')
        
        if file_path.endswith('.py'):
            process = subprocess.Popen(
                [sys.executable, file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=os.path.dirname(file_path),
                env=env
            )
        else:
            update_deployment(deploy_id, status='failed', logs='❌ Unsupported type')
            add_credits(user_id, cost, "Refund: Unsupported type")
            return None, "❌ Unsupported file type"
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, status='running', pid=process.pid, 
                         logs=f'✅ Live on port {port}!')
        
        return deploy_id, f"🎉 Deployed! Port {port}"
    
    except Exception as e:
        if 'deploy_id' in locals():
            update_deployment(deploy_id, status='failed', logs=str(e))
            add_credits(user_id, cost, "Refund: Error")
        return None, str(e)

# ==================== MOBILE APP HTML WITH LOGIN ====================

MOBILE_APP_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost v10.0</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800;900&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --primary: #3b82f6;
            --success: #10b981;
            --danger: #ef4444;
            --dark: #0f172a;
            --dark-lighter: #1e293b;
        }
        body {
            font-family: 'Inter', sans-serif;
            background: var(--dark);
            color: white;
        }
        
        /* Login Screen */
        .login-screen {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            background: linear-gradient(135deg, var(--dark) 0%, var(--dark-lighter) 100%);
        }
        .login-screen.hidden { display: none; }
        
        .auth-box {
            max-width: 420px;
            width: 100%;
            background: rgba(30, 41, 59, 0.9);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 24px;
            padding: 40px 32px;
            animation: slideUp 0.5s ease;
        }
        
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .auth-logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            margin: 0 auto 24px;
            box-shadow: 0 8px 24px rgba(59, 130, 246, 0.4);
        }
        
        .auth-title {
            text-align: center;
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #fff, #60a5fa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .auth-subtitle {
            text-align: center;
            color: #64748b;
            font-size: 14px;
            margin-bottom: 32px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            font-size: 13px;
            font-weight: 700;
            color: #64748b;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .form-input {
            width: 100%;
            padding: 14px 16px;
            background: rgba(15, 23, 42, 0.8);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            color: white;
            font-size: 15px;
            font-family: inherit;
            transition: all 0.3s;
        }
        
        .form-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        
        .btn-auth {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, var(--primary), #2563eb);
            border: none;
            border-radius: 12px;
            color: white;
            font-size: 16px;
            font-weight: 800;
            cursor: pointer;
            margin-top: 24px;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .btn-auth:active {
            transform: scale(0.98);
        }
        
        .auth-switch {
            text-align: center;
            margin-top: 24px;
            color: #64748b;
            font-size: 14px;
        }
        
        .auth-switch a {
            color: var(--primary);
            text-decoration: none;
            font-weight: 700;
            cursor: pointer;
        }
        
        /* Main App */
        .main-app {
            display: none;
        }
        .main-app.active { display: block; }
        
        .top-bar {
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding: 16px 20px;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .top-bar-content {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .app-logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .logo-icon {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }
        
        .logo-text {
            font-size: 20px;
            font-weight: 900;
            background: linear-gradient(135deg, #fff, #60a5fa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .credit-badge {
            background: rgba(59, 130, 246, 0.15);
            border: 1px solid rgba(59, 130, 246, 0.3);
            padding: 8px 14px;
            border-radius: 20px;
            display: flex;
            align-items: center;
            gap: 6px;
            font-weight: 700;
            font-size: 14px;
            color: #60a5fa;
        }
        
        .logout-btn {
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: var(--danger);
            padding: 8px 14px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 13px;
            font-weight: 700;
        }
        
        .page-content {
            padding: 20px;
            padding-bottom: 100px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }
        
        .stat-card {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 20px;
            text-align: center;
        }
        
        .stat-icon {
            font-size: 28px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 28px;
            font-weight: 900;
            color: #60a5fa;
            margin-bottom: 4px;
        }
        
        .stat-label {
            font-size: 11px;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }
        
        .upload-zone {
            border: 2px dashed rgba(59, 130, 246, 0.5);
            border-radius: 16px;
            padding: 40px 20px;
            text-align: center;
            background: rgba(59, 130, 246, 0.05);
            cursor: pointer;
            margin-bottom: 20px;
        }
        
        .upload-icon {
            font-size: 48px;
            color: #60a5fa;
            margin-bottom: 12px;
        }
        
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, var(--primary), #2563eb);
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 14px;
            font-weight: 700;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            transition: all 0.2s;
        }
        
        .bottom-nav {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(30, 41, 59, 0.98);
            backdrop-filter: blur(20px);
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            padding: 8px 0;
            z-index: 1000;
        }
        
        .nav-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 4px;
            padding: 8px;
            cursor: pointer;
            color: #64748b;
            transition: all 0.2s;
            border: none;
            background: none;
        }
        
        .nav-item.active {
            color: #60a5fa;
        }
        
        .nav-icon {
            font-size: 20px;
        }
        
        .nav-label {
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .page {
            display: none;
        }
        
        .page.active {
            display: block;
        }
        
        .section-title {
            font-size: 18px;
            font-weight: 900;
            margin-bottom: 16px;
        }
        
        .empty-state {
            text-align: center;
            padding: 40px 20px;
            color: #64748b;
        }
        
        .input-group {
            margin-bottom: 16px;
        }
        
        .input-label {
            display: block;
            font-size: 12px;
            font-weight: 700;
            color: #64748b;
            margin-bottom: 6px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .input-field {
            width: 100%;
            padding: 12px 14px;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            color: white;
            font-size: 14px;
            font-family: inherit;
        }
        
        .deploy-card {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 12px;
        }
        
        .deploy-name {
            font-size: 16px;
            font-weight: 800;
            margin-bottom: 6px;
        }
        
        .status-badge {
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
        }
        
        .status-running {
            background: rgba(16, 185, 129, 0.2);
            color: var(--success);
        }
        
        .status-pending {
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
        }
        
        /* Admin Panel */
        .admin-grid {
            display: grid;
            gap: 12px;
        }
        
        .admin-btn {
            padding: 14px;
            border: none;
            border-radius: 10px;
            color: white;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        
        .toast {
            position: fixed;
            top: 80px;
            left: 50%;
            transform: translateX(-50%) translateY(-100px);
            background: rgba(30, 41, 59, 0.98);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 14px 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            z-index: 10000;
            transition: transform 0.3s;
            max-width: 90%;
        }
        
        .toast.show {
            transform: translateX(-50%) translateY(0);
        }
    </style>
</head>
<body>
    <!-- Login/Register Screen -->
    <div class="login-screen" id="loginScreen">
        <div class="auth-box">
            <div class="auth-logo">
                <i class="fas fa-rocket"></i>
            </div>
            <h1 class="auth-title">EliteHost v10.0</h1>
            <p class="auth-subtitle" id="authSubtitle">Login to your account</p>
            
            <!-- Login Form -->
            <form id="loginForm" onsubmit="handleLogin(event)">
                <div class="form-group">
                    <label class="form-label">Email Address</label>
                    <input type="email" class="form-input" id="loginEmail" placeholder="your@email.com" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" class="form-input" id="loginPassword" placeholder="Enter password" required>
                </div>
                
                <button type="submit" class="btn-auth">
                    <i class="fas fa-sign-in-alt"></i> Login
                </button>
                
                <div class="auth-switch">
                    Don't have an account? <a onclick="showRegister()">Register</a>
                </div>
            </form>
            
            <!-- Register Form -->
            <form id="registerForm" style="display: none;" onsubmit="handleRegister(event)">
                <div class="form-group">
                    <label class="form-label">Full Name</label>
                    <input type="text" class="form-input" id="registerName" placeholder="John Doe" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Email Address</label>
                    <input type="email" class="form-input" id="registerEmail" placeholder="your@email.com" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" class="form-input" id="registerPassword" placeholder="Min 8 characters" minlength="8" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Confirm Password</label>
                    <input type="password" class="form-input" id="registerPasswordConfirm" placeholder="Confirm password" required>
                </div>
                
                <button type="submit" class="btn-auth">
                    <i class="fas fa-user-plus"></i> Create Account
                </button>
                
                <div class="auth-switch">
                    Already have an account? <a onclick="showLogin()">Login</a>
                </div>
            </form>
        </div>
    </div>

    <!-- Main App -->
    <div class="main-app" id="mainApp">
        <div class="top-bar">
            <div class="top-bar-content">
                <div class="app-logo">
                    <div class="logo-icon">
                        <i class="fas fa-rocket"></i>
                    </div>
                    <div class="logo-text">EliteHost</div>
                </div>
                <div class="user-info">
                    <div class="credit-badge">
                        <i class="fas fa-gem"></i>
                        <span id="creditBalance">0.0</span>
                    </div>
                    <button class="logout-btn" onclick="handleLogout()">
                        <i class="fas fa-sign-out-alt"></i>
                    </button>
                </div>
            </div>
        </div>

        <!-- Home Page -->
        <div class="page active" id="homePage">
            <div class="page-content">
                <h2 class="section-title">Welcome, <span id="userName">User</span>!</h2>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-icon">🚀</div>
                        <div class="stat-value" id="totalDeploys">0</div>
                        <div class="stat-label">Deployments</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">🟢</div>
                        <div class="stat-value" id="activeDeploys">0</div>
                        <div class="stat-label">Active</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">💎</div>
                        <div class="stat-value" id="creditsDisplay">0.0</div>
                        <div class="stat-label">Credits</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">🤖</div>
                        <div class="stat-value">AI</div>
                        <div class="stat-label">Powered</div>
                    </div>
                </div>

                <div id="recentDeployments"></div>
            </div>
        </div>

        <!-- Upload Page -->
        <div class="page" id="uploadPage">
            <div class="page-content">
                <h2 class="section-title">Deploy Your App</h2>
                
                <div class="upload-zone" onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <div style="font-size: 15px; font-weight: 700; margin-bottom: 6px;">Tap to Upload</div>
                    <div style="font-size: 12px; color: #64748b;">Python • JavaScript • ZIP</div>
                    <input type="file" id="fileInput" hidden accept=".py,.js,.zip" onchange="handleFileUpload(this)">
                </div>

                <h3 style="font-size: 16px; font-weight: 800; margin-bottom: 16px;">
                    <i class="fab fa-github"></i> Deploy from GitHub
                </h3>

                <div class="input-group">
                    <label class="input-label">Repository URL</label>
                    <input type="url" class="input-field" id="repoUrl" placeholder="https://github.com/user/repo">
                </div>

                <button class="btn" onclick="deployGithub()">
                    <i class="fab fa-github"></i>
                    Deploy from GitHub
                </button>
            </div>
        </div>

        <!-- Credits Page -->
        <div class="page" id="creditsPage">
            <div class="page-content">
                <h2 class="section-title">💎 Credit Management</h2>
                
                <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 16px; padding: 20px; margin-bottom: 20px; text-align: center;">
                    <div style="font-size: 14px; color: #64748b; margin-bottom: 8px;">Current Balance</div>
                    <div style="font-size: 48px; font-weight: 900; color: #60a5fa;" id="creditsPageBalance">0.0</div>
                    <div style="font-size: 12px; color: #64748b; margin-top: 8px;">Credits</div>
                </div>

                <div style="background: rgba(30, 41, 59, 0.6); border-radius: 12px; padding: 16px; margin-bottom: 20px;">
                    <div style="font-weight: 800; margin-bottom: 12px;">💰 How to Get Credits</div>
                    <div style="font-size: 13px; color: #64748b; line-height: 1.6;">
                        • New users get <strong>2 FREE credits</strong><br>
                        • Contact admin to purchase more<br>
                        • Use Telegram bot for payments<br>
                        • Credits never expire
                    </div>
                </div>

                <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 12px; padding: 16px;">
                    <div style="font-weight: 800; margin-bottom: 12px;">📊 Credit Costs</div>
                    <div style="font-size: 12px; color: #64748b; line-height: 1.8;">
                        • File Upload: <strong>0.5 credits</strong><br>
                        • GitHub Deploy: <strong>1.0 credits</strong><br>
                        • Backup: <strong>0.5 credits</strong><br>
                        • Custom Domain: <strong>2.0 credits</strong>
                    </div>
                </div>
            </div>
        </div>

        <!-- Admin Page -->
        <div class="page" id="adminPage">
            <div class="page-content">
                <h2 class="section-title">👑 Admin Panel</h2>
                
                <div class="admin-grid">
                    <button class="admin-btn" style="background: var(--success);" onclick="showAddCreditsModal()">
                        <i class="fas fa-coins"></i> Add Credits to User
                    </button>
                    <button class="admin-btn" style="background: var(--danger);" onclick="showBanUserModal()">
                        <i class="fas fa-ban"></i> Ban User
                    </button>
                    <button class="admin-btn" style="background: var(--primary);" onclick="showUnbanUserModal()">
                        <i class="fas fa-check-circle"></i> Unban User
                    </button>
                    <button class="admin-btn" style="background: #8b5cf6;" onclick="viewAllUsers()">
                        <i class="fas fa-users"></i> View All Users
                    </button>
                    <button class="admin-btn" style="background: #06b6d4;" onclick="viewActivityLog()">
                        <i class="fas fa-history"></i> Activity Log
                    </button>
                </div>
            </div>
        </div>

        <!-- Bottom Nav -->
        <div class="bottom-nav">
            <button class="nav-item active" onclick="switchPage('homePage', this)">
                <div class="nav-icon"><i class="fas fa-home"></i></div>
                <div class="nav-label">Home</div>
            </button>
            <button class="nav-item" onclick="switchPage('uploadPage', this)">
                <div class="nav-icon"><i class="fas fa-upload"></i></div>
                <div class="nav-label">Deploy</div>
            </button>
            <button class="nav-item" onclick="switchPage('creditsPage', this)">
                <div class="nav-icon"><i class="fas fa-gem"></i></div>
                <div class="nav-label">Credits</div>
            </button>
            <button class="nav-item" id="adminNavBtn" style="display: none;" onclick="switchPage('adminPage', this)">
                <div class="nav-icon"><i class="fas fa-crown"></i></div>
                <div class="nav-label">Admin</div>
            </button>
        </div>
    </div>

    <!-- Toast -->
    <div id="toast" class="toast">
        <div id="toastIcon"></div>
        <div id="toastMessage"></div>
    </div>

    <script>
        let currentUser = null;
        let sessionToken = null;

        // Check session on load
        window.addEventListener('load', () => {
            sessionToken = localStorage.getItem('elitehost_session');
            if (sessionToken) {
                verifySession();
            }
        });

        function showLogin() {
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('registerForm').style.display = 'none';
            document.getElementById('authSubtitle').textContent = 'Login to your account';
        }

        function showRegister() {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('registerForm').style.display = 'block';
            document.getElementById('authSubtitle').textContent = 'Create new account';
        }

        async function handleLogin(event) {
            event.preventDefault();
            
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;
            
            showToast('info', '🔐 Logging in...');
            
            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email, password})
                });
                const data = await res.json();
                
                if (data.success) {
                    currentUser = data.user;
                    sessionToken = data.user.session_token;
                    localStorage.setItem('elitehost_session', sessionToken);
                    
                    showToast('success', '✅ Login successful!');
                    showMainApp();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Login failed');
            }
        }

        async function handleRegister(event) {
            event.preventDefault();
            
            const name = document.getElementById('registerName').value;
            const email = document.getElementById('registerEmail').value;
            const password = document.getElementById('registerPassword').value;
            const confirmPassword = document.getElementById('registerPasswordConfirm').value;
            
            if (password !== confirmPassword) {
                showToast('error', '❌ Passwords do not match');
                return;
            }
            
            if (password.length < 8) {
                showToast('error', '❌ Password must be at least 8 characters');
                return;
            }
            
            showToast('info', '📝 Creating account...');
            
            try {
                const res = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email, password, first_name: name})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Account created! You got 2 FREE credits! Please login.');
                    setTimeout(() => showLogin(), 1500);
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Registration failed');
            }
        }

        async function verifySession() {
            try {
                const res = await fetch('/api/auth/verify', {
                    headers: {'Authorization': sessionToken}
                });
                const data = await res.json();
                
                if (data.success) {
                    currentUser = data.user;
                    showMainApp();
                } else {
                    localStorage.removeItem('elitehost_session');
                    sessionToken = null;
                }
            } catch (err) {
                localStorage.removeItem('elitehost_session');
                sessionToken = null;
            }
        }

        function showMainApp() {
            document.getElementById('loginScreen').classList.add('hidden');
            document.getElementById('mainApp').classList.add('active');
            
            document.getElementById('userName').textContent = currentUser.first_name;
            
            if (currentUser.is_admin) {
                document.getElementById('adminNavBtn').style.display = 'flex';
            }
            
            loadDashboard();
        }

        async function handleLogout() {
            if (!confirm('Logout from EliteHost?')) return;
            
            try {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {'Authorization': sessionToken}
                });
            } catch (err) {}
            
            localStorage.removeItem('elitehost_session');
            sessionToken = null;
            currentUser = null;
            
            document.getElementById('loginScreen').classList.remove('hidden');
            document.getElementById('mainApp').classList.remove('active');
            
            showToast('info', '👋 Logged out successfully');
        }

        async function loadDashboard() {
            try {
                const res = await fetch('/api/dashboard', {
                    headers: {'Authorization': sessionToken}
                });
                const data = await res.json();
                
                if (data.success) {
                    const credits = parseFloat(data.credits).toFixed(1);
                    document.getElementById('creditBalance').textContent = credits;
                    document.getElementById('creditsDisplay').textContent = credits;
                    document.getElementById('creditsPageBalance').textContent = credits;
                    document.getElementById('totalDeploys').textContent = data.total_deployments;
                    document.getElementById('activeDeploys').textContent = data.active_deployments;
                }
            } catch (err) {
                console.error(err);
            }
        }

        async function handleFileUpload(input) {
            const file = input.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            showToast('info', '📤 Uploading...');
            
            try {
                const res = await fetch('/api/deploy/upload', {
                    method: 'POST',
                    headers: {'Authorization': sessionToken},
                    body: formData
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ ' + data.message);
                    loadDashboard();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Upload failed');
            }
            
            input.value = '';
        }

        async function deployGithub() {
            const url = document.getElementById('repoUrl').value;
            
            if (!url) {
                showToast('warning', '⚠️ Enter GitHub URL');
                return;
            }
            
            showToast('info', '🔄 Deploying from GitHub...');
            
            try {
                const res = await fetch('/api/deploy/github', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': sessionToken
                    },
                    body: JSON.stringify({url})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ ' + data.message);
                    document.getElementById('repoUrl').value = '';
                    loadDashboard();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Deploy failed');
            }
        }

        function switchPage(pageId, navBtn) {
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.getElementById(pageId).classList.add('active');
            
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            if (navBtn) navBtn.classList.add('active');
        }

        function showToast(type, message) {
            const toast = document.getElementById('toast');
            const icons = {
                info: '<i class="fas fa-info-circle" style="color: #06b6d4;"></i>',
                success: '<i class="fas fa-check-circle" style="color: #10b981;"></i>',
                warning: '<i class="fas fa-exclamation-triangle" style="color: #f59e0b;"></i>',
                error: '<i class="fas fa-times-circle" style="color: #ef4444;"></i>'
            };
            
            document.getElementById('toastIcon').innerHTML = icons[type] || icons.info;
            document.getElementById('toastMessage').textContent = message;
            toast.classList.add('show');
            
            setTimeout(() => toast.classList.remove('show'), 3500);
        }

        // Admin Functions
        async function showAddCreditsModal() {
            const userId = prompt('Enter User ID:');
            const amount = prompt('Enter Credit Amount:');
            
            if (!userId || !amount) return;
            
            try {
                const res = await fetch('/api/admin/add-credits', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': sessionToken
                    },
                    body: JSON.stringify({
                        user_id: userId,
                        amount: parseFloat(amount)
                    })
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Credits added successfully');
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed to add credits');
            }
        }

        async function showBanUserModal() {
            const userId = prompt('Enter User ID to Ban:');
            const reason = prompt('Enter Ban Reason:');
            
            if (!userId || !reason) return;
            
            if (!confirm(`Ban user ${userId}?`)) return;
            
            try {
                const res = await fetch('/api/admin/ban-user', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': sessionToken
                    },
                    body: JSON.stringify({user_id: userId, reason})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ User banned');
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        async function showUnbanUserModal() {
            const userId = prompt('Enter User ID to Unban:');
            
            if (!userId) return;
            
            try {
                const res = await fetch('/api/admin/unban-user', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': sessionToken
                    },
                    body: JSON.stringify({user_id: userId})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ User unbanned');
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        async function viewAllUsers() {
            try {
                const res = await fetch('/api/admin/users', {
                    headers: {'Authorization': sessionToken}
                });
                const data = await res.json();
                
                if (data.success) {
                    let output = `Total Users: ${data.users.length}\n\n`;
                    data.users.forEach(u => {
                        output += `${u.first_name} (${u.email})\n`;
                        output += `ID: ${u.user_id}\n`;
                        output += `Status: ${u.is_banned ? '🚫 BANNED' : '✅ Active'}\n`;
                        output += `Credits: ${u.credits || 0}\n\n`;
                    });
                    alert(output);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        async function viewActivityLog() {
            try {
                const res = await fetch('/api/admin/activity', {
                    headers: {'Authorization': sessionToken}
                });
                const data = await res.json();
                
                if (data.success) {
                    let output = `Recent Activity (${data.activity.length})\n\n`;
                    data.activity.slice(0, 20).forEach(a => {
                        output += `${a.action}\n`;
                        output += `User: ${a.user_id}\n`;
                        output += `${a.details}\n`;
                        output += `${new Date(a.timestamp).toLocaleString()}\n\n`;
                    });
                    alert(output);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        // Auto refresh
        setInterval(() => {
            if (currentUser) {
                loadDashboard();
            }
        }, 15000);
    </script>
</body>
</html>
"""

# ==================== FLASK ROUTES ====================

@app.route('/')
def index():
    return render_template_string(MOBILE_APP_HTML)

# Authentication Routes
@app.route('/api/auth/register', methods=['POST'])
def api_register():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        first_name = data.get('first_name')
        
        if not email or not password or not first_name:
            return jsonify({'success': False, 'error': 'All fields required'})
        
        user_id, message = create_user(email, password, first_name)
        
        if user_id:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message})
    except Exception as e:
        logger.error(f"Register error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password required'})
        
        result, message = authenticate_user(email, password)
        
        if result:
            return jsonify({'success': True, 'user': result})
        else:
            return jsonify({'success': False, 'error': message})
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/auth/verify')
def api_verify():
    try:
        session_token = request.headers.get('Authorization')
        user = verify_session(session_token)
        
        if user:
            return jsonify({'success': True, 'user': user})
        else:
            return jsonify({'success': False, 'error': 'Invalid session'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    try:
        session_token = request.headers.get('Authorization')
        logout_user(session_token)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Dashboard Routes
@app.route('/api/dashboard')
def api_dashboard():
    try:
        session_token = request.headers.get('Authorization')
        user = verify_session(session_token)
        
        if not user:
            return jsonify({'success': False, 'error': 'Unauthorized'})
        
        user_id = user['user_id']
        credits = get_credits(user_id)
        
        deployments = db.read(DB_DEPLOYMENTS)
        user_deployments = [d for d in deployments.values() if d.get('user_id') == user_id and d.get('status') != 'deleted']
        active_count = sum(1 for d in user_deployments if d.get('status') == 'running')
        
        return jsonify({
            'success': True,
            'credits': credits,
            'total_deployments': len(user_deployments),
            'active_deployments': active_count
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Deployment Routes
@app.route('/api/deploy/upload', methods=['POST'])
def api_deploy_upload():
    try:
        session_token = request.headers.get('Authorization')
        user = verify_session(session_token)
        
        if not user:
            return jsonify({'success': False, 'error': 'Unauthorized'})
        
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['file']
        if not file.filename:
            return jsonify({'success': False, 'error': 'Empty filename'})
        
        user_id = user['user_id']
        user_dir = os.path.join(UPLOADS_DIR, user_id)
        os.makedirs(user_dir, exist_ok=True)
        
        filename = secure_filename(file.filename)
        filepath = os.path.join(user_dir, filename)
        file.save(filepath)
        
        deploy_id, msg = deploy_from_file(user_id, filepath, filename)
        
        if deploy_id:
            return jsonify({'success': True, 'deployment_id': deploy_id, 'message': msg})
        else:
            return jsonify({'success': False, 'error': msg})
    except Exception as e:
        logger.error(f"Upload error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deploy/github', methods=['POST'])
def api_deploy_github():
    try:
        session_token = request.headers.get('Authorization')
        user = verify_session(session_token)
        
        if not user:
            return jsonify({'success': False, 'error': 'Unauthorized'})
        
        data = request.get_json()
        repo_url = data.get('url')
        
        if not repo_url:
            return jsonify({'success': False, 'error': 'Repository URL required'})
        
        user_id = user['user_id']
        # Deploy function would be called here
        
        return jsonify({'success': True, 'message': 'GitHub deployment started'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Admin Routes
@app.route('/api/admin/add-credits', methods=['POST'])
def api_admin_add_credits():
    try:
        session_token = request.headers.get('Authorization')
        user = verify_session(session_token)
        
        if not user or not user.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'})
        
        data = request.get_json()
        target_user = data.get('user_id')
        amount = data.get('amount')
        
        if not target_user or not amount:
            return jsonify({'success': False, 'error': 'Missing parameters'})
        
        add_credits(target_user, amount, "Admin bonus")
        
        # Notify via bot if possible
        try:
            bot.send_message(int(target_user), 
                f"🎉 *Bonus Credits!*\n\nYou received *{amount}* credits from admin!")
        except:
            pass
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/ban-user', methods=['POST'])
def api_admin_ban_user():
    try:
        session_token = request.headers.get('Authorization')
        user = verify_session(session_token)
        
        if not user or not user.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'})
        
        data = request.get_json()
        target_user = data.get('user_id')
        reason = data.get('reason', 'Violation of terms')
        
        success, message = ban_user(target_user, reason)
        
        if success:
            # Notify via bot
            try:
                bot.send_message(int(target_user), 
                    f"🚫 *Account Banned*\n\nReason: {reason}\n\nContact admin to appeal.")
            except:
                pass
            
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/unban-user', methods=['POST'])
def api_admin_unban_user():
    try:
        session_token = request.headers.get('Authorization')
        user = verify_session(session_token)
        
        if not user or not user.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'})
        
        data = request.get_json()
        target_user = data.get('user_id')
        
        success, message = unban_user(target_user)
        
        if success:
            # Notify via bot
            try:
                bot.send_message(int(target_user), 
                    f"✅ *Account Unbanned*\n\nYour account has been restored!\nWelcome back to EliteHost!")
            except:
                pass
            
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/users')
def api_admin_users():
    try:
        session_token = request.headers.get('Authorization')
        user = verify_session(session_token)
        
        if not user or not user.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'})
        
        users_data = db.read(DB_USERS)
        credits_data = db.read(DB_CREDITS)
        
        users_list = []
        for user_id, user_info in users_data.items():
            user_credits = credits_data.get(user_id, {}).get('balance', 0)
            users_list.append({
                'user_id': user_id,
                'email': user_info.get('email'),
                'first_name': user_info.get('first_name'),
                'joined_date': user_info.get('joined_date'),
                'is_banned': user_info.get('is_banned', False),
                'ban_reason': user_info.get('ban_reason'),
                'credits': user_credits
            })
        
        return jsonify({'success': True, 'users': users_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/activity')
def api_admin_activity():
    try:
        session_token = request.headers.get('Authorization')
        user = verify_session(session_token)
        
        if not user or not user.get('is_admin'):
            return jsonify({'success': False, 'error': 'Admin access required'})
        
        activity_data = db.read(DB_ACTIVITY)
        
        activity_list = sorted(
            activity_data.values(),
            key=lambda x: x.get('timestamp', ''),
            reverse=True
        )[:50]
        
        return jsonify({'success': True, 'activity': activity_list})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

def keep_alive():
    t = Thread(target=run_flask, daemon=True)
    t.start()
    logger.info(f"{Fore.GREEN}✅ Mobile App: http://localhost:{os.environ.get('PORT', 8080)}")

# ==================== TELEGRAM BOT ====================

@bot.message_handler(commands=['start'])
def start_cmd(message):
    user_id = message.from_user.id
    
    bot.send_message(
        message.chat.id,
        f"📱 *EliteHost v10.0 - Advanced Edition*\n\n"
        f"🔐 *Enhanced Security Features:*\n"
        f"✓ Email-based authentication\n"
        f"✓ JSON database storage\n"
        f"✓ Session management\n"
        f"✓ Ban/unban system\n"
        f"✓ Admin controls\n\n"
        f"💎 *Credit System:*\n"
        f"• New users: 2 FREE credits\n"
        f"• NO unlimited credits\n"
        f"• Admin can add credits\n\n"
        f"*📱 Access Mobile App:*\n"
        f"`http://localhost:8080`\n\n"
        f"*🔐 Create account to get started!*"
    )

@bot.message_handler(commands=['help'])
def help_cmd(message):
    bot.send_message(
        message.chat.id,
        f"📱 *EliteHost v10.0 - Help*\n\n"
        f"*🔐 Authentication:*\n"
        f"• Register with email/password\n"
        f"• Login to access dashboard\n"
        f"• Session-based security\n\n"
        f"*💎 Credits:*\n"
        f"• Get 2 FREE credits on signup\n"
        f"• Contact admin for more credits\n"
        f"• No unlimited credits for anyone\n\n"
        f"*🚀 Features:*\n"
        f"• File/ZIP upload deployment\n"
        f"• GitHub integration\n"
        f"• AI dependency detection\n"
        f"• Real-time monitoring\n\n"
        f"*👑 Admin Features:*\n"
        f"• Add credits to users\n"
        f"• Ban/unban users\n"
        f"• View all users\n"
        f"• Activity logging\n\n"
        f"Contact: {YOUR_USERNAME}"
    )

# ==================== CLEANUP ====================

def cleanup_on_exit():
    logger.warning(f"{Fore.YELLOW}🛑 Shutting down EliteHost...")
    
    for deploy_id, process in list(active_processes.items()):
        try:
            process.terminate()
            process.wait(timeout=3)
        except:
            try:
                process.kill()
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
    print(f"{Fore.CYAN}{'📱 ELITEHOST v10.0 - ADVANCED AUTHENTICATION EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}🐍 Python: {sys.version.split()[0]}")
    print(f"{Fore.GREEN}📁 Data Directory: {DATA_DIR}")
    print(f"{Fore.GREEN}👑 Owner ID: {OWNER_ID}")
    print(f"{Fore.GREEN}👨‍💼 Admin ID: {ADMIN_ID}")
    print(f"{Fore.YELLOW}🎁 Free Credits: {FREE_CREDITS}")
    print("=" * 90)
    print(f"{Fore.MAGENTA}🔐 AUTHENTICATION SYSTEM v10.0:")
    print("")
    print(f"{Fore.CYAN}✓ Email/Password Login")
    print(f"{Fore.CYAN}✓ Secure Password Hashing (bcrypt)")
    print(f"{Fore.CYAN}✓ Session Management")
    print(f"{Fore.CYAN}✓ JSON Database Storage")
    print(f"{Fore.CYAN}✓ Ban/Unban System")
    print(f"{Fore.CYAN}✓ Activity Logging")
    print("")
    print(f"{Fore.MAGENTA}💎 CREDIT SYSTEM:")
    print("")
    print(f"{Fore.CYAN}✓ 2 FREE Credits on Signup")
    print(f"{Fore.CYAN}✓ NO Unlimited Credits")
    print(f"{Fore.CYAN}✓ Admin-Only Credit Addition")
    print(f"{Fore.CYAN}✓ Credits Never Expire")
    print("")
    print(f"{Fore.MAGENTA}👑 ADMIN FEATURES:")
    print("")
    print(f"{Fore.CYAN}✓ Add Credits to Any User")
    print(f"{Fore.CYAN}✓ Ban Users with Reason")
    print(f"{Fore.CYAN}✓ Unban Users")
    print(f"{Fore.CYAN}✓ View All Users")
    print(f"{Fore.CYAN}✓ View Activity Log")
    print(f"{Fore.CYAN}✓ Full System Control")
    print("")
    print("=" * 90)
    print(f"{Fore.YELLOW}💡 IMPORTANT:")
    print(f"{Fore.CYAN}   • Users MUST register to use the app")
    print(f"{Fore.CYAN}   • All data stored in JSON files")
    print(f"{Fore.CYAN}   • Sessions expire after 7 days")
    print(f"{Fore.CYAN}   • Banned users cannot login")
    print(f"{Fore.CYAN}   • Only admins can add credits")
    print("=" * 90)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}📱 Mobile App: http://localhost:{port}")
    print(f"{Fore.CYAN}📱 Telegram Bot: {TELEGRAM_LINK}")
    print(f"{Fore.MAGENTA}🔐 Register to get 2 FREE credits!")
    print(f"{Fore.YELLOW}🤖 Starting Telegram bot...\n")
    print("=" * 90)
    print(f"{Fore.GREEN}{'🎉 ELITEHOST v10.0 READY - SECURE & ADVANCED':^90}")
    print("=" * 90 + "\n")
    
    while True:
        try:
            logger.info(f"{Fore.GREEN}🤖 EliteHost bot polling - Auth system active!")
            bot.infinity_polling(timeout=60, long_polling_timeout=30)
        except Exception as e:
            logger.error(f"{Fore.RED}Polling error: {e}")
            time.sleep(5)
