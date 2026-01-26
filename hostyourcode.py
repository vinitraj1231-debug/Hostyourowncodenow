# -*- coding: utf-8 -*-
"""
🚀 ELITEHOST v11.0 - PROFESSIONAL DEPLOYMENT PLATFORM
Advanced Features | Modern UI | Production Ready
"""

import sys
import subprocess
import os

# ==================== DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 INSTALLING DEPENDENCIES...")
print("=" * 90)

REQUIRED = {
    'pyTelegramBotAPI': 'telebot',
    'flask': 'flask',
    'flask-cors': 'flask_cors',
    'requests': 'requests',
    'cryptography': 'cryptography',
    'psutil': 'psutil',
    'werkzeug': 'werkzeug',
    'python-dotenv': 'dotenv',
    'bcrypt': 'bcrypt'
}

def install(pkg, imp):
    try:
        __import__(imp)
        print(f"✓ {pkg:30} [OK]")
        return True
    except ImportError:
        print(f"⚡ {pkg:30} [INSTALLING...]", end=' ')
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("✅")
            return True
        except:
            print("❌")
            return False

failed = [p for p, i in REQUIRED.items() if not install(p, i)]
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
from flask import Flask, render_template_string, request, jsonify, session, send_file, redirect, make_response
from flask_cors import CORS
from threading import Thread, Lock
import uuid
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import psutil
import bcrypt
import re

# ==================== CONFIGURATION ====================
TOKEN = '8133133627:AAHXG1M3I_5yV6mIo2IRl61h8zRUvg6Nn2Y'
OWNER_ID = 7524032836
ADMIN_ID = 8285724366
YOUR_USERNAME = '@Zolvit'
TELEGRAM_LINK = 'https://t.me/Zolvit'

# Admin credentials
ADMIN_EMAIL = 'Kvinit6421@gmail.com'
ADMIN_PASSWORD = '28@HumblerRaj'

WEB_SECRET_KEY = secrets.token_hex(32)
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

FREE_CREDITS = 2.0
CREDIT_COSTS = {
    'file_upload': 0.5,
    'github_deploy': 1.0,
    'backup': 0.5,
}

CREDIT_PRICES = {
    '5': 50,    # 5 credits = ₹50
    '10': 90,   # 10 credits = ₹90
    '25': 200,  # 25 credits = ₹200
    '50': 350,  # 50 credits = ₹350
    '100': 600  # 100 credits = ₹600
}

# Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'elitehost_data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
DEPLOYS_DIR = os.path.join(DATA_DIR, 'deployments')
BACKUPS_DIR = os.path.join(DATA_DIR, 'backups')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
DB_FILE = os.path.join(DATA_DIR, 'database.json')

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, BACKUPS_DIR, LOGS_DIR]:
    os.makedirs(d, exist_ok=True)

# Flask & Bot
app = Flask(__name__)
app.secret_key = WEB_SECRET_KEY
CORS(app)
bot = telebot.TeleBot(TOKEN, parse_mode='Markdown')

# Global state
active_processes = {}
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

# ==================== DATABASE ====================

def load_db():
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {
        'users': {},
        'sessions': {},
        'deployments': {},
        'payments': {},
        'support': {},
        'activity': [],
        'banned_devices': []
    }

def save_db(db):
    with DB_LOCK:
        with open(DB_FILE, 'w') as f:
            json.dump(db, f, indent=2, default=str)

db = load_db()

# ==================== TELEGRAM NOTIFICATIONS ====================

def notify_owner(message):
    """Send notification to owner"""
    try:
        bot.send_message(OWNER_ID, message, parse_mode='Markdown')
    except Exception as e:
        logger.error(f"Failed to notify owner: {e}")

def notify_owner_new_user(email, user_id):
    """Notify owner about new user registration"""
    msg = f"""
🎉 *NEW USER REGISTERED*

👤 Email: `{email}`
🆔 User ID: `{user_id}`
💎 Credits: {FREE_CREDITS}
📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    notify_owner(msg)

def notify_owner_deployment(email, deploy_type, name, deploy_id):
    """Notify owner about new deployment"""
    msg = f"""
🚀 *NEW DEPLOYMENT*

👤 User: `{email}`
📦 Type: *{deploy_type}*
📄 Name: `{name}`
🆔 Deploy ID: `{deploy_id}`
📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    notify_owner(msg)

def notify_owner_payment(email, amount, price):
    """Notify owner about payment request"""
    msg = f"""
💰 *PAYMENT REQUEST*

👤 User: `{email}`
💎 Credits: {amount}
💵 Amount: ₹{price}
📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    notify_owner(msg)

def notify_owner_support(email, subject, message):
    """Notify owner about support request"""
    msg = f"""
🆘 *SUPPORT REQUEST*

👤 User: `{email}`
📋 Subject: *{subject}*
💬 Message:
{message}

📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    notify_owner(msg)

# ==================== HELPER FUNCTIONS ====================

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def get_device_fingerprint(request):
    user_agent = request.headers.get('User-Agent', '')
    ip = request.remote_addr or 'unknown'
    accept_lang = request.headers.get('Accept-Language', '')
    fingerprint_str = f"{user_agent}|{ip}|{accept_lang}"
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()

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
        'is_banned': False
    }
    
    save_db(db)
    notify_owner_new_user(email, user_id)
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
        'expires_at': (datetime.now() + timedelta(days=30)).isoformat()
    }
    
    save_db(db)
    return session_token

def verify_session(session_token, fingerprint):
    if not session_token or session_token not in db['sessions']:
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
    return True

# ==================== DEPLOYMENT FUNCTIONS ====================

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port

def extract_imports(code):
    imports = set()
    for line in code.split('\n'):
        if re.match(r'^\s*import\s+([a-zA-Z0-9_\.]+)', line):
            module = re.match(r'^\s*import\s+([a-zA-Z0-9_\.]+)', line).group(1).split('.')[0]
            imports.add(module)
        elif re.match(r'^\s*from\s+([a-zA-Z0-9_\.]+)\s+import', line):
            module = re.match(r'^\s*from\s+([a-zA-Z0-9_\.]+)\s+import', line).group(1).split('.')[0]
            imports.add(module)
    return imports

def install_dependencies(project_path):
    installed = []
    log = ["🤖 AI DEPENDENCY ANALYZER\n" + "=" * 60 + "\n"]
    
    # Check requirements.txt
    req_file = os.path.join(project_path, 'requirements.txt')
    if os.path.exists(req_file):
        log.append("\n📦 INSTALLING FROM REQUIREMENTS.TXT\n")
        try:
            with open(req_file, 'r') as f:
                packages = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            for pkg in packages:
                try:
                    subprocess.run([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                                 check=True, capture_output=True, timeout=300)
                    log.append(f"  ✅ {pkg}")
                    installed.append(pkg)
                except:
                    log.append(f"  ⚠️  {pkg} (skipped)")
        except Exception as e:
            log.append(f"❌ Error: {str(e)[:100]}")
    
    # Analyze Python files
    stdlib = {'os', 'sys', 'time', 'json', 're', 'math', 'random', 'datetime'}
    mapping = {
        'cv2': 'opencv-python', 'PIL': 'pillow', 'sklearn': 'scikit-learn',
        'yaml': 'pyyaml', 'dotenv': 'python-dotenv', 'telebot': 'pyTelegramBotAPI',
        'bs4': 'beautifulsoup4'
    }
    
    all_imports = set()
    for root, dirs, files in os.walk(project_path):
        for file in files:
            if file.endswith('.py'):
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                        all_imports.update(extract_imports(f.read()))
                except:
                    continue
    
    third_party = all_imports - stdlib
    if third_party:
        log.append("\n🔍 AUTO-DETECTED DEPENDENCIES\n")
        for imp in third_party:
            pkg = mapping.get(imp, imp)
            try:
                __import__(imp)
            except ImportError:
                try:
                    subprocess.run([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                                 check=True, capture_output=True, timeout=300)
                    log.append(f"  ✅ {pkg} (auto-installed)")
                    installed.append(pkg)
                except:
                    pass
    
    log.append(f"\n{'=' * 60}")
    log.append(f"📦 Total Installed: {len(installed)}")
    log.append("=" * 60)
    
    return installed, "\n".join(log)

def create_deployment(user_id, name, deploy_type, **kwargs):
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
        'env_vars': kwargs.get('env_vars', {}),
        'build_command': kwargs.get('build_command', ''),
        'start_command': kwargs.get('start_command', ''),
        'repo_url': kwargs.get('repo_url', ''),
        'branch': kwargs.get('branch', 'main')
    }
    
    db['deployments'][deploy_id] = deployment
    
    user = get_user(user_id)
    if user:
        user['deployments'].append(deploy_id)
        update_user(user_id, deployments=user['deployments'])
    
    save_db(db)
    
    # Notify owner
    notify_owner_deployment(user['email'], deploy_type, name, deploy_id)
    
    return deploy_id, port

def update_deployment(deploy_id, **kwargs):
    if deploy_id in db['deployments']:
        db['deployments'][deploy_id].update(kwargs)
        db['deployments'][deploy_id]['updated_at'] = datetime.now().isoformat()
        save_db(db)

def deploy_from_file(user_id, file_path, filename, env_vars=None, start_command=None):
    try:
        cost = CREDIT_COSTS['file_upload']
        if not deduct_credits(user_id, cost):
            return None, f"❌ Need {cost} credits"
        
        deploy_id, port = create_deployment(user_id, filename, 'file_upload', 
                                           env_vars=env_vars or {}, start_command=start_command or '')
        
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
                add_credits(user_id, cost, "Refund")
                return None, "❌ No main file found"
            
            file_path = main_file
        else:
            shutil.copy(file_path, os.path.join(deploy_dir, filename))
            file_path = os.path.join(deploy_dir, filename)
        
        update_deployment(deploy_id, status='installing', logs='🤖 Analyzing dependencies...')
        installed_deps, install_log = install_dependencies(deploy_dir)
        update_deployment(deploy_id, dependencies=installed_deps, logs=install_log)
        
        # Prepare environment
        env = os.environ.copy()
        env['PORT'] = str(port)
        if env_vars:
            env.update(env_vars)
        
        # Determine start command
        if start_command:
            cmd = start_command.split()
        elif file_path.endswith('.py'):
            cmd = [sys.executable, file_path]
        elif file_path.endswith('.js'):
            cmd = ['node', file_path]
        else:
            update_deployment(deploy_id, status='failed', logs='❌ Unknown file type')
            add_credits(user_id, cost, "Refund")
            return None, "❌ Unknown file type"
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Starting on port {port}...')
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.dirname(file_path),
            env=env
        )
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, status='running', pid=process.pid, 
                        logs=f'✅ Running on port {port}!\n\n{install_log}')
        
        return deploy_id, f"🎉 Deployed on port {port}"
    
    except Exception as e:
        if 'deploy_id' in locals():
            update_deployment(deploy_id, status='failed', logs=str(e))
            add_credits(user_id, cost, "Refund")
        return None, str(e)

def deploy_from_github(user_id, repo_url, branch='main', env_vars=None, build_command=None, start_command=None):
    try:
        cost = CREDIT_COSTS['github_deploy']
        if not deduct_credits(user_id, cost):
            return None, f"❌ Need {cost} credits"
        
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        deploy_id, port = create_deployment(user_id, repo_name, 'github', 
                                           repo_url=repo_url, branch=branch,
                                           env_vars=env_vars or {}, 
                                           build_command=build_command or '',
                                           start_command=start_command or '')
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        update_deployment(deploy_id, status='cloning', logs=f'🔄 Cloning {repo_url}...')
        
        result = subprocess.run(['git', 'clone', '-b', branch, '--depth', '1', repo_url, deploy_dir],
                              capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0:
            update_deployment(deploy_id, status='failed', logs='❌ Clone failed')
            add_credits(user_id, cost, "Refund")
            return None, "❌ Clone failed"
        
        update_deployment(deploy_id, status='installing', logs='🤖 Installing dependencies...')
        installed_deps, install_log = install_dependencies(deploy_dir)
        update_deployment(deploy_id, dependencies=installed_deps)
        
        # Execute build command if provided
        if build_command:
            update_deployment(deploy_id, status='building', logs=f'🔨 Building: {build_command}')
            build_result = subprocess.run(build_command, shell=True, cwd=deploy_dir,
                                        capture_output=True, text=True, timeout=600)
            if build_result.returncode != 0:
                update_deployment(deploy_id, status='failed', 
                                logs=f'❌ Build failed:\n{build_result.stderr}')
                add_credits(user_id, cost, "Refund")
                return None, "❌ Build failed"
        
        # Determine start command
        if start_command:
            cmd = start_command
        else:
            # Auto-detect
            main_files = {
                'main.py': f'{sys.executable} main.py',
                'app.py': f'{sys.executable} app.py',
                'bot.py': f'{sys.executable} bot.py',
                'index.js': 'node index.js',
                'server.js': 'node server.js'
            }
            
            cmd = None
            for file, command in main_files.items():
                if os.path.exists(os.path.join(deploy_dir, file)):
                    cmd = command
                    break
            
            if not cmd:
                update_deployment(deploy_id, status='failed', logs='❌ No start command')
                add_credits(user_id, cost, "Refund")
                return None, "❌ No start file found"
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Starting...')
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        if env_vars:
            env.update(env_vars)
        
        process = subprocess.Popen(
            cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=deploy_dir,
            env=env
        )
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, status='running', pid=process.pid, 
                        logs=f'✅ Running on port {port}!\n\n{install_log}')
        
        return deploy_id, f"🎉 Deployed on port {port}"
    
    except Exception as e:
        if 'deploy_id' in locals():
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
        return False, str(e)

def create_backup(deploy_id):
    try:
        if deploy_id not in db['deployments']:
            return None, "Deployment not found"
        
        deploy = db['deployments'][deploy_id]
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        
        if not os.path.exists(deploy_dir):
            return None, "Deployment directory not found"
        
        backup_name = f"{deploy['name']}_{deploy_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        backup_path = os.path.join(BACKUPS_DIR, backup_name)
        
        shutil.make_archive(backup_path.replace('.zip', ''), 'zip', deploy_dir)
        
        return backup_path, backup_name
    except Exception as e:
        return None, str(e)

# ==================== HTML TEMPLATES ====================

MODERN_BASE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - EliteHost</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        [x-cloak] { display: none !important; }
        .gradient-bg { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
        .gradient-text { background: linear-gradient(135deg, #667eea, #764ba2); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .animate-fade-in { animation: fadeIn 0.3s ease-in; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        
        /* Dark mode colors */
        .dark { background-color: #0a0a0a; color: #e5e5e5; }
        .card-dark { background-color: #1a1a1a; border: 1px solid #2a2a2a; }
        .input-dark { background-color: #1a1a1a; border: 1px solid #2a2a2a; color: #e5e5e5; }
        .input-dark:focus { border-color: #667eea; outline: none; }
        
        /* Custom scrollbar */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: #1a1a1a; }
        ::-webkit-scrollbar-thumb { background: #2a2a2a; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #3a3a3a; }
    </style>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        primary: '#667eea',
                        secondary: '#764ba2',
                    }
                }
            }
        }
    </script>
</head>
<body class="dark min-h-screen">
    {% block content %}{% endblock %}
</body>
</html>
"""

AUTH_PAGE = """
{% extends "base.html" %}
{% block content %}
<div class="min-h-screen flex items-center justify-center px-4 py-12">
    <div class="max-w-md w-full">
        <!-- Logo -->
        <div class="text-center mb-8 animate-fade-in">
            <div class="inline-flex items-center justify-center w-16 h-16 gradient-bg rounded-2xl mb-4">
                <i class="fas fa-rocket text-3xl text-white"></i>
            </div>
            <h1 class="text-4xl font-black gradient-text mb-2">EliteHost</h1>
            <p class="text-gray-400">Professional Deployment Platform</p>
        </div>

        <!-- Card -->
        <div class="card-dark rounded-2xl p-8 shadow-2xl animate-fade-in">
            {% if error %}
            <div class="bg-red-500/10 border border-red-500/50 rounded-lg p-4 mb-6 flex items-start gap-3">
                <i class="fas fa-exclamation-circle text-red-500 mt-0.5"></i>
                <span class="text-red-400 text-sm">{{ error }}</span>
            </div>
            {% endif %}
            
            {% if success %}
            <div class="bg-green-500/10 border border-green-500/50 rounded-lg p-4 mb-6 flex items-start gap-3">
                <i class="fas fa-check-circle text-green-500 mt-0.5"></i>
                <span class="text-green-400 text-sm">{{ success }}</span>
            </div>
            {% endif %}

            <form method="POST" action="{{ action }}" class="space-y-6">
                <div>
                    <label class="block text-sm font-semibold text-gray-300 mb-2">
                        <i class="fas fa-envelope mr-2"></i>Email Address
                    </label>
                    <input type="email" name="email" required
                           class="input-dark w-full px-4 py-3 rounded-lg transition-all"
                           placeholder="you@example.com">
                </div>

                <div>
                    <label class="block text-sm font-semibold text-gray-300 mb-2">
                        <i class="fas fa-lock mr-2"></i>Password
                    </label>
                    <input type="password" name="password" required
                           class="input-dark w-full px-4 py-3 rounded-lg transition-all"
                           placeholder="Enter your password">
                </div>

                {% if is_login %}
                <div class="text-right">
                    <a href="{{ TELEGRAM_LINK }}" target="_blank" 
                       class="text-sm text-primary hover:text-secondary transition-colors">
                        <i class="fas fa-key mr-1"></i>Forgot Password?
                    </a>
                </div>
                {% endif %}

                <button type="submit" 
                        class="w-full gradient-bg text-white font-bold py-3 px-6 rounded-lg hover:opacity-90 transition-all transform hover:scale-[1.02]">
                    <i class="fas fa-{{ icon }} mr-2"></i>{{ button_text }}
                </button>
            </form>

            <div class="mt-6 text-center text-sm text-gray-400">
                {{ toggle_text }}
                <a href="{{ toggle_link }}" class="text-primary hover:text-secondary font-semibold ml-1">
                    {{ toggle_action }}
                </a>
            </div>

            {% if not is_login %}
            <div class="mt-6 p-4 bg-blue-500/10 border border-blue-500/30 rounded-lg">
                <div class="flex items-start gap-3">
                    <i class="fas fa-info-circle text-blue-400 mt-0.5"></i>
                    <div class="text-xs text-blue-300">
                        <strong>One Account Per Device:</strong> For security, each device can only register one account.
                    </div>
                </div>
            </div>
            {% endif %}
        </div>

        <div class="mt-6 text-center text-xs text-gray-500">
            <p>© 2025 EliteHost. All rights reserved.</p>
        </div>
    </div>
</div>
{% endblock %}
