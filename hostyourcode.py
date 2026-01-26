# -*- coding: utf-8 -*-
"""
🚀 ELITEHOST v11.0 - ULTIMATE MOBILE-FIRST EDITION
Next-Gen AI-Powered Deployment Platform
Advanced Mobile UI | Fixed Bottom Actions | Real-time Updates
"""

import sys
import subprocess
import os

# ==================== SMART DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 ENTERPRISE DEPENDENCY INSTALLER v11.0")
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
    'vps_command': 0.3,
    'backup': 0.5,
}

# Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'elitehost_data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
DEPLOYS_DIR = os.path.join(DATA_DIR, 'deployments')
BACKUPS_DIR = os.path.join(DATA_DIR, 'backups')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
PAYMENTS_DIR = os.path.join(DATA_DIR, 'payments')
DB_FILE = os.path.join(DATA_DIR, 'database.json')

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, BACKUPS_DIR, LOGS_DIR, PAYMENTS_DIR]:
    os.makedirs(d, exist_ok=True)

# Flask & Bot
app = Flask(__name__)
app.secret_key = WEB_SECRET_KEY
CORS(app)
bot = telebot.TeleBot(TOKEN, parse_mode='Markdown')

# Global state
active_processes = {}
deployment_logs = {}
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

# ==================== DATABASE FUNCTIONS ====================

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
        'activity': [],
        'banned_devices': [],
        'password_reset_tokens': {}
    }

def save_db(db):
    with DB_LOCK:
        db_copy = db.copy()
        if 'banned_devices' in db_copy and isinstance(db_copy['banned_devices'], set):
            db_copy['banned_devices'] = list(db_copy['banned_devices'])
        with open(DB_FILE, 'w') as f:
            json.dump(db_copy, f, indent=2, default=str)

db = load_db()
if 'banned_devices' in db and isinstance(db['banned_devices'], list):
    db['banned_devices'] = set(db['banned_devices'])
if 'password_reset_tokens' not in db:
    db['password_reset_tokens'] = {}

# ==================== HELPER FUNCTIONS ====================

def get_device_fingerprint(request):
    user_agent = request.headers.get('User-Agent', '')
    ip = request.remote_addr or request.environ.get('HTTP_X_REAL_IP', 'unknown')
    accept_lang = request.headers.get('Accept-Language', '')
    fingerprint_str = f"{user_agent}|{ip}|{accept_lang}"
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()

def is_device_banned(fingerprint):
    return fingerprint in db.get('banned_devices', set())

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
    
    try:
        bot.send_message(
            OWNER_ID,
            f"🎉 *New User Registration*\n\n"
            f"📧 Email: `{email}`\n"
            f"🆔 ID: `{user_id}`\n"
            f"📍 IP: `{ip}`\n"
            f"💎 Credits: {FREE_CREDITS}\n"
            f"📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
    except:
        pass
    
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

# ==================== AI DEPENDENCY SYSTEM ====================

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
    
    install_log.append("🤖 AI DEPENDENCY ANALYZER v11.0")
    install_log.append("=" * 60)
    
    req_file = os.path.join(project_path, 'requirements.txt')
    if os.path.exists(req_file):
        install_log.append("\n📦 REQUIREMENTS.TXT DETECTED")
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
                except:
                    install_log.append(f"  ⚠️  {pkg} (skipped)")
        except Exception as e:
            install_log.append(f"❌ Error: {str(e)[:100]}")
    
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
            except:
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
                        install_log.append(f"  ✅ {pkg} (auto-detected)")
                        installed.append(pkg)
                    except:
                        pass
    
    install_log.append("\n" + "=" * 60)
    install_log.append(f"📦 Total: {len(installed)} packages")
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
        'env_vars': kwargs.get('env_vars', {}),
        'path': ''
    }
    
    db['deployments'][deploy_id] = deployment
    
    user = get_user(user_id)
    if user:
        user['deployments'].append(deploy_id)
        update_user(user_id, deployments=user['deployments'])
    
    log_activity(user_id, 'DEPLOYMENT_CREATE', f"{name} ({deploy_type})")
    save_db(db)
    
    return deploy_id, port

def update_deployment(deploy_id, **kwargs):
    if deploy_id in db['deployments']:
        db['deployments'][deploy_id].update(kwargs)
        db['deployments'][deploy_id]['updated_at'] = datetime.now().isoformat()
        save_db(db)

def deploy_from_file(user_id, file_path, filename):
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
                add_credits(user_id, cost, "Refund")
                return None, "❌ No main file found"
            
            file_path = main_file
        else:
            shutil.copy(file_path, os.path.join(deploy_dir, filename))
            file_path = os.path.join(deploy_dir, filename)
        
        update_deployment(deploy_id, path=deploy_dir, status='installing', logs='🤖 AI analyzing...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        update_deployment(deploy_id, dependencies=installed_deps)
        
        user = get_user(user_id)
        try:
            bot.send_message(
                OWNER_ID,
                f"📁 *File Upload Deploy*\n\n"
                f"👤 User: `{user['email']}`\n"
                f"📄 File: `{filename}`\n"
                f"🆔 ID: `{deploy_id}`\n"
                f"🔌 Port: `{port}`\n"
                f"📦 Deps: `{len(installed_deps)}`"
            )
        except:
            pass
        
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
        if 'deploy_id' in locals():
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
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        update_deployment(deploy_id, path=deploy_dir, status='cloning', logs=f'🔄 Cloning {repo_url}...')
        
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
        
        user = get_user(user_id)
        try:
            bot.send_message(
                OWNER_ID,
                f"🐙 *GitHub Deploy*\n\n"
                f"👤 User: `{user['email']}`\n"
                f"📦 Repo: `{repo_url}`\n"
                f"🌿 Branch: `{branch}`\n"
                f"🆔 ID: `{deploy_id}`\n"
                f"🔌 Port: `{port}`"
            )
        except:
            pass
        
        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        update_deployment(deploy_id, dependencies=installed_deps)
        
        if build_cmd:
            update_deployment(deploy_id, status='building', logs=f'🔨 Building: {build_cmd}...')
            result = subprocess.run(
                build_cmd,
                shell=True,
                cwd=deploy_dir,
                capture_output=True,
                text=True,
                timeout=600
            )
            if result.returncode != 0:
                update_deployment(deploy_id, status='failed', logs=f'❌ Build failed: {result.stderr}')
                add_credits(user_id, cost, "Refund")
                return None, "❌ Build failed"
        
        if start_cmd:
            command = start_cmd
        else:
            main_files = {
                'main.py': f'{sys.executable} main.py',
                'app.py': f'{sys.executable} app.py',
                'bot.py': f'{sys.executable} bot.py',
                'index.js': 'node index.js',
                'server.js': 'node server.js',
            }
            
            command = None
            for file, cmd in main_files.items():
                if os.path.exists(os.path.join(deploy_dir, file)):
                    command = cmd
                    break
            
            if not command:
                update_deployment(deploy_id, status='failed', logs='❌ No start command')
                add_credits(user_id, cost, "Refund")
                return None, "❌ No start file found"
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Starting...')
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        deployment = db['deployments'][deploy_id]
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = value
        
        process = subprocess.Popen(
            command.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=deploy_dir,
            env=env
        )
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, status='running', pid=process.pid, logs=f'✅ Running on port {port}!')
        
        return deploy_id, f"🎉 Deployed! Port {port}"
    
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
        
        deployment = db['deployments'][deploy_id]
        deploy_dir = deployment.get('path', '')
        
        if not deploy_dir or not os.path.exists(deploy_dir):
            return None, "Deployment path not found"
        
        backup_name = f"{deployment['name']}_{deploy_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        backup_path = os.path.join(BACKUPS_DIR, backup_name)
        
        shutil.make_archive(backup_path.replace('.zip', ''), 'zip', deploy_dir)
        
        return backup_path, backup_name
    except Exception as e:
        return None, str(e)

def get_deployment_files(deploy_id):
    try:
        if deploy_id not in db['deployments']:
            return []
        
        deployment = db['deployments'][deploy_id]
        deploy_dir = deployment.get('path', '')
        
        if not deploy_dir or not os.path.exists(deploy_dir):
            return []
        
        files = []
        for root, dirs, filenames in os.walk(deploy_dir):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, deploy_dir)
                size = os.path.getsize(filepath)
                files.append({
                    'name': filename,
                    'path': rel_path,
                    'size': size,
                    'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                })
        
        return files
    except Exception as e:
        return []

# ==================== HTML TEMPLATES ====================

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>EliteHost - Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        * { -webkit-tap-highlight-color: transparent; }
        body { overscroll-behavior-y: contain; }
        @keyframes slideUp {
            from { transform: translateY(20px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .animate-slide-up { animation: slideUp 0.4s ease-out; }
    </style>
</head>
<body class="bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900 text-gray-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md animate-slide-up">
        <div class="bg-gray-900/80 backdrop-blur-xl border border-gray-700 rounded-3xl p-8 shadow-2xl">
            <div class="text-center mb-8">
                <div class="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl mb-4 shadow-lg shadow-blue-500/50">
                    <i class="fas fa-rocket text-3xl text-white"></i>
                </div>
                <h1 class="text-4xl font-black mb-2 bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">EliteHost</h1>
                <p class="text-gray-400 text-sm">Mobile-First Deployment Platform</p>
            </div>
            
            {% if error %}
            <div class="bg-red-500/10 border-l-4 border-red-500 text-red-400 px-4 py-3 rounded-lg mb-4 text-sm animate-slide-up">
                <i class="fas fa-exclamation-circle mr-2"></i>{{ error }}
            </div>
            {% endif %}
            
            {% if success %}
            <div class="bg-green-500/10 border-l-4 border-green-500 text-green-400 px-4 py-3 rounded-lg mb-4 text-sm animate-slide-up">
                <i class="fas fa-check-circle mr-2"></i>{{ success }}
            </div>
            {% endif %}
            
            <form method="POST" action="{{ action }}" class="space-y-5">
                <div>
                    <label class="block text-sm font-semibold mb-2 text-gray-300">
                        <i class="fas fa-envelope mr-2 text-blue-400"></i>Email
                    </label>
                    <input type="email" name="email" required
                        class="w-full px-5 py-4 bg-gray-800/50 border border-gray-700 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition text-white text-lg">
                </div>
                
                <div>
                    <label class="block text-sm font-semibold mb-2 text-gray-300">
                        <i class="fas fa-lock mr-2 text-purple-400"></i>Password
                    </label>
                    <input type="password" name="password" required
                        class="w-full px-5 py-4 bg-gray-800/50 border border-gray-700 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition text-white text-lg">
                </div>
                
                <button type="submit" 
                    class="w-full py-4 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 rounded-xl font-bold text-lg transition transform active:scale-95 shadow-lg shadow-blue-500/50">
                    <i class="fas fa-{{ icon }} mr-2"></i>{{ button_text }}
                </button>
            </form>
            
            <div class="mt-6 text-center text-sm text-gray-400">
                {{ toggle_text }} <a href="{{ toggle_link }}" class="text-blue-400 hover:text-blue-300 font-bold">{{ toggle_action }}</a>
            </div>
            
            {% if action == '/login' %}
            <div class="mt-4 text-center">
                <a href="/forgot-password" class="text-sm text-purple-400 hover:text-purple-300 font-semibold">
                    <i class="fas fa-key mr-1"></i>Forgot Password?
                </a>
            </div>
            {% endif %}
            
            <div class="mt-6 pt-6 border-t border-gray-700">
                <div class="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4 text-xs text-gray-300">
                    <i class="fas fa-shield-alt text-blue-400 mr-2"></i>
                    <strong>Secure:</strong> One account per device
                </div>
            </div>
        </div>
        
        <div class="text-center mt-6 text-xs text-gray-500">
            <p>© 2025 EliteHost v11.0 - Ultimate Edition</p>
        </div>
    </div>
</body>
</html>
"""

FORGOT_PASSWORD_PAGE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Forgot Password - EliteHost</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gradient-to-br from-gray-900 via-orange-900 to-red-900 text-gray-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md">
        <div class="bg-gray-900/80 backdrop-blur-xl border border-gray-700 rounded-3xl p-8 shadow-2xl">
            <div class="text-center mb-8">
                <div class="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-orange-500 to-red-600 rounded-2xl mb-4 shadow-lg">
                    <i class="fas fa-key text-3xl text-white"></i>
                </div>
                <h1 class="text-3xl font-black mb-2">Reset Password</h1>
                <p class="text-gray-400 text-sm">Contact admin for assistance</p>
            </div>
            
            <div class="bg-yellow-500/10 border-l-4 border-yellow-500 text-yellow-400 px-4 py-4 rounded-lg mb-6 text-sm">
                <i class="fas fa-info-circle mr-2"></i>
                <strong>Reset Process:</strong> Contact admin via Telegram
            </div>
            
            <a href="{{ telegram_link }}" target="_blank"
                class="block w-full py-4 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 rounded-xl font-bold text-center transition transform active:scale-95 shadow-lg text-lg">
                <i class="fab fa-telegram mr-2"></i>Contact Admin
            </a>
            
            <div class="mt-6 text-center">
                <a href="/login" class="text-sm text-gray-400 hover:text-gray-300 font-semibold">
                    <i class="fas fa-arrow-left mr-1"></i>Back to Login
                </a>
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Dashboard - EliteHost</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        * { -webkit-tap-highlight-color: transparent; }
        [x-cloak] { display: none !important; }
        body { overscroll-behavior-y: contain; padding-bottom: 80px; }
        .scrollbar-hide::-webkit-scrollbar { display: none; }
        .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
        @keyframes pulse-subtle { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
        .animate-pulse-subtle { animation: pulse-subtle 2s ease-in-out infinite; }
    </style>
</head>
<body class="bg-gray-950 text-gray-100" x-data="dashboard()" x-init="init()">
    
    <!-- Top Bar -->
    <div class="fixed top-0 left-0 right-0 z-50 bg-gray-900/95 backdrop-blur-lg border-b border-gray-800">
        <div class="flex items-center justify-between px-4 py-3">
            <div class="flex items-center gap-3">
                <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl flex items-center justify-center shadow-lg">
                    <i class="fas fa-rocket text-white"></i>
                </div>
                <div>
                    <h1 class="font-black text-lg leading-none">EliteHost</h1>
                    <p class="text-xs text-gray-400">v11.0</p>
                </div>
            </div>
            <div class="flex items-center gap-3">
                <div class="bg-gradient-to-r from-blue-500 to-purple-600 px-4 py-2 rounded-full flex items-center gap-2 shadow-lg">
                    <i class="fas fa-gem text-white"></i>
                    <span class="font-bold text-white" x-text="credits === Infinity ? '∞' : credits.toFixed(1)">0</span>
                </div>
                {% if is_admin %}
                <button @click="window.location.href='/admin'" class="w-10 h-10 bg-yellow-500/20 rounded-xl flex items-center justify-center">
                    <i class="fas fa-crown text-yellow-400"></i>
                </button>
                {% endif %}
            </div>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="pt-20 px-4 pb-4">
        
        <!-- Tab Navigation -->
        <div class="flex gap-2 mb-6 overflow-x-auto scrollbar-hide pb-2">
            <button @click="currentTab = 'overview'" 
                    :class="currentTab === 'overview' ? 'bg-blue-500 text-white' : 'bg-gray-800 text-gray-400'"
                    class="px-6 py-3 rounded-xl font-bold whitespace-nowrap transition transform active:scale-95 flex-shrink-0">
                <i class="fas fa-home mr-2"></i>Overview
            </button>
            <button @click="currentTab = 'deployments'" 
                    :class="currentTab === 'deployments' ? 'bg-blue-500 text-white' : 'bg-gray-800 text-gray-400'"
                    class="px-6 py-3 rounded-xl font-bold whitespace-nowrap transition transform active:scale-95 flex-shrink-0">
                <i class="fas fa-rocket mr-2"></i>Deployments
            </button>
        </div>
        
        <!-- Overview Tab -->
        <div x-show="currentTab === 'overview'" x-cloak>
            <h2 class="text-2xl font-black mb-4">Welcome Back! 👋</h2>
            
            <!-- Stats Grid -->
            <div class="grid grid-cols-2 gap-3 mb-6">
                <div class="bg-gradient-to-br from-blue-500/20 to-blue-600/20 border border-blue-500/30 rounded-2xl p-4">
                    <div class="text-3xl font-black mb-1" x-text="deployments.length">0</div>
                    <div class="text-xs text-gray-400 font-semibold">Total Deploys</div>
                    <i class="fas fa-rocket text-blue-400 text-2xl opacity-20 absolute bottom-2 right-2"></i>
                </div>
                
                <div class="bg-gradient-to-br from-green-500/20 to-green-600/20 border border-green-500/30 rounded-2xl p-4">
                    <div class="text-3xl font-black mb-1" x-text="deployments.filter(d => d.status === 'running').length">0</div>
                    <div class="text-xs text-gray-400 font-semibold">Active Now</div>
                    <i class="fas fa-play text-green-400 text-2xl opacity-20 absolute bottom-2 right-2"></i>
                </div>
                
                <div class="bg-gradient-to-br from-purple-500/20 to-purple-600/20 border border-purple-500/30 rounded-2xl p-4">
                    <div class="text-3xl font-black mb-1" x-text="credits === Infinity ? '∞' : credits.toFixed(1)">0</div>
                    <div class="text-xs text-gray-400 font-semibold">Credits</div>
                    <i class="fas fa-gem text-purple-400 text-2xl opacity-20 absolute bottom-2 right-2"></i>
                </div>
                
                <div class="bg-gradient-to-br from-orange-500/20 to-orange-600/20 border border-orange-500/30 rounded-2xl p-4">
                    <div class="text-3xl font-black mb-1">AI</div>
                    <div class="text-xs text-gray-400 font-semibold">Auto Install</div>
                    <i class="fas fa-robot text-orange-400 text-2xl opacity-20 absolute bottom-2 right-2"></i>
                </div>
            </div>
            
            <!-- Recent Deployments -->
            <div class="bg-gray-900 border border-gray-800 rounded-2xl p-4 mb-4">
                <h3 class="font-black text-lg mb-3">Recent Deployments</h3>
                <div class="space-y-2" x-show="deployments.length > 0">
                    <template x-for="deploy in deployments.slice(0, 3)" :key="deploy.id">
                        <div @click="viewDeployment(deploy.id)" class="bg-gray-800 rounded-xl p-4 active:bg-gray-700 transition">
                            <div class="flex items-center justify-between mb-2">
                                <span class="font-bold" x-text="deploy.name"></span>
                                <span :class="{
                                    'bg-green-500/20 text-green-400': deploy.status === 'running',
                                    'bg-yellow-500/20 text-yellow-400': deploy.status === 'pending',
                                    'bg-red-500/20 text-red-400': deploy.status === 'stopped'
                                }" class="px-3 py-1 rounded-full text-xs font-bold" x-text="deploy.status"></span>
                            </div>
                            <div class="text-xs text-gray-400">
                                <i class="fas fa-network-wired mr-1"></i>Port <span x-text="deploy.port"></span>
                            </div>
                        </div>
                    </template>
                </div>
                <div x-show="deployments.length === 0" class="text-center py-8 text-gray-500">
                    <i class="fas fa-rocket text-4xl mb-2 opacity-30"></i>
                    <p class="text-sm">No deployments yet</p>
                </div>
            </div>
        </div>
        
        <!-- Deployments Tab -->
        <div x-show="currentTab === 'deployments'" x-cloak>
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-2xl font-black">All Deployments</h2>
                <button @click="loadDeployments()" class="w-10 h-10 bg-gray-800 rounded-xl flex items-center justify-center active:bg-gray-700">
                    <i class="fas fa-sync" :class="{'animate-spin': loading}"></i>
                </button>
            </div>
            
            <div class="space-y-3" x-show="deployments.length > 0">
                <template x-for="deploy in deployments" :key="deploy.id">
                    <div class="bg-gray-900 border border-gray-800 rounded-2xl p-4">
                        <div class="flex items-start justify-between mb-3">
                            <div class="flex-1">
                                <h3 class="font-bold text-lg mb-1" x-text="deploy.name"></h3>
                                <div class="flex flex-wrap gap-2 text-xs text-gray-400">
                                    <span><i class="fas fa-fingerprint mr-1"></i><span x-text="deploy.id"></span></span>
                                    <span><i class="fas fa-network-wired mr-1"></i>Port <span x-text="deploy.port"></span></span>
                                </div>
                            </div>
                            <span :class="{
                                'bg-green-500/20 text-green-400': deploy.status === 'running',
                                'bg-yellow-500/20 text-yellow-400': deploy.status === 'pending',
                                'bg-red-500/20 text-red-400': deploy.status === 'stopped'
                            }" class="px-3 py-1 rounded-full text-xs font-bold uppercase" x-text="deploy.status"></span>
                        </div>
                        
                        <div class="grid grid-cols-2 gap-2">
                            <button @click="viewDeployment(deploy.id)" 
                                    class="py-3 bg-blue-500/20 text-blue-400 rounded-xl font-bold text-sm transition active:scale-95">
                                <i class="fas fa-eye mr-1"></i>View
                            </button>
                            <button @click="stopDeploy(deploy.id)" 
                                    class="py-3 bg-red-500/20 text-red-400 rounded-xl font-bold text-sm transition active:scale-95">
                                <i class="fas fa-stop mr-1"></i>Stop
                            </button>
                        </div>
                    </div>
                </template>
            </div>
            
            <div x-show="deployments.length === 0" class="text-center py-16">
                <i class="fas fa-rocket text-6xl text-gray-700 mb-4 animate-pulse-subtle"></i>
                <h3 class="text-xl font-bold mb-2">No Deployments</h3>
                <p class="text-gray-400 mb-6">Start deploying your apps now!</p>
            </div>
        </div>
    </div>
    
    <!-- Deployment Detail Modal -->
    <div x-show="selectedDeploy" 
         x-cloak
         @click.self="selectedDeploy = null"
         class="fixed inset-0 bg-black/90 z-[60] flex items-end sm:items-center justify-center p-0 sm:p-4">
        <div @click.stop class="bg-gray-900 border-t sm:border border-gray-800 rounded-t-3xl sm:rounded-3xl w-full sm:max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
            
            <!-- Modal Header -->
            <div class="flex items-center justify-between p-6 border-b border-gray-800 bg-gray-900/95 backdrop-blur-lg sticky top-0 z-10">
                <div class="flex-1 pr-4">
                    <h2 class="text-xl font-black truncate" x-text="selectedDeploy?.name"></h2>
                    <p class="text-xs text-gray-400 truncate">ID: <span x-text="selectedDeploy?.id"></span></p>
                </div>
                <button @click="selectedDeploy = null" class="w-10 h-10 bg-gray-800 rounded-xl flex items-center justify-center flex-shrink-0">
                    <i class="fas fa-times text-xl"></i>
                </button>
            </div>
            
            <!-- Modal Tabs -->
            <div class="border-b border-gray-800 bg-gray-900 sticky top-[73px] z-10">
                <div class="flex gap-1 overflow-x-auto scrollbar-hide px-4">
                    <button @click="modalTab = 'info'" 
                            :class="modalTab === 'info' ? 'bg-blue-500 text-white' : 'text-gray-400'"
                            class="py-3 px-4 font-bold text-sm whitespace-nowrap rounded-t-xl transition">
                        <i class="fas fa-info-circle mr-1"></i>Info
                    </button>
                    <button @click="modalTab = 'logs'; loadLogs()" 
                            :class="modalTab === 'logs' ? 'bg-blue-500 text-white' : 'text-gray-400'"
                            class="py-3 px-4 font-bold text-sm whitespace-nowrap rounded-t-xl transition">
                        <i class="fas fa-terminal mr-1"></i>Logs
                    </button>
                    <button @click="modalTab = 'env'; loadEnvVars()" 
                            :class="modalTab === 'env' ? 'bg-blue-500 text-white' : 'text-gray-400'"
                            class="py-3 px-4 font-bold text-sm whitespace-nowrap rounded-t-xl transition">
                        <i class="fas fa-key mr-1"></i>Env
                    </button>
                    <button @click="modalTab = 'files'; loadFiles()" 
                            :class="modalTab === 'files' ? 'bg-blue-500 text-white' : 'text-gray-400'"
                            class="py-3 px-4 font-bold text-sm whitespace-nowrap rounded-t-xl transition">
                        <i class="fas fa-folder mr-1"></i>Files
                    </button>
                    <button @click="modalTab = 'backup'" 
                            :class="modalTab === 'backup' ? 'bg-blue-500 text-white' : 'text-gray-400'"
                            class="py-3 px-4 font-bold text-sm whitespace-nowrap rounded-t-xl transition">
                        <i class="fas fa-download mr-1"></i>Backup
                    </button>
                </div>
            </div>
            
            <!-- Modal Content -->
            <div class="flex-1 overflow-y-auto p-6 scrollbar-hide">
                
                <!-- Info Tab -->
                <div x-show="modalTab === 'info'" class="space-y-3">
                    <div class="grid grid-cols-2 gap-3">
                        <div class="bg-gray-800 rounded-xl p-4">
                        <h4 class="font-bold mb-3 text-sm">What's Included</h4>
                        <ul class="space-y-2 text-sm text-gray-400">
                            <li><i class="fas fa-check text-green-400 mr-2"></i>All project files</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>ZIP format</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>Ready for re-deploy</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Fixed Bottom Actions -->
    <div class="fixed bottom-0 left-0 right-0 z-50 bg-gray-900/95 backdrop-blur-lg border-t border-gray-800 p-4">
        <div class="grid grid-cols-2 gap-3 max-w-lg mx-auto">
            <button @click="showUploadModal = true" 
                    class="py-4 bg-gradient-to-r from-blue-500 to-blue-600 rounded-2xl font-bold shadow-lg shadow-blue-500/30 transition active:scale-95">
                <i class="fas fa-cloud-upload-alt mr-2"></i>Upload File
            </button>
            <button @click="showGithubModal = true" 
                    class="py-4 bg-gradient-to-r from-gray-700 to-gray-800 rounded-2xl font-bold shadow-lg transition active:scale-95">
                <i class="fab fa-github mr-2"></i>GitHub
            </button>
        </div>
    </div>
    
    <!-- Upload Modal -->
    <div x-show="showUploadModal" 
         x-cloak
         @click.self="showUploadModal = false"
         class="fixed inset-0 bg-black/90 z-[70] flex items-end sm:items-center justify-center p-0 sm:p-4">
        <div @click.stop class="bg-gray-900 border-t sm:border border-gray-800 rounded-t-3xl sm:rounded-3xl w-full sm:max-w-lg p-6">
            <div class="flex items-center justify-between mb-6">
                <h2 class="text-2xl font-black">Upload & Deploy</h2>
                <button @click="showUploadModal = false" class="w-10 h-10 bg-gray-800 rounded-xl">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <div @click="$refs.fileInput.click()" 
                 class="border-2 border-dashed border-blue-500/50 rounded-2xl p-12 text-center mb-4 active:bg-blue-500/5">
                <i class="fas fa-cloud-upload-alt text-5xl text-blue-400 mb-4"></i>
                <h3 class="font-bold text-lg mb-2">Tap to Upload</h3>
                <p class="text-sm text-gray-400 mb-1">Python, JavaScript, ZIP</p>
                <p class="text-xs text-gray-500">AI auto-install dependencies</p>
                <input type="file" x-ref="fileInput" @change="uploadFile($event)" accept=".py,.js,.zip" class="hidden">
            </div>
            
            <div class="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4 text-sm text-gray-300">
                <strong>Cost:</strong> 0.5 credits
            </div>
        </div>
    </div>
    
    <!-- GitHub Modal -->
    <div x-show="showGithubModal" 
         x-cloak
         @click.self="showGithubModal = false"
         class="fixed inset-0 bg-black/90 z-[70] flex items-end sm:items-center justify-center p-0 sm:p-4 overflow-y-auto">
        <div @click.stop class="bg-gray-900 border-t sm:border border-gray-800 rounded-t-3xl sm:rounded-3xl w-full sm:max-w-lg p-6 my-auto">
            <div class="flex items-center justify-between mb-6">
                <h2 class="text-2xl font-black">GitHub Deploy</h2>
                <button @click="showGithubModal = false" class="w-10 h-10 bg-gray-800 rounded-xl">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <form @submit.prevent="deployGithub()" class="space-y-4">
                <div>
                    <label class="block text-sm font-bold mb-2">Repository URL *</label>
                    <input type="url" x-model="githubUrl" required placeholder="https://github.com/user/repo"
                           class="w-full px-4 py-4 bg-gray-800 border border-gray-700 rounded-xl outline-none text-white">
                </div>
                
                <div class="grid grid-cols-2 gap-3">
                    <div>
                        <label class="block text-sm font-bold mb-2">Branch</label>
                        <input type="text" x-model="githubBranch" placeholder="main"
                               class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl outline-none text-white">
                    </div>
                    <div>
                        <label class="block text-sm font-bold mb-2">Build Cmd</label>
                        <input type="text" x-model="buildCommand" placeholder="npm install"
                               class="w-full px-4 py-3 bg-gray-800 border border-gray-700 rounded-xl outline-none text-white">
                    </div>
                </div>
                
                <div>
                    <label class="block text-sm font-bold mb-2">Start Command</label>
                    <input type="text" x-model="startCommand" placeholder="node index.js"
                           class="w-full px-4 py-4 bg-gray-800 border border-gray-700 rounded-xl outline-none text-white">
                </div>
                
                <button type="submit" 
                        class="w-full py-4 bg-gradient-to-r from-gray-700 to-gray-900 rounded-xl font-bold transition active:scale-95">
                    <i class="fab fa-github mr-2"></i>Deploy (1.0 credit)
                </button>
            </form>
            
            <div class="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4 text-sm text-gray-300 mt-4">
                <strong>AI Features:</strong> Auto-detects, installs deps, deploys
            </div>
        </div>
    </div>
    
    <!-- Logout Confirmation -->
    <div x-show="showLogoutModal" 
         x-cloak
         @click.self="showLogoutModal = false"
         class="fixed inset-0 bg-black/90 z-[70] flex items-center justify-center p-4">
        <div @click.stop class="bg-gray-900 border border-gray-800 rounded-3xl p-6 max-w-sm w-full">
            <h3 class="text-xl font-black mb-4">Logout?</h3>
            <p class="text-gray-400 mb-6">Are you sure you want to logout?</p>
            <div class="grid grid-cols-2 gap-3">
                <button @click="showLogoutModal = false" class="py-3 bg-gray-800 rounded-xl font-bold">Cancel</button>
                <button @click="window.location.href='/logout'" class="py-3 bg-red-500 rounded-xl font-bold">Logout</button>
            </div>
        </div>
    </div>
    
    <script>
        function dashboard() {
            return {
                currentTab: 'overview',
                modalTab: 'info',
                deployments: [],
                credits: 0,
                selectedDeploy: null,
                logs: '',
                envVars: {},
                files: [],
                showAddEnv: false,
                newEnvKey: '',
                newEnvValue: '',
                githubUrl: '',
                githubBranch: 'main',
                buildCommand: '',
                startCommand: '',
                showUploadModal: false,
                showGithubModal: false,
                showLogoutModal: false,
                loading: false,
                
                init() {
                    this.loadDeployments();
                    this.loadCredits();
                    setInterval(() => {
                        this.loadDeployments();
                        this.loadCredits();
                    }, 10000);
                },
                
                async loadDeployments() {
                    try {
                        this.loading = true;
                        const res = await fetch('/api/deployments');
                        const data = await res.json();
                        if (data.success) {
                            this.deployments = data.deployments;
                        }
                    } catch (e) {
                        console.error(e);
                    } finally {
                        this.loading = false;
                    }
                },
                
                async loadCredits() {
                    try {
                        const res = await fetch('/api/credits');
                        const data = await res.json();
                        if (data.success) {
                            this.credits = data.credits;
                        }
                    } catch (e) {
                        console.error(e);
                    }
                },
                
                async uploadFile(event) {
                    const file = event.target.files[0];
                    if (!file) return;
                    
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    this.showUploadModal = false;
                    alert('🤖 Uploading... Please wait!');
                    
                    try {
                        const res = await fetch('/api/deploy/upload', {
                            method: 'POST',
                            body: formData
                        });
                        const data = await res.json();
                        
                        if (data.success) {
                            alert('✅ Success!\n\n' + data.message);
                            this.loadDeployments();
                            this.loadCredits();
                            this.currentTab = 'deployments';
                        } else {
                            alert('❌ Error: ' + data.error);
                        }
                    } catch (e) {
                        alert('❌ Error: ' + e.message);
                    }
                    
                    event.target.value = '';
                },
                
                async deployGithub() {
                    if (!this.githubUrl) return;
                    
                    this.showGithubModal = false;
                    alert('🤖 Cloning... This may take a minute!');
                    
                    try {
                        const res = await fetch('/api/deploy/github', {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                url: this.githubUrl,
                                branch: this.githubBranch || 'main',
                                build_command: this.buildCommand,
                                start_command: this.startCommand
                            })
                        });
                        const data = await res.json();
                        
                        if (data.success) {
                            alert('✅ Success!\n\n' + data.message);
                            this.loadDeployments();
                            this.loadCredits();
                            this.currentTab = 'deployments';
                            this.githubUrl = '';
                            this.githubBranch = 'main';
                            this.buildCommand = '';
                            this.startCommand = '';
                        } else {
                            alert('❌ Error: ' + data.error);
                        }
                    } catch (e) {
                        alert('❌ Error: ' + e.message);
                    }
                },
                
                viewDeployment(id) {
                    this.selectedDeploy = this.deployments.find(d => d.id === id);
                    this.modalTab = 'info';
                },
                
                async loadLogs() {
                    if (!this.selectedDeploy) return;
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/logs`);
                        const data = await res.json();
                        this.logs = data.logs || 'No logs';
                    } catch (e) {
                        this.logs = 'Error loading logs';
                    }
                },
                
                async loadEnvVars() {
                    if (!this.selectedDeploy) return;
                    this.envVars = this.selectedDeploy.env_vars || {};
                },
                
                async addEnvVar() {
                    if (!this.newEnvKey || !this.newEnvValue || !this.selectedDeploy) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env`, {
                            method: 'POST',
                            headers: {'Content-Type': 'application/json'},
                            body: JSON.stringify({
                                key: this.newEnvKey,
                                value: this.newEnvValue
                            })
                        });
                        const data = await res.json();
                        
                        if (data.success) {
                            this.envVars[this.newEnvKey] = this.newEnvValue;
                            this.newEnvKey = '';
                            this.newEnvValue = '';
                            this.showAddEnv = false;
                            await this.loadDeployments();
                            alert('✅ Variable added!');
                        } else {
                            alert('❌ Error: ' + data.error);
                        }
                    } catch (e) {
                        alert('❌ Error: ' + e.message);
                    }
                },
                
                async deleteEnvVar(key) {
                    if (!confirm(`Delete "${key}"?`)) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env/${key}`, {
                            method: 'DELETE'
                        });
                        const data = await res.json();
                        
                        if (data.success) {
                            delete this.envVars[key];
                            await this.loadDeployments();
                            alert('✅ Deleted!');
                        } else {
                            alert('❌ Error: ' + data.error);
                        }
                    } catch (e) {
                        alert('❌ Error: ' + e.message);
                    }
                },
                
                async loadFiles() {
                    if (!this.selectedDeploy) return;
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/files`);
                        const data = await res.json();
                        this.files = data.files || [];
                    } catch (e) {
                        this.files = [];
                    }
                },
                
                async createBackup() {
                    if (!confirm('Create backup for 0.5 credits?')) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/backup`, {
                            method: 'POST'
                        });
                        
                        if (res.ok) {
                            const blob = await res.blob();
                            const url = window.URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = `backup_${this.selectedDeploy.id}.zip`;
                            a.click();
                            window.URL.revokeObjectURL(url);
                            this.loadCredits();
                            alert('✅ Backup downloaded!');
                        } else {
                            const data = await res.json();
                            alert('❌ Error: ' + data.error);
                        }
                    } catch (e) {
                        alert('❌ Error: ' + e.message);
                    }
                },
                
                async stopDeploy(id) {
                    if (!confirm('Stop deployment?')) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${id}/stop`, {method: 'POST'});
                        const data = await res.json();
                        alert(data.success ? '✅ Stopped' : '❌ ' + data.message);
                        await this.loadDeployments();
                    } catch (e) {
                        alert('❌ Error: ' + e.message);
                    }
                },
                
                async deleteDeploy(id) {
                    if (!confirm('Delete permanently?')) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${id}`, {method: 'DELETE'});
                        const data = await res.json();
                        alert(data.success ? '✅ Deleted' : '❌ Failed');
                        await this.loadDeployments();
                    } catch (e) {
                        alert('❌ Error: ' + e.message);
                    }
                }
            }
        }
    </script>
</body>
</html>
"""

ADMIN_PANEL_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Admin Panel - EliteHost</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        * { -webkit-tap-highlight-color: transparent; }
        body { overscroll-behavior-y: contain; }
    </style>
</head>
<body class="bg-gray-950 text-gray-100">
    <div class="min-h-screen pb-20">
        <!-- Header -->
        <header class="bg-gradient-to-r from-yellow-900 to-orange-900 border-b border-yellow-700">
            <div class="px-4 sm:px-6 lg:px-8 py-6">
                <div class="flex items-center justify-between mb-4">
                    <div class="flex items-center gap-3">
                        <div class="w-12 h-12 bg-yellow-500 rounded-xl flex items-center justify-center shadow-lg">
                            <i class="fas fa-crown text-gray-900 text-xl"></i>
                        </div>
                        <div>
                            <h1 class="text-2xl font-black">Admin Panel</h1>
                            <p class="text-yellow-200 text-sm">System Control</p>
                        </div>
                    </div>
                </div>
                <div class="flex gap-2">
                    <button onclick="location.reload()" class="px-4 py-2 bg-yellow-500/20 border border-yellow-500/50 rounded-xl font-bold text-sm">
                        <i class="fas fa-sync mr-2"></i>Refresh
                    </button>
                    <button onclick="window.location.href='/dashboard'" class="px-4 py-2 bg-blue-500 rounded-xl font-bold text-sm">
                        <i class="fas fa-arrow-left mr-2"></i>Dashboard
                    </button>
                </div>
            </div>
        </header>
        
        <main class="px-4 sm:px-6 lg:px-8 py-6">
            <!-- Stats -->
            <div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
                <div class="bg-gray-900 border border-gray-800 rounded-2xl p-4">
                    <div class="text-3xl font-black mb-1">{{ stats.total_users }}</div>
                    <div class="text-xs text-gray-400">Users</div>
                </div>
                <div class="bg-gray-900 border border-gray-800 rounded-2xl p-4">
                    <div class="text-3xl font-black mb-1">{{ stats.total_deployments }}</div>
                    <div class="text-xs text-gray-400">Deploys</div>
                </div>
                <div class="bg-gray-900 border border-gray-800 rounded-2xl p-4">
                    <div class="text-3xl font-black mb-1">{{ stats.active_processes }}</div>
                    <div class="text-xs text-gray-400">Active</div>
                </div>
                <div class="bg-gray-900 border border-gray-800 rounded-2xl p-4">
                    <div class="text-3xl font-black mb-1">{{ stats.pending_payments }}</div>
                    <div class="text-xs text-gray-400">Payments</div>
                </div>
            </div>
            
            <!-- Users -->
            <div class="bg-gray-900 border border-gray-800 rounded-2xl p-4 mb-6">
                <h2 class="text-xl font-black mb-4">Users</h2>
                <div class="space-y-2">
                    {% for user in users %}
                    <div class="bg-gray-800 rounded-xl p-4">
                        <div class="flex items-start justify-between mb-2">
                            <div class="flex-1 min-w-0 pr-4">
                                <div class="font-bold truncate">{{ user.email }}</div>
                                <div class="text-xs text-gray-400">
                                    💎 {{ user.credits }} | 🚀 {{ user.deployments|length }}
                                </div>
                            </div>
                            {% if user.is_banned %}
                            <span class="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-xs font-bold">Banned</span>
                            {% else %}
                            <span class="px-3 py-1 bg-green-500/20 text-green-400 rounded-full text-xs font-bold">Active</span>
                            {% endif %}
                        </div>
                        <div class="grid grid-cols-2 gap-2">
                            <button onclick="addCreditsPrompt('{{ user.id }}')" 
                                    class="py-2 bg-green-500/20 text-green-400 rounded-lg font-bold text-sm">
                                <i class="fas fa-plus mr-1"></i>Credits
                            </button>
                            {% if not user.is_banned %}
                            <button onclick="banUser('{{ user.id }}')" 
                                    class="py-2 bg-red-500/20 text-red-400 rounded-lg font-bold text-sm">
                                <i class="fas fa-ban mr-1"></i>Ban
                            </button>
                            {% else %}
                            <button onclick="unbanUser('{{ user.id }}')" 
                                    class="py-2 bg-blue-500/20 text-blue-400 rounded-lg font-bold text-sm">
                                <i class="fas fa-check mr-1"></i>Unban
                            </button>
                            {% endif %}
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
            
            <!-- Payments -->
            <div class="bg-gray-900 border border-gray-800 rounded-2xl p-4">
                <h2 class="text-xl font-black mb-4">Payments</h2>
                <div class="space-y-2">
                    {% for payment in payments %}
                    <div class="bg-gray-800 rounded-xl p-4">
                        <div class="flex items-start justify-between mb-2">
                            <div class="flex-1 min-w-0 pr-4">
                                <div class="font-bold truncate">{{ payment.user_email }}</div>
                                <div class="text-sm text-gray-400">{{ payment.amount }} credits</div>
                            </div>
                            {% if payment.status == 'pending' %}
                            <span class="px-3 py-1 bg-yellow-500/20 text-yellow-400 rounded-full text-xs font-bold">Pending</span>
                            {% elif payment.status == 'approved' %}
                            <span class="px-3 py-1 bg-green-500/20 text-green-400 rounded-full text-xs font-bold">Approved</span>
                            {% else %}
                            <span class="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-xs font-bold">Rejected</span>
                            {% endif %}
                        </div>
                        {% if payment.status == 'pending' %}
                        <div class="grid grid-cols-2 gap-2">
                            <button onclick="approvePayment('{{ payment.id }}', '{{ payment.user_id }}', {{ payment.amount }})" 
                                    class="py-2 bg-green-500/20 text-green-400 rounded-lg font-bold text-sm">
                                <i class="fas fa-check mr-1"></i>Approve
                            </button>
                            <button onclick="rejectPayment('{{ payment.id }}')" 
                                    class="py-2 bg-red-500/20 text-red-400 rounded-lg font-bold text-sm">
                                <i class="fas fa-times mr-1"></i>Reject
                            </button>
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
            </div>
        </main>
    </div>
    
    <script>
        function addCreditsPrompt(userId) {
            const amount = prompt('Credits to add:');
            if (!amount || isNaN(amount)) return;
            
            fetch('/api/admin/add-credits', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({user_id: userId, amount: parseFloat(amount)})
            })
            .then(r => r.json())
            .then(data => {
                alert(data.success ? '✅ Added!' : '❌ ' + data.error);
                location.reload();
            });
        }
        
        function banUser(userId) {
            if (!confirm('Ban this user?')) return;
            
            fetch('/api/admin/ban-user', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({user_id: userId, ban: true})
            })
            .then(r => r.json())
            .then(data => {
                alert(data.success ? '✅ Banned' : '❌ ' + data.error);
                location.reload();
            });
        }
        
        function unbanUser(userId) {
            if (!confirm('Unban this user?')) return;
            
            fetch('/api/admin/ban-user', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({user_id: userId, ban: false})
            })
            .then(r => r.json())
            .then(data => {
                alert(data.success ? '✅ Unbanned' : '❌ ' + data.error);
                location.reload();
            });
        }
        
        function approvePayment(paymentId, userId, amount) {
            if (!confirm(`Approve ${amount} credits?`)) return;
            
            fetch('/api/admin/approve-payment', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({payment_id: paymentId, user_id: userId, amount: amount})
            })
            .then(r => r.json())
            .then(data => {
                alert(data.success ? '✅ Approved!' : '❌ ' + data.error);
                location.reload();
            });
        }
        
        function rejectPayment(paymentId) {
            if (!confirm('Reject payment?')) return;
            
            fetch('/api/admin/reject-payment', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({payment_id: paymentId})
            })
            .then(r => r.json())
            .then(data => {
                alert(data.success ? '✅ Rejected' : '❌ ' + data.error);
                location.reload();
            });
        }
    </script>
</body>
</html>
"""

# ==================== FLASK ROUTES (CONTINUED) ====================

@app.route('/')
def index():
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string(LOGIN_PAGE,
            action='/register',
            button_text='Create Account',
            icon='user-plus',
            toggle_text='Already have account?',
            toggle_link='/login',
            toggle_action='Login',
            error=request.args.get('error'),
            success=request.args.get('success')
        )
    
    email = request.form.get('email')
    password = request.form.get('password')
    fingerprint = get_device_fingerprint(request)
    ip = request.remote_addr
    
    if is_device_banned(fingerprint):
        return render_template_string(LOGIN_PAGE,
            action='/register',
            button_text='Create Account',
            icon='user-plus',
            toggle_text='Already have account?',
            toggle_link='/login',
            toggle_action='Login',
            error='Device banned'
        )
    
    for user_data in db['users'].values():
        if user_data['email'] == email:
            return render_template_string(LOGIN_PAGE,
                action='/register',
                button_text='Create Account',
                icon='user-plus',
                toggle_text='Already have account?',
                toggle_link='/login',
                toggle_action='Login',
                error='Email already registered'
            )
    
    user_id = create_user(email, password, fingerprint, ip)
    
    return redirect('/login?success=Account created!')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_PAGE,
            action='/login',
            button_text='Login',
            icon='sign-in-alt',
            toggle_text="Don't have account?",
            toggle_link='/register',
            toggle_action='Register',
            error=request.args.get('error'),
            success=request.args.get('success')
        )
    
    email = request.form.get('email')
    password = request.form.get('password')
    fingerprint = get_device_fingerprint(request)
    
    if is_device_banned(fingerprint):
        return render_template_string(LOGIN_PAGE,
            action='/login',
            button_text='Login',
            icon='sign-in-alt',
            toggle_text="Don't have account?",
            toggle_link='/register',
            toggle_action='Register',
            error='Device banned'
        )
    
    user_id = authenticate_user(email, password)
    
    if not user_id:
        return render_template_string(LOGIN_PAGE,
            action='/login',
            button_text='Login',
            icon='sign-in-alt',
            toggle_text="Don't have account?",
            toggle_link='/register',
            toggle_action='Register',
            error='Invalid credentials'
        )
    
    user = get_user(user_id)
    
    if user.get('is_banned'):
        return render_template_string(LOGIN_PAGE,
            action='/login',
            button_text='Login',
            icon='sign-in-alt',
            toggle_text="Don't have account?",
            toggle_link='/register',
            toggle_action='Register',
            error='Account banned'
        )
    
    session_token = create_session(user_id, fingerprint)
    update_user(user_id, last_login=datetime.now().isoformat(), device_fingerprint=fingerprint)
    log_activity(user_id, 'USER_LOGIN', f'Login from {request.remote_addr}', request.remote_addr)
    
    response = make_response(redirect('/dashboard'))
    response.set_cookie('session_token', session_token, max_age=30*24*60*60)
    return response

@app.route('/forgot-password')
def forgot_password():
    return render_template_string(FORGOT_PASSWORD_PAGE, telegram_link=TELEGRAM_LINK)

@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')
    if session_token and session_token in db['sessions']:
        del db['sessions'][session_token]
        save_db(db)
    
    response = make_response(redirect('/login?success=Logged out'))
    response.set_cookie('session_token', '', max_age=0)
    return response

@app.route('/dashboard')
def dashboard():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    
    user_id = verify_session(session_token, fingerprint)
    if not user_id:
        return redirect('/login?error=Please login')
    
    user = get_user(user_id)
    if not user or user.get('is_banned'):
        return redirect('/login?error=Access denied')
    
    is_admin = str(user_id) == str(OWNER_ID) or str(user_id) == str(ADMIN_ID)
    
    return render_template_string(DASHBOARD_HTML, is_admin=is_admin)

@app.route('/admin')
def admin_panel():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    
    user_id = verify_session(session_token, fingerprint)
    if not user_id:
        return redirect('/login?error=Please login')
    
    if str(user_id) != str(OWNER_ID) and str(user_id) != str(ADMIN_ID):
        return redirect('/dashboard?error=Admin only')
    
    stats = {
        'total_users': len(db['users']),
        'total_deployments': len(db['deployments']),
        'active_processes': len(active_processes),
        'pending_payments': len([p for p in db.get('payments', {}).values() if p.get('status') == 'pending'])
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
        user = get_user(payment_data['user_id'])
        payments.append({
            'id': pid,
            'user_id': payment_data['user_id'],
            'user_email': user['email'] if user else 'Unknown',
            'amount': payment_data['amount'],
            'status': payment_data['status'],
            'created_at': payment_data['created_at']
        })
    
    return render_template_string(ADMIN_PANEL_HTML, stats=stats, users=users, payments=payments)

# ==================== API ROUTES ====================

@app.route('/api/credits')
def api_credits():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    return jsonify({'success': True, 'credits': get_credits(user_id)})

@app.route('/api/deployments')
def api_deployments():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user = get_user(user_id)
    deployments = [db['deployments'][d_id] for d_id in user.get('deployments', []) if d_id in db['deployments']]
    
    return jsonify({'success': True, 'deployments': deployments})

@app.route('/api/deploy/upload', methods=['POST'])
def api_deploy_upload():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file'})
    
    file = request.files['file']
    if not file.filename:
        return jsonify({'success': False, 'error': 'Empty filename'})
    
    try:
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
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deploy/github', methods=['POST'])
def api_deploy_github():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    data = request.get_json()
    repo_url = data.get('url')
    branch = data.get('branch', 'main')
    build_cmd = data.get('build_command', '')
    start_cmd = data.get('start_command', '')
    
    if not repo_url:
        return jsonify({'success': False, 'error': 'URL required'})
    
    deploy_id, msg = deploy_from_github(user_id, repo_url, branch, build_cmd, start_cmd)
    
    if deploy_id:
        return jsonify({'success': True, 'deployment_id': deploy_id, 'message': msg})
    else:
        return jsonify({'success': False, 'error': msg})

@app.route('/api/deployment/<deploy_id>/logs')
def api_deployment_logs(deploy_id):
    if deploy_id not in db['deployments']:
        return jsonify({'success': False, 'error': 'Not found'})
    
    logs = db['deployments'][deploy_id].get('logs', 'No logs')
    return jsonify({'success': True, 'logs': logs})

@app.route('/api/deployment/<deploy_id>/stop', methods=['POST'])
def api_stop_deployment(deploy_id):
    success, msg = stop_deployment(deploy_id)
    return jsonify({'success': success, 'message': msg})

@app.route('/api/deployment/<deploy_id>', methods=['DELETE'])
def api_delete_deployment(deploy_id):
    try:
        stop_deployment(deploy_id)
        if deploy_id in db['deployments']:
            del db['deployments'][deploy_id]
            save_db(db)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployment/<deploy_id>/env', methods=['POST'])
def api_add_env_var(deploy_id):
    if deploy_id not in db['deployments']:
        return jsonify({'success': False, 'error': 'Not found'})
    
    data = request.get_json()
    key = data.get('key')
    value = data.get('value')
    
    if not key or not value:
        return jsonify({'success': False, 'error': 'Key and value required'})
    
    if 'env_vars' not in db['deployments'][deploy_id]:
        db['deployments'][deploy_id]['env_vars'] = {}
    
    db['deployments'][deploy_id]['env_vars'][key] = value
    save_db(db)
    
    return jsonify({'success': True})

@app.route('/api/deployment/<deploy_id>/env/<key>', methods=['DELETE'])
def api_delete_env_var(deploy_id, key):
    if deploy_id not in db['deployments']:
        return jsonify({'success': False, 'error': 'Not found'})
    
    if 'env_vars' in db['deployments'][deploy_id] and key in db['deployments'][deploy_id]['env_vars']:
        del db['deployments'][deploy_id]['env_vars'][key]
        save_db(db)
    
    return jsonify({'success': True})

@app.route('/api/deployment/<deploy_id>/files')
def api_deployment_files(deploy_id):
    files = get_deployment_files(deploy_id)
    return jsonify({'success': True, 'files': files})

@app.route('/api/deployment/<deploy_id>/backup', methods=['POST'])
def api_create_backup(deploy_id):
    cost = CREDIT_COSTS['backup']
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    if not deduct_credits(user_id, cost, f"Backup: {deploy_id}"):
        return jsonify({'success': False, 'error': f'Need {cost} credits'}), 400
    
    backup_path, backup_name = create_backup(deploy_id)
    
    if not backup_path:
        add_credits(user_id, cost, "Refund")
        return jsonify({'success': False, 'error': backup_name}), 400
    
    return send_file(backup_path, as_attachment=True, download_name=backup_name)

@app.route('/api/admin/add-credits', methods=['POST'])
def api_admin_add_credits():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    admin_id = verify_session(session_token, fingerprint)
    
    if str(admin_id) != str(OWNER_ID) and str(admin_id) != str(ADMIN_ID):
        return jsonify({'success': False, 'error': 'Admin only'})
    
    data = request.get_json()
    target_user = data.get('user_id')
    amount = data.get('amount')
    
    if add_credits(target_user, amount, "Admin bonus"):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed'})

@app.route('/api/admin/ban-user', methods=['POST'])
def api_admin_ban_user():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    admin_id = verify_session(session_token, fingerprint)
    
    if str(admin_id) != str(OWNER_ID) and str(admin_id) != str(ADMIN_ID):
        return jsonify({'success': False, 'error': 'Admin only'})
    
    data = request.get_json()
    target_user = data.get('user_id')
    ban = data.get('ban', True)
    
    user = get_user(target_user)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'})
    
    if ban:
        db['banned_devices'].add(user['device_fingerprint'])
    
    update_user(target_user, is_banned=ban)
    
    return jsonify({'success': True})

@app.route('/api/admin/approve-payment', methods=['POST'])
def api_admin_approve_payment():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    admin_id = verify_session(session_token, fingerprint)
    
    if str(admin_id) != str(OWNER_ID) and str(admin_id) != str(ADMIN_ID):
        return jsonify({'success': False, 'error': 'Admin only'})
    
    data = request.get_json()
    payment_id = data.get('payment_id')
    user_id = data.get('user_id')
    amount = data.get('amount')
    
    if payment_id in db.get('payments', {}):
        db['payments'][payment_id]['status'] = 'approved'
        add_credits(user_id, amount, f"Payment: {payment_id}")
        save_db(db)
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Not found'})

@app.route('/api/admin/reject-payment', methods=['POST'])
def api_admin_reject_payment():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    admin_id = verify_session(session_token, fingerprint)
    
    if str(admin_id) != str(OWNER_ID) and str(admin_id) != str(ADMIN_ID):
        return jsonify({'success': False, 'error': 'Admin only'})
    
    data = request.get_json()
    payment_id = data.get('payment_id')
    
    if payment_id in db.get('payments', {}):
        db['payments'][payment_id]['status'] = 'rejected'
        save_db(db)
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Not found'})

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

def keep_alive():
    t = Thread(target=run_flask, daemon=True)
    t.start()
    logger.info(f"{Fore.GREEN}✅ Web: http://localhost:{os.environ.get('PORT', 8080)}")

# ==================== CLEANUP ====================

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
    print(f"{Fore.CYAN}{'🚀 ELITEHOST v11.0 - ULTIMATE MOBILE-FIRST EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}✨ ULTIMATE FEATURES:")
    print(f"{Fore.CYAN}   📱 Mobile-First Design - Perfect for phones")
    print(f"{Fore.CYAN}   🎯 Fixed Bottom Buttons - Always accessible")
    print(f"{Fore.CYAN}   🎨 Modern Dark UI - Gradient accents")
    print(f"{Fore.CYAN}   ⚡ Super Fast - Optimized animations")
    print(f"{Fore.CYAN}   🔐 Advanced Auth - Session management")
    print(f"{Fore.CYAN}   🔑 Environment Vars - Per deployment")
    print(f"{Fore.CYAN}   📁 File Browser - View all files")
    print(f"{Fore.CYAN}   💾 Backup System - Download backups")
    print(f"{Fore.CYAN}   📊 Live Logs - Auto-refresh console")
    print(f"{Fore.CYAN}   🛠️ Custom Commands - Build & start")
    print(f"{Fore.CYAN}   🤖 AI Auto-Install - Smart dependencies")
    print(f"{Fore.CYAN}   👑 Admin Panel - Full control")
    print(f"{Fore.CYAN}   📧 Telegram Alerts - Owner notifications")
    print(f"{Fore.CYAN}   🔄 Forgot Password - Easy recovery")
    print(f"{Fore.CYAN}   💎 Credit System - With refunds")
    print(f"{Fore.CYAN}   🎯 Touch Optimized - Smooth interactions")
    print("=" * 90)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 Web: http://localhost:{port}")
    print(f"{Fore.YELLOW}📱 Register: http://localhost:{port}/register")
    print(f"{Fore.YELLOW}🔑 Login: http://localhost:{port}/login")
    print(f"{Fore.MAGENTA}👑 Admin: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")
    print(f"{Fore.MAGENTA}📱 Panel: http://localhost:{port}/admin")
    print(f"\n{Fore.GREEN}{'✅ ELITEHOST v11.0 READY - MOBILE OPTIMIZED':^90}")
    print("=" * 90 + "\n")
    
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
