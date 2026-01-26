# -*- coding: utf-8 -*-
"""
🚀 ELITEHOST v11.0 - ULTIMATE ENTERPRISE EDITION
Modern SPA Interface | Environment Variables | File Manager | Live Logs
Advanced Admin Dashboard | Backup System | Dark Mode UI
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
import bcrypt
import re

init(autoreset=True)

# ==================== CONFIGURATION ====================
TOKEN = '8133133627:AAHXG1M3I_5yV6mIo2IRl61h8zRUvg6Nn2Y'
OWNER_ID = 7524032836
ADMIN_ID = 8285724366
YOUR_USERNAME = '@Zolvit'
TELEGRAM_LINK = 'https://t.me/Zolvit'
WEB_SECRET_KEY = secrets.token_hex(32)
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

# Credit system
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

# ==================== JSON DATABASE ====================

def load_db():
    """Load database from JSON file"""
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
        'banned_devices': set()
    }

def save_db(db):
    """Save database to JSON file"""
    with DB_LOCK:
        db_copy = db.copy()
        if 'banned_devices' in db_copy and isinstance(db_copy['banned_devices'], set):
            db_copy['banned_devices'] = list(db_copy['banned_devices'])
        
        with open(DB_FILE, 'w') as f:
            json.dump(db_copy, f, indent=2, default=str)

# Load database
db = load_db()
if 'banned_devices' in db and isinstance(db['banned_devices'], list):
    db['banned_devices'] = set(db['banned_devices'])

# ==================== DEVICE FINGERPRINTING ====================

def get_device_fingerprint(request):
    """Generate unique device fingerprint"""
    user_agent = request.headers.get('User-Agent', '')
    ip = request.remote_addr or request.environ.get('HTTP_X_REAL_IP', 'unknown')
    accept_lang = request.headers.get('Accept-Language', '')
    
    fingerprint_str = f"{user_agent}|{ip}|{accept_lang}"
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()

def is_device_banned(fingerprint):
    """Check if device is banned"""
    return fingerprint in db.get('banned_devices', set())

def check_existing_account(fingerprint):
    """Check if device already has an account"""
    for user_id, user_data in db['users'].items():
        if user_data.get('device_fingerprint') == fingerprint:
            return user_id
    return None

# ==================== USER AUTHENTICATION ====================

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed):
    """Verify password"""
    return bcrypt.checkpw(password.encode(), hashed.encode())

def create_user(email, password, fingerprint, ip):
    """Create new user account"""
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
    return user_id

def authenticate_user(email, password):
    """Authenticate user by email and password"""
    for user_id, user_data in db['users'].items():
        if user_data['email'] == email:
            if verify_password(password, user_data['password']):
                return user_id
    return None

def create_session(user_id, fingerprint):
    """Create user session"""
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
    """Verify session token"""
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
    """Get user data"""
    return db['users'].get(user_id)

def update_user(user_id, **kwargs):
    """Update user data"""
    if user_id in db['users']:
        db['users'][user_id].update(kwargs)
        save_db(db)

def log_activity(user_id, action, details, ip=''):
    """Log user activity"""
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
    """Get user credits"""
    if user_id == str(OWNER_ID):
        return float('inf')
    user = get_user(user_id)
    return user['credits'] if user else 0

def add_credits(user_id, amount, description="Credit added"):
    """Add credits to user"""
    user = get_user(user_id)
    if not user:
        return False
    
    user['credits'] += amount
    user['total_earned'] += amount
    update_user(user_id, credits=user['credits'], total_earned=user['total_earned'])
    log_activity(user_id, 'CREDIT_ADD', f"{amount} - {description}")
    return True

def deduct_credits(user_id, amount, description="Credit used"):
    """Deduct credits from user"""
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

# ==================== AI DEPENDENCY DETECTOR ====================

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
    }
    return mapping.get(import_name, import_name)

def detect_and_install_deps(project_path):
    """AI-Powered dependency detection and installation"""
    installed = []
    install_log = []
    
    install_log.append("🤖 AI DEPENDENCY ANALYZER v11.0")
    install_log.append("=" * 60)
    
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
                        install_log.append(f"  ✅ {pkg} (auto-installed)")
                        installed.append(pkg)
                    except:
                        pass
    
    install_log.append("\n" + "=" * 60)
    install_log.append(f"📦 Total Packages Installed: {len(installed)}")
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

def update_deployment(deploy_id, **kwargs):
    if deploy_id in db['deployments']:
        db['deployments'][deploy_id].update(kwargs)
        db['deployments'][deploy_id]['updated_at'] = datetime.now().isoformat()
        save_db(db)

def get_deployment_files(deploy_id):
    """Get list of files in deployment directory"""
    if deploy_id not in db['deployments']:
        return []
    
    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    if not os.path.exists(deploy_dir):
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

def create_backup(deploy_id):
    """Create backup ZIP of deployment"""
    if deploy_id not in db['deployments']:
        return None, "Deployment not found"
    
    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    if not os.path.exists(deploy_dir):
        return None, "Deployment directory not found"
    
    backup_name = f"backup_{deploy_id}_{int(time.time())}.zip"
    backup_path = os.path.join(BACKUPS_DIR, backup_name)
    
    try:
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(deploy_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, deploy_dir)
                    zipf.write(file_path, arcname)
        
        return backup_path, backup_name
    except Exception as e:
        return None, str(e)

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
                    if file in ['main.py', 'app.py', 'bot.py']:
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
        
        files = get_deployment_files(deploy_id)
        update_deployment(deploy_id, dependencies=installed_deps, files=files)
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        deployment = db['deployments'][deploy_id]
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = value
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Launching on port {port}...')
        
        process = subprocess.Popen(
            [sys.executable, file_path],
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

def deploy_from_github(user_id, repo_url, branch='main'):
    try:
        cost = CREDIT_COSTS['github_deploy']
        if not deduct_credits(user_id, cost, f"GitHub: {repo_url}"):
            return None, f"❌ Need {cost} credits"
        
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        deploy_id, port = create_deployment(user_id, repo_name, 'github', repo_url=repo_url, branch=branch)
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
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
        
        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        files = get_deployment_files(deploy_id)
        update_deployment(deploy_id, dependencies=installed_deps, files=files)
        
        main_files = {
            'main.py': f'{sys.executable} main.py',
            'app.py': f'{sys.executable} app.py',
            'bot.py': f'{sys.executable} bot.py',
        }
        
        start_command = None
        for file, cmd in main_files.items():
            if os.path.exists(os.path.join(deploy_dir, file)):
                start_command = cmd
                break
        
        if not start_command:
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
            start_command.split(),
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

def get_system_stats():
    """Get system CPU and RAM usage"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    
    process_stats = []
    for deploy_id, process in active_processes.items():
        try:
            p = psutil.Process(process.pid)
            process_stats.append({
                'deploy_id': deploy_id,
                'cpu': p.cpu_percent(),
                'memory': p.memory_info().rss / 1024 / 1024,  # MB
                'status': p.status()
            })
        except:
            pass
    
    return {
        'system_cpu': cpu_percent,
        'system_memory': memory.percent,
        'total_memory': memory.total / 1024 / 1024 / 1024,  # GB
        'used_memory': memory.used / 1024 / 1024 / 1024,  # GB
        'processes': process_stats
    }

# ==================== MODERN SPA HTML ====================

SPA_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost v11.0 - Ultimate Deployment Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        dark: {
                            50: '#f8fafc',
                            100: '#f1f5f9',
                            200: '#e2e8f0',
                            300: '#cbd5e1',
                            400: '#94a3b8',
                            500: '#64748b',
                            600: '#475569',
                            700: '#334155',
                            800: '#1e293b',
                            900: '#0f172a',
                            950: '#020617',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        [x-cloak] { display: none !important; }
        
        .scrollbar-thin::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }
        
        .scrollbar-thin::-webkit-scrollbar-track {
            background: #1e293b;
        }
        
        .scrollbar-thin::-webkit-scrollbar-thumb {
            background: #475569;
            border-radius: 3px;
        }
        
        .scrollbar-thin::-webkit-scrollbar-thumb:hover {
            background: #64748b;
        }
        
        .terminal {
            font-family: 'Courier New', monospace;
            background: #0f172a;
            color: #10b981;
            padding: 1rem;
            border-radius: 0.5rem;
            max-height: 400px;
            overflow-y: auto;
        }
    </style>
</head>
<body class="bg-dark-950 text-gray-100" x-data="app()" x-init="init()">
    
    <!-- Main Container -->
    <div class="flex h-screen overflow-hidden">
        
        <!-- Sidebar -->
        <div class="w-64 bg-dark-900 border-r border-dark-800 flex flex-col">
            <!-- Logo -->
            <div class="p-6 border-b border-dark-800">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                        <i class="fas fa-rocket text-white text-xl"></i>
                    </div>
                    <div>
                        <div class="text-lg font-bold">EliteHost</div>
                        <div class="text-xs text-gray-400">v11.0 Ultimate</div>
                    </div>
                </div>
            </div>
            
            <!-- Credits Badge -->
            <div class="px-6 py-4 border-b border-dark-800">
                <div class="bg-gradient-to-r from-blue-500 to-purple-600 rounded-lg p-3">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center gap-2">
                            <i class="fas fa-gem text-white"></i>
                            <span class="text-white font-semibold">Credits</span>
                        </div>
                        <span class="text-white font-bold text-xl" x-text="credits"></span>
                    </div>
                </div>
            </div>
            
            <!-- Navigation -->
            <nav class="flex-1 overflow-y-auto scrollbar-thin py-4">
                <template x-for="item in navItems" :key="item.id">
                    <button 
                        @click="currentView = item.id"
                        :class="currentView === item.id ? 'bg-dark-800 text-blue-400 border-l-4 border-blue-500' : 'text-gray-400 hover:bg-dark-800 hover:text-gray-200'"
                        class="w-full px-6 py-3 flex items-center gap-3 transition-all">
                        <i :class="item.icon" class="w-5"></i>
                        <span class="font-medium" x-text="item.label"></span>
                    </button>
                </template>
            </nav>
            
            <!-- User Info -->
            <div class="p-4 border-t border-dark-800">
                <div class="flex items-center gap-3 mb-3">
                    <div class="w-10 h-10 bg-gradient-to-br from-green-400 to-blue-500 rounded-full flex items-center justify-center">
                        <i class="fas fa-user text-white"></i>
                    </div>
                    <div class="flex-1 min-w-0">
                        <div class="text-sm font-medium truncate" x-text="userEmail"></div>
                        <div class="text-xs text-gray-400">Active User</div>
                    </div>
                </div>
                <button @click="logout()" class="w-full px-4 py-2 bg-red-500 hover:bg-red-600 rounded-lg text-white text-sm font-medium transition-colors">
                    <i class="fas fa-sign-out-alt mr-2"></i>Logout
                </button>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="flex-1 flex flex-col overflow-hidden">
            
            <!-- Header -->
            <header class="bg-dark-900 border-b border-dark-800 px-6 py-4">
                <div class="flex items-center justify-between">
                    <div>
                        <h1 class="text-2xl font-bold" x-text="currentViewTitle"></h1>
                        <p class="text-sm text-gray-400 mt-1" x-text="currentViewSubtitle"></p>
                    </div>
                    <div class="flex items-center gap-3">
                        <button @click="refreshData()" class="px-4 py-2 bg-dark-800 hover:bg-dark-700 rounded-lg text-sm font-medium transition-colors">
                            <i class="fas fa-sync mr-2"></i>Refresh
                        </button>
                        <template x-if="isAdmin">
                            <button @click="currentView = 'admin'" class="px-4 py-2 bg-orange-500 hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors">
                                <i class="fas fa-crown mr-2"></i>Admin
                            </button>
                        </template>
                    </div>
                </div>
            </header>
            
            <!-- Content Area -->
            <main class="flex-1 overflow-y-auto scrollbar-thin p-6">
                
                <!-- Dashboard View -->
                <div x-show="currentView === 'dashboard'" x-cloak>
                    <!-- Stats Grid -->
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
                        <div class="bg-dark-900 rounded-xl p-6 border border-dark-800">
                            <div class="flex items-center justify-between mb-4">
                                <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                    <i class="fas fa-rocket text-blue-400 text-xl"></i>
                                </div>
                                <span class="text-3xl font-bold" x-text="deployments.length"></span>
                            </div>
                            <div class="text-gray-400 text-sm font-medium">Total Deployments</div>
                        </div>
                        
                        <div class="bg-dark-900 rounded-xl p-6 border border-dark-800">
                            <div class="flex items-center justify-between mb-4">
                                <div class="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                                    <i class="fas fa-check-circle text-green-400 text-xl"></i>
                                </div>
                                <span class="text-3xl font-bold" x-text="deployments.filter(d => d.status === 'running').length"></span>
                            </div>
                            <div class="text-gray-400 text-sm font-medium">Active Now</div>
                        </div>
                        
                        <div class="bg-dark-900 rounded-xl p-6 border border-dark-800">
                            <div class="flex items-center justify-between mb-4">
                                <div class="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                                    <i class="fas fa-gem text-purple-400 text-xl"></i>
                                </div>
                                <span class="text-3xl font-bold" x-text="credits"></span>
                            </div>
                            <div class="text-gray-400 text-sm font-medium">Available Credits</div>
                        </div>
                        
                        <div class="bg-dark-900 rounded-xl p-6 border border-dark-800">
                            <div class="flex items-center justify-between mb-4">
                                <div class="w-12 h-12 bg-orange-500/20 rounded-lg flex items-center justify-center">
                                    <i class="fas fa-robot text-orange-400 text-xl"></i>
                                </div>
                                <span class="text-3xl font-bold">AI</span>
                            </div>
                            <div class="text-gray-400 text-sm font-medium">Auto Install</div>
                        </div>
                    </div>
                    
                    <!-- Quick Actions -->
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                        <button @click="showUploadModal = true" class="bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 rounded-xl p-6 text-left transition-all transform hover:scale-105">
                            <div class="flex items-center gap-4">
                                <div class="w-14 h-14 bg-white/20 rounded-lg flex items-center justify-center">
                                    <i class="fas fa-cloud-upload-alt text-3xl"></i>
                                </div>
                                <div>
                                    <div class="text-xl font-bold mb-1">Upload & Deploy</div>
                                    <div class="text-sm opacity-90">Deploy Python, JS, or ZIP files</div>
                                </div>
                            </div>
                        </button>
                        
                        <button @click="showGithubModal = true" class="bg-gradient-to-r from-purple-500 to-purple-600 hover:from-purple-600 hover:to-purple-700 rounded-xl p-6 text-left transition-all transform hover:scale-105">
                            <div class="flex items-center gap-4">
                                <div class="w-14 h-14 bg-white/20 rounded-lg flex items-center justify-center">
                                    <i class="fab fa-github text-3xl"></i>
                                </div>
                                <div>
                                    <div class="text-xl font-bold mb-1">GitHub Deploy</div>
                                    <div class="text-sm opacity-90">Clone and deploy from repository</div>
                                </div>
                            </div>
                        </button>
                    </div>
                    
                    <!-- Recent Deployments -->
                    <div class="bg-dark-900 rounded-xl border border-dark-800 overflow-hidden">
                        <div class="px-6 py-4 border-b border-dark-800">
                            <h2 class="text-lg font-bold">Recent Deployments</h2>
                        </div>
                        <div class="divide-y divide-dark-800">
                            <template x-if="deployments.length === 0">
                                <div class="px-6 py-12 text-center">
                                    <div class="w-20 h-20 bg-dark-800 rounded-full flex items-center justify-center mx-auto mb-4">
                                        <i class="fas fa-rocket text-4xl text-gray-600"></i>
                                    </div>
                                    <div class="text-lg font-semibold mb-2">No Deployments Yet</div>
                                    <div class="text-sm text-gray-400">Click the buttons above to deploy your first app!</div>
                                </div>
                            </template>
                            
                            <template x-for="deploy in deployments.slice(0, 5)" :key="deploy.id">
                                <div class="px-6 py-4 hover:bg-dark-800 transition-colors cursor-pointer" @click="selectDeployment(deploy)">
                                    <div class="flex items-center justify-between">
                                        <div class="flex-1">
                                            <div class="flex items-center gap-3 mb-2">
                                                <div class="text-base font-semibold" x-text="deploy.name"></div>
                                                <span :class="getStatusClass(deploy.status)" class="px-2 py-1 text-xs font-bold rounded uppercase" x-text="deploy.status"></span>
                                            </div>
                                            <div class="flex items-center gap-4 text-xs text-gray-400">
                                                <span><i class="fas fa-fingerprint mr-1"></i><span x-text="deploy.id"></span></span>
                                                <span><i class="fas fa-network-wired mr-1"></i>Port <span x-text="deploy.port"></span></span>
                                                <span x-show="deploy.dependencies && deploy.dependencies.length > 0">
                                                    <i class="fas fa-robot mr-1"></i><span x-text="deploy.dependencies.length"></span> packages
                                                </span>
                                            </div>
                                        </div>
                                        <button class="px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg text-sm font-medium transition-colors">
                                            View Details
                                        </button>
                                    </div>
                                </div>
                            </template>
                        </div>
                    </div>
                </div>
                
                <!-- Deployments View -->
                <div x-show="currentView === 'deployments'" x-cloak>
                    <div class="space-y-4">
                        <template x-if="deployments.length === 0">
                            <div class="bg-dark-900 rounded-xl border border-dark-800 px-6 py-12 text-center">
                                <div class="w-20 h-20 bg-dark-800 rounded-full flex items-center justify-center mx-auto mb-4">
                                    <i class="fas fa-rocket text-4xl text-gray-600"></i>
                                </div>
                                <div class="text-lg font-semibold mb-2">No Deployments</div>
                                <div class="text-sm text-gray-400 mb-6">Start by deploying your first application</div>
                                <div class="flex gap-3 justify-center">
                                    <button @click="showUploadModal = true" class="px-6 py-3 bg-blue-500 hover:bg-blue-600 rounded-lg font-medium transition-colors">
                                        <i class="fas fa-upload mr-2"></i>Upload File
                                    </button>
                                    <button @click="showGithubModal = true" class="px-6 py-3 bg-purple-500 hover:bg-purple-600 rounded-lg font-medium transition-colors">
                                        <i class="fab fa-github mr-2"></i>GitHub Deploy
                                    </button>
                                </div>
                            </div>
                        </template>
                        
                        <template x-for="deploy in deployments" :key="deploy.id">
                            <div class="bg-dark-900 rounded-xl border border-dark-800 overflow-hidden hover:border-blue-500 transition-colors">
                                <div class="p-6">
                                    <div class="flex items-start justify-between mb-4">
                                        <div class="flex-1">
                                            <div class="flex items-center gap-3 mb-2">
                                                <h3 class="text-xl font-bold" x-text="deploy.name"></h3>
                                                <span :class="getStatusClass(deploy.status)" class="px-3 py-1 text-xs font-bold rounded-full uppercase" x-text="deploy.status"></span>
                                            </div>
                                            <div class="flex items-center gap-4 text-sm text-gray-400">
                                                <span><i class="fas fa-fingerprint mr-1"></i><span x-text="deploy.id"></span></span>
                                                <span><i class="fas fa-network-wired mr-1"></i>Port <span x-text="deploy.port"></span></span>
                                                <span><i class="fas fa-clock mr-1"></i><span x-text="new Date(deploy.created_at).toLocaleDateString()"></span></span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="flex flex-wrap gap-2">
                                        <button @click="selectDeployment(deploy); currentView = 'deployment-detail'" class="px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg text-sm font-medium transition-colors">
                                            <i class="fas fa-eye mr-2"></i>View Details
                                        </button>
                                        <button @click="viewLogs(deploy.id)" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition-colors">
                                            <i class="fas fa-terminal mr-2"></i>Logs
                                        </button>
                                        <button @click="stopDeployment(deploy.id)" class="px-4 py-2 bg-orange-500 hover:bg-orange-600 rounded-lg text-sm font-medium transition-colors">
                                            <i class="fas fa-stop mr-2"></i>Stop
                                        </button>
                                        <button @click="deleteDeployment(deploy.id)" class="px-4 py-2 bg-red-500 hover:bg-red-600 rounded-lg text-sm font-medium transition-colors">
                                            <i class="fas fa-trash mr-2"></i>Delete
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </template>
                    </div>
                </div>
                
                <!-- Deployment Detail View -->
                <div x-show="currentView === 'deployment-detail' && selectedDeployment" x-cloak>
                    <div class="space-y-6">
                        <!-- Back Button -->
                        <button @click="currentView = 'deployments'" class="px-4 py-2 bg-dark-800 hover:bg-dark-700 rounded-lg text-sm font-medium transition-colors">
                            <i class="fas fa-arrow-left mr-2"></i>Back to Deployments
                        </button>
                        
                        <!-- Tabs -->
                        <div class="bg-dark-900 rounded-xl border border-dark-800 overflow-hidden">
                            <div class="flex border-b border-dark-800">
                                <button @click="detailTab = 'overview'" :class="detailTab === 'overview' ? 'bg-dark-800 text-blue-400 border-b-2 border-blue-500' : 'text-gray-400 hover:text-gray-200'" class="px-6 py-3 font-medium transition-colors">
                                    <i class="fas fa-info-circle mr-2"></i>Overview
                                </button>
                                <button @click="detailTab = 'settings'" :class="detailTab === 'settings' ? 'bg-dark-800 text-blue-400 border-b-2 border-blue-500' : 'text-gray-400 hover:text-gray-200'" class="px-6 py-3 font-medium transition-colors">
                                    <i class="fas fa-cog mr-2"></i>Settings
                                </button>
                                <button @click="detailTab = 'files'" :class="detailTab === 'files' ? 'bg-dark-800 text-blue-400 border-b-2 border-blue-500' : 'text-gray-400 hover:text-gray-200'" class="px-6 py-3 font-medium transition-colors">
                                    <i class="fas fa-folder mr-2"></i>Files
                                </button>
                                <button @click="detailTab = 'console'" :class="detailTab === 'console' ? 'bg-dark-800 text-blue-400 border-b-2 border-blue-500' : 'text-gray-400 hover:text-gray-200'" class="px-6 py-3 font-medium transition-colors">
                                    <i class="fas fa-terminal mr-2"></i>Console
                                </button>
                                <button @click="detailTab = 'backup'" :class="detailTab === 'backup' ? 'bg-dark-800 text-blue-400 border-b-2 border-blue-500' : 'text-gray-400 hover:text-gray-200'" class="px-6 py-3 font-medium transition-colors">
                                    <i class="fas fa-download mr-2"></i>Backup
                                </button>
                            </div>
                            
                            <div class="p-6">
                                <!-- Overview Tab -->
                                <div x-show="detailTab === 'overview'" x-cloak>
                                    <div class="space-y-4">
                                        <div class="grid grid-cols-2 gap-4">
                                            <div>
                                                <div class="text-sm text-gray-400 mb-1">Deployment ID</div>
                                                <div class="font-mono" x-text="selectedDeployment.id"></div>
                                            </div>
                                            <div>
                                                <div class="text-sm text-gray-400 mb-1">Status</div>
                                                <span :class="getStatusClass(selectedDeployment.status)" class="px-3 py-1 text-xs font-bold rounded uppercase" x-text="selectedDeployment.status"></span>
                                            </div>
                                            <div>
                                                <div class="text-sm text-gray-400 mb-1">Port</div>
                                                <div class="font-semibold" x-text="selectedDeployment.port"></div>
                                            </div>
                                            <div>
                                                <div class="text-sm text-gray-400 mb-1">Type</div>
                                                <div class="capitalize" x-text="selectedDeployment.type"></div>
                                            </div>
                                            <div>
                                                <div class="text-sm text-gray-400 mb-1">Created</div>
                                                <div x-text="new Date(selectedDeployment.created_at).toLocaleString()"></div>
                                            </div>
                                            <div>
                                                <div class="text-sm text-gray-400 mb-1">Last Updated</div>
                                                <div x-text="new Date(selectedDeployment.updated_at).toLocaleString()"></div>
                                            </div>
                                        </div>
                                        
                                        <template x-if="selectedDeployment.dependencies && selectedDeployment.dependencies.length > 0">
                                            <div>
                                                <div class="text-sm text-gray-400 mb-2">AI Installed Dependencies</div>
                                                <div class="flex flex-wrap gap-2">
                                                    <template x-for="dep in selectedDeployment.dependencies" :key="dep">
                                                        <span class="px-3 py-1 bg-green-500/20 text-green-400 rounded-full text-xs font-medium">
                                                            <i class="fas fa-check-circle mr-1"></i><span x-text="dep"></span>
                                                        </span>
                                                    </template>
                                                </div>
                                            </div>
                                        </template>
                                    </div>
                                </div>
                                
                                <!-- Settings Tab (Environment Variables) -->
                                <div x-show="detailTab === 'settings'" x-cloak>
                                    <div class="mb-4">
                                        <h3 class="text-lg font-bold mb-2">Environment Variables</h3>
                                        <p class="text-sm text-gray-400">Add key-value pairs that will be injected into your deployment</p>
                                    </div>
                                    
                                    <div class="space-y-3 mb-4">
                                        <template x-if="Object.keys(selectedDeployment.env_vars || {}).length === 0">
                                            <div class="text-center py-8 text-gray-400">
                                                <i class="fas fa-key text-4xl mb-3 opacity-50"></i>
                                                <div>No environment variables set</div>
                                            </div>
                                        </template>
                                        
                                        <template x-for="[key, value] in Object.entries(selectedDeployment.env_vars || {})" :key="key">
                                            <div class="flex items-center gap-3 p-3 bg-dark-800 rounded-lg">
                                                <div class="flex-1 grid grid-cols-2 gap-3">
                                                    <div>
                                                        <div class="text-xs text-gray-400 mb-1">Key</div>
                                                        <div class="font-mono text-sm" x-text="key"></div>
                                                    </div>
                                                    <div>
                                                        <div class="text-xs text-gray-400 mb-1">Value</div>
                                                        <div class="font-mono text-sm" x-text="value"></div>
                                                    </div>
                                                </div>
                                                <button @click="deleteEnvVar(key)" class="px-3 py-2 bg-red-500 hover:bg-red-600 rounded-lg text-sm transition-colors">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                            </div>
                                        </template>
                                    </div>
                                    
                                    <div class="p-4 bg-dark-800 rounded-lg">
                                        <div class="grid grid-cols-2 gap-3 mb-3">
                                            <input x-model="newEnvKey" type="text" placeholder="KEY" class="px-4 py-2 bg-dark-900 border border-dark-700 rounded-lg focus:border-blue-500 focus:outline-none">
                                            <input x-model="newEnvValue" type="text" placeholder="value" class="px-4 py-2 bg-dark-900 border border-dark-700 rounded-lg focus:border-blue-500 focus:outline-none">
                                        </div>
                                        <button @click="addEnvVar()" class="w-full px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg font-medium transition-colors">
                                            <i class="fas fa-plus mr-2"></i>Add Variable
                                        </button>
                                    </div>
                                </div>
                                
                                <!-- Files Tab -->
                                <div x-show="detailTab === 'files'" x-cloak>
                                    <div class="mb-4">
                                        <h3 class="text-lg font-bold mb-2">File Manager</h3>
                                        <p class="text-sm text-gray-400">Browse files in your deployment</p>
                                    </div>
                                    
                                    <div class="space-y-2">
                                        <template x-if="!selectedDeployment.files || selectedDeployment.files.length === 0">
                                            <div class="text-center py-8 text-gray-400">
                                                <i class="fas fa-folder-open text-4xl mb-3 opacity-50"></i>
                                                <div>No files found</div>
                                            </div>
                                        </template>
                                        
                                        <template x-for="file in selectedDeployment.files || []" :key="file.path">
                                            <div class="flex items-center gap-3 p-3 bg-dark-800 rounded-lg hover:bg-dark-700 transition-colors">
                                                <i class="fas fa-file text-blue-400"></i>
                                                <div class="flex-1">
                                                    <div class="font-mono text-sm" x-text="file.path"></div>
                                                    <div class="text-xs text-gray-400">
                                                        <span x-text="(file.size / 1024).toFixed(2)"></span> KB
                                                    </div>
                                                </div>
                                            </div>
                                        </template>
                                    </div>
                                </div>
                                
                                <!-- Console Tab (Live Logs) -->
                                <div x-show="detailTab === 'console'" x-cloak>
                                    <div class="mb-4 flex items-center justify-between">
                                        <div>
                                            <h3 class="text-lg font-bold mb-1">Live Console</h3>
                                            <p class="text-sm text-gray-400">Real-time logs from your deployment</p>
                                        </div>
                                        <button @click="refreshLogs()" class="px-4 py-2 bg-dark-800 hover:bg-dark-700 rounded-lg text-sm font-medium transition-colors">
                                            <i class="fas fa-sync mr-2"></i>Refresh
                                        </button>
                                    </div>
                                    
                                    <div class="terminal" x-text="consoleLogs || 'No logs available'"></div>
                                </div>
                                
                                <!-- Backup Tab -->
                                <div x-show="detailTab === 'backup'" x-cloak>
                                    <div class="mb-4">
                                        <h3 class="text-lg font-bold mb-2">Backup & Export</h3>
                                        <p class="text-sm text-gray-400">Create a ZIP snapshot of your deployment</p>
                                    </div>
                                    
                                    <div class="bg-dark-800 rounded-lg p-6 text-center">
                                        <div class="w-16 h-16 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                                            <i class="fas fa-download text-blue-400 text-2xl"></i>
                                        </div>
                                        <div class="text-lg font-semibold mb-2">Create Backup</div>
                                        <div class="text-sm text-gray-400 mb-6">Download a complete snapshot of your deployment files</div>
                                        <button @click="createBackup()" class="px-6 py-3 bg-blue-500 hover:bg-blue-600 rounded-lg font-medium transition-colors">
                                            <i class="fas fa-download mr-2"></i>Create & Download Backup (0.5 credits)
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Admin View -->
                <div x-show="currentView === 'admin' && isAdmin" x-cloak>
                    <div class="space-y-6">
                        <!-- System Stats -->
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                            <div class="bg-dark-900 rounded-xl p-6 border border-dark-800">
                                <div class="text-sm text-gray-400 mb-2">System CPU</div>
                                <div class="text-3xl font-bold" x-text="(systemStats.system_cpu || 0).toFixed(1) + '%'"></div>
                            </div>
                            <div class="bg-dark-900 rounded-xl p-6 border border-dark-800">
                                <div class="text-sm text-gray-400 mb-2">System RAM</div>
                                <div class="text-3xl font-bold" x-text="(systemStats.system_memory || 0).toFixed(1) + '%'"></div>
                            </div>
                            <div class="bg-dark-900 rounded-xl p-6 border border-dark-800">
                                <div class="text-sm text-gray-400 mb-2">Active Processes</div>
                                <div class="text-3xl font-bold" x-text="(systemStats.processes || []).length"></div>
                            </div>
                            <div class="bg-dark-900 rounded-xl p-6 border border-dark-800">
                                <div class="text-sm text-gray-400 mb-2">Total Users</div>
                                <div class="text-3xl font-bold" x-text="adminData.users ? adminData.users.length : 0"></div>
                            </div>
                        </div>
                        
                        <!-- Process Monitor -->
                        <div class="bg-dark-900 rounded-xl border border-dark-800 overflow-hidden">
                            <div class="px-6 py-4 border-b border-dark-800">
                                <h2 class="text-lg font-bold">Live Process Monitor</h2>
                            </div>
                            <div class="overflow-x-auto">
                                <table class="w-full">
                                    <thead class="bg-dark-800">
                                        <tr>
                                            <th class="px-6 py-3 text-left text-xs font-bold text-gray-400 uppercase">Deploy ID</th>
                                            <th class="px-6 py-3 text-left text-xs font-bold text-gray-400 uppercase">CPU %</th>
                                            <th class="px-6 py-3 text-left text-xs font-bold text-gray-400 uppercase">Memory (MB)</th>
                                            <th class="px-6 py-3 text-left text-xs font-bold text-gray-400 uppercase">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody class="divide-y divide-dark-800">
                                        <template x-if="!systemStats.processes || systemStats.processes.length === 0">
                                            <tr>
                                                <td colspan="4" class="px-6 py-8 text-center text-gray-400">
                                                    No active processes
                                                </td>
                                            </tr>
                                        </template>
                                        <template x-for="proc in systemStats.processes || []" :key="proc.deploy_id">
                                            <tr class="hover:bg-dark-800">
                                                <td class="px-6 py-4 font-mono text-sm" x-text="proc.deploy_id"></td>
                                                <td class="px-6 py-4">
                                                    <span class="px-3 py-1 bg-blue-500/20 text-blue-400 rounded-full text-xs font-bold" x-text="proc.cpu.toFixed(1) + '%'"></span>
                                                </td>
                                                <td class="px-6 py-4">
                                                    <span class="px-3 py-1 bg-purple-500/20 text-purple-400 rounded-full text-xs font-bold" x-text="proc.memory.toFixed(1) + ' MB'"></span>
                                                </td>
                                                <td class="px-6 py-4">
                                                    <span class="px-3 py-1 bg-green-500/20 text-green-400 rounded-full text-xs font-bold uppercase" x-text="proc.status"></span>
                                                </td>
                                            </tr>
                                        </template>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        
                        <!-- User Management -->
                        <div class="bg-dark-900 rounded-xl border border-dark-800 overflow-hidden">
                            <div class="px-6 py-4 border-b border-dark-800">
                                <h2 class="text-lg font-bold">User Management</h2>
                            </div>
                            <div class="overflow-x-auto">
                                <table class="w-full">
                                    <thead class="bg-dark-800">
                                        <tr>
                                            <th class="px-6 py-3 text-left text-xs font-bold text-gray-400 uppercase">Email</th>
                                            <th class="px-6 py-3 text-left text-xs font-bold text-gray-400 uppercase">Credits</th>
                                            <th class="px-6 py-3 text-left text-xs font-bold text-gray-400 uppercase">Deployments</th>
                                            <th class="px-6 py-3 text-left text-xs font-bold text-gray-400 uppercase">Status</th>
                                            <th class="px-6 py-3 text-left text-xs font-bold text-gray-400 uppercase">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody class="divide-y divide-dark-800">
                                        <template x-for="user in adminData.users || []" :key="user.id">
                                            <tr class="hover:bg-dark-800">
                                                <td class="px-6 py-4 text-sm" x-text="user.email"></td>
                                                <td class="px-6 py-4 font-bold" x-text="user.credits"></td>
                                                <td class="px-6 py-4" x-text="user.deployments.length"></td>
                                                <td class="px-6 py-4">
                                                    <span :class="user.is_banned ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'" class="px-3 py-1 rounded-full text-xs font-bold uppercase" x-text="user.is_banned ? 'Banned' : 'Active'"></span>
                                                </td>
                                                <td class="px-6 py-4">
                                                    <div class="flex gap-2">
                                                        <button @click="adminAddCredits(user.id)" class="px-3 py-1 bg-blue-500 hover:bg-blue-600 rounded text-xs font-medium transition-colors">
                                                            <i class="fas fa-plus mr-1"></i>Credits
                                                        </button>
                                                        <button @click="adminBanUser(user.id, !user.is_banned)" :class="user.is_banned ? 'bg-green-500 hover:bg-green-600' : 'bg-red-500 hover:bg-red-600'" class="px-3 py-1 rounded text-xs font-medium transition-colors">
                                                            <i :class="user.is_banned ? 'fas fa-check' : 'fas fa-ban'" class="mr-1"></i>
                                                            <span x-text="user.is_banned ? 'Unban' : 'Ban'"></span>
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        </template>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
            </main>
        </div>
    </div>
    
    <!-- Upload Modal -->
    <div x-show="showUploadModal" x-cloak class="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
        <div @click.away="showUploadModal = false" class="bg-dark-900 rounded-xl max-w-lg w-full border border-dark-800">
            <div class="px-6 py-4 border-b border-dark-800 flex items-center justify-between">
                <h2 class="text-xl font-bold">Upload & Deploy</h2>
                <button @click="showUploadModal = false" class="w-8 h-8 bg-dark-800 hover:bg-dark-700 rounded-lg flex items-center justify-center transition-colors">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="p-6">
                <div class="border-2 border-dashed border-dark-700 rounded-xl p-8 text-center mb-4 hover:border-blue-500 transition-colors cursor-pointer" onclick="document.getElementById('fileInput').click()">
                    <div class="w-16 h-16 bg-blue-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
                        <i class="fas fa-cloud-upload-alt text-blue-400 text-3xl"></i>
                    </div>
                    <div class="text-lg font-semibold mb-2">Click to Upload</div>
                    <div class="text-sm text-gray-400">Python, JavaScript, or ZIP files</div>
                    <input type="file" id="fileInput" hidden accept=".py,.js,.zip" @change="uploadFile($event)">
                </div>
                <div class="bg-dark-800 rounded-lg p-4 text-sm">
                    <div class="flex items-start gap-3 mb-2">
                        <i class="fas fa-info-circle text-blue-400 mt-0.5"></i>
                        <div>
                            <div class="font-semibold mb-1">Cost: 0.5 credits</div>
                            <div class="text-gray-400">AI will automatically detect and install all dependencies</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- GitHub Modal -->
    <div x-show="showGithubModal" x-cloak class="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
        <div @click.away="showGithubModal = false" class="bg-dark-900 rounded-xl max-w-lg w-full border border-dark-800">
            <div class="px-6 py-4 border-b border-dark-800 flex items-center justify-between">
                <h2 class="text-xl font-bold">Deploy from GitHub</h2>
                <button @click="showGithubModal = false" class="w-8 h-8 bg-dark-800 hover:bg-dark-700 rounded-lg flex items-center justify-center transition-colors">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <form @submit.prevent="deployGithub()" class="p-6">
                <div class="mb-4">
                    <label class="block text-sm font-medium mb-2">Repository URL</label>
                    <input x-model="githubUrl" type="url" placeholder="https://github.com/user/repo" required class="w-full px-4 py-3 bg-dark-800 border border-dark-700 rounded-lg focus:border-blue-500 focus:outline-none">
                </div>
                <div class="mb-6">
                    <label class="block text-sm font-medium mb-2">Branch</label>
                    <input x-model="githubBranch" type="text" placeholder="main" value="main" required class="w-full px-4 py-3 bg-dark-800 border border-dark-700 rounded-lg focus:border-blue-500 focus:outline-none">
                </div>
                <button type="submit" class="w-full px-6 py-3 bg-gradient-to-r from-purple-500 to-purple-600 hover:from-purple-600 hover:to-purple-700 rounded-lg font-medium transition-all">
                    <i class="fab fa-github mr-2"></i>Deploy (1.0 credit)
                </button>
                <div class="bg-dark-800 rounded-lg p-4 text-sm mt-4">
                    <div class="flex items-start gap-3">
                        <i class="fas fa-robot text-purple-400 mt-0.5"></i>
                        <div class="text-gray-400">AI will clone the repo, detect the language, install dependencies, and deploy automatically</div>
                    </div>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Logs Modal -->
    <div x-show="showLogsModal" x-cloak class="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
        <div @click.away="showLogsModal = false" class="bg-dark-900 rounded-xl max-w-3xl w-full border border-dark-800 max-h-[80vh] flex flex-col">
            <div class="px-6 py-4 border-b border-dark-800 flex items-center justify-between">
                <h2 class="text-xl font-bold">Deployment Logs</h2>
                <button @click="showLogsModal = false" class="w-8 h-8 bg-dark-800 hover:bg-dark-700 rounded-lg flex items-center justify-center transition-colors">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="flex-1 overflow-hidden">
                <div class="terminal" style="max-height: 60vh;" x-text="currentLogs || 'No logs available'"></div>
            </div>
        </div>
    </div>
    
    <script>
        function app() {
            return {
                currentView: 'dashboard',
                detailTab: 'overview',
                credits: 0,
                userEmail: '',
                isAdmin: false,
                deployments: [],
                selectedDeployment: null,
                showUploadModal: false,
                showGithubModal: false,
                showLogsModal: false,
                currentLogs: '',
                consoleLogs: '',
                githubUrl: '',
                githubBranch: 'main',
                newEnvKey: '',
                newEnvValue: '',
                systemStats: {},
                adminData: { users: [] },
                
                navItems: [
                    { id: 'dashboard', label: 'Dashboard', icon: 'fas fa-home' },
                    { id: 'deployments', label: 'Deployments', icon: 'fas fa-rocket' },
                ],
                
                init() {
                    this.loadUserData();
                    this.loadDeployments();
                    this.loadSystemStats();
                    setInterval(() => this.loadDeployments(), 10000);
                    setInterval(() => this.loadSystemStats(), 5000);
                    setInterval(() => {
                        if (this.detailTab === 'console' && this.selectedDeployment) {
                            this.refreshLogs();
                        }
                    }, 3000);
                },
                
                async loadUserData() {
                    try {
                        const res = await fetch('/api/user-info');
                        const data = await res.json();
                        if (data.success) {
                            this.credits = data.credits === Infinity ? '∞' : data.credits.toFixed(1);
                            this.userEmail = data.email;
                            this.isAdmin = data.is_admin;
                            if (this.isAdmin) {
                                this.loadAdminData();
                            }
                        }
                    } catch (e) {
                        console.error('Failed to load user data', e);
                    }
                },
                
                async loadDeployments() {
                    try {
                        const res = await fetch('/api/deployments');
                        const data = await res.json();
                        if (data.success) {
                            this.deployments = data.deployments;
                            if (this.selectedDeployment) {
                                const updated = this.deployments.find(d => d.id === this.selectedDeployment.id);
                                if (updated) this.selectedDeployment = updated;
                            }
                        }
                    } catch (e) {
                        console.error('Failed to load deployments', e);
                    }
                },
                
                async loadSystemStats() {
                    if (!this.isAdmin) return;
                    try {
                        const res = await fetch('/api/admin/system-stats');
                        const data = await res.json();
                        if (data.success) {
                            this.systemStats = data.stats;
                        }
                    } catch (e) {
                        console.error('Failed to load system stats', e);
                    }
                },
                
                async loadAdminData() {
                    try {
                        const res = await fetch('/api/admin/users');
                        const data = await res.json();
                        if (data.success) {
                            this.adminData = data;
                        }
                    } catch (e) {
                        console.error('Failed to load admin data', e);
                    }
                },
                
                async uploadFile(event) {
                    const file = event.target.files[0];
                    if (!file) return;
                    
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    this.showUploadModal = false;
                    
                    try {
                        const res = await fetch('/api/deploy/upload', {
                            method: 'POST',
                            body: formData
                        });
                        const data = await res.json();
                        
                        if (data.success) {
                            alert('✅ Deployment successful!\n\n' + data.message);
                            this.loadDeployments();
                            this.loadUserData();
                        } else {
                            alert('❌ Error: ' + data.error);
                        }
                    } catch (e) {
                        alert('❌ Upload failed: ' + e.message);
                    }
                    
                    event.target.value = '';
                },
                
                async deployGithub() {
                    if (!this.githubUrl) return;
                    
                    this.showGithubModal = false;
                    
                    try {
                        const res = await fetch('/api/deploy/github', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                url: this.githubUrl,
                                branch: this.githubBranch
                            })
                        });
                        const data = await res.json();
                        
                        if (data.success) {
                            alert('✅ GitHub deployment successful!\n\n' + data.message);
                            this.loadDeployments();
                            this.loadUserData();
                        } else {
                            alert('❌ Error: ' + data.error);
                        }
                    } catch (e) {
                        alert('❌ Deployment failed: ' + e.message);
                    }
                    
                    this.githubUrl = '';
                    this.githubBranch = 'main';
                },
                
                selectDeployment(deploy) {
                    this.selectedDeployment = deploy;
                    this.detailTab = 'overview';
                    if (this.currentView !== 'deployment-detail') {
                        this.currentView = 'deployment-detail';
                    }
                },
                
                async viewLogs(deployId) {
                    try {
                        const res = await fetch(`/api/deployment/${deployId}/logs`);
                        const data = await res.json();
                        this.currentLogs = data.logs || 'No logs available';
                        this.showLogsModal = true;
                    } catch (e) {
                        alert('Failed to load logs');
                    }
                },
                
                async refreshLogs() {
                    if (!this.selectedDeployment) return;
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeployment.id}/logs`);
                        const data = await res.json();
                        this.consoleLogs = data.logs || 'No logs available';
                    } catch (e) {
                        console.error('Failed to refresh logs', e);
                    }
                },
                
                async stopDeployment(deployId) {
                    if (!confirm('Stop this deployment?')) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${deployId}/stop`, {
                            method: 'POST'
                        });
                        const data = await res.json();
                        alert(data.success ? '✅ Stopped' : '❌ ' + data.message);
                        this.loadDeployments();
                    } catch (e) {
                        alert('Failed to stop deployment');
                    }
                },
                
                async deleteDeployment(deployId) {
                    if (!confirm('Delete this deployment permanently?')) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${deployId}`, {
                            method: 'DELETE'
                        });
                        const data = await res.json();
                        alert(data.success ? '✅ Deleted' : '❌ Failed');
                        this.loadDeployments();
                        if (this.selectedDeployment && this.selectedDeployment.id === deployId) {
                            this.selectedDeployment = null;
                            this.currentView = 'deployments';
                        }
                    } catch (e) {
                        alert('Failed to delete deployment');
                    }
                },
                
                async addEnvVar() {
                    if (!this.newEnvKey || !this.newEnvValue || !this.selectedDeployment) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeployment.id}/env`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                key: this.newEnvKey,
                                value: this.newEnvValue
                            })
                        });
                        const data = await res.json();
                        
                        if (data.success) {
                            this.newEnvKey = '';
                            this.newEnvValue = '';
                            this.loadDeployments();
                            alert('✅ Environment variable added!');
                        } else {
                            alert('❌ Failed to add variable');
                        }
                    } catch (e) {
                        alert('Failed to add environment variable');
                    }
                },
                
                async deleteEnvVar(key) {
                    if (!confirm(`Delete environment variable "${key}"?`)) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeployment.id}/env/${key}`, {
                            method: 'DELETE'
                        });
                        const data = await res.json();
                        
                        if (data.success) {
                            this.loadDeployments();
                            alert('✅ Variable deleted');
                        } else {
                            alert('❌ Failed to delete');
                        }
                    } catch (e) {
                        alert('Failed to delete variable');
                    }
                },
                
                async createBackup() {
                    if (!this.selectedDeployment) return;
                    
                    if (!confirm('Create backup? This will cost 0.5 credits')) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeployment.id}/backup`, {
                            method: 'POST'
                        });
                        
                        if (res.ok) {
                            const blob = await res.blob();
                            const url = window.URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = `backup_${this.selectedDeployment.id}.zip`;
                            a.click();
                            this.loadUserData();
                            alert('✅ Backup downloaded successfully!');
                        } else {
                            const data = await res.json();
                            alert('❌ ' + (data.error || 'Backup failed'));
                        }
                    } catch (e) {
                        alert('Failed to create backup');
                    }
                },
                
                async adminAddCredits(userId) {
                    const amount = prompt('Enter amount of credits to add:');
                    if (!amount || isNaN(amount)) return;
                    
                    try {
                        const res = await fetch('/api/admin/add-credits', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                user_id: userId,
                                amount: parseFloat(amount)
                            })
                        });
                        const data = await res.json();
                        alert(data.success ? '✅ Credits added!' : '❌ ' + data.error);
                        this.loadAdminData();
                    } catch (e) {
                        alert('Failed to add credits');
                    }
                },
                
                async adminBanUser(userId, ban) {
                    const action = ban ? 'ban' : 'unban';
                    if (!confirm(`${action.charAt(0).toUpperCase() + action.slice(1)} this user?`)) return;
                    
                    try {
                        const res = await fetch('/api/admin/ban-user', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                user_id: userId,
                                ban: ban
                            })
                        });
                        const data = await res.json();
                        alert(data.success ? `✅ User ${action}ned` : '❌ ' + data.error);
                        this.loadAdminData();
                    } catch (e) {
                        alert(`Failed to ${action} user`);
                    }
                },
                
                refreshData() {
                    this.loadUserData();
                    this.loadDeployments();
                    if (this.isAdmin) {
                        this.loadSystemStats();
                        this.loadAdminData();
                    }
                },
                
                logout() {
                    if (confirm('Logout from EliteHost?')) {
                        window.location.href = '/logout';
                    }
                },
                
                getStatusClass(status) {
                    const classes = {
                        'running': 'bg-green-500/20 text-green-400',
                        'pending': 'bg-yellow-500/20 text-yellow-400',
                        'stopped': 'bg-red-500/20 text-red-400',
                        'failed': 'bg-red-500/20 text-red-400',
                        'installing': 'bg-blue-500/20 text-blue-400',
                        'starting': 'bg-blue-500/20 text-blue-400',
                    };
                    return classes[status] || 'bg-gray-500/20 text-gray-400';
                },
                
                get currentViewTitle() {
                    if (this.currentView === 'deployment-detail' && this.selectedDeployment) {
                        return this.selectedDeployment.name;
                    }
                    const titles = {
                        'dashboard': 'Dashboard',
                        'deployments': 'All Deployments',
                        'admin': 'Admin Control Panel'
                    };
                    return titles[this.currentView] || 'Dashboard';
                },
                
                get currentViewSubtitle() {
                    if (this.currentView === 'deployment-detail' && this.selectedDeployment) {
                        return `Manage your deployment - ID: ${this.selectedDeployment.id}`;
                    }
                    const subtitles = {
                        'dashboard': 'Overview of your deployments and resources',
                        'deployments': 'Manage all your deployed applications',
                        'admin': 'System monitoring and user management'
                    };
                    return subtitles[this.currentView] || '';
                }
            }
        }
    </script>
</body>
</html>
"""

# ==================== FLASK ROUTES (CONTINUED) ====================

@app.route('/app')
def spa_app():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    
    user_id = verify_session(session_token, fingerprint)
    if not user_id:
        return redirect('/login?error=Please login first')
    
    user = get_user(user_id)
    if not user or user.get('is_banned'):
        return redirect('/login?error=Access denied')
    
    return render_template_string(SPA_HTML)

@app.route('/api/user-info')
def api_user_info():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user = get_user(user_id)
    is_admin = str(user_id) == str(OWNER_ID) or str(user_id) == str(ADMIN_ID)
    
    return jsonify({
        'success': True,
        'credits': get_credits(user_id),
        'email': user['email'],
        'is_admin': is_admin
    })

@app.route('/api/deployment/<deploy_id>/env', methods=['POST'])
def api_add_env_var(deploy_id):
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    if deploy_id not in db['deployments']:
        return jsonify({'success': False, 'error': 'Deployment not found'})
    
    deployment = db['deployments'][deploy_id]
    if deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    data = request.get_json()
    key = data.get('key')
    value = data.get('value')
    
    if not key or not value:
        return jsonify({'success': False, 'error': 'Key and value required'})
    
    if 'env_vars' not in deployment:
        deployment['env_vars'] = {}
    
    deployment['env_vars'][key] = value
    update_deployment(deploy_id, env_vars=deployment['env_vars'])
    
    return jsonify({'success': True})

@app.route('/api/deployment/<deploy_id>/env/<key>', methods=['DELETE'])
def api_delete_env_var(deploy_id, key):
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    if deploy_id not in db['deployments']:
        return jsonify({'success': False, 'error': 'Deployment not found'})
    
    deployment = db['deployments'][deploy_id]
    if deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    if 'env_vars' in deployment and key in deployment['env_vars']:
        del deployment['env_vars'][key]
        update_deployment(deploy_id, env_vars=deployment['env_vars'])
    
    return jsonify({'success': True})

@app.route('/api/deployment/<deploy_id>/backup', methods=['POST'])
def api_create_backup(deploy_id):
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    if deploy_id not in db['deployments']:
        return jsonify({'success': False, 'error': 'Deployment not found'})
    
    deployment = db['deployments'][deploy_id]
    if deployment['user_id'] != user_id:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    cost = CREDIT_COSTS['backup']
    if not deduct_credits(user_id, cost, f"Backup: {deploy_id}"):
        return jsonify({'success': False, 'error': f'Need {cost} credits'}), 400
    
    backup_path, backup_name = create_backup(deploy_id)
    
    if not backup_path:
        add_credits(user_id, cost, "Refund")
        return jsonify({'success': False, 'error': backup_name}), 400
    
    return send_file(backup_path, as_attachment=True, download_name=backup_name)

@app.route('/api/admin/system-stats')
def api_admin_system_stats():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    admin_id = verify_session(session_token, fingerprint)
    
    if str(admin_id) != str(OWNER_ID) and str(admin_id) != str(ADMIN_ID):
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    stats = get_system_stats()
    return jsonify({'success': True, 'stats': stats})

@app.route('/api/admin/users')
def api_admin_users():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    admin_id = verify_session(session_token, fingerprint)
    
    if str(admin_id) != str(OWNER_ID) and str(admin_id) != str(ADMIN_ID):
        return jsonify({'success': False, 'error': 'Admin access required'})
    
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
    
    return jsonify({'success': True, 'users': users})

# Redirect root to app
@app.route('/')
def index():
    session_token = request.cookies.get('session_token')
    if session_token:
        return redirect('/app')
    return redirect('/login')

@app.route('/dashboard')
def dashboard_redirect():
    return redirect('/app')

# ==================== LOGIN/REGISTER HTML ====================

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost - {{ title }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        dark: {
                            800: '#1e293b',
                            900: '#0f172a',
                            950: '#020617',
                        }
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-gradient-to-br from-blue-900 via-purple-900 to-pink-900 min-h-screen flex items-center justify-center p-4">
    <div class="bg-dark-900 rounded-2xl shadow-2xl max-w-md w-full p-8 border border-dark-800">
        <!-- Logo -->
        <div class="text-center mb-8">
            <div class="w-20 h-20 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center mx-auto mb-4">
                <i class="fas fa-rocket text-white text-4xl"></i>
            </div>
            <h1 class="text-3xl font-bold text-white mb-2">EliteHost</h1>
            <p class="text-gray-400">Ultimate Deployment Platform</p>
        </div>
        
        <!-- Alerts -->
        {% if error %}
        <div class="bg-red-500/20 border border-red-500 text-red-400 px-4 py-3 rounded-lg mb-6 flex items-start gap-3">
            <i class="fas fa-exclamation-circle mt-0.5"></i>
            <div>{{ error }}</div>
        </div>
        {% endif %}
        
        {% if success %}
        <div class="bg-green-500/20 border border-green-500 text-green-400 px-4 py-3 rounded-lg mb-6 flex items-start gap-3">
            <i class="fas fa-check-circle mt-0.5"></i>
            <div>{{ success }}</div>
        </div>
        {% endif %}
        
        <!-- Device Info -->
        <div class="bg-blue-500/20 border border-blue-500 text-blue-400 px-4 py-3 rounded-lg mb-6 text-sm flex items-start gap-3">
            <i class="fas fa-shield-alt mt-0.5"></i>
            <div>
                <strong>Secure Login:</strong> One account per device for maximum security
            </div>
        </div>
        
        <!-- Form -->
        <form method="POST" action="{{ action }}" class="space-y-4">
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">
                    <i class="fas fa-envelope mr-2"></i>Email Address
                </label>
                <input type="email" name="email" placeholder="you@example.com" required 
                    class="w-full px-4 py-3 bg-dark-800 border border-dark-700 rounded-lg text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none transition-colors">
            </div>
            
            <div>
                <label class="block text-sm font-medium text-gray-300 mb-2">
                    <i class="fas fa-lock mr-2"></i>Password
                </label>
                <input type="password" name="password" placeholder="Enter your password" required 
                    class="w-full px-4 py-3 bg-dark-800 border border-dark-700 rounded-lg text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none transition-colors">
            </div>
            
            <button type="submit" class="w-full py-3 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white font-bold rounded-lg transition-all transform hover:scale-105">
                <i class="fas fa-{{ icon }} mr-2"></i>{{ button_text }}
            </button>
        </form>
        
        <!-- Toggle -->
        <div class="text-center mt-6 text-sm text-gray-400">
            {{ toggle_text }} <a href="{{ toggle_link }}" class="text-blue-400 hover:text-blue-300 font-semibold">{{ toggle_action }}</a>
        </div>
    </div>
</body>
</html>
"""

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string(LOGIN_PAGE,
            title='Register',
            action='/register',
            button_text='Create Account',
            icon='user-plus',
            toggle_text='Already have an account?',
            toggle_link='/login',
            toggle_action='Login here',
            error=request.args.get('error'),
            success=request.args.get('success')
        )
    
    email = request.form.get('email')
    password = request.form.get('password')
    fingerprint = get_device_fingerprint(request)
    ip = request.remote_addr
    
    if is_device_banned(fingerprint):
        return render_template_string(LOGIN_PAGE,
            title='Register',
            action='/register',
            button_text='Create Account',
            icon='user-plus',
            toggle_text='Already have an account?',
            toggle_link='/login',
            toggle_action='Login here',
            error='This device is banned from EliteHost'
        )
    
    existing_user = check_existing_account(fingerprint)
    if existing_user:
        return render_template_string(LOGIN_PAGE,
            title='Register',
            action='/register',
            button_text='Create Account',
            icon='user-plus',
            toggle_text='Already have an account?',
            toggle_link='/login',
            toggle_action='Login here',
            error='This device already has an account. One account per device only.'
        )
    
    for user_data in db['users'].values():
        if user_data['email'] == email:
            return render_template_string(LOGIN_PAGE,
                title='Register',
                action='/register',
                button_text='Create Account',
                icon='user-plus',
                toggle_text='Already have an account?',
                toggle_link='/login',
                toggle_action='Login here',
                error='Email already registered'
            )
    
    user_id = create_user(email, password, fingerprint, ip)
    
    return redirect('/login?success=Account created! Please login.')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string(LOGIN_PAGE,
            title='Login',
            action='/login',
            button_text='Login',
            icon='sign-in-alt',
            toggle_text="Don't have an account?",
            toggle_link='/register',
            toggle_action='Register here',
            error=request.args.get('error'),
            success=request.args.get('success')
        )
    
    email = request.form.get('email')
    password = request.form.get('password')
    fingerprint = get_device_fingerprint(request)
    
    if is_device_banned(fingerprint):
        return render_template_string(LOGIN_PAGE,
            title='Login',
            action='/login',
            button_text='Login',
            icon='sign-in-alt',
            toggle_text="Don't have an account?",
            toggle_link='/register',
            toggle_action='Register here',
            error='This device is banned from EliteHost'
        )
    
    user_id = authenticate_user(email, password)
    
    if not user_id:
        return render_template_string(LOGIN_PAGE,
            title='Login',
            action='/login',
            button_text='Login',
            icon='sign-in-alt',
            toggle_text="Don't have an account?",
            toggle_link='/register',
            toggle_action='Register here',
            error='Invalid email or password'
        )
    
    user = get_user(user_id)
    
    if user.get('is_banned'):
        return render_template_string(LOGIN_PAGE,
            title='Login',
            action='/login',
            button_text='Login',
            icon='sign-in-alt',
            toggle_text="Don't have an account?",
            toggle_link='/register',
            toggle_action='Register here',
            error='Your account has been banned'
        )
    
    if user['device_fingerprint'] != fingerprint:
        return render_template_string(LOGIN_PAGE,
            title='Login',
            action='/login',
            button_text='Login',
            icon='sign-in-alt',
            toggle_text="Don't have an account?",
            toggle_link='/register',
            toggle_action='Register here',
            error='This account is registered on a different device'
        )
    
    session_token = create_session(user_id, fingerprint)
    
    update_user(user_id, last_login=datetime.now().isoformat())
    log_activity(user_id, 'USER_LOGIN', f'Login from {request.remote_addr}', request.remote_addr)
    
    response = make_response(redirect('/app'))
    response.set_cookie('session_token', session_token, max_age=7*24*60*60)
    return response

@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')
    if session_token and session_token in db['sessions']:
        del db['sessions'][session_token]
        save_db(db)
    
    response = make_response(redirect('/login?success=Logged out successfully'))
    response.set_cookie('session_token', '', max_age=0)
    return response

@app.route('/admin')
def admin_redirect():
    return redirect('/app')

# Keep existing API routes
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
        return jsonify({'success': False, 'error': 'No file uploaded'})
    
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
    
    if not repo_url:
        return jsonify({'success': False, 'error': 'Repository URL required'})
    
    deploy_id, msg = deploy_from_github(user_id, repo_url, branch)
    
    if deploy_id:
        return jsonify({'success': True, 'deployment_id': deploy_id, 'message': msg})
    else:
        return jsonify({'success': False, 'error': msg})

@app.route('/api/deployment/<deploy_id>/logs')
def api_deployment_logs(deploy_id):
    if deploy_id not in db['deployments']:
        return jsonify({'success': False, 'error': 'Not found'})
    
    logs = db['deployments'][deploy_id].get('logs', 'No logs available')
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

@app.route('/api/admin/add-credits', methods=['POST'])
def api_admin_add_credits():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    admin_id = verify_session(session_token, fingerprint)
    
    if str(admin_id) != str(OWNER_ID) and str(admin_id) != str(ADMIN_ID):
        return jsonify({'success': False, 'error': 'Admin access required'})
    
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
        return jsonify({'success': False, 'error': 'Admin access required'})
    
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

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

def keep_alive():
    t = Thread(target=run_flask, daemon=True)
    t.start()
    logger.info(f"{Fore.GREEN}✅ Web App: http://localhost:{os.environ.get('PORT', 8080)}")

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
    print(f"{Fore.CYAN}{'🚀 ELITEHOST v11.0 - ULTIMATE ENTERPRISE EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}✨ NEW FEATURES v11.0:")
    print(f"{Fore.CYAN}   🎨 Modern SPA UI with TailwindCSS & Alpine.js")
    print(f"{Fore.CYAN}   🌙 Dark Mode by Default (Vercel/Railway style)")
    print(f"{Fore.CYAN}   📁 Sidebar Navigation")
    print(f"{Fore.CYAN}   🔑 Environment Variables Management")
    print(f"{Fore.CYAN}   💾 Backup System (Create & Download ZIP)")
    print(f"{Fore.CYAN}   📂 File Manager (Browse deployment files)")
    print(f"{Fore.CYAN}   💻 Live Console (Auto-refresh logs)")
    print(f"{Fore.CYAN}   👑 Advanced Admin Dashboard")
    print(f"{Fore.CYAN}   📊 CPU/RAM Monitoring per Process")
    print(f"{Fore.CYAN}   🤖 AI Auto-Install Dependencies")
    print(f"{Fore.CYAN}   🔐 Advanced Authentication & Security")
    print("=" * 90)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 Web App: http://localhost:{port}/app")
    print(f"{Fore.YELLOW}📱 Register: http://localhost:{port}/register")
    print(f"{Fore.YELLOW}🔑 Login: http://localhost:{port}/login")
    print(f"\n{Fore.GREEN}{'✅ ELITEHOST v11.0 ULTIMATE READY':^90}")
    print("=" * 90 + "\n")
    
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
