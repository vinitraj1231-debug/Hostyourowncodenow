# -*- coding: utf-8 -*-
"""
🚀 ELITEHOST v11.0 - ULTIMATE ENTERPRISE EDITION
Next-Gen AI-Powered Deployment Platform
Dark Mode | SPA Design | Environment Variables | File Manager | Live Logs
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
from flask import Flask, render_template_string, request, jsonify, session, send_file, redirect, make_response, send_from_directory
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
        'banned_devices': [],
        'password_reset_tokens': {}
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
if 'password_reset_tokens' not in db:
    db['password_reset_tokens'] = {}

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
    
    # Send notification to owner
    try:
        bot.send_message(
            OWNER_ID,
            f"🎉 *New User Registration*\n\n"
            f"📧 Email: `{email}`\n"
            f"🆔 ID: `{user_id}`\n"
            f"📍 IP: `{ip}`\n"
            f"💎 Credits: {FREE_CREDITS}\n"
            f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
    except:
        pass
    
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
        'expires_at': (datetime.now() + timedelta(days=30)).isoformat()
    }
    
    save_db(db)
    return session_token

def verify_session(session_token, fingerprint):
    """Verify session token"""
    if session_token not in db['sessions']:
        return None
    
    session_data = db['sessions'][session_token]
    
    # Check expiration
    if datetime.fromisoformat(session_data['expires_at']) < datetime.now():
        del db['sessions'][session_token]
        save_db(db)
        return None
    
    # Check fingerprint match
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

def create_password_reset_token(email):
    """Create password reset token"""
    token = secrets.token_urlsafe(32)
    db['password_reset_tokens'][token] = {
        'email': email,
        'created_at': datetime.now().isoformat(),
        'expires_at': (datetime.now() + timedelta(hours=1)).isoformat()
    }
    save_db(db)
    return token

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
    
    # Check requirements.txt
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
    
    # Smart code analysis
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
        
        # Send notification to owner
        user = get_user(user_id)
        try:
            bot.send_message(
                OWNER_ID,
                f"📁 *File Upload Deployment*\n\n"
                f"👤 User: `{user['email']}`\n"
                f"📄 File: `{filename}`\n"
                f"🆔 Deploy ID: `{deploy_id}`\n"
                f"🔌 Port: `{port}`\n"
                f"📦 Deps: `{len(installed_deps)}`"
            )
        except:
            pass
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        # Add custom env vars
        deployment = db['deployments'][deploy_id]
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = value
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Launching on port {port}...')
        
        # Determine command
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
        
        # Send notification to owner
        user = get_user(user_id)
        try:
            bot.send_message(
                OWNER_ID,
                f"🐙 *GitHub Deployment*\n\n"
                f"👤 User: `{user['email']}`\n"
                f"📦 Repo: `{repo_url}`\n"
                f"🌿 Branch: `{branch}`\n"
                f"🆔 Deploy ID: `{deploy_id}`\n"
                f"🔌 Port: `{port}`"
            )
        except:
            pass
        
        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        update_deployment(deploy_id, dependencies=installed_deps)
        
        # Run build command if provided
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
        
        # Determine start command
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
        
        # Add custom env vars
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
    """Create backup of deployment"""
    try:
        if deploy_id not in db['deployments']:
            return None, "Deployment not found"
        
        deployment = db['deployments'][deploy_id]
        deploy_dir = deployment.get('path', '')
        
        if not deploy_dir or not os.path.exists(deploy_dir):
            return None, "Deployment path not found"
        
        # Create backup
        backup_name = f"{deployment['name']}_{deploy_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        backup_path = os.path.join(BACKUPS_DIR, backup_name)
        
        shutil.make_archive(backup_path.replace('.zip', ''), 'zip', deploy_dir)
        
        return backup_path, backup_name
    except Exception as e:
        return None, str(e)

def get_deployment_files(deploy_id):
    """Get list of files in deployment"""
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost - Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        dark: {
                            bg: '#0a0a0a',
                            card: '#111111',
                            border: '#1f1f1f'
                        }
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-dark-bg text-gray-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md">
        <div class="bg-dark-card border border-dark-border rounded-2xl p-8 shadow-2xl">
            <!-- Logo -->
            <div class="text-center mb-8">
                <div class="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-600 rounded-xl mb-4">
                    <i class="fas fa-rocket text-2xl text-white"></i>
                </div>
                <h1 class="text-3xl font-bold mb-2">EliteHost</h1>
                <p class="text-gray-400 text-sm">Enterprise Deployment Platform</p>
            </div>
            
            {% if error %}
            <div class="bg-red-500/10 border border-red-500/50 text-red-400 px-4 py-3 rounded-lg mb-4 text-sm">
                <i class="fas fa-exclamation-circle mr-2"></i>{{ error }}
            </div>
            {% endif %}
            
            {% if success %}
            <div class="bg-green-500/10 border border-green-500/50 text-green-400 px-4 py-3 rounded-lg mb-4 text-sm">
                <i class="fas fa-check-circle mr-2"></i>{{ success }}
            </div>
            {% endif %}
            
            <form method="POST" action="{{ action }}">
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium mb-2 text-gray-300">
                            <i class="fas fa-envelope mr-2"></i>Email
                        </label>
                        <input type="email" name="email" required
                            class="w-full px-4 py-3 bg-dark-bg border border-dark-border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition text-white">
                    </div>
                    
                    <div>
                        <label class="block text-sm font-medium mb-2 text-gray-300">
                            <i class="fas fa-lock mr-2"></i>Password
                        </label>
                        <input type="password" name="password" required
                            class="w-full px-4 py-3 bg-dark-bg border border-dark-border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none transition text-white">
                    </div>
                    
                    <button type="submit" 
                        class="w-full py-3 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 rounded-lg font-semibold transition transform hover:scale-[1.02] active:scale-[0.98]">
                        <i class="fas fa-{{ icon }} mr-2"></i>{{ button_text }}
                    </button>
                </div>
            </form>
            
            <div class="mt-6 text-center text-sm text-gray-400">
                {{ toggle_text }} <a href="{{ toggle_link }}" class="text-blue-400 hover:text-blue-300 font-semibold">{{ toggle_action }}</a>
            </div>
            
            {% if action == '/login' %}
            <div class="mt-4 text-center">
                <a href="/forgot-password" class="text-sm text-gray-400 hover:text-gray-300">
                    <i class="fas fa-key mr-1"></i>Forgot Password?
                </a>
            </div>
            {% endif %}
            
            <div class="mt-6 pt-6 border-t border-dark-border">
                <div class="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3 text-xs text-gray-300">
                    <i class="fas fa-shield-alt text-blue-400 mr-2"></i>
                    <strong>Secure Login:</strong> One account per device policy
                </div>
            </div>
        </div>
        
        <div class="text-center mt-6 text-sm text-gray-500">
            <p>© 2025 EliteHost v11.0 - Enterprise Edition</p>
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - EliteHost</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-dark-bg text-gray-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md">
        <div class="bg-dark-card border border-dark-border rounded-2xl p-8 shadow-2xl">
            <div class="text-center mb-8">
                <div class="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-orange-500 to-red-600 rounded-xl mb-4">
                    <i class="fas fa-key text-2xl text-white"></i>
                </div>
                <h1 class="text-2xl font-bold mb-2">Reset Password</h1>
                <p class="text-gray-400 text-sm">Contact admin to reset your password</p>
            </div>
            
            <div class="bg-yellow-500/10 border border-yellow-500/50 text-yellow-400 px-4 py-4 rounded-lg mb-6 text-sm">
                <i class="fas fa-info-circle mr-2"></i>
                <strong>Password Reset Process:</strong><br>
                Please contact the admin via Telegram to reset your password.
            </div>
            
            <a href="{{ telegram_link }}" target="_blank"
                class="block w-full py-3 bg-gradient-to-r from-blue-500 to-blue-600 hover:from-blue-600 hover:to-blue-700 rounded-lg font-semibold text-center transition transform hover:scale-[1.02] active:scale-[0.98]">
                <i class="fab fa-telegram mr-2"></i>Contact Admin
            </a>
            
            <div class="mt-6 text-center">
                <a href="/login" class="text-sm text-gray-400 hover:text-gray-300">
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - EliteHost</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        dark: {
                            bg: '#0a0a0a',
                            card: '#111111',
                            border: '#1f1f1f'
                        }
                    }
                }
            }
        }
    </script>
    <style>
        [x-cloak] { display: none !important; }
        .scrollbar-hide::-webkit-scrollbar { display: none; }
        .scrollbar-hide { -ms-overflow-style: none; scrollbar-width: none; }
    </style>
</head>
<body class="bg-dark-bg text-gray-100" x-data="dashboard()" x-init="init()">
    <!-- Mobile Sidebar Overlay -->
    <div x-show="sidebarOpen" 
         x-cloak
         @click="sidebarOpen = false"
         class="fixed inset-0 bg-black/50 z-40 lg:hidden"></div>
    
    <!-- Sidebar -->
    <aside :class="sidebarOpen ? 'translate-x-0' : '-translate-x-full'"
           class="fixed inset-y-0 left-0 w-64 bg-dark-card border-r border-dark-border z-50 transition-transform lg:translate-x-0">
        <div class="flex flex-col h-full">
            <!-- Logo -->
            <div class="p-6 border-b border-dark-border">
                <div class="flex items-center gap-3">
                    <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center">
                        <i class="fas fa-rocket text-white"></i>
                    </div>
                    <div>
                        <h1 class="font-bold text-lg">EliteHost</h1>
                        <p class="text-xs text-gray-400">v11.0</p>
                    </div>
                </div>
            </div>
            
            <!-- Navigation -->
            <nav class="flex-1 p-4 space-y-2 overflow-y-auto scrollbar-hide">
                <button @click="currentTab = 'overview'" 
                        :class="currentTab === 'overview' ? 'bg-blue-500/20 text-blue-400 border-blue-500/50' : 'text-gray-400 hover:bg-dark-border'"
                        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition border border-transparent">
                    <i class="fas fa-home w-5"></i>
                    <span class="font-medium">Overview</span>
                </button>
                
                <button @click="currentTab = 'deployments'" 
                        :class="currentTab === 'deployments' ? 'bg-blue-500/20 text-blue-400 border-blue-500/50' : 'text-gray-400 hover:bg-dark-border'"
                        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition border border-transparent">
                    <i class="fas fa-rocket w-5"></i>
                    <span class="font-medium">Deployments</span>
                </button>
                
                <button @click="currentTab = 'deploy'" 
                        :class="currentTab === 'deploy' ? 'bg-blue-500/20 text-blue-400 border-blue-500/50' : 'text-gray-400 hover:bg-dark-border'"
                        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition border border-transparent">
                    <i class="fas fa-plus-circle w-5"></i>
                    <span class="font-medium">New Deploy</span>
                </button>
                
                {% if is_admin %}
                <button @click="window.location.href='/admin'" 
                        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition text-yellow-400 hover:bg-yellow-500/10 border border-transparent hover:border-yellow-500/30">
                    <i class="fas fa-crown w-5"></i>
                    <span class="font-medium">Admin Panel</span>
                </button>
                {% endif %}
            </nav>
            
            <!-- User Info -->
            <div class="p-4 border-t border-dark-border">
                <div class="bg-dark-bg rounded-lg p-4 mb-3">
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-sm text-gray-400">Credits</span>
                        <span class="text-xl font-bold text-blue-400" x-text="credits === Infinity ? '∞' : credits.toFixed(1)"></span>
                    </div>
                    <div class="h-2 bg-dark-border rounded-full overflow-hidden">
                        <div class="h-full bg-gradient-to-r from-blue-500 to-purple-600" 
                             :style="`width: ${credits === Infinity ? 100 : Math.min(credits * 50, 100)}%`"></div>
                    </div>
                </div>
                
                <button @click="logout()" 
                        class="w-full py-2 bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-lg transition font-medium">
                    <i class="fas fa-sign-out-alt mr-2"></i>Logout
                </button>
            </div>
        </div>
    </aside>
    
    <!-- Main Content -->
    <main class="lg:ml-64 min-h-screen pb-20">
        <!-- Mobile Header -->
        <header class="lg:hidden sticky top-0 z-30 bg-dark-card border-b border-dark-border p-4">
            <div class="flex items-center justify-between">
                <button @click="sidebarOpen = !sidebarOpen" class="text-gray-400">
                    <i class="fas fa-bars text-xl"></i>
                </button>
                <h2 class="font-bold text-lg">EliteHost</h2>
                <div class="w-6"></div>
            </div>
        </header>
        
        <div class="p-4 lg:p-8">
            <!-- Overview Tab -->
            <div x-show="currentTab === 'overview'" x-cloak class="space-y-6">
                <div>
                    <h1 class="text-3xl font-bold mb-2">Welcome Back!</h1>
                    <p class="text-gray-400">Manage your deployments with AI-powered automation</p>
                </div>
                
                <!-- Stats Grid -->
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    <div class="bg-dark-card border border-dark-border rounded-xl p-6">
                        <div class="flex items-center justify-between mb-3">
                            <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-rocket text-blue-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1" x-text="deployments.length">0</div>
                        <div class="text-sm text-gray-400">Total Deployments</div>
                    </div>
                    
                    <div class="bg-dark-card border border-dark-border rounded-xl p-6">
                        <div class="flex items-center justify-between mb-3">
                            <div class="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-check-circle text-green-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1" x-text="deployments.filter(d => d.status === 'running').length">0</div>
                        <div class="text-sm text-gray-400">Active Now</div>
                    </div>
                    
                    <div class="bg-dark-card border border-dark-border rounded-xl p-6">
                        <div class="flex items-center justify-between mb-3">
                            <div class="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-gem text-purple-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1" x-text="credits === Infinity ? '∞' : credits.toFixed(1)">0</div>
                        <div class="text-sm text-gray-400">Credits Available</div>
                    </div>
                    
                    <div class="bg-dark-card border border-dark-border rounded-xl p-6">
                        <div class="flex items-center justify-between mb-3">
                            <div class="w-12 h-12 bg-orange-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-robot text-orange-400 text-xl"></i>
                            </div>
                        </div>
                        <div class="text-3xl font-bold mb-1">AI</div>
                        <div class="text-sm text-gray-400">Auto Install</div>
                    </div>
                </div>
                
                <!-- Quick Actions -->
                <div class="bg-dark-card border border-dark-border rounded-xl p-6">
                    <h2 class="text-xl font-bold mb-4">Quick Actions</h2>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <button @click="currentTab = 'deploy'" 
                                class="p-4 bg-gradient-to-br from-blue-500/20 to-purple-500/20 hover:from-blue-500/30 hover:to-purple-500/30 border border-blue-500/30 rounded-xl transition text-left">
                            <i class="fas fa-cloud-upload-alt text-2xl text-blue-400 mb-2"></i>
                            <h3 class="font-semibold mb-1">Upload Files</h3>
                            <p class="text-sm text-gray-400">Deploy Python, JS, or ZIP files</p>
                        </button>
                        
                        <button @click="currentTab = 'deploy'" 
                                class="p-4 bg-gradient-to-br from-gray-700/50 to-black/50 hover:from-gray-700/70 hover:to-black/70 border border-gray-600 rounded-xl transition text-left">
                            <i class="fab fa-github text-2xl text-white mb-2"></i>
                            <h3 class="font-semibold mb-1">GitHub Deploy</h3>
                            <p class="text-sm text-gray-400">Clone and deploy from repository</p>
                        </button>
                    </div>
                </div>
            </div>
            
            <!-- Deployments Tab -->
            <div x-show="currentTab === 'deployments'" x-cloak class="space-y-6">
                <div class="flex items-center justify-between">
                    <h1 class="text-3xl font-bold">Deployments</h1>
                    <button @click="loadDeployments()" class="px-4 py-2 bg-dark-card border border-dark-border rounded-lg hover:bg-dark-border transition">
                        <i class="fas fa-sync mr-2"></i>Refresh
                    </button>
                </div>
                
                <div class="space-y-4" x-show="deployments.length > 0">
                    <template x-for="deploy in deployments" :key="deploy.id">
                        <div class="bg-dark-card border border-dark-border rounded-xl p-6 hover:border-blue-500/50 transition">
                            <div class="flex items-start justify-between mb-4">
                                <div class="flex-1">
                                    <h3 class="text-lg font-bold mb-2" x-text="deploy.name"></h3>
                                    <div class="flex flex-wrap gap-3 text-sm text-gray-400">
                                        <span><i class="fas fa-fingerprint mr-1"></i><span x-text="deploy.id"></span></span>
                                        <span><i class="fas fa-network-wired mr-1"></i>Port <span x-text="deploy.port"></span></span>
                                        <span x-show="deploy.dependencies && deploy.dependencies.length > 0">
                                            <i class="fas fa-robot mr-1"></i><span x-text="deploy.dependencies.length"></span> AI installs
                                        </span>
                                    </div>
                                </div>
                                <span :class="{
                                    'bg-green-500/20 text-green-400': deploy.status === 'running',
                                    'bg-yellow-500/20 text-yellow-400': deploy.status === 'pending' || deploy.status === 'installing',
                                    'bg-red-500/20 text-red-400': deploy.status === 'stopped' || deploy.status === 'failed'
                                }" class="px-3 py-1 rounded-full text-xs font-bold uppercase" x-text="deploy.status"></span>
                            </div>
                            
                            <div class="flex flex-wrap gap-2">
                                <button @click="viewDeployment(deploy.id)" 
                                        class="px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 text-blue-400 rounded-lg transition text-sm font-medium">
                                    <i class="fas fa-eye mr-1"></i>View
                                </button>
                                <button @click="viewLogs(deploy.id)" 
                                        class="px-4 py-2 bg-gray-700/50 hover:bg-gray-700/70 text-gray-300 rounded-lg transition text-sm font-medium">
                                    <i class="fas fa-terminal mr-1"></i>Logs
                                </button>
                                <button @click="stopDeploy(deploy.id)" 
                                        class="px-4 py-2 bg-orange-500/20 hover:bg-orange-500/30 text-orange-400 rounded-lg transition text-sm font-medium">
                                    <i class="fas fa-stop mr-1"></i>Stop
                                </button>
                                <button @click="deleteDeploy(deploy.id)" 
                                        class="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-400 rounded-lg transition text-sm font-medium">
                                    <i class="fas fa-trash mr-1"></i>Delete
                                </button>
                            </div>
                        </div>
                    </template>
                </div>
                
                <div x-show="deployments.length === 0" class="text-center py-16">
                    <i class="fas fa-rocket text-6xl text-gray-600 mb-4"></i>
                    <h3 class="text-xl font-bold mb-2">No Deployments Yet</h3>
                    <p class="text-gray-400 mb-6">Start by deploying your first application</p>
                    <button @click="currentTab = 'deploy'" 
                            class="px-6 py-3 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 rounded-lg font-semibold transition">
                        <i class="fas fa-plus mr-2"></i>New Deployment
                    </button>
                </div>
            </div>
            
            <!-- Deploy Tab -->
            <div x-show="currentTab === 'deploy'" x-cloak class="space-y-6">
                <h1 class="text-3xl font-bold">New Deployment</h1>
                
                <!-- Deploy Method Selection -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <button @click="deployMethod = 'file'" 
                            :class="deployMethod === 'file' ? 'border-blue-500 bg-blue-500/10' : 'border-dark-border'"
                            class="p-6 border-2 rounded-xl transition text-left">
                        <div class="flex items-center gap-4 mb-3">
                            <div class="w-14 h-14 bg-blue-500/20 rounded-xl flex items-center justify-center">
                                <i class="fas fa-cloud-upload-alt text-2xl text-blue-400"></i>
                            </div>
                            <div>
                                <h3 class="font-bold text-lg">Upload Files</h3>
                                <p class="text-sm text-gray-400">0.5 credits</p>
                            </div>
                        </div>
                        <p class="text-sm text-gray-400">Deploy Python, JavaScript, or ZIP files with AI auto-install</p>
                    </button>
                    
                    <button @click="deployMethod = 'github'" 
                            :class="deployMethod === 'github' ? 'border-gray-600 bg-gray-700/20' : 'border-dark-border'"
                            class="p-6 border-2 rounded-xl transition text-left">
                        <div class="flex items-center gap-4 mb-3">
                            <div class="w-14 h-14 bg-gray-700/50 rounded-xl flex items-center justify-center">
                                <i class="fab fa-github text-2xl text-white"></i>
                            </div>
                            <div>
                                <h3 class="font-bold text-lg">GitHub Deploy</h3>
                                <p class="text-sm text-gray-400">1.0 credit</p>
                            </div>
                        </div>
                        <p class="text-sm text-gray-400">Clone repository and deploy with custom build commands</p>
                    </button>
                </div>
                
                <!-- File Upload Form -->
                <div x-show="deployMethod === 'file'" class="bg-dark-card border border-dark-border rounded-xl p-6">
                    <h2 class="text-xl font-bold mb-4">Upload & Deploy</h2>
                    
                    <div @click="$refs.fileInput.click()" 
                         class="border-2 border-dashed border-blue-500/50 rounded-xl p-12 text-center cursor-pointer hover:border-blue-500 hover:bg-blue-500/5 transition">
                        <i class="fas fa-cloud-upload-alt text-5xl text-blue-400 mb-4"></i>
                        <h3 class="font-semibold text-lg mb-2">Click to Upload</h3>
                        <p class="text-sm text-gray-400 mb-2">Python (.py), JavaScript (.js), or ZIP files</p>
                        <p class="text-xs text-gray-500">AI will automatically detect and install dependencies</p>
                        <input type="file" x-ref="fileInput" @change="uploadFile($event)" accept=".py,.js,.zip" class="hidden">
                    </div>
                </div>
                
                <!-- GitHub Deploy Form -->
                <div x-show="deployMethod === 'github'" class="bg-dark-card border border-dark-border rounded-xl p-6">
                    <h2 class="text-xl font-bold mb-4">Deploy from GitHub</h2>
                    
                    <form @submit.prevent="deployGithub()" class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium mb-2">Repository URL *</label>
                            <input type="url" x-model="githubUrl" required
                                   placeholder="https://github.com/username/repo"
                                   class="w-full px-4 py-3 bg-dark-bg border border-dark-border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none">
                        </div>
                        
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div>
                                <label class="block text-sm font-medium mb-2">Branch</label>
                                <input type="text" x-model="githubBranch"
                                       placeholder="main"
                                       class="w-full px-4 py-3 bg-dark-bg border border-dark-border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none">
                            </div>
                            
                            <div>
                                <label class="block text-sm font-medium mb-2">Build Command (Optional)</label>
                                <input type="text" x-model="buildCommand"
                                       placeholder="npm install"
                                       class="w-full px-4 py-3 bg-dark-bg border border-dark-border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none">
                            </div>
                        </div>
                        
                        <div>
                            <label class="block text-sm font-medium mb-2">Start Command (Optional)</label>
                            <input type="text" x-model="startCommand"
                                   placeholder="python main.py or node index.js"
                                   class="w-full px-4 py-3 bg-dark-bg border border-dark-border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent outline-none">
                        </div>
                        
                        <button type="submit" 
                                class="w-full py-3 bg-gradient-to-r from-gray-700 to-black hover:from-gray-600 hover:to-gray-900 rounded-lg font-semibold transition">
                            <i class="fab fa-github mr-2"></i>Deploy from GitHub (1.0 credit)
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </main>
    
    <!-- Deployment Detail Modal -->
    <div x-show="selectedDeploy" 
         x-cloak
         @click.self="selectedDeploy = null"
         class="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4 overflow-y-auto">
        <div @click.stop class="bg-dark-card border border-dark-border rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
            <!-- Modal Header -->
            <div class="flex items-center justify-between p-6 border-b border-dark-border">
                <div>
                    <h2 class="text-2xl font-bold" x-text="selectedDeploy?.name"></h2>
                    <p class="text-sm text-gray-400 mt-1">Deployment ID: <span x-text="selectedDeploy?.id"></span></p>
                </div>
                <button @click="selectedDeploy = null" class="text-gray-400 hover:text-white">
                    <i class="fas fa-times text-2xl"></i>
                </button>
            </div>
            
            <!-- Modal Tabs -->
            <div class="border-b border-dark-border px-6">
                <div class="flex gap-4 overflow-x-auto scrollbar-hide">
                    <button @click="modalTab = 'info'" 
                            :class="modalTab === 'info' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400'"
                            class="py-4 px-2 border-b-2 font-medium whitespace-nowrap transition">
                        <i class="fas fa-info-circle mr-2"></i>Info
                    </button>
                    <button @click="modalTab = 'logs'" 
                            :class="modalTab === 'logs' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400'"
                            class="py-4 px-2 border-b-2 font-medium whitespace-nowrap transition">
                        <i class="fas fa-terminal mr-2"></i>Logs
                    </button>
                    <button @click="modalTab = 'env'; loadEnvVars()" 
                            :class="modalTab === 'env' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400'"
                            class="py-4 px-2 border-b-2 font-medium whitespace-nowrap transition">
                        <i class="fas fa-key mr-2"></i>Environment
                    </button>
                    <button @click="modalTab = 'files'; loadFiles()" 
                            :class="modalTab === 'files' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400'"
                            class="py-4 px-2 border-b-2 font-medium whitespace-nowrap transition">
                        <i class="fas fa-folder mr-2"></i>Files
                    </button>
                    <button @click="modalTab = 'backup'" 
                            :class="modalTab === 'backup' ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-400'"
                            class="py-4 px-2 border-b-2 font-medium whitespace-nowrap transition">
                        <i class="fas fa-download mr-2"></i>Backup
                    </button>
                </div>
            </div>
            
            <!-- Modal Content -->
            <div class="flex-1 overflow-y-auto p-6">
                <!-- Info Tab -->
                <div x-show="modalTab === 'info'" class="space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="bg-dark-bg rounded-lg p-4">
                            <div class="text-sm text-gray-400 mb-1">Status</div>
                            <div class="font-semibold capitalize" x-text="selectedDeploy?.status"></div>
                        </div>
                        <div class="bg-dark-bg rounded-lg p-4">
                            <div class="text-sm text-gray-400 mb-1">Port</div>
                            <div class="font-semibold" x-text="selectedDeploy?.port"></div>
                        </div>
                        <div class="bg-dark-bg rounded-lg p-4">
                            <div class="text-sm text-gray-400 mb-1">Type</div>
                            <div class="font-semibold capitalize" x-text="selectedDeploy?.type"></div>
                        </div>
                        <div class="bg-dark-bg rounded-lg p-4">
                            <div class="text-sm text-gray-400 mb-1">Created</div>
                            <div class="font-semibold" x-text="new Date(selectedDeploy?.created_at).toLocaleString()"></div>
                        </div>
                    </div>
                    
                    <div x-show="selectedDeploy?.repo_url" class="bg-dark-bg rounded-lg p-4">
                        <div class="text-sm text-gray-400 mb-1">Repository</div>
                        <div class="font-mono text-sm" x-text="selectedDeploy?.repo_url"></div>
                    </div>
                    
                    <div x-show="selectedDeploy?.dependencies?.length > 0" class="bg-dark-bg rounded-lg p-4">
                        <div class="text-sm text-gray-400 mb-2">AI Installed Dependencies</div>
                        <div class="flex flex-wrap gap-2">
                            <template x-for="dep in selectedDeploy?.dependencies" :key="dep">
                                <span class="px-3 py-1 bg-blue-500/20 text-blue-400 rounded-full text-xs font-medium" x-text="dep"></span>
                            </template>
                        </div>
                    </div>
                </div>
                
                <!-- Logs Tab -->
                <div x-show="modalTab === 'logs'" class="space-y-4">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="font-semibold">Live Console</h3>
                        <button @click="loadLogs()" class="text-sm text-blue-400 hover:text-blue-300">
                            <i class="fas fa-sync mr-1"></i>Refresh
                        </button>
                    </div>
                    <div class="bg-black rounded-lg p-4 font-mono text-sm text-green-400 h-96 overflow-y-auto whitespace-pre-wrap scrollbar-hide" x-text="logs || 'No logs available'"></div>
                </div>
                
                <!-- Environment Tab -->
                <div x-show="modalTab === 'env'" class="space-y-4">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="font-semibold">Environment Variables</h3>
                        <button @click="showAddEnv = true" class="px-4 py-2 bg-blue-500/20 text-blue-400 rounded-lg hover:bg-blue-500/30 transition text-sm">
                            <i class="fas fa-plus mr-2"></i>Add Variable
                        </button>
                    </div>
                    
                    <div x-show="showAddEnv" class="bg-dark-bg rounded-lg p-4 mb-4">
                        <form @submit.prevent="addEnvVar()" class="space-y-3">
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                                <input type="text" x-model="newEnvKey" placeholder="KEY" required
                                       class="px-4 py-2 bg-dark-card border border-dark-border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none">
                                <input type="text" x-model="newEnvValue" placeholder="value" required
                                       class="px-4 py-2 bg-dark-card border border-dark-border rounded-lg focus:ring-2 focus:ring-blue-500 outline-none">
                            </div>
                            <div class="flex gap-2">
                                <button type="submit" class="px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg text-sm font-medium transition">
                                    Add
                                </button>
                                <button type="button" @click="showAddEnv = false; newEnvKey = ''; newEnvValue = ''" 
                                        class="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm font-medium transition">
                                    Cancel
                                </button>
                            </div>
                        </form>
                    </div>
                    
                    <div class="space-y-2">
                        <template x-for="(value, key) in envVars" :key="key">
                            <div class="bg-dark-bg rounded-lg p-4 flex items-center justify-between">
                                <div class="flex-1">
                                    <div class="font-mono text-sm text-blue-400" x-text="key"></div>
                                    <div class="font-mono text-xs text-gray-400 mt-1" x-text="value"></div>
                                </div>
                                <button @click="deleteEnvVar(key)" class="text-red-400 hover:text-red-300 ml-4">
                                    <i class="fas fa-trash"></i>
                                </button>
                            </div>
                        </template>
                        <div x-show="Object.keys(envVars).length === 0" class="text-center py-8 text-gray-400">
                            <i class="fas fa-key text-4xl mb-2 opacity-30"></i>
                            <p>No environment variables set</p>
                        </div>
                    </div>
                </div>
                
                <!-- Files Tab -->
                <div x-show="modalTab === 'files'" class="space-y-4">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="font-semibold">File Browser</h3>
                        <button @click="loadFiles()" class="text-sm text-blue-400 hover:text-blue-300">
                            <i class="fas fa-sync mr-1"></i>Refresh
                        </button>
                    </div>
                    
                    <div class="space-y-2">
                        <template x-for="file in files" :key="file.path">
                            <div class="bg-dark-bg rounded-lg p-4 hover:bg-dark-border transition">
                                <div class="flex items-center gap-3">
                                    <i class="fas fa-file-code text-blue-400"></i>
                                    <div class="flex-1">
                                        <div class="font-mono text-sm" x-text="file.path"></div>
                                        <div class="text-xs text-gray-400 mt-1">
                                            <span x-text="(file.size / 1024).toFixed(2)"></span> KB
                                            <span class="mx-2">•</span>
                                            <span x-text="new Date(file.modified).toLocaleString()"></span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </template>
                        <div x-show="files.length === 0" class="text-center py-8 text-gray-400">
                            <i class="fas fa-folder-open text-4xl mb-2 opacity-30"></i>
                            <p>No files found</p>
                        </div>
                    </div>
                </div>
                
                <!-- Backup Tab -->
                <div x-show="modalTab === 'backup'" class="space-y-4">
                    <div class="bg-yellow-500/10 border border-yellow-500/50 rounded-lg p-4 text-sm text-yellow-400">
                        <i class="fas fa-info-circle mr-2"></i>
                        Creating a backup will cost 0.5 credits
                    </div>
                    
                    <button @click="createBackup()" 
                            class="w-full py-4 bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 rounded-lg font-semibold transition">
                        <i class="fas fa-download mr-2"></i>Create & Download Backup
                    </button>
                    
                    <div class="bg-dark-bg rounded-lg p-4">
                        <h4 class="font-semibold mb-3">Backup Information</h4>
                        <ul class="space-y-2 text-sm text-gray-400">
                            <li><i class="fas fa-check text-green-400 mr-2"></i>All project files included</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>ZIP format for easy extraction</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>Environment variables excluded</li>
                            <li><i class="fas fa-check text-green-400 mr-2"></i>Ready for re-deployment</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        function dashboard() {
            return {
                sidebarOpen: false,
                currentTab: 'overview',
                modalTab: 'info',
                deployMethod: 'file',
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
                        const res = await fetch('/api/deployments');
                        const data = await res.json();
                        if (data.success) {
                            this.deployments = data.deployments;
                        }
                    } catch (e) {
                        console.error(e);
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
                    
                    alert('🤖 Uploading and deploying... Please wait!');
                    
                    try {
                        const res = await fetch('/api/deploy/upload', {
                            method: 'POST',
                            body: formData
                        });
                        const data = await res.json();
                        
                        if (data.success) {
                            alert('✅ Deployment successful!\n\n' + data.message);
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
                    
                    alert('🤖 Cloning and deploying... This may take a minute!');
                    
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
                            alert('✅ GitHub deployment successful!\n\n' + data.message);
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
                
                async viewLogs(id) {
                    this.selectedDeploy = this.deployments.find(d => d.id === id);
                    this.modalTab = 'logs';
                    await this.loadLogs();
                },
                
                async loadLogs() {
                    if (!this.selectedDeploy) return;
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/logs`);
                        const data = await res.json();
                        this.logs = data.logs || 'No logs available';
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
                        } else {
                            alert('❌ Error: ' + data.error);
                        }
                    } catch (e) {
                        alert('❌ Error: ' + e.message);
                    }
                },
                
                async deleteEnvVar(key) {
                    if (!confirm(`Delete environment variable "${key}"?`)) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env/${key}`, {
                            method: 'DELETE'
                        });
                        const data = await res.json();
                        
                        if (data.success) {
                            delete this.envVars[key];
                            await this.loadDeployments();
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
                            alert('✅ Backup created and downloaded!');
                        } else {
                            const data = await res.json();
                            alert('❌ Error: ' + data.error);
                        }
                    } catch (e) {
                        alert('❌ Error: ' + e.message);
                    }
                },
                
                async stopDeploy(id) {
                    if (!confirm('Stop this deployment?')) return;
                    
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
                    if (!confirm('Delete this deployment permanently?')) return;
                    
                    try {
                        const res = await fetch(`/api/deployment/${id}`, {method: 'DELETE'});
                        const data = await res.json();
                        alert(data.success ? '✅ Deleted' : '❌ Failed');
                        await this.loadDeployments();
                    } catch (e) {
                        alert('❌ Error: ' + e.message);
                    }
                },
                
                logout() {
                    if (confirm('Logout from EliteHost?')) {
                        window.location.href = '/logout';
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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel - EliteHost</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        dark: {
                            bg: '#0a0a0a',
                            card: '#111111',
                            border: '#1f1f1f'
                        }
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-dark-bg text-gray-100" x-data="adminPanel()" x-init="init()">
    <div class="min-h-screen">
        <!-- Header -->
        <header class="bg-dark-card border-b border-dark-border">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
                <div class="flex items-center justify-between">
                    <div>
                        <h1 class="text-3xl font-bold flex items-center gap-3">
                            <i class="fas fa-crown text-yellow-400"></i>
                            Admin Control Panel
                        </h1>
                        <p class="text-gray-400 mt-1">System management and monitoring</p>
                    </div>
                    <div class="flex gap-3">
                        <button @click="location.reload()" class="px-4 py-2 bg-dark-bg border border-dark-border rounded-lg hover:bg-dark-border transition">
                            <i class="fas fa-sync mr-2"></i>Refresh
                        </button>
                        <button @click="window.location.href='/dashboard'" class="px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded-lg transition">
                            <i class="fas fa-arrow-left mr-2"></i>Dashboard
                        </button>
                    </div>
                </div>
            </div>
        </header>
        
        <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <!-- Stats -->
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div class="bg-dark-card border border-dark-border rounded-xl p-6">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                            <i class="fas fa-users text-blue-400 text-xl"></i>
                        </div>
                    </div>
                    <div class="text-3xl font-bold mb-1">{{ stats.total_users }}</div>
                    <div class="text-sm text-gray-400">Total Users</div>
                </div>
                
                <div class="bg-dark-card border border-dark-border rounded-xl p-6">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                            <i class="fas fa-rocket text-green-400 text-xl"></i>
                        </div>
                    </div>
                    <div class="text-3xl font-bold mb-1">{{ stats.total_deployments }}</div>
                    <div class="text-sm text-gray-400">Deployments</div>
                </div>
                
                <div class="bg-dark-card border border-dark-border rounded-xl p-6">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                            <i class="fas fa-play text-purple-400 text-xl"></i>
                        </div>
                    </div>
                    <div class="text-3xl font-bold mb-1">{{ stats.active_processes }}</div>
                    <div class="text-sm text-gray-400">Active Now</div>
                </div>
                
                <div class="bg-dark-card border border-dark-border rounded-xl p-6">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                            <i class="fas fa-clock text-yellow-400 text-xl"></i>
                        </div>
                    </div>
                    <div class="text-3xl font-bold mb-1">{{ stats.pending_payments }}</div>
                    <div class="text-sm text-gray-400">Pending Payments</div>
                </div>
            </div>
            
            <!-- Users Section -->
            <div class="bg-dark-card border border-dark-border rounded-xl p-6 mb-8">
                <h2 class="text-2xl font-bold mb-6">User Management</h2>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead>
                            <tr class="border-b border-dark-border">
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">Email</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">Credits</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">Deploys</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">Joined</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">Status</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for user in users %}
                            <tr class="border-b border-dark-border hover:bg-dark-bg transition">
                                <td class="py-4 px-4">{{ user.email }}</td>
                                <td class="py-4 px-4 font-semibold">{{ user.credits }}</td>
                                <td class="py-4 px-4">{{ user.deployments|length }}</td>
                                <td class="py-4 px-4 text-sm text-gray-400">{{ user.created_at[:10] }}</td>
                                <td class="py-4 px-4">
                                    {% if user.is_banned %}
                                    <span class="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-xs font-semibold">Banned</span>
                                    {% else %}
                                    <span class="px-3 py-1 bg-green-500/20 text-green-400 rounded-full text-xs font-semibold">Active</span>
                                    {% endif %}
                                </td>
                                <td class="py-4 px-4">
                                    <div class="flex gap-2">
                                        <button onclick="addCreditsPrompt('{{ user.id }}')" 
                                                class="px-3 py-1 bg-green-500/20 text-green-400 rounded hover:bg-green-500/30 transition text-sm">
                                            <i class="fas fa-plus mr-1"></i>Credits
                                        </button>
                                        {% if not user.is_banned %}
                                        <button onclick="banUser('{{ user.id }}')" 
                                                class="px-3 py-1 bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 transition text-sm">
                                            <i class="fas fa-ban mr-1"></i>Ban
                                        </button>
                                        {% else %}
                                        <button onclick="unbanUser('{{ user.id }}')" 
                                                class="px-3 py-1 bg-blue-500/20 text-blue-400 rounded hover:bg-blue-500/30 transition text-sm">
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
            
            <!-- Payments Section -->
            <div class="bg-dark-card border border-dark-border rounded-xl p-6">
                <h2 class="text-2xl font-bold mb-6">Payment Requests</h2>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead>
                            <tr class="border-b border-dark-border">
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">User</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">Amount</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">Date</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">Status</th>
                                <th class="text-left py-3 px-4 text-sm font-semibold text-gray-400">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for payment in payments %}
                            <tr class="border-b border-dark-border hover:bg-dark-bg transition">
                                <td class="py-4 px-4">{{ payment.user_email }}</td>
                                <td class="py-4 px-4 font-semibold">{{ payment.amount }} credits</td>
                                <td class="py-4 px-4 text-sm text-gray-400">{{ payment.created_at[:10] }}</td>
                                <td class="py-4 px-4">
                                    {% if payment.status == 'approved' %}
                                    <span class="px-3 py-1 bg-green-500/20 text-green-400 rounded-full text-xs font-semibold">Approved</span>
                                    {% elif payment.status == 'pending' %}
                                    <span class="px-3 py-1 bg-yellow-500/20 text-yellow-400 rounded-full text-xs font-semibold">Pending</span>
                                    {% else %}
                                    <span class="px-3 py-1 bg-red-500/20 text-red-400 rounded-full text-xs font-semibold">Rejected</span>
                                    {% endif %}
                                </td>
                                <td class="py-4 px-4">
                                    {% if payment.status == 'pending' %}
                                    <div class="flex gap-2">
                                        <button onclick="approvePayment('{{ payment.id }}', '{{ payment.user_id }}', {{ payment.amount }})" 
                                                class="px-3 py-1 bg-green-500/20 text-green-400 rounded hover:bg-green-500/30 transition text-sm">
                                            <i class="fas fa-check mr-1"></i>Approve
                                        </button>
                                        <button onclick="rejectPayment('{{ payment.id }}')" 
                                                class="px-3 py-1 bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 transition text-sm">
                                            <i class="fas fa-times mr-1"></i>Reject
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
        </main>
    </div>
    
    <script>
        function adminPanel() {
            return {
                init() {
                    console.log('Admin panel loaded');
                }
            }
        }
        
        function addCreditsPrompt(userId) {
            const amount = prompt('Enter amount of credits to add:');
            if (!amount || isNaN(amount)) return;
            
            fetch('/api/admin/add-credits', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({user_id: userId, amount: parseFloat(amount)})
            })
            .then(r => r.json())
            .then(data => {
                alert(data.success ? '✅ Credits added!' : '❌ ' + data.error);
                location.reload();
            });
        }
        
        function banUser(userId) {
            if (!confirm('Ban this user? They will not be able to login.')) return;
            
            fetch('/api/admin/ban-user', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({user_id: userId, ban: true})
            })
            .then(r => r.json())
            .then(data => {
                alert(data.success ? '✅ User banned' : '❌ ' + data.error);
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
                alert(data.success ? '✅ User unbanned' : '❌ ' + data.error);
                location.reload();
            });
        }
        
        function approvePayment(paymentId, userId, amount) {
            if (!confirm(`Approve payment for ${amount} credits?`)) return;
            
            fetch('/api/admin/approve-payment', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({payment_id: paymentId, user_id: userId, amount: amount})
            })
            .then(r => r.json())
            .then(data => {
                alert(data.success ? '✅ Payment approved!' : '❌ ' + data.error);
                location.reload();
            });
        }
        
        function rejectPayment(paymentId) {
            if (!confirm('Reject this payment?')) return;
            
            fetch('/api/admin/reject-payment', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({payment_id: paymentId})
            })
            .then(r => r.json())
            .then(data => {
                alert(data.success ? '✅ Payment rejected' : '❌ ' + data.error);
                location.reload();
            });
        }
    </script>
</body>
</html>
"""

# ==================== FLASK ROUTES ====================

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
            action='/register',
            button_text='Create Account',
            icon='user-plus',
            toggle_text='Already have an account?',
            toggle_link='/login',
            toggle_action='Login here',
            error='This device is banned from EliteHost'
        )
    
    for user_data in db['users'].values():
        if user_data['email'] == email:
            return render_template_string(LOGIN_PAGE,
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
            action='/login',
            button_text='Login',
            icon='sign-in-alt',
            toggle_text="Don't have an account?",
            toggle_link='/register',
            toggle_action='Register here',
            error='Your account has been banned'
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
    
    response = make_response(redirect('/login?success=Logged out successfully'))
    response.set_cookie('session_token', '', max_age=0)
    return response

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
    
    is_admin = str(user_id) == str(OWNER_ID) or str(user_id) == str(ADMIN_ID)
    
    return render_template_string(DASHBOARD_HTML, is_admin=is_admin)

@app.route('/admin')
def admin_panel():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    
    user_id = verify_session(session_token, fingerprint)
    if not user_id:
        return redirect('/login?error=Please login first')
    
    if str(user_id) != str(OWNER_ID) and str(user_id) != str(ADMIN_ID):
        return redirect('/dashboard?error=Admin access denied')
    
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
    build_cmd = data.get('build_command', '')
    start_cmd = data.get('start_command', '')
    
    if not repo_url:
        return jsonify({'success': False, 'error': 'Repository URL required'})
    
    deploy_id, msg = deploy_from_github(user_id, repo_url, branch, build_cmd, start_cmd)
    
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

@app.route('/api/deployment/<deploy_id>/env', methods=['POST'])
def api_add_env_var(deploy_id):
    if deploy_id not in db['deployments']:
        return jsonify({'success': False, 'error': 'Deployment not found'})
    
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
        return jsonify({'success': False, 'error': 'Deployment not found'})
    
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

@app.route('/api/admin/approve-payment', methods=['POST'])
def api_admin_approve_payment():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    admin_id = verify_session(session_token, fingerprint)
    
    if str(admin_id) != str(OWNER_ID) and str(admin_id) != str(ADMIN_ID):
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    data = request.get_json()
    payment_id = data.get('payment_id')
    user_id = data.get('user_id')
    amount = data.get('amount')
    
    if payment_id in db.get('payments', {}):
        db['payments'][payment_id]['status'] = 'approved'
        add_credits(user_id, amount, f"Payment approved: {payment_id}")
        save_db(db)
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Payment not found'})

@app.route('/api/admin/reject-payment', methods=['POST'])
def api_admin_reject_payment():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    admin_id = verify_session(session_token, fingerprint)
    
    if str(admin_id) != str(OWNER_ID) and str(admin_id) != str(ADMIN_ID):
        return jsonify({'success': False, 'error': 'Admin access required'})
    
    data = request.get_json()
    payment_id = data.get('payment_id')
    
    if payment_id in db.get('payments', {}):
        db['payments'][payment_id]['status'] = 'rejected'
        save_db(db)
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Payment not found'})

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
    print(f"{Fore.CYAN}   🎨 Modern Dark UI - Vercel/Railway inspired")
    print(f"{Fore.CYAN}   📱 Full mobile responsive SPA design")
    print(f"{Fore.CYAN}   🔐 Advanced authentication with session management")
    print(f"{Fore.CYAN}   🔑 Environment variables per deployment")
    print(f"{Fore.CYAN}   📁 File browser for deployments")
    print(f"{Fore.CYAN}   💾 Backup system with download")
    print(f"{Fore.CYAN}   📊 Live console logs auto-refresh")
    print(f"{Fore.CYAN}   🛠️ Custom build & start commands")
    print(f"{Fore.CYAN}   🤖 AI dependency auto-install")
    print(f"{Fore.CYAN}   👑 Advanced admin panel")
    print(f"{Fore.CYAN}   📧 Telegram notifications to owner")
    print(f"{Fore.CYAN}   🔄 Forgot password system")
    print(f"{Fore.CYAN}   💎 Credit system with refunds")
    print("=" * 90)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 Web App: http://localhost:{port}")
    print(f"{Fore.YELLOW}📱 Register: http://localhost:{port}/register")
    print(f"{Fore.YELLOW}🔑 Login: http://localhost:{port}/login")
    print(f"{Fore.MAGENTA}👑 Admin: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")
    print(f"{Fore.MAGENTA}📱 Admin Panel: http://localhost:{port}/admin")
    print(f"\n{Fore.GREEN}{'✅ ELITEHOST v11.0 READY':^90}")
    print("=" * 90 + "\n")
    
    # Keep running
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
