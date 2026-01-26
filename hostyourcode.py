# -*- coding: utf-8 -*-
"""
🚀 ELITEHOST v11.0 - ADVANCED SPA EDITION
Revolutionary AI-Powered Deployment Platform
Single Page Application | Environment Variables | Backups | File Manager | Live Console
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
FREE_CREDITS = 5.0
CREDIT_COSTS = {
    'file_upload': 0.5,
    'github_deploy': 1.0,
    'vps_command': 0.3,
    'backup': 0.2,
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
        'banned_devices': []
    }

def save_db(db):
    """Save database to JSON file"""
    with DB_LOCK:
        with open(DB_FILE, 'w') as f:
            json.dump(db, f, indent=2, default=str)

# Load database
db = load_db()

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
    return fingerprint in db.get('banned_devices', [])

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
    # Keep only last 1000 activities
    db['activity'] = db['activity'][-1000:]
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

def append_deployment_log(deploy_id, log_line):
    """Append log to deployment"""
    if deploy_id in db['deployments']:
        current_logs = db['deployments'][deploy_id].get('logs', '')
        db['deployments'][deploy_id]['logs'] = current_logs + log_line + '\n'
        save_db(db)

def get_deployment_files(deploy_id):
    """Get list of files in deployment"""
    if deploy_id not in db['deployments']:
        return []
    
    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    if not os.path.exists(deploy_dir):
        return []
    
    files = []
    for root, dirs, filenames in os.walk(deploy_dir):
        for filename in filenames:
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, deploy_dir)
            size = os.path.getsize(full_path)
            files.append({
                'name': filename,
                'path': rel_path,
                'size': size,
                'size_human': format_bytes(size)
            })
    
    return files

def format_bytes(bytes):
    """Format bytes to human readable"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes < 1024:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024
    return f"{bytes:.1f} TB"

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
                    if file in ['main.py', 'app.py', 'bot.py', 'index.py']:
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
        
        update_deployment(deploy_id, dependencies=installed_deps, logs=install_log)
        
        # Get file list
        files = get_deployment_files(deploy_id)
        update_deployment(deploy_id, files=files)
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        # Add user's environment variables
        deployment = db['deployments'][deploy_id]
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = value
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Launching on port {port}...')
        
        process = subprocess.Popen(
            [sys.executable, file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.dirname(file_path),
            env=env,
            bufsize=1,
            universal_newlines=True
        )
        
        active_processes[deploy_id] = process
        
        # Start log streaming thread
        def stream_logs():
            for line in process.stdout:
                append_deployment_log(deploy_id, line.strip())
        
        Thread(target=stream_logs, daemon=True).start()
        
        update_deployment(deploy_id, status='running', pid=process.pid)
        
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
            update_deployment(deploy_id, status='failed', logs='❌ Clone failed\n' + result.stderr)
            add_credits(user_id, cost, "Refund")
            return None, "❌ Clone failed"
        
        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        update_deployment(deploy_id, dependencies=installed_deps, logs=install_log)
        
        # Get file list
        files = get_deployment_files(deploy_id)
        update_deployment(deploy_id, files=files)
        
        # Find start command
        main_files = {
            'main.py': f'{sys.executable} main.py',
            'app.py': f'{sys.executable} app.py',
            'bot.py': f'{sys.executable} bot.py',
            'index.py': f'{sys.executable} index.py',
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
        
        # Add user's environment variables
        deployment = db['deployments'][deploy_id]
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = value
        
        process = subprocess.Popen(
            start_command.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=deploy_dir,
            env=env,
            bufsize=1,
            universal_newlines=True
        )
        
        active_processes[deploy_id] = process
        
        # Start log streaming thread
        def stream_logs():
            for line in process.stdout:
                append_deployment_log(deploy_id, line.strip())
        
        Thread(target=stream_logs, daemon=True).start()
        
        update_deployment(deploy_id, status='running', pid=process.pid)
        
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
            update_deployment(deploy_id, status='stopped', logs='🛑 Stopped by user')
            return True, "Stopped"
        return False, "Not running"
    except Exception as e:
        return False, str(e)

def restart_deployment(deploy_id):
    """Restart a deployment"""
    if deploy_id not in db['deployments']:
        return False, "Not found"
    
    deployment = db['deployments'][deploy_id]
    
    # Stop if running
    stop_deployment(deploy_id)
    
    # Start again
    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    
    # Find main file
    main_file = None
    for root, dirs, files in os.walk(deploy_dir):
        for file in files:
            if file in ['main.py', 'app.py', 'bot.py', 'index.py']:
                main_file = os.path.join(root, file)
                break
        if main_file:
            break
    
    if not main_file:
        return False, "No main file"
    
    env = os.environ.copy()
    env['PORT'] = str(deployment['port'])
    
    # Add environment variables
    for key, value in deployment.get('env_vars', {}).items():
        env[key] = value
    
    process = subprocess.Popen(
        [sys.executable, main_file],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=os.path.dirname(main_file),
        env=env,
        bufsize=1,
        universal_newlines=True
    )
    
    active_processes[deploy_id] = process
    
    # Start log streaming
    def stream_logs():
        for line in process.stdout:
            append_deployment_log(deploy_id, line.strip())
    
    Thread(target=stream_logs, daemon=True).start()
    
    update_deployment(deploy_id, status='running', pid=process.pid)
    
    return True, "Restarted"

def create_backup(deploy_id):
    """Create backup of deployment"""
    if deploy_id not in db['deployments']:
        return None, "Not found"
    
    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    if not os.path.exists(deploy_dir):
        return None, "Directory not found"
    
    backup_name = f"{deploy_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    backup_path = os.path.join(BACKUPS_DIR, backup_name)
    
    with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(deploy_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, deploy_dir)
                zipf.write(file_path, arcname)
    
    return backup_path, backup_name

# ==================== SPA HTML TEMPLATE ====================

SPA_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost v11.0 - Advanced Platform</title>
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
                            50: '#f9fafb',
                            100: '#f3f4f6',
                            200: '#e5e7eb',
                            300: '#d1d5db',
                            400: '#9ca3af',
                            500: '#6b7280',
                            600: '#4b5563',
                            700: '#374151',
                            800: '#1f2937',
                        900: '#111827',
                        950: '#030712'
                    }
                }
            }
        }
    </script>
    <style>
        [x-cloak] { display: none !important; }
        
        .glass {
            background: rgba(17, 24, 39, 0.8);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(75, 85, 99, 0.3);
        }
        
        .gradient-border {
            border: 2px solid transparent;
            background: linear-gradient(#111827, #111827) padding-box,
                        linear-gradient(135deg, #667eea, #764ba2) border-box;
        }
        
        ::-webkit-scrollbar {
            width: 8px;
            height: 8px;
        }
        
        ::-webkit-scrollbar-track {
            background: #1f2937;
        }
        
        ::-webkit-scrollbar-thumb {
            background: #4b5563;
            border-radius: 4px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: #6b7280;
        }
        
        .terminal {
            font-family: 'Courier New', monospace;
            background: #0d1117;
            color: #58a6ff;
        }
    </style>
</head>
<body class="bg-dark-950 text-gray-100 font-sans" x-data="appData()" x-cloak>
    
    <!-- Sidebar -->
    <div class="fixed left-0 top-0 h-full w-64 glass border-r border-dark-700 z-50">
        <div class="p-6">
            <div class="flex items-center gap-3 mb-8">
                <div class="w-12 h-12 bg-gradient-to-br from-purple-500 to-pink-500 rounded-xl flex items-center justify-center">
                    <i class="fas fa-rocket text-white text-xl"></i>
                </div>
                <div>
                    <h1 class="text-xl font-black">EliteHost</h1>
                    <p class="text-xs text-gray-400">v11.0 Advanced</p>
                </div>
            </div>
            
            <!-- Navigation -->
            <nav class="space-y-2">
                <button @click="currentView = 'dashboard'" 
                        :class="currentView === 'dashboard' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:bg-dark-800'"
                        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition font-medium">
                    <i class="fas fa-home w-5"></i>
                    <span>Dashboard</span>
                </button>
                
                <button @click="currentView = 'deployments'" 
                        :class="currentView === 'deployments' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:bg-dark-800'"
                        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition font-medium">
                    <i class="fas fa-rocket w-5"></i>
                    <span>Deployments</span>
                    <span x-text="deployments.length" class="ml-auto bg-dark-700 px-2 py-1 rounded-full text-xs"></span>
                </button>
                
                <button @click="currentView = 'settings'" 
                        :class="currentView === 'settings' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:bg-dark-800'"
                        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition font-medium">
                    <i class="fas fa-cog w-5"></i>
                    <span>Settings</span>
                </button>
                
                <button @click="currentView = 'activity'" 
                        :class="currentView === 'activity' ? 'bg-purple-600 text-white' : 'text-gray-400 hover:bg-dark-800'"
                        class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition font-medium">
                    <i class="fas fa-history w-5"></i>
                    <span>Activity</span>
                </button>
                
                <template x-if="isAdmin">
                    <button @click="currentView = 'admin'" 
                            :class="currentView === 'admin' ? 'bg-orange-600 text-white' : 'text-gray-400 hover:bg-dark-800'"
                            class="w-full flex items-center gap-3 px-4 py-3 rounded-lg transition font-medium">
                        <i class="fas fa-crown w-5"></i>
                        <span>Admin Panel</span>
                    </button>
                </template>
            </nav>
            
            <!-- User Info -->
            <div class="absolute bottom-6 left-6 right-6">
                <div class="glass rounded-xl p-4">
                    <div class="flex items-center gap-3 mb-3">
                        <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-full flex items-center justify-center text-white font-bold">
                            <span x-text="userEmail ? userEmail[0].toUpperCase() : 'U'"></span>
                        </div>
                        <div class="flex-1 min-w-0">
                            <p class="text-sm font-medium truncate" x-text="userEmail"></p>
                            <p class="text-xs text-gray-400">User Account</p>
                        </div>
                    </div>
                    <div class="flex items-center justify-between mb-2">
                        <span class="text-xs text-gray-400">Credits</span>
                        <span class="text-lg font-bold text-purple-400" x-text="credits === Infinity ? '∞' : credits.toFixed(1)"></span>
                    </div>
                    <button @click="logout()" class="w-full bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg text-sm font-medium transition">
                        <i class="fas fa-sign-out-alt mr-2"></i>Logout
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="ml-64 p-8">
        
        <!-- Dashboard View -->
        <div x-show="currentView === 'dashboard'" x-transition>
            <div class="mb-8">
                <h2 class="text-3xl font-black mb-2">Dashboard</h2>
                <p class="text-gray-400">Welcome back! Here's your deployment overview.</p>
            </div>
            
            <!-- Stats Grid -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div class="glass rounded-2xl p-6 gradient-border">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-blue-500/20 rounded-xl flex items-center justify-center">
                            <i class="fas fa-rocket text-blue-400 text-xl"></i>
                        </div>
                        <span class="text-3xl font-black" x-text="deployments.length"></span>
                    </div>
                    <p class="text-gray-400 text-sm font-medium">Total Deployments</p>
                </div>
                
                <div class="glass rounded-2xl p-6 gradient-border">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-green-500/20 rounded-xl flex items-center justify-center">
                            <i class="fas fa-check-circle text-green-400 text-xl"></i>
                        </div>
                        <span class="text-3xl font-black text-green-400" x-text="deployments.filter(d => d.status === 'running').length"></span>
                    </div>
                    <p class="text-gray-400 text-sm font-medium">Active Now</p>
                </div>
                
                <div class="glass rounded-2xl p-6 gradient-border">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-purple-500/20 rounded-xl flex items-center justify-center">
                            <i class="fas fa-gem text-purple-400 text-xl"></i>
                        </div>
                        <span class="text-3xl font-black text-purple-400" x-text="credits === Infinity ? '∞' : credits.toFixed(1)"></span>
                    </div>
                    <p class="text-gray-400 text-sm font-medium">Available Credits</p>
                </div>
                
                <div class="glass rounded-2xl p-6 gradient-border">
                    <div class="flex items-center justify-between mb-4">
                        <div class="w-12 h-12 bg-pink-500/20 rounded-xl flex items-center justify-center">
                            <i class="fas fa-robot text-pink-400 text-xl"></i>
                        </div>
                        <span class="text-3xl font-black text-pink-400">AI</span>
                    </div>
                    <p class="text-gray-400 text-sm font-medium">Auto Dependencies</p>
                </div>
            </div>
            
            <!-- Quick Actions -->
            <div class="glass rounded-2xl p-6 mb-8">
                <h3 class="text-xl font-bold mb-4">Quick Deploy</h3>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <button @click="showModal = 'upload'" 
                            class="bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white py-4 px-6 rounded-xl font-bold transition flex items-center justify-center gap-3">
                        <i class="fas fa-cloud-upload-alt text-2xl"></i>
                        <div class="text-left">
                            <div>Upload Files</div>
                            <div class="text-xs opacity-80">Deploy from ZIP or Python files</div>
                        </div>
                    </button>
                    
                    <button @click="showModal = 'github'" 
                            class="bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black text-white py-4 px-6 rounded-xl font-bold transition flex items-center justify-center gap-3">
                        <i class="fab fa-github text-2xl"></i>
                        <div class="text-left">
                            <div>GitHub Deploy</div>
                            <div class="text-xs opacity-80">Clone and deploy from repository</div>
                        </div>
                    </button>
                </div>
            </div>
            
            <!-- Recent Deployments -->
            <div class="glass rounded-2xl p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-xl font-bold">Recent Deployments</h3>
                    <button @click="loadDeployments()" class="text-purple-400 hover:text-purple-300">
                        <i class="fas fa-sync-alt"></i>
                    </button>
                </div>
                
                <template x-if="deployments.length === 0">
                    <div class="text-center py-12">
                        <i class="fas fa-rocket text-6xl text-gray-700 mb-4"></i>
                        <p class="text-gray-400">No deployments yet. Start by deploying your first app!</p>
                    </div>
                </template>
                
                <div class="space-y-3">
                    <template x-for="deploy in deployments.slice(0, 5)" :key="deploy.id">
                        <div class="bg-dark-800 rounded-xl p-4 hover:bg-dark-700 transition cursor-pointer"
                             @click="viewDeployment(deploy.id)">
                            <div class="flex items-center justify-between">
                                <div class="flex items-center gap-3 flex-1">
                                    <div class="w-10 h-10 bg-gradient-to-br from-blue-500 to-purple-500 rounded-lg flex items-center justify-center">
                                        <i class="fas fa-rocket text-white"></i>
                                    </div>
                                    <div class="flex-1 min-w-0">
                                        <h4 class="font-bold truncate" x-text="deploy.name"></h4>
                                        <p class="text-xs text-gray-400">
                                            Port <span x-text="deploy.port"></span> • 
                                            <span x-text="new Date(deploy.created_at).toLocaleDateString()"></span>
                                        </p>
                                    </div>
                                </div>
                                <span :class="{
                                    'bg-green-500/20 text-green-400': deploy.status === 'running',
                                    'bg-yellow-500/20 text-yellow-400': deploy.status === 'pending',
                                    'bg-red-500/20 text-red-400': deploy.status === 'stopped' || deploy.status === 'failed'
                                }" class="px-3 py-1 rounded-full text-xs font-bold uppercase" x-text="deploy.status"></span>
                            </div>
                        </div>
                    </template>
                </div>
            </div>
        </div>
        
        <!-- Deployments View -->
        <div x-show="currentView === 'deployments'" x-transition>
            <div class="mb-8 flex items-center justify-between">
                <div>
                    <h2 class="text-3xl font-black mb-2">All Deployments</h2>
                    <p class="text-gray-400">Manage your deployed applications</p>
                </div>
                <button @click="loadDeployments()" class="bg-purple-600 hover:bg-purple-700 px-4 py-2 rounded-lg font-medium transition">
                    <i class="fas fa-sync-alt mr-2"></i>Refresh
                </button>
            </div>
            
            <template x-if="deployments.length === 0">
                <div class="glass rounded-2xl p-12 text-center">
                    <i class="fas fa-rocket text-6xl text-gray-700 mb-4"></i>
                    <h3 class="text-2xl font-bold mb-2">No Deployments Yet</h3>
                    <p class="text-gray-400 mb-6">Get started by deploying your first application</p>
                    <div class="flex gap-4 justify-center">
                        <button @click="showModal = 'upload'" class="bg-purple-600 hover:bg-purple-700 px-6 py-3 rounded-lg font-bold transition">
                            <i class="fas fa-cloud-upload-alt mr-2"></i>Upload Files
                        </button>
                        <button @click="showModal = 'github'" class="bg-gray-700 hover:bg-gray-600 px-6 py-3 rounded-lg font-bold transition">
                            <i class="fab fa-github mr-2"></i>GitHub Deploy
                        </button>
                    </div>
                </div>
            </template>
            
            <div class="grid grid-cols-1 gap-6">
                <template x-for="deploy in deployments" :key="deploy.id">
                    <div class="glass rounded-2xl p-6">
                        <div class="flex items-start justify-between mb-4">
                            <div class="flex items-center gap-4 flex-1">
                                <div class="w-16 h-16 bg-gradient-to-br from-blue-500 to-purple-500 rounded-xl flex items-center justify-center">
                                    <i class="fas fa-rocket text-white text-2xl"></i>
                                </div>
                                <div class="flex-1 min-w-0">
                                    <h3 class="text-xl font-bold mb-1" x-text="deploy.name"></h3>
                                    <div class="flex flex-wrap gap-3 text-sm text-gray-400">
                                        <span><i class="fas fa-fingerprint mr-1"></i><span x-text="deploy.id"></span></span>
                                        <span><i class="fas fa-network-wired mr-1"></i>Port <span x-text="deploy.port"></span></span>
                                        <span><i class="fas fa-calendar mr-1"></i><span x-text="new Date(deploy.created_at).toLocaleDateString()"></span></span>
                                        <template x-if="deploy.dependencies && deploy.dependencies.length > 0">
                                            <span><i class="fas fa-robot mr-1"></i><span x-text="deploy.dependencies.length"></span> packages</span>
                                        </template>
                                    </div>
                                </div>
                            </div>
                            <span :class="{
                                'bg-green-500/20 text-green-400 border-green-500/30': deploy.status === 'running',
                                'bg-yellow-500/20 text-yellow-400 border-yellow-500/30': deploy.status === 'pending',
                                'bg-red-500/20 text-red-400 border-red-500/30': deploy.status === 'stopped' || deploy.status === 'failed'
                            }" class="px-4 py-2 rounded-lg text-sm font-bold uppercase border" x-text="deploy.status"></span>
                        </div>
                        
                        <div class="flex flex-wrap gap-2">
                            <button @click="viewDeployment(deploy.id)" 
                                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg font-medium transition">
                                <i class="fas fa-eye mr-2"></i>View Details
                            </button>
                            <button @click="viewLogs(deploy.id)" 
                                    class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg font-medium transition">
                                <i class="fas fa-terminal mr-2"></i>Console
                            </button>
                            <button @click="restartDeploy(deploy.id)" 
                                    class="bg-yellow-600 hover:bg-yellow-700 text-white px-4 py-2 rounded-lg font-medium transition">
                                <i class="fas fa-redo mr-2"></i>Restart
                            </button>
                            <button @click="stopDeploy(deploy.id)" 
                                    class="bg-orange-600 hover:bg-orange-700 text-white px-4 py-2 rounded-lg font-medium transition">
                                <i class="fas fa-stop mr-2"></i>Stop
                            </button>
                            <button @click="createBackup(deploy.id)" 
                                    class="bg-purple-600 hover:bg-purple-700 text-white px-4 py-2 rounded-lg font-medium transition">
                                <i class="fas fa-download mr-2"></i>Backup
                            </button>
                            <button @click="deleteDeploy(deploy.id)" 
                                    class="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-medium transition">
                                <i class="fas fa-trash mr-2"></i>Delete
                            </button>
                        </div>
                    </div>
                </template>
            </div>
        </div>
        
        <!-- Settings View -->
        <div x-show="currentView === 'settings'" x-transition>
            <div class="mb-8">
                <h2 class="text-3xl font-black mb-2">Settings</h2>
                <p class="text-gray-400">Manage your account and preferences</p>
            </div>
            
            <div class="glass rounded-2xl p-6 mb-6">
                <h3 class="text-xl font-bold mb-4">Account Information</h3>
                <div class="space-y-4">
                    <div>
                        <label class="text-sm text-gray-400 block mb-2">Email Address</label>
                        <input type="email" x-model="userEmail" disabled 
                               class="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-gray-300">
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="text-sm text-gray-400 block mb-2">Total Credits Earned</label>
                            <input type="text" :value="totalEarned" disabled 
                                   class="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-gray-300">
                        </div>
                        <div>
                            <label class="text-sm text-gray-400 block mb-2">Total Credits Spent</label>
                            <input type="text" :value="totalSpent" disabled 
                                   class="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3 text-gray-300">
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="glass rounded-2xl p-6">
                <h3 class="text-xl font-bold mb-4 text-yellow-400">
                    <i class="fas fa-exclamation-triangle mr-2"></i>Danger Zone
                </h3>
                <p class="text-gray-400 mb-4">These actions are irreversible. Please be careful.</p>
                <button class="bg-red-600 hover:bg-red-700 text-white px-6 py-3 rounded-lg font-bold transition">
                    <i class="fas fa-trash mr-2"></i>Delete All Deployments
                </button>
            </div>
        </div>
        
        <!-- Activity View -->
        <div x-show="currentView === 'activity'" x-transition>
            <div class="mb-8">
                <h2 class="text-3xl font-black mb-2">Activity Log</h2>
                <p class="text-gray-400">Recent account activity and actions</p>
            </div>
            
            <div class="glass rounded-2xl p-6">
                <div class="space-y-3">
                    <template x-for="activity in activityLog" :key="activity.timestamp">
                        <div class="bg-dark-800 rounded-lg p-4 flex items-center gap-4">
                            <div class="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
                                <i class="fas fa-history text-purple-400"></i>
                            </div>
                            <div class="flex-1">
                                <p class="font-medium" x-text="activity.details"></p>
                                <p class="text-xs text-gray-400" x-text="new Date(activity.timestamp).toLocaleString()"></p>
                            </div>
                            <span class="text-xs text-gray-500" x-text="activity.action"></span>
                        </div>
                    </template>
                </div>
            </div>
        </div>
        
        <!-- Admin Panel -->
        <template x-if="isAdmin">
            <div x-show="currentView === 'admin'" x-transition>
                <div class="mb-8">
                    <h2 class="text-3xl font-black mb-2">
                        <i class="fas fa-crown text-yellow-400 mr-2"></i>Admin Control Panel
                    </h2>
                    <p class="text-gray-400">System monitoring and user management</p>
                </div>
                
                <!-- System Stats -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                    <div class="glass rounded-2xl p-6">
                        <div class="text-3xl font-black mb-2" x-text="adminStats.total_users"></div>
                        <p class="text-gray-400 text-sm">Total Users</p>
                    </div>
                    <div class="glass rounded-2xl p-6">
                        <div class="text-3xl font-black text-green-400 mb-2" x-text="adminStats.total_deployments"></div>
                        <p class="text-gray-400 text-sm">Deployments</p>
                    </div>
                    <div class="glass rounded-2xl p-6">
                        <div class="text-3xl font-black text-blue-400 mb-2" x-text="adminStats.active_processes"></div>
                        <p class="text-gray-400 text-sm">Active Processes</p>
                    </div>
                    <div class="glass rounded-2xl p-6">
                        <div class="text-3xl font-black text-purple-400 mb-2" x-text="systemStats.cpu + '%'"></div>
                        <p class="text-gray-400 text-sm">CPU Usage</p>
                    </div>
                </div>
                
                <!-- Users Table -->
                <div class="glass rounded-2xl p-6 mb-6">
                    <h3 class="text-xl font-bold mb-4">All Users</h3>
                    <div class="overflow-x-auto">
                        <table class="w-full">
                            <thead>
                                <tr class="border-b border-dark-700">
                                    <th class="text-left py-3 px-4 text-sm font-bold text-gray-400">Email</th>
                                    <th class="text-left py-3 px-4 text-sm font-bold text-gray-400">Credits</th>
                                    <th class="text-left py-3 px-4 text-sm font-bold text-gray-400">Deployments</th>
                                    <th class="text-left py-3 px-4 text-sm font-bold text-gray-400">Status</th>
                                    <th class="text-left py-3 px-4 text-sm font-bold text-gray-400">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <template x-for="user in allUsers" :key="user.id">
                                    <tr class="border-b border-dark-800 hover:bg-dark-800">
                                        <td class="py-3 px-4" x-text="user.email"></td>
                                        <td class="py-3 px-4 font-bold text-purple-400" x-text="user.credits.toFixed(1)"></td>
                                        <td class="py-3 px-4" x-text="user.deployments.length"></td>
                                        <td class="py-3 px-4">
                                            <span :class="user.is_banned ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'" 
                                                  class="px-3 py-1 rounded-full text-xs font-bold"
                                                  x-text="user.is_banned ? 'BANNED' : 'ACTIVE'"></span>
                                        </td>
                                        <td class="py-3 px-4">
                                            <button @click="adminAddCredits(user.id)" 
                                                    class="bg-green-600 hover:bg-green-700 text-white px-3 py-1 rounded text-xs font-medium mr-2">
                                                <i class="fas fa-plus"></i> Credits
                                            </button>
                                            <button @click="adminBanUser(user.id, !user.is_banned)" 
                                                    :class="user.is_banned ? 'bg-blue-600 hover:bg-blue-700' : 'bg-red-600 hover:bg-red-700'"
                                                    class="text-white px-3 py-1 rounded text-xs font-medium">
                                                <i :class="user.is_banned ? 'fas fa-check' : 'fas fa-ban'"></i>
                                                <span x-text="user.is_banned ? 'Unban' : 'Ban'"></span>
                                            </button>
                                        </td>
                                    </tr>
                                </template>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </template>
    </div>
    
    <!-- Deployment Detail Modal -->
    <div x-show="showModal === 'detail'" 
         x-transition
         class="fixed inset-0 bg-black/80 flex items-center justify-center z-[100] p-4"
         @click.self="showModal = null">
        <div class="glass rounded-2xl max-w-6xl w-full max-h-[90vh] overflow-hidden flex flex-col">
            <div class="p-6 border-b border-dark-700 flex items-center justify-between">
                <div>
                    <h3 class="text-2xl font-bold" x-text="selectedDeploy?.name"></h3>
                    <p class="text-sm text-gray-400">Deployment ID: <span x-text="selectedDeploy?.id"></span></p>
                </div>
                <button @click="showModal = null" class="w-10 h-10 bg-dark-800 hover:bg-dark-700 rounded-lg flex items-center justify-center">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <div class="flex-1 overflow-y-auto p-6">
                <!-- Tabs -->
                <div class="flex gap-2 mb-6 border-b border-dark-700">
                    <button @click="detailTab = 'overview'" 
                            :class="detailTab === 'overview' ? 'border-purple-500 text-white' : 'border-transparent text-gray-400'"
                            class="px-4 py-2 border-b-2 font-medium transition">
                        <i class="fas fa-info-circle mr-2"></i>Overview
                    </button>
                    <button @click="detailTab = 'console'" 
                            :class="detailTab === 'console' ? 'border-purple-500 text-white' : 'border-transparent text-gray-400'"
                            class="px-4 py-2 border-b-2 font-medium transition">
                        <i class="fas fa-terminal mr-2"></i>Live Console
                    </button>
                    <button @click="detailTab = 'env'" 
                            :class="detailTab === 'env' ? 'border-purple-500 text-white' : 'border-transparent text-gray-400'"
                            class="px-4 py-2 border-b-2 font-medium transition">
                        <i class="fas fa-key mr-2"></i>Environment
                    </button>
                    <button @click="detailTab = 'files'" 
                            :class="detailTab === 'files' ? 'border-purple-500 text-white' : 'border-transparent text-gray-400'"
                            class="px-4 py-2 border-b-2 font-medium transition">
                        <i class="fas fa-folder mr-2"></i>Files
                    </button>
                    <button @click="detailTab = 'backup'" 
                            :class="detailTab === 'backup' ? 'border-purple-500 text-white' : 'border-transparent text-gray-400'"
                            class="px-4 py-2 border-b-2 font-medium transition">
                        <i class="fas fa-archive mr-2"></i>Backup
                    </button>
                </div>
                
                <!-- Overview Tab -->
                <div x-show="detailTab === 'overview'" x-transition>
                    <div class="grid grid-cols-2 gap-6">
                        <div>
                            <label class="text-sm text-gray-400 block mb-2">Status</label>
                            <span :class="{
                                'bg-green-500/20 text-green-400': selectedDeploy?.status === 'running',
                                'bg-yellow-500/20 text-yellow-400': selectedDeploy?.status === 'pending',
                                'bg-red-500/20 text-red-400': selectedDeploy?.status === 'stopped'
                            }" class="inline-block px-4 py-2 rounded-lg font-bold uppercase" x-text="selectedDeploy?.status"></span>
                        </div>
                        <div>
                            <label class="text-sm text-gray-400 block mb-2">Port</label>
                            <div class="bg-dark-800 rounded-lg px-4 py-2 font-mono" x-text="selectedDeploy?.port"></div>
                        </div>
                        <div>
                            <label class="text-sm text-gray-400 block mb-2">Type</label>
                            <div class="bg-dark-800 rounded-lg px-4 py-2" x-text="selectedDeploy?.type"></div>
                        </div>
                        <div>
                            <label class="text-sm text-gray-400 block mb-2">Process ID</label>
                            <div class="bg-dark-800 rounded-lg px-4 py-2 font-mono" x-text="selectedDeploy?.pid || 'N/A'"></div>
                        </div>
                        <div class="col-span-2">
                            <label class="text-sm text-gray-400 block mb-2">Created At</label>
                            <div class="bg-dark-800 rounded-lg px-4 py-2" x-text="selectedDeploy?.created_at ? new Date(selectedDeploy.created_at).toLocaleString() : 'N/A'"></div>
                        </div>
                        <template x-if="selectedDeploy?.repo_url">
                            <div class="col-span-2">
                                <label class="text-sm text-gray-400 block mb-2">Repository URL</label>
                                <div class="bg-dark-800 rounded-lg px-4 py-2 font-mono text-sm break-all" x-text="selectedDeploy.repo_url"></div>
                            </div>
                        </template>
                        <template x-if="selectedDeploy?.dependencies?.length > 0">
                            <div class="col-span-2">
                                <label class="text-sm text-gray-400 block mb-2">AI Installed Dependencies</label>
                                <div class="bg-dark-800 rounded-lg p-4 max-h-40 overflow-y-auto">
                                    <div class="flex flex-wrap gap-2">
                                        <template x-for="dep in selectedDeploy.dependencies" :key="dep">
                                            <span class="bg-purple-500/20 text-purple-400 px-3 py-1 rounded-full text-xs font-medium" x-text="dep"></span>
                                        </template>
                                    </div>
                                </div>
                            </div>
                        </template>
                    </div>
                </div>
                
                <!-- Console Tab -->
                <div x-show="detailTab === 'console'" x-transition>
                    <div class="mb-4 flex gap-2">
                        <button @click="refreshLogs(selectedDeploy?.id)" 
                                class="bg-green-600 hover:bg-green-700 px-4 py-2 rounded-lg font-medium transition">
                            <i class="fas fa-sync-alt mr-2"></i>Refresh Logs
                        </button>
                        <button @click="clearLogs()" 
                                class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg font-medium transition">
                            <i class="fas fa-trash mr-2"></i>Clear Display
                        </button>
                    </div>
                    <div class="terminal rounded-xl p-4 h-96 overflow-y-auto font-mono text-sm" x-ref="consoleOutput">
                        <pre x-text="consoleLog || 'No logs available'"></pre>
                    </div>
                </div>
                
                <!-- Environment Tab -->
                <div x-show="detailTab === 'env'" x-transition>
                    <div class="mb-4">
                        <p class="text-sm text-gray-400 mb-4">Add environment variables (secrets) for this deployment. Changes require restart.</p>
                        <div class="flex gap-2 mb-4">
                            <input x-model="newEnvKey" 
                                   type="text" 
                                   placeholder="KEY" 
                                   class="flex-1 bg-dark-800 border border-dark-700 rounded-lg px-4 py-2">
                            <input x-model="newEnvValue" 
                                   type="text" 
                                   placeholder="VALUE" 
                                   class="flex-1 bg-dark-800 border border-dark-700 rounded-lg px-4 py-2">
                            <button @click="addEnvVar()" 
                                    class="bg-purple-600 hover:bg-purple-700 px-6 py-2 rounded-lg font-medium transition">
                                <i class="fas fa-plus mr-2"></i>Add
                            </button>
                        </div>
                    </div>
                    
                    <div class="space-y-2">
                        <template x-if="!selectedDeploy?.env_vars || Object.keys(selectedDeploy.env_vars).length === 0">
                            <div class="text-center py-8 text-gray-400">
                                <i class="fas fa-key text-4xl mb-2 opacity-30"></i>
                                <p>No environment variables set</p>
                            </div>
                        </template>
                        
                        <template x-for="[key, value] in Object.entries(selectedDeploy?.env_vars || {})" :key="key">
                            <div class="bg-dark-800 rounded-lg p-3 flex items-center justify-between">
                                <div class="flex-1 grid grid-cols-2 gap-4">
                                    <div>
                                        <span class="text-xs text-gray-400">Key</span>
                                        <div class="font-mono font-bold" x-text="key"></div>
                                    </div>
                                    <div>
                                        <span class="text-xs text-gray-400">Value</span>
                                        <div class="font-mono" x-text="value"></div>
                                    </div>
                                </div>
                                <button @click="deleteEnvVar(key)" 
                                        class="bg-red-600 hover:bg-red-700 w-8 h-8 rounded-lg flex items-center justify-center ml-4">
                                    <i class="fas fa-trash text-xs"></i>
                                </button>
                            </div>
                        </template>
                    </div>
                </div>
                
                <!-- Files Tab -->
                <div x-show="detailTab === 'files'" x-transition>
                    <div class="mb-4">
                        <p class="text-sm text-gray-400">Browse deployment files (read-only)</p>
                    </div>
                    
                    <template x-if="!deploymentFiles || deploymentFiles.length === 0">
                        <div class="text-center py-8 text-gray-400">
                            <i class="fas fa-folder-open text-4xl mb-2 opacity-30"></i>
                            <p>No files found</p>
                        </div>
                    </template>
                    
                    <div class="space-y-2 max-h-96 overflow-y-auto">
                        <template x-for="file in deploymentFiles" :key="file.path">
                            <div class="bg-dark-800 rounded-lg p-3 flex items-center justify-between hover:bg-dark-700 transition">
                                <div class="flex items-center gap-3 flex-1">
                                    <i class="fas fa-file-code text-purple-400"></i>
                                    <div class="flex-1 min-w-0">
                                        <div class="font-mono text-sm truncate" x-text="file.path"></div>
                                        <div class="text-xs text-gray-400" x-text="file.size_human"></div>
                                    </div>
                                </div>
                            </div>
                        </template>
                    </div>
                </div>
                
                <!-- Backup Tab -->
                <div x-show="detailTab === 'backup'" x-transition>
                    <div class="text-center py-8">
                        <div class="w-20 h-20 bg-purple-500/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                            <i class="fas fa-archive text-purple-400 text-3xl"></i>
                        </div>
                        <h4 class="text-xl font-bold mb-2">Create Backup</h4>
                        <p class="text-gray-400 mb-6">Download a complete snapshot of this deployment as a ZIP file</p>
                        <button @click="createBackup(selectedDeploy?.id)" 
                                class="bg-purple-600 hover:bg-purple-700 px-8 py-3 rounded-lg font-bold transition">
                            <i class="fas fa-download mr-2"></i>Create & Download Backup (0.2 credits)
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Upload Modal -->
    <div x-show="showModal === 'upload'" 
         x-transition
         class="fixed inset-0 bg-black/80 flex items-center justify-center z-[100] p-4"
         @click.self="showModal = null">
        <div class="glass rounded-2xl max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-6">
                <h3 class="text-2xl font-bold">Upload & Deploy</h3>
                <button @click="showModal = null" class="w-10 h-10 bg-dark-800 hover:bg-dark-700 rounded-lg flex items-center justify-center">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <div @click="$refs.fileUpload.click()" 
                 class="border-2 border-dashed border-purple-500 rounded-xl p-12 text-center cursor-pointer hover:bg-purple-500/5 transition mb-4">
                <i class="fas fa-cloud-upload-alt text-6xl text-purple-400 mb-4"></i>
                <p class="font-bold mb-2">Click to Upload</p>
                <p class="text-sm text-gray-400">Python files (.py) or ZIP archives</p>
                <input type="file" x-ref="fileUpload" @change="uploadFile($event)" accept=".py,.zip" class="hidden">
            </div>
            
            <div class="bg-dark-800 rounded-xl p-4 text-sm">
                <div class="flex items-start gap-3">
                    <i class="fas fa-info-circle text-blue-400 mt-1"></i>
                    <div>
                        <p class="font-bold mb-1">Features:</p>
                        <ul class="text-gray-400 space-y-1">
                            <li>• AI auto-detects and installs dependencies</li>
                            <li>• Supports requirements.txt</li>
                            <li>• Cost: 0.5 credits per deployment</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- GitHub Modal -->
    <div x-show="showModal === 'github'" 
         x-transition
         class="fixed inset-0 bg-black/80 flex items-center justify-center z-[100] p-4"
         @click.self="showModal = null">
        <div class="glass rounded-2xl max-w-md w-full p-6">
            <div class="flex items-center justify-between mb-6">
                <h3 class="text-2xl font-bold">
                    <i class="fab fa-github mr-2"></i>GitHub Deploy
                </h3>
                <button @click="showModal = null" class="w-10 h-10 bg-dark-800 hover:bg-dark-700 rounded-lg flex items-center justify-center">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <form @submit.prevent="deployGithub()">
                <div class="space-y-4 mb-6">
                    <div>
                        <label class="block text-sm font-medium mb-2">Repository URL</label>
                        <input x-model="githubRepo" 
                               type="url" 
                               required
                               placeholder="https://github.com/username/repo"
                               class="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-2">Branch</label>
                        <input x-model="githubBranch" 
                               type="text" 
                               required
                               placeholder="main"
                               class="w-full bg-dark-800 border border-dark-700 rounded-lg px-4 py-3">
                    </div>
                </div>
                
                <button type="submit" 
                        class="w-full bg-gradient-to-r from-gray-800 to-gray-900 hover:from-gray-900 hover:to-black text-white py-3 rounded-lg font-bold transition mb-4">
                    <i class="fab fa-github mr-2"></i>Deploy from GitHub (1.0 credit)
                </button>
                
                <div class="bg-dark-800 rounded-xl p-4 text-sm">
                    <div class="flex items-start gap-3">
                        <i class="fas fa-robot text-purple-400 mt-1"></i>
                        <div>
                            <p class="font-bold mb-1">AI Features:</p>
                            <ul class="text-gray-400 space-y-1">
                                <li>• Auto-clone repository</li>
                                <li>• Smart dependency detection</li>
                                <li>• Auto-install packages</li>
                            </ul>
                        </div>
                    </div>
                </div>
            </form>
        </div>
    </div>
    
    <script>
        function appData() {
            return {
                currentView: 'dashboard',
                showModal: null,
                detailTab: 'overview',
                
                // User data
                userEmail: '',
                credits: 0,
                totalEarned: 0,
                totalSpent: 0,
                isAdmin: false,
                
                // Deployments
                deployments: [],
                selectedDeploy: null,
                deploymentFiles: [],
                
                // Console
                consoleLog: '',
                
                // Environment
                newEnvKey: '',
                newEnvValue: '',
                
                // GitHub
                githubRepo: '',
                githubBranch: 'main',
                
                // Activity
                activityLog: [],
                
                // Admin
                adminStats: {
                    total_users: 0,
                    total_deployments: 0,
                    active_processes: 0
                },
                systemStats: {
                    cpu: 0,
                    memory: 0
                },
                allUsers: [],
                
                async init() {
                    await this.loadUserData();
                    await this.loadDeployments();
                    await this.loadActivity();
                    
                    if (this.isAdmin) {
                        await this.loadAdminData();
                    }
                    
                    // Auto refresh every 10 seconds
                    setInterval(() => {
                        this.loadDeployments();
                        if (this.detailTab === 'console' && this.selectedDeploy) {
                            this.refreshLogs(this.selectedDeploy.id);
                        }
                    }, 10000);
                },
                
                async loadUserData() {
                    const res = await fetch('/api/user');
                    const data = await res.json();
                    if (data.success) {
                        this.userEmail = data.user.email;
                        this.credits = data.user.credits;
                        this.totalEarned = data.user.total_earned;
                        this.totalSpent = data.user.total_spent;
                        this.isAdmin = data.user.is_admin;
                    }
                },
                
                async loadDeployments() {
                    const res = await fetch('/api/deployments');
                    const data = await res.json();
                    if (data.success) {
                        this.deployments = data.deployments;
                    }
                },
                
                async loadActivity() {
                    const res = await fetch('/api/activity');
                    const data = await res.json();
                    if (data.success) {
                        this.activityLog = data.activity;
                    }
                },
                
                async loadAdminData() {
                    const res = await fetch('/api/admin/stats');
                    const data = await res.json();
                    if (data.success) {
                        this.adminStats = data.stats;
                        this.systemStats = data.system;
                        this.allUsers = data.users;
                    }
                },
                
                async viewDeployment(deployId) {
                    const deploy = this.deployments.find(d => d.id === deployId);
                    if (!deploy) return;
                    
                    this.selectedDeploy = deploy;
                    this.detailTab = 'overview';
                    this.showModal = 'detail';
                    
                    // Load files
                    const res = await fetch(`/api/deployment/${deployId}/files`);
                    const data = await res.json();
                    if (data.success) {
                        this.deploymentFiles = data.files;
                    }
                    
                    // Load logs
                    await this.refreshLogs(deployId);
                },
                
                async viewLogs(deployId) {
                    await this.viewDeployment(deployId);
                    this.detailTab = 'console';
                },
                
                async refreshLogs(deployId) {
                    const res = await fetch(`/api/deployment/${deployId}/logs`);
                    const data = await res.json();
                    if (data.success) {
                        this.consoleLog = data.logs;
                        this.$nextTick(() => {
                            if (this.$refs.consoleOutput) {
                                this.$refs.consoleOutput.scrollTop = this.$refs.consoleOutput.scrollHeight;
                            }
                        });
                    }
                },
                
                clearLogs() {
                    this.consoleLog = '';
                },
                
                async addEnvVar() {
                    if (!this.newEnvKey || !this.newEnvValue || !this.selectedDeploy) return;
                    
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            key: this.newEnvKey,
                            value: this.newEnvValue
                        })
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        this.selectedDeploy.env_vars[this.newEnvKey] = this.newEnvValue;
                        this.newEnvKey = '';
                        this.newEnvValue = '';
                        alert('✅ Environment variable added! Restart deployment for changes to take effect.');
                    } else {
                        alert('❌ ' + data.error);
                    }
                },
                
                async deleteEnvVar(key) {
                    if (!confirm(`Delete environment variable "${key}"?`)) return;
                    
                    const res = await fetch(`/api/deployment/${this.selectedDeploy.id}/env/${key}`, {
                        method: 'DELETE'
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        delete this.selectedDeploy.env_vars[key];
                        alert('✅ Environment variable deleted!');
                    } else {
                        alert('❌ ' + data.error);
                    }
                },
                
                async uploadFile(event) {
                    const file = event.target.files[0];
                    if (!file) return;
                    
                    const formData = new FormData();
                    formData.append('file', file);
                    
                    this.showModal = null;
                    alert('🤖 Uploading and deploying... Please wait!');
                    
                    const res = await fetch('/api/deploy/upload', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        alert('✅ ' + data.message);
                        await this.loadDeployments();
                        await this.loadUserData();
                    } else {
                        alert('❌ ' + data.error);
                    }
                },
                
                async deployGithub() {
                    if (!this.githubRepo) return;
                    
                    this.showModal = null;
                    alert('🤖 Cloning and deploying... This may take a minute!');
                    
                    const res = await fetch('/api/deploy/github', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            url: this.githubRepo,
                            branch: this.githubBranch
                        })
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        alert('✅ ' + data.message);
                        await this.loadDeployments();
                        await this.loadUserData();
                        this.githubRepo = '';
                        this.githubBranch = 'main';
                    } else {
                        alert('❌ ' + data.error);
                    }
                },
                
                async restartDeploy(deployId) {
                    if (!confirm('Restart this deployment?')) return;
                    
                    const res = await fetch(`/api/deployment/${deployId}/restart`, {
                        method: 'POST'
                    });
                    
                    const data = await res.json();
                    alert(data.success ? '✅ Restarted!' : '❌ ' + data.message);
                    await this.loadDeployments();
                },
                
                async stopDeploy(deployId) {
                    if (!confirm('Stop this deployment?')) return;
                    
                    const res = await fetch(`/api/deployment/${deployId}/stop`, {
                        method: 'POST'
                    });
                    
                    const data = await res.json();
                    alert(data.success ? '✅ Stopped' : '❌ ' + data.message);
                    await this.loadDeployments();
                },
                
                async deleteDeploy(deployId) {
                    if (!confirm('Delete this deployment permanently?')) return;
                    
                    const res = await fetch(`/api/deployment/${deployId}`, {
                        method: 'DELETE'
                    });
                    
                    const data = await res.json();
                    alert(data.success ? '✅ Deleted' : '❌ Failed');
                    await this.loadDeployments();
                },
                
                async createBackup(deployId) {
                    if (!confirm('Create backup? This will cost 0.2 credits.')) return;
                    
                    const res = await fetch(`/api/deployment/${deployId}/backup`, {
                        method: 'POST'
                    });
                    
                    const data = await res.json();
                    if (data.success) {
                        // Download backup
                        window.location.href = `/api/download/${data.filename}`;
                        alert('✅ Backup created and downloading!');
                        await this.loadUserData();
                    } else {
                        alert('❌ ' + data.error);
                    }
                },
                
                async adminAddCredits(userId) {
                    const amount = prompt('Enter amount of credits to add:');
                    if (!amount || isNaN(amount)) return;
                    
                    const res = await fetch('/api/admin/add-credits', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ user_id: userId, amount: parseFloat(amount) })
                    });
                    
                    const data = await res.json();
                    alert(data.success ? '✅ Credits added!' : '❌ ' + data.error);
                    await this.loadAdminData();
                },
                
                async adminBanUser(userId, ban) {
                    if (!confirm(ban ? 'Ban this user?' : 'Unban this user?')) return;
                    
                    const res = await fetch('/api/admin/ban-user', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ user_id: userId, ban })
                    });
                    
                    const data = await res.json();
                    alert(data.success ? '✅ Done!' : '❌ ' + data.error);
                    await this.loadAdminData();
                },
                
                async logout() {
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

# ==================== FLASK ROUTES ====================

@app.route('/')
def index():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if user_id:
        return render_template_string(SPA_TEMPLATE)
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template_string("""
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - EliteHost</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script>tailwind.config = { darkMode: 'class' }</script>
</head>
<body class="bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 min-h-screen flex items-center justify-center p-4">
    <div class="bg-gray-800 rounded-2xl p-8 max-w-md w-full shadow-2xl border border-gray-700">
        <div class="text-center mb-8">
            <div class="w-20 h-20 bg-gradient-to-br from-purple-500 to-pink-500 rounded-2xl flex items-center justify-center mx-auto mb-4">
                <i class="fas fa-rocket text-white text-3xl"></i>
            </div>
            <h1 class="text-3xl font-black text-white mb-2">EliteHost</h1>
            <p class="text-gray-400">v11.0 Advanced Edition</p>
        </div>
        {% if error %}
        <div class="bg-red-500/20 border border-red-500 text-red-400 px-4 py-3 rounded-lg mb-4">
            <i class="fas fa-exclamation-circle mr-2"></i>{{ error }}
        </div>
        {% endif %}
        {% if success %}
        <div class="bg-green-500/20 border border-green-500 text-green-400 px-4 py-3 rounded-lg mb-4">
            <i class="fas fa-check-circle mr-2"></i>{{ success }}
        </div>
        {% endif %}
        <form method="POST">
            <div class="space-y-4 mb-6">
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Email</label>
                    <input type="email" name="email" required class="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-4 py-3 focus:border-purple-500 focus:outline-none">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Password</label>
                    <input type="password" name="password" required class="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-4 py-3 focus:border-purple-500 focus:outline-none">
                </div>
            </div>
            <button type="submit" class="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white py-3 rounded-lg font-bold transition mb-4">
                <i class="fas fa-sign-in-alt mr-2"></i>Login
            </button>
        </form>
        <p class="text-center text-gray-400 text-sm">
            Don't have an account? <a href="/register" class="text-purple-400 hover:text-purple-300 font-medium">Register</a>
        </p>
    </div>
</body>
</html>
        """, error=request.args.get('error'), success=request.args.get('success'))
    
    email = request.form.get('email')
    password = request.form.get('password')
    fingerprint = get_device_fingerprint(request)
    
    if is_device_banned(fingerprint):
        return redirect('/login?error=Device banned')
    
    user_id = authenticate_user(email, password)
    if not user_id:
        return redirect('/login?error=Invalid credentials')
    
    user = get_user(user_id)
    if user.get('is_banned'):
        return redirect('/login?error=Account banned')
    
    if user['device_fingerprint'] != fingerprint:
        return redirect('/login?error=Wrong device')
    
    session_token = create_session(user_id, fingerprint)
    update_user(user_id, last_login=datetime.now().isoformat())
    log_activity(user_id, 'USER_LOGIN', f'Login', request.remote_addr)
    
    response = make_response(redirect('/'))
    response.set_cookie('session_token', session_token, max_age=30*24*60*60)
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string("""
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - EliteHost</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <script>tailwind.config = { darkMode: 'class' }</script>
</head>
<body class="bg-gradient-to-br from-gray-900 via-purple-900 to-gray-900 min-h-screen flex items-center justify-center p-4">
    <div class="bg-gray-800 rounded-2xl p-8 max-w-md w-full shadow-2xl border border-gray-700">
        <div class="text-center mb-8">
            <div class="w-20 h-20 bg-gradient-to-br from-purple-500 to-pink-500 rounded-2xl flex items-center justify-center mx-auto mb-4">
                <i class="fas fa-rocket text-white text-3xl"></i>
            </div>
            <h1 class="text-3xl font-black text-white mb-2">Create Account</h1>
            <p class="text-gray-400">Join EliteHost v11.0</p>
        </div>
        {% if error %}
        <div class="bg-red-500/20 border border-red-500 text-red-400 px-4 py-3 rounded-lg mb-4">
            <i class="fas fa-exclamation-circle mr-2"></i>{{ error }}
        </div>
        {% endif %}
        <div class="bg-blue-500/20 border border-blue-500 text-blue-400 px-4 py-3 rounded-lg mb-4 text-sm">
            <i class="fas fa-shield-alt mr-2"></i>One account per device for security
        </div>
        <form method="POST">
            <div class="space-y-4 mb-6">
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Email</label>
                    <input type="email" name="email" required class="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-4 py-3 focus:border-purple-500 focus:outline-none">
                </div>
                <div>
                    <label class="block text-sm font-medium text-gray-300 mb-2">Password</label>
                    <input type="password" name="password" required minlength="6" class="w-full bg-gray-700 border border-gray-600 text-white rounded-lg px-4 py-3 focus:border-purple-500 focus:outline-none">
                </div>
            </div>
            <button type="submit" class="w-full bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white py-3 rounded-lg font-bold transition mb-4">
                <i class="fas fa-user-plus mr-2"></i>Create Account (Get 5 Free Credits!)
            </button>
        </form>
        <p class="text-center text-gray-400 text-sm">
            Already have an account? <a href="/login" class="text-purple-400 hover:text-purple-300 font-medium">Login</a>
        </p>
    </div>
</body>
</html>
        """, error=request.args.get('error'))
    
    email = request.form.get('email')
    password = request.form.get('password')
    fingerprint = get_device_fingerprint(request)
    ip = request.remote_addr
    
    if is_device_banned(fingerprint):
        return redirect('/register?error=Device banned')
    
    if check_existing_account(fingerprint):
        return redirect('/register?error=Device already has account')
    
    for user_data in db['users'].values():
        if user_data['email'] == email:
            return redirect('/register?error=Email already exists')
    
    create_user(email, password, fingerprint, ip)
    return redirect('/login?success=Account created! Login now.')

@app.route('/logout')
def logout():
    session_token = request.cookies.get('session_token')
    if session_token and session_token in db['sessions']:
        del db['sessions'][session_token]
        save_db(db)
    
    response = make_response(redirect('/login?success=Logged out'))
    response.set_cookie('session_token', '', max_age=0)
    return response

# ==================== API ROUTES ====================

@app.route('/api/user')
def api_user():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user = get_user(user_id)
    is_admin = str(user_id) in [str(OWNER_ID), str(ADMIN_ID)]
    
    return jsonify({
        'success': True,
        'user': {
            'email': user['email'],
            'credits': user['credits'],
            'total_earned': user['total_earned'],
            'total_spent': user['total_spent'],
            'is_admin': is_admin
        }
    })

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

@app.route('/api/activity')
def api_activity():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    user_activity = [a for a in db['activity'] if a['user_id'] == user_id][-50:]
    
    return jsonify({'success': True, 'activity': user_activity})

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

@app.route('/api/deployment/<deploy_id>/files')
def api_deployment_files(deploy_id):
    if deploy_id not in db['deployments']:
        return jsonify({'success': False, 'error': 'Not found'})
    
    files = get_deployment_files(deploy_id)
    return jsonify({'success': True, 'files': files})

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
    
    return jsonify({'success': False, 'error': 'Key not found'})

@app.route('/api/deployment/<deploy_id>/restart', methods=['POST'])
def api_restart_deployment(deploy_id):
    success, msg = restart_deployment(deploy_id)
    return jsonify({'success': success, 'message': msg})

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

@app.route('/api/deployment/<deploy_id>/backup', methods=['POST'])
def api_create_backup(deploy_id):
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if not user_id:
        return jsonify({'success': False, 'error': 'Not authenticated'})
    
    cost = CREDIT_COSTS['backup']
    if not deduct_credits(user_id, cost, f"Backup: {deploy_id}"):
        return jsonify({'success': False, 'error': f'Need {cost} credits'})
    
    backup_path, backup_name = create_backup(deploy_id)
    
    if backup_path:
        return jsonify({'success': True, 'filename': backup_name})
    else:
        add_credits(user_id, cost, "Refund")
        return jsonify({'success': False, 'error': backup_name})

@app.route('/api/download/<filename>')
def api_download(filename):
    backup_path = os.path.join(BACKUPS_DIR, secure_filename(filename))
    if os.path.exists(backup_path):
        return send_file(backup_path, as_attachment=True)
    return jsonify({'success': False, 'error': 'Not found'})

@app.route('/api/admin/stats')
def api_admin_stats():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    user_id = verify_session(session_token, fingerprint)
    
    if str(user_id) not in [str(OWNER_ID), str(ADMIN_ID)]:
        return jsonify({'success': False, 'error': 'Admin only'})
    
    stats = {
        'total_users': len(db['users']),
        'total_deployments': len(db['deployments']),
        'active_processes': len(active_processes)
    }
    
    system = {
        'cpu': psutil.cpu_percent(interval=1),
        'memory': psutil.virtual_memory().percent
    }
    
    users = []
    for uid, user_data in db['users'].items():
        users.append({
            'id': uid,
            'email': user_data['email'],
            'credits': user_data['credits'],
            'deployments': user_data.get('deployments', []),
            'is_banned': user_data.get('is_banned', False)
        })
    
    return jsonify({'success': True, 'stats': stats, 'system': system, 'users': users})

@app.route('/api/admin/add-credits', methods=['POST'])
def api_admin_add_credits():
    session_token = request.cookies.get('session_token')
    fingerprint = get_device_fingerprint(request)
    admin_id = verify_session(session_token, fingerprint)
    
    if str(admin_id) not in [str(OWNER_ID), str(ADMIN_ID)]:
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
    
    if str(admin_id) not in [str(OWNER_ID), str(ADMIN_ID)]:
        return jsonify({'success': False, 'error': 'Admin only'})
    
    data = request.get_json()
    target_user = data.get('user_id')
    ban = data.get('ban', True)
    
    user = get_user(target_user)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'})
    
    if ban:
        if user['device_fingerprint'] not in db['banned_devices']:
            db['banned_devices'].append(user['device_fingerprint'])
    
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
    print(f"{Fore.CYAN}{'🚀 ELITEHOST v11.0 - ADVANCED SPA EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}✨ NEW FEATURES v11.0:")
    print(f"{Fore.CYAN}   🎨 Modern SPA with TailwindCSS + Alpine.js")
    print(f"{Fore.CYAN}   🌙 Dark mode by default (Vercel/Railway style)")
    print(f"{Fore.CYAN}   📂 Detailed sidebar navigation")
    print(f"{Fore.CYAN}   🔑 Environment variables (secrets) per deployment")
    print(f"{Fore.CYAN}   💾 Backup system with download")
    print(f"{Fore.CYAN}   📁 File manager (read-only browser)")
    print(f"{Fore.CYAN}   📟 Live console with auto-refresh")
    print(f"{Fore.CYAN}   👑 Advanced admin dashboard with CPU/RAM")
    print(f"{Fore.CYAN}   🤖 AI auto-install dependencies")
    print(f"{Fore.CYAN}   💎 5 free credits for new users")
    print("=" * 90)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 Web App: http://localhost:{port}")
    print(f"{Fore.YELLOW}📱 Register: http://localhost:{port}/register")
    print(f"{Fore.YELLOW}🔑 Login: http://localhost:{port}/login")
    print(f"\n{Fore.GREEN}{'✅ ELITEHOST v11.0 READY':^90}")
    print("=" * 90 + "\n")
    
    # Keep running
    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt:
            break
