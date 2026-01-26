# -*- coding: utf-8 -*-
"""
🚀 ELITEHOST v11.0 - ULTIMATE EDITION
Revolutionary AI-Powered Deployment Platform
✨ NEW: Env Vars | Backups | File Manager | Live Console | Build Commands
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

# ==================== ENCRYPTION HELPERS ====================

def encrypt_value(value):
    """Encrypt sensitive value"""
    return fernet.encrypt(value.encode()).decode()

def decrypt_value(encrypted_value):
    """Decrypt sensitive value"""
    try:
        return fernet.decrypt(encrypted_value.encode()).decode()
    except:
        return encrypted_value

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
        'build_command': kwargs.get('build_command', ''),
        'start_command': kwargs.get('start_command', ''),
        'env_vars': {},
        'backups': []
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
        
        update_deployment(deploy_id, dependencies=installed_deps)
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        deployment = db['deployments'][deploy_id]
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = decrypt_value(value)
        
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

def deploy_from_github(user_id, repo_url, branch='main', build_cmd='', start_cmd=''):
    try:
        cost = CREDIT_COSTS['github_deploy']
        if not deduct_credits(user_id, cost, f"GitHub: {repo_url}"):
            return None, f"❌ Need {cost} credits"
        
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        deploy_id, port = create_deployment(
            user_id, repo_name, 'github', 
            repo_url=repo_url, branch=branch,
            build_command=build_cmd, start_command=start_cmd
        )
        
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
        
        update_deployment(deploy_id, dependencies=installed_deps)
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        deployment = db['deployments'][deploy_id]
        for key, value in deployment.get('env_vars', {}).items():
            env[key] = decrypt_value(value)
        
        # Build command
        if build_cmd:
            update_deployment(deploy_id, status='building', logs=f'🔨 Building: {build_cmd}')
            result = subprocess.run(
                build_cmd, shell=True, cwd=deploy_dir,
                capture_output=True, text=True, timeout=600, env=env
            )
            if result.returncode != 0:
                update_deployment(deploy_id, status='failed', logs=f'❌ Build failed:\n{result.stderr}')
                add_credits(user_id, cost, "Refund")
                return None, "❌ Build failed"
        
        # Start command
        if not start_cmd:
            main_files = {
                'main.py': f'{sys.executable} main.py',
                'app.py': f'{sys.executable} app.py',
                'bot.py': f'{sys.executable} bot.py',
            }
            
            for file, cmd in main_files.items():
                if os.path.exists(os.path.join(deploy_dir, file)):
                    start_cmd = cmd
                    break
        
        if not start_cmd:
            update_deployment(deploy_id, status='failed', logs='❌ No start command')
            add_credits(user_id, cost, "Refund")
            return None, "❌ No start file found"
        
        update_deployment(deploy_id, status='starting', logs=f'🚀 Starting: {start_cmd}')
        
        process = subprocess.Popen(
            start_cmd, shell=True,
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

def create_backup(deploy_id, user_id):
    """Create backup of deployment"""
    try:
        cost = CREDIT_COSTS['backup']
        if not deduct_credits(user_id, cost, f"Backup: {deploy_id}"):
            return None, f"❌ Need {cost} credits"
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if not os.path.exists(deploy_dir):
            add_credits(user_id, cost, "Refund")
            return None, "Deployment not found"
        
        backup_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"{deploy_id}_backup_{timestamp}.zip"
        backup_path = os.path.join(BACKUPS_DIR, backup_filename)
        
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(deploy_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, deploy_dir)
                    zipf.write(file_path, arcname)
        
        backup_size = os.path.getsize(backup_path)
        
        backup_info = {
            'id': backup_id,
            'filename': backup_filename,
            'created_at': datetime.now().isoformat(),
            'size_bytes': backup_size
        }
        
        deployment = db['deployments'][deploy_id]
        deployment['backups'].append(backup_info)
        save_db(db)
        
        return backup_filename, "Backup created successfully"
    except Exception as e:
        if 'cost' in locals():
            add_credits(user_id, cost, "Refund")
        return None, str(e)

def get_file_tree(deploy_id):
    """Get file tree structure"""
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
                'path': rel_path,
                'name': filename,
                'size': size,
                'type': 'file'
            })
    
    return files

def read_file_content(deploy_id, file_path):
    """Read file content"""
    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    full_path = os.path.join(deploy_dir, file_path)
    
    if not os.path.exists(full_path) or not full_path.startswith(deploy_dir):
        return None
    
    try:
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except:
        return None

# ==================== HTML TEMPLATES ====================

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost - Login</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .login-container { max-width: 450px; width: 100%; background: white; border-radius: 20px; padding: 40px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); }
        .logo { text-align: center; margin-bottom: 30px; }
        .logo-icon { width: 80px; height: 80px; background: linear-gradient(135deg, #667eea, #764ba2); border-radius: 20px; display: inline-flex; align-items: center; justify-content: center; font-size: 40px; color: white; margin-bottom: 15px; }
        h1 { font-size: 32px; font-weight: 900; color: #1a202c; margin-bottom: 10px; }
        .subtitle { color: #718096; font-size: 14px; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-weight: 600; color: #2d3748; margin-bottom: 8px; font-size: 14px; }
        input { width: 100%; padding: 14px 16px; border: 2px solid #e2e8f0; border-radius: 10px; font-size: 15px; transition: all 0.3s; font-family: inherit; }
        input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
        .btn { width: 100%; padding: 16px; background: linear-gradient(135deg, #667eea, #764ba2); color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 700; cursor: pointer; transition: transform 0.2s; margin-top: 10px; }
        .btn:hover { transform: translateY(-2px); }
        .toggle-auth { text-align: center; margin-top: 20px; font-size: 14px; color: #718096; }
        .toggle-auth a { color: #667eea; font-weight: 600; text-decoration: none; }
        .alert { padding: 12px 16px; border-radius: 10px; margin-bottom: 20px; font-size: 14px; }
        .alert-error { background: #fee; color: #c00; border: 1px solid #fcc; }
        .alert-success { background: #efe; color: #0a0; border: 1px solid #cfc; }
        .device-info { background: #f7fafc; padding: 15px; border-radius: 10px; margin-bottom: 20px; font-size: 12px; color: #4a5568; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <div class="logo-icon"><i class="fas fa-rocket"></i></div>
            <h1>EliteHost</h1>
            <p class="subtitle">Enterprise Deployment Platform</p>
        </div>
        {% if error %}<div class="alert alert-error"><i class="fas fa-exclamation-circle"></i> {{ error }}</div>{% endif %}
        {% if success %}<div class="alert alert-success"><i class="fas fa-check-circle"></i> {{ success }}</div>{% endif %}
        <div class="device-info"><i class="fas fa-shield-alt"></i> <strong>Secure Login:</strong> One account per device for maximum security</div>
        <form method="POST" action="{{ action }}">
            <div class="form-group">
                <label for="email"><i class="fas fa-envelope"></i> Email Address</label>
                <input type="email" id="email" name="email" placeholder="you@example.com" required>
            </div>
            <div class="form-group">
                <label for="password"><i class="fas fa-lock"></i> Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required>
            </div>
            <button type="submit" class="btn"><i class="fas fa-{{ icon }}"></i> {{ button_text }}</button>
        </form>
        <div class="toggle-auth">{{ toggle_text }} <a href="{{ toggle_link }}">{{ toggle_action }}</a></div>
    </div>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EliteHost v11.0 - Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root { --primary: #667eea; --secondary: #764ba2; --success: #48bb78; --danger: #f56565; --warning: #ed8936; --dark: #1a202c; --gray: #718096; --light: #f7fafc; }
        body { font-family: 'Inter', sans-serif; background: #f7fafc; color: #2d3748; min-height: 100vh; padding-bottom: 80px; }
        .header { background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 100; }
        .header-content { max-width: 1200px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; height: 70px; }
        .logo { display: flex; align-items: center; gap: 12px; font-size: 24px; font-weight: 900; color: var(--dark); }
        .logo-icon { width: 40px; height: 40px; background: linear-gradient(135deg, var(--primary), var(--secondary)); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: white; font-size: 20px; }
        .header-nav { display: flex; gap: 20px; align-items: center; }
        .credit-badge { background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; padding: 8px 16px; border-radius: 20px; font-weight: 700; font-size: 14px; display: flex; align-items: center; gap: 6px; }
        .nav-btn { padding: 8px 16px; border-radius: 8px; font-weight: 600; font-size: 14px; cursor: pointer; border: none; transition: all 0.2s; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; }
        .nav-btn-admin { background: var(--warning); color: white; }
        .nav-btn-logout { background: var(--danger); color: white; }
        .nav-btn:hover { transform: translateY(-2px); }
        .container { max-width: 1200px; margin: 0 auto; padding: 30px 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; border-radius: 16px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .stat-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .stat-icon { width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 24px; }
        .stat-value { font-size: 32px; font-weight: 900; color: var(--dark); margin-bottom: 4px; }
        .stat-label { font-size: 14px; color: var(--gray); font-weight: 600; }
        .section { background: white; border-radius: 16px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .section-title { font-size: 20px; font-weight: 800; color: var(--dark); }
        .deploy-card { background: var(--light); border-radius: 12px; padding: 16px; margin-bottom: 12px; border: 2px solid transparent; transition: all 0.2s; }
        .deploy-card:hover { border-color: var(--primary); }
        .deploy-header { display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px; }
        .deploy-name { font-size: 16px; font-weight: 700; color: var(--dark); margin-bottom: 6px; }
        .deploy-meta { font-size: 12px; color: var(--gray); display: flex; gap: 12px; flex-wrap: wrap; }
        .status-badge { padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
        .status-running { background: #c6f6d5; color: #22543d; }
        .status-pending { background: #feebc8; color: #7c2d12; }
        .status-stopped { background: #fed7d7; color: #742a2a; }
        .status-failed { background: #fed7d7; color: #742a2a; }
        .deploy-actions { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
        .btn-small { padding: 8px 12px; border-radius: 8px; font-size: 12px; font-weight: 600; border: none; cursor: pointer; transition: all 0.2s; color: white; }
        .btn-small:hover { transform: translateY(-2px); }
        .empty-state { text-align: center; padding: 60px 20px; color: var(--gray); }
        .empty-icon { font-size: 64px; margin-bottom: 16px; opacity: 0.3; }
        .fixed-buttons { position: fixed; bottom: 0; left: 0; right: 0; background: white; border-top: 1px solid #e2e8f0; padding: 16px 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 12px; max-width: 1200px; margin: 0 auto; z-index: 50; }
        .btn-deploy { padding: 16px; border-radius: 12px; font-size: 16px; font-weight: 700; border: none; cursor: pointer; transition: all 0.2s; color: white; display: flex; align-items: center; justify-content: center; gap: 8px; }
        .btn-file { background: linear-gradient(135deg, var(--primary), var(--secondary)); }
        .btn-github { background: linear-gradient(135deg, #24292e, #000); }
        .btn-deploy:hover { transform: translateY(-2px); }
        .modal { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; align-items: center; justify-content: center; padding: 20px; overflow-y: auto; }
        .modal.active { display: flex; }
        .modal-content { background: white; border-radius: 16px; padding: 30px; max-width: 800px; width: 100%; max-height: 90vh; overflow-y: auto; margin: auto; }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-title { font-size: 24px; font-weight: 800; }
        .close-btn { width: 32px; height: 32px; border-radius: 8px; border: none; background: var(--light); cursor: pointer; display: flex; align-items: center; justify-content: center; }
        .form-group { margin-bottom: 16px; }
        label { display: block; font-weight: 600; margin-bottom: 6px; font-size: 14px; }
        input, textarea { width: 100%; padding: 12px; border: 2px solid #e2e8f0; border-radius: 8px; font-family: inherit; font-size: 14px; }
        input:focus, textarea:focus { outline: none; border-color: var(--primary); }
        .btn-primary { width: 100%; padding: 14px; background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; border: none; border-radius: 10px; font-weight: 700; font-size: 16px; cursor: pointer; margin-top: 10px; }
        .upload-zone { border: 2px dashed var(--primary); border-radius: 12px; padding: 40px 20px; text-align: center; background: #f0f4ff; cursor: pointer; margin-bottom: 16px; }
        .upload-icon { font-size: 48px; color: var(--primary); margin-bottom: 12px; }
        .env-var-row { display: grid; grid-template-columns: 1fr 1fr auto; gap: 8px; margin-bottom: 8px; }
        .file-tree { max-height: 400px; overflow-y: auto; font-family: monospace; font-size: 12px; }
        .file-item { padding: 8px; cursor: pointer; border-radius: 4px; }
        .file-item:hover { background: var(--light); }
        .file-viewer { background: #1a202c; color: #48bb78; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 12px; max-height: 500px; overflow: auto; white-space: pre-wrap; }
        .logs-console { background: #1a202c; color: #48bb78; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 12px; max-height: 400px; overflow-y: auto; white-space: pre-wrap; }
        .tabs { display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 2px solid #e2e8f0; }
        .tab { padding: 12px 20px; cursor: pointer; font-weight: 600; border-bottom: 2px solid transparent; margin-bottom: -2px; transition: all 0.2s; }
        .tab.active { border-bottom-color: var(--primary); color: var(--primary); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">
                <div class="logo-icon"><i class="fas fa-rocket"></i></div>
                <span>EliteHost v11</span>
            </div>
            <div class="header-nav">
                <div class="credit-badge"><i class="fas fa-gem"></i> <span id="creditBalance">{{ credits }}</span></div>
                {% if is_admin %}<button class="nav-btn nav-btn-admin" onclick="window.location.href='/admin'"><i class="fas fa-crown"></i> Admin</button>{% endif %}
                <button class="nav-btn nav-btn-logout" onclick="logout()"><i class="fas fa-sign-out-alt"></i> Logout</button>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-header">
                    <div>
                        <div class="stat-value" id="totalDeploys">{{ total_deploys }}</div>
                        <div class="stat-label">Total Deployments</div>
                    </div>
                    <div class="stat-icon" style="background: #e6fffa; color: #319795;"><i class="fas fa-rocket"></i></div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-header">
                    <div>
                        <div class="stat-value" id="activeDeploys">{{ active_deploys }}</div>
                        <div class="stat-label">Active Now</div>
                    </div>
                    <div class="stat-icon" style="background: #c6f6d5; color: #22543d;"><i class="fas fa-check-circle"></i></div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-header">
                    <div>
                        <div class="stat-value">{{ credits }}</div>
                        <div class="stat-label">Available Credits</div>
                    </div>
                    <div class="stat-icon" style="background: #feebc8; color: #7c2d12;"><i class="fas fa-gem"></i></div>
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-header">
                    <div>
                        <div class="stat-value">AI</div>
                        <div class="stat-label">Auto Install</div>
                    </div>
                    <div class="stat-icon" style="background: #e9d8fd; color: #553c9a;"><i class="fas fa-robot"></i></div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h2 class="section-title">Your Deployments</h2>
                <button class="nav-btn" style="background: var(--primary); color: white;" onclick="loadDeployments()"><i class="fas fa-sync"></i> Refresh</button>
            </div>
            <div id="deploymentsList"></div>
        </div>
    </div>
    
    <div class="fixed-buttons">
        <button class="btn-deploy btn-file" onclick="showFileUpload()"><i class="fas fa-cloud-upload-alt"></i> Upload File</button>
        <button class="btn-deploy btn-github" onclick="showGithubDeploy()"><i class="fab fa-github"></i> GitHub Deploy</button>
    </div>
    
    <!-- File Upload Modal -->
    <div class="modal" id="fileModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Upload & Deploy</h3>
                <button class="close-btn" onclick="closeModal('fileModal')"><i class="fas fa-times"></i></button>
            </div>
            <div class="upload-zone" onclick="document.getElementById('fileInput').click()">
                <div class="upload-icon"><i class="fas fa-cloud-upload-alt"></i></div>
                <div style="font-weight: 600; margin-bottom: 4px;">Click to Upload</div>
                <div style="font-size: 12px; color: var(--gray);">Python, JavaScript, ZIP files</div>
                <input type="file" id="fileInput" hidden accept=".py,.js,.zip" onchange="uploadFile(this)">
            </div>
            <div style="padding: 12px; background: var(--light); border-radius: 8px; font-size: 13px;">
                <strong>Cost:</strong> 0.5 credits per deployment<br>
                <strong>AI Features:</strong> Auto-detects and installs dependencies
            </div>
        </div>
    </div>
    
    <!-- GitHub Deploy Modal -->
    <div class="modal" id="githubModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Deploy from GitHub</h3>
                <button class="close-btn" onclick="closeModal('githubModal')"><i class="fas fa-times"></i></button>
            </div>
            <form onsubmit="deployGithub(event)">
                <div class="form-group">
                    <label>Repository URL *</label>
                    <input type="url" id="repoUrl" placeholder="https://github.com/user/repo" required>
                </div>
                <div class="form-group">
                    <label>Branch</label>
                    <input type="text" id="repoBranch" value="main" required>
                </div>
                <div class="form-group">
                    <label>Build Command (optional)</label>
                    <input type="text" id="buildCmd" placeholder="npm run build">
                    <small style="color: var(--gray);">e.g., npm install, pip install -r requirements.txt</small>
                </div>
                <div class="form-group">
                    <label>Start Command (optional)</label>
                    <input type="text" id="startCmd" placeholder="python main.py">
                    <small style="color: var(--gray);">Auto-detected if left empty</small>
                </div>
                <button type="submit" class="btn-primary"><i class="fab fa-github"></i> Deploy (1.0 credit)</button>
            </form>
            <div style="padding: 12px; background: var(--light); border-radius: 8px; font-size: 13px; margin-top: 16px;">
                <strong>✨ NEW:</strong> Custom build & start commands supported!
            </div>
        </div>
    </div>
    
    <!-- Deployment Details Modal -->
    <div class="modal" id="detailsModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title" id="detailsTitle">Deployment Details</h3>
                <button class="close-btn" onclick="closeModal('detailsModal')"><i class="fas fa-times"></i></button>
            </div>
            
            <div class="tabs">
                <div class="tab active" onclick="switchTab('logs')"><i class="fas fa-terminal"></i> Live Console</div>
                <div class="tab" onclick="switchTab('env')"><i class="fas fa-key"></i> Environment</div>
                <div class="tab" onclick="switchTab('files')"><i class="fas fa-folder"></i> Files</div>
                <div class="tab" onclick="switchTab('backups')"><i class="fas fa-download"></i> Backups</div>
            </div>
            
            <div id="tab-logs" class="tab-content active">
                <div class="logs-console" id="logsContent">Loading...</div>
                <button class="btn-primary" style="margin-top: 12px;" onclick="refreshLogs()"><i class="fas fa-sync"></i> Refresh Logs</button>
            </div>
            
            <div id="tab-env" class="tab-content">
                <div id="envVarsList"></div>
                <button class="btn-primary" onclick="showAddEnvVar()"><i class="fas fa-plus"></i> Add Variable</button>
            </div>
            
            <div id="tab-files" class="tab-content">
                <div class="file-tree" id="fileTree">Loading...</div>
            </div>
            
            <div id="tab-backups" class="tab-content">
                <div id="backupsList">Loading...</div>
                <button class="btn-primary" onclick="createBackup()"><i class="fas fa-archive"></i> Create New Backup (0.2 credits)</button>
            </div>
        </div>
    </div>
    
    <!-- File Viewer Modal -->
    <div class="modal" id="fileViewerModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title" id="fileViewerTitle">File</h3>
                <button class="close-btn" onclick="closeModal('fileViewerModal')"><i class="fas fa-times"></i></button>
            </div>
            <div class="file-viewer" id="fileViewerContent">Loading...</div>
        </div>
    </div>
    
    <script>
        let currentDeployId = null;
        let logsInterval = null;
        
        function loadDeployments() {
            fetch('/api/deployments')
                .then(r => r.json())
                .then(data => {
                    const list = document.getElementById('deploymentsList');
                    if (!data.deployments || data.deployments.length === 0) {
                        list.innerHTML = '<div class="empty-state"><div class="empty-icon"><i class="fas fa-rocket"></i></div><div style="font-size: 18px; font-weight: 700; margin-bottom: 8px;">No Deployments Yet</div><div>Click the buttons below to deploy your first app!</div></div>';
                        return;
                    }
                    list.innerHTML = data.deployments.map(d => `
                        <div class="deploy-card">
                            <div class="deploy-header">
                                <div>
                                    <div class="deploy-name">${d.name}</div>
                                    <div class="deploy-meta">
                                        <span><i class="fas fa-fingerprint"></i> ${d.id}</span>
                                        <span><i class="fas fa-network-wired"></i> Port ${d.port}</span>
                                        ${d.dependencies && d.dependencies.length > 0 ? `<span><i class="fas fa-robot"></i> ${d.dependencies.length} pkgs</span>` : ''}
                                        ${d.env_vars && Object.keys(d.env_vars).length > 0 ? `<span><i class="fas fa-key"></i> ${Object.keys(d.env_vars).length} vars</span>` : ''}
                                    </div>
                                </div>
                                <span class="status-badge status-${d.status}">${d.status}</span>
                            </div>
                            <div class="deploy-actions">
                                <button class="btn-small" style="background: #4299e1;" onclick="viewDetails('${d.id}')"><i class="fas fa-info-circle"></i> Details</button>
                                <button class="btn-small" style="background: #48bb78;" onclick="restartDeploy('${d.id}')"><i class="fas fa-redo"></i> Restart</button>
                                <button class="btn-small" style="background: #ed8936;" onclick="stopDeploy('${d.id}')"><i class="fas fa-stop"></i> Stop</button>
                                <button class="btn-small" style="background: #f56565;" onclick="deleteDeploy('${d.id}')"><i class="fas fa-trash"></i> Delete</button>
                            </div>
                        </div>
                    `).join('');
                    document.getElementById('totalDeploys').textContent = data.deployments.length;
                    document.getElementById('activeDeploys').textContent = data.deployments.filter(d => d.status === 'running').length;
                });
        }
        
        function showFileUpload() { document.getElementById('fileModal').classList.add('active'); }
        function showGithubDeploy() { document.getElementById('githubModal').classList.add('active'); }
        function closeModal(id) {
            document.getElementById(id).classList.remove('active');
            if (id === 'detailsModal' && logsInterval) {
                clearInterval(logsInterval);
                logsInterval = null;
            }
        }
        
        function uploadFile(input) {
            const file = input.files[0];
            if (!file) return;
            const formData = new FormData();
            formData.append('file', file);
            alert('🤖 Uploading and deploying... Please wait!');
            closeModal('fileModal');
            fetch('/api/deploy/upload', { method: 'POST', body: formData })
                .then(r => r.json())
                .then(data => {
                    alert(data.success ? '✅ Deployment successful!\\n\\n' + data.message : '❌ Error: ' + data.error);
                    loadDeployments();
                    updateCredits();
                });
        }
        
        function deployGithub(e) {
            e.preventDefault();
            const url = document.getElementById('repoUrl').value;
            const branch = document.getElementById('repoBranch').value;
            const buildCmd = document.getElementById('buildCmd').value;
            const startCmd = document.getElementById('startCmd').value;
            alert('🤖 Cloning and deploying... This may take a minute!');
            closeModal('githubModal');
            fetch('/api/deploy/github', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url, branch, build_command: buildCmd, start_command: startCmd})
            })
                .then(r => r.json())
                .then(data => {
                    alert(data.success ? '✅ GitHub deployment successful!\\n\\n' + data.message : '❌ Error: ' + data.error);
                    loadDeployments();
                    updateCredits();
                });
        }
        
        function viewDetails(deployId) {
            currentDeployId = deployId;
            fetch(`/api/deployment/${deployId}`)
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        document.getElementById('detailsTitle').textContent = data.deployment.name;
                        loadLogs(deployId);
                        loadEnvVars(deployId);
                        loadFiles(deployId);
                        loadBackups(deployId);
                        document.getElementById('detailsModal').classList.add('active');
                        switchTab('logs');
                        logsInterval = setInterval(() => loadLogs(deployId), 3000);
                    }
                });
        }
        
        function switchTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById(`tab-${tabName}`).classList.add('active');
        }
        
        function loadLogs(deployId) {
            fetch(`/api/deployment/${deployId}/logs`)
                .then(r => r.json())
                .then(data => {
                    document.getElementById('logsContent').textContent = data.logs || 'No logs available';
                    const console = document.getElementById('logsContent');
                    console.scrollTop = console.scrollHeight;
                });
        }
        
        function refreshLogs() { if (currentDeployId) loadLogs(currentDeployId); }
        
        function loadEnvVars(deployId) {
            fetch(`/api/deployment/${deployId}/env`)
                .then(r => r.json())
                .then(data => {
                    const list = document.getElementById('envVarsList');
                    const vars = data.env_vars || {};
                    if (Object.keys(vars).length === 0) {
                        list.innerHTML = '<p style="color: var(--gray); text-align: center; padding: 20px;">No environment variables</p>';
                    } else {
                        list.innerHTML = Object.entries(vars).map(([key, value]) => `
                            <div class="env-var-row">
                                <input type="text" value="${key}" readonly style="background: #f7fafc;">
                                <input type="password" value="••••••••" readonly style="background: #f7fafc;">
                                <button class="btn-small" style="background: #f56565;" onclick="deleteEnvVar('${deployId}', '${key}')"><i class="fas fa-trash"></i></button>
                            </div>
                        `).join('');
                    }
                });
        }
        
        function showAddEnvVar() {
            const key = prompt('Environment Variable Key:');
            if (!key) return;
            const value = prompt('Environment Variable Value:');
            if (!value) return;
            fetch(`/api/deployment/${currentDeployId}/env`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({key, value})
            })
                .then(r => r.json())
                .then(data => {
                    alert(data.success ? '✅ Variable added!' : '❌ ' + data.error);
                    loadEnvVars(currentDeployId);
                    updateCredits();
                });
        }
        
        function deleteEnvVar(deployId, key) {
            if (!confirm(`Delete variable "${key}"?`)) return;
            fetch(`/api/deployment/${deployId}/env/${key}`, {method: 'DELETE'})
                .then(r => r.json())
                .then(data => {
                    alert(data.success ? '✅ Deleted' : '❌ Failed');
                    loadEnvVars(deployId);
                });
        }
        
        function loadFiles(deployId) {
            fetch(`/api/deployment/${deployId}/files`)
                .then(r => r.json())
                .then(data => {
                    const tree = document.getElementById('fileTree');
                    if (!data.files || data.files.length === 0) {
                        tree.innerHTML = '<p style="color: var(--gray); text-align: center; padding: 20px;">No files found</p>';
                    } else {
                        tree.innerHTML = data.files.map(f => `
                            <div class="file-item" onclick="viewFile('${deployId}', '${f.path}', '${f.name}')">
                                <i class="fas fa-file"></i> ${f.path} <span style="color: var(--gray); font-size: 10px;">(${(f.size/1024).toFixed(1)} KB)</span>
                            </div>
                        `).join('');
                    }
                });
        }
        
        function viewFile(deployId, path, name) {
            fetch(`/api/deployment/${deployId}/file?path=${encodeURIComponent(path)}`)
                .then(r => r.json())
                .then(data => {
                    document.getElementById('fileViewerTitle').textContent = name;
                    document.getElementById('fileViewerContent').textContent = data.content || 'Cannot read file';
                    document.getElementById('fileViewerModal').classList.add('active');
                });
        }
        
        function loadBackups(deployId) {
            fetch(`/api/deployment/${deployId}`)
                .then(r => r.json())
                .then(data => {
                    const list = document.getElementById('backupsList');
                    const backups = data.deployment.backups || [];
                    if (backups.length === 0) {
                        list.innerHTML = '<p style="color: var(--gray); text-align: center; padding: 20px;">No backups yet</p>';
                    } else {
                        list.innerHTML = backups.map(b => `
                            <div style="background: var(--light); padding: 12px; border-radius: 8px; margin-bottom: 8px;">
                                <div style="font-weight: 600;"><i class="fas fa-archive"></i> ${b.filename}</div>
                                <div style="font-size: 12px; color: var(--gray); margin-top: 4px;">
                                    Size: ${(b.size_bytes/1024/1024).toFixed(2)} MB | Created: ${new Date(b.created_at).toLocaleString()}
                                </div>
                                <button class="btn-small" style="background: #4299e1; margin-top: 8px;" onclick="downloadBackup('${b.filename}')"><i class="fas fa-download"></i> Download</button>
                            </div>
                        `).join('');
                    }
                });
        }
        
        function createBackup() {
            if (!confirm('Create backup? (0.2 credits)')) return;
            fetch(`/api/deployment/${currentDeployId}/backup`, {method: 'POST'})
                .then(r => r.json())
                .then(data => {
                    alert(data.success ? '✅ Backup created!' : '❌ ' + data.error);
                    loadBackups(currentDeployId);
                    updateCredits();
                });
        }
        
        function downloadBackup(filename) {
            window.location.href = `/api/backup/${filename}`;
        }
        
        function stopDeploy(deployId) {
            if (!confirm('Stop this deployment?')) return;
            fetch(`/api/deployment/${deployId}/stop`, {method: 'POST'})
                .then(r => r.json())
                .then(data => {
                    alert(data.success ? '✅ Stopped' : '❌ ' + data.message);
                    loadDeployments();
                });
        }
        
        function restartDeploy(deployId) {
            if (!confirm('Restart this deployment?')) return;
            fetch(`/api/deployment/${deployId}/restart`, {method: 'POST'})
                .then(r => r.json())
                .then(data => {
                    alert(data.success ? '✅ Restarting...' : '❌ ' + data.message);
                    setTimeout(loadDeployments, 2000);
                });
        }
        
        function deleteDeploy(deployId) {
            if (!confirm('Delete this deployment permanently?')) return;
            fetch(`/api/deployment/${deployId}`, {method: 'DELETE'})
                .then(r => r.json())
                .then(data => {
                    alert(data.success ? '✅ Deleted' : '❌ Failed');
                    loadDeployments();
                });
        }
        
        function updateCredits() {
            fetch('/api/credits')
                .then(r => r.json())
                .then(data => {
                    const credits = data.credits === Infinity ? '∞' : data.credits.toFixed(1);
                    document.getElementById('creditBalance').textContent = credits;
                });
        }
        
        function logout() {
            if (confirm('Logout from EliteHost?')) window.location.href = '/logout';
        }
        
        loadDeployments();
        setInterval(loadDeployments, 10000);
        setInterval(updateCredits, 15000);
    </script>
</body>
</html>
"""
