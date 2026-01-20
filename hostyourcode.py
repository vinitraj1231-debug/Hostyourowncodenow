# -*- coding: utf-8 -*-
"""
🚀 ULTRA ADVANCED DEVOPS BOT v9.0 - ULTIMATE PROFESSIONAL EDITION
Revolutionary AI-Powered Deployment Platform
Bot + Web Fully Integrated | Payment Gateway | Per-User Credits
"""

import sys
import subprocess
import os

# ==================== SMART DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 NEXT-GEN DEPENDENCY INSTALLER v9.0")
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
    'qrcode': 'qrcode'
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
import sqlite3
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
import qrcode

init(autoreset=True)

# ==================== ADVANCED CONFIGURATION ====================
TOKEN = '8451737127:AAGRbO0CygbnYuqMCBolTP8_EG7NLrh5d04'
OWNER_ID = 7524032836
ADMIN_ID = 8285724366
YOUR_USERNAME = '@Zolvit'
TELEGRAM_LINK = 'https://t.me/Zolvit'
WEB_SECRET_KEY = secrets.token_hex(32)
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

# Enhanced credit system - PER USER
FREE_CREDITS = 2.0
CREDIT_PACKAGES = {
    '99': {'credits': 10, 'price': 99, 'name': 'Starter Pack'},
    '399': {'credits': 50, 'price': 399, 'name': 'Pro Pack'},
    '699': {'credits': 100, 'price': 699, 'name': 'Ultimate Pack'}
}

CREDIT_COSTS = {
    'file_upload': 0.5,
    'github_deploy': 1.0,
    'vps_command': 0.3,
    'backup': 0.5,
}

# Payment Gateway (UPI)
UPI_ID = "7905733737@ybl"  # Replace with your UPI ID
PAYMENT_QR_DIR = 'payment_qr'

# Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'devops_data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
DEPLOYS_DIR = os.path.join(DATA_DIR, 'deployments')
BACKUPS_DIR = os.path.join(DATA_DIR, 'backups')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
DB_PATH = os.path.join(DATA_DIR, 'devops.db')
ANALYTICS_DIR = os.path.join(DATA_DIR, 'analytics')

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, BACKUPS_DIR, LOGS_DIR, ANALYTICS_DIR, PAYMENT_QR_DIR]:
    os.makedirs(d, exist_ok=True)

# Flask & Bot
app = Flask(__name__)
app.secret_key = WEB_SECRET_KEY
CORS(app)
bot = telebot.TeleBot(TOKEN, parse_mode='Markdown')

# Global state - PER USER ISOLATION
user_credits = {}  # {user_id: credits}
active_users = set()
admin_ids = {ADMIN_ID, OWNER_ID}
active_deployments = {}  # {user_id: [deployments]}
active_processes = {}
deployment_logs = {}
user_vps = {}
user_env_vars = {}  # {user_id: {key: value}}
deployment_analytics = {}
user_sessions = {}  # {session_id: user_id}
pending_payments = {}  # {payment_id: {user_id, amount, credits, status}}
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

# ==================== 🤖 AI DEPENDENCY DETECTOR ====================

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
        'magic': 'python-magic',
        'dateutil': 'python-dateutil',
    }
    return mapping.get(import_name, import_name)

def detect_and_install_deps(project_path):
    """🤖 AI-Powered dependency detection and installation"""
    installed = []
    install_log = []
    
    logger.info(f"{Fore.CYAN}🤖 AI DEPENDENCY ANALYZER v9.0 - STARTING...")
    install_log.append("🤖 AI DEPENDENCY ANALYZER v9.0")
    install_log.append("=" * 60)
    
    # PYTHON REQUIREMENTS.TXT
    req_file = os.path.join(project_path, 'requirements.txt')
    if os.path.exists(req_file):
        logger.info(f"{Fore.CYAN}📦 Found requirements.txt")
        install_log.append("\n📦 PYTHON REQUIREMENTS.TXT DETECTED")
        try:
            with open(req_file, 'r') as f:
                packages = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if packages:
                logger.info(f"{Fore.YELLOW}⚡ Installing {len(packages)} Python packages...")
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
                
                logger.info(f"{Fore.GREEN}✅ Python packages installed")
                install_log.append("✅ Python requirements.txt processed")
        except Exception as e:
            logger.error(f"{Fore.RED}❌ requirements.txt error: {e}")
            install_log.append(f"❌ Error: {str(e)[:100]}")
    
    # SMART CODE ANALYSIS
    install_log.append("\n🧠 AI CODE ANALYSIS - Scanning project files...")
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
            install_log.append(f"\n🔍 Detected {len(all_imports)} imports from code analysis")
            install_log.append("🤖 AI auto-installing missing packages...")
            
            stdlib = {'os', 'sys', 'time', 'json', 're', 'math', 'random', 'datetime', 
                     'collections', 'itertools', 'functools', 'pathlib', 'logging', 
                     'threading', 'subprocess', 'socket', 'http', 'urllib', 'email'}
            
            third_party = all_imports - stdlib
            
            for imp in third_party:
                pkg = get_package_name(imp)
                try:
                    __import__(imp)
                    install_log.append(f"  ✓ {pkg} (already installed)")
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
    
    # NODE.JS PACKAGE.JSON
    pkg_file = os.path.join(project_path, 'package.json')
    if os.path.exists(pkg_file):
        logger.info(f"{Fore.CYAN}📦 Found package.json")
        install_log.append("\n📦 NODE.JS PACKAGE.JSON DETECTED")
        try:
            subprocess.run(['npm', '--version'], check=True, capture_output=True)
            logger.info(f"{Fore.YELLOW}⚡ Installing Node.js packages...")
            install_log.append("⚡ Running npm install...")
            
            result = subprocess.run(
                ['npm', 'install', '--silent'],
                cwd=project_path,
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode == 0:
                installed.append('npm packages')
                install_log.append("✅ Node.js packages installed successfully")
        except:
            install_log.append("⚠️  npm not available")
    
    install_log.append("\n" + "=" * 60)
    install_log.append(f"🎉 AI ANALYSIS COMPLETE")
    install_log.append(f"📦 Total Packages Installed: {len(installed)}")
    install_log.append("=" * 60)
    
    return installed, "\n".join(install_log)

# ==================== DATABASE V9 - PER USER ====================

def init_db():
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT,
            joined_date TEXT,
            last_active TEXT,
            total_deployments INTEGER DEFAULT 0,
            successful_deployments INTEGER DEFAULT 0,
            total_api_calls INTEGER DEFAULT 0,
            pro_member INTEGER DEFAULT 0
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS credits (
            user_id INTEGER PRIMARY KEY,
            balance REAL DEFAULT 0,
            total_spent REAL DEFAULT 0,
            total_earned REAL DEFAULT 0,
            last_purchase TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS deployments (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            name TEXT,
            type TEXT,
            status TEXT,
            port INTEGER,
            pid INTEGER,
            created_at TEXT,
            updated_at TEXT,
            repo_url TEXT,
            branch TEXT,
            build_cmd TEXT,
            start_cmd TEXT,
            logs TEXT,
            dependencies_installed TEXT,
            install_log TEXT,
            cpu_usage REAL DEFAULT 0,
            memory_usage REAL DEFAULT 0,
            uptime INTEGER DEFAULT 0
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS env_vars (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            deployment_id TEXT,
            key TEXT,
            value_encrypted TEXT,
            created_at TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS payments (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            amount REAL,
            credits REAL,
            status TEXT,
            payment_method TEXT,
            transaction_id TEXT,
            created_at TEXT,
            completed_at TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT
        )''')
        
        conn.commit()
        conn.close()

def load_data():
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        c.execute('SELECT user_id FROM users')
        active_users.update(row[0] for row in c.fetchall())
        
        c.execute('SELECT user_id, balance FROM credits')
        for user_id, balance in c.fetchall():
            user_credits[user_id] = balance
        
        c.execute('SELECT id, user_id, name, type, status, port, pid, repo_url, branch FROM deployments WHERE status != "deleted"')
        for dep_id, user_id, name, dep_type, status, port, pid, repo_url, branch in c.fetchall():
            if user_id not in active_deployments:
                active_deployments[user_id] = []
            active_deployments[user_id].append({
                'id': dep_id,
                'name': name,
                'type': dep_type,
                'status': status,
                'port': port,
                'pid': pid,
                'repo_url': repo_url,
                'branch': branch
            })
        
        c.execute('SELECT user_id, key, value_encrypted FROM env_vars')
        for user_id, key, value_enc in c.fetchall():
            if user_id not in user_env_vars:
                user_env_vars[user_id] = {}
            try:
                value = fernet.decrypt(value_enc.encode()).decode()
            except:
                value = value_enc
            user_env_vars[user_id][key] = value
        
        conn.close()

init_db()
load_data()

# ==================== CREDIT SYSTEM - PER USER ====================

def get_credits(user_id):
    if user_id in admin_ids:
        return float('inf')
    return user_credits.get(user_id, 0.0)

def add_credits(user_id, amount, description="Credit added"):
    if user_id in admin_ids:
        return True
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        current = get_credits(user_id)
        new_balance = current + amount
        
        c.execute('''INSERT OR REPLACE INTO credits 
                    (user_id, balance, total_earned, last_purchase) 
                    VALUES (?, ?, COALESCE((SELECT total_earned FROM credits WHERE user_id = ?), 0) + ?, ?)''',
                 (user_id, new_balance, user_id, amount, datetime.now().isoformat()))
        
        c.execute('INSERT INTO activity_log (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)',
                 (user_id, 'CREDIT_ADD', f"{amount} - {description}", datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        user_credits[user_id] = new_balance
        return True

def deduct_credits(user_id, amount, description="Credit used"):
    if user_id in admin_ids:
        return True
    
    current = get_credits(user_id)
    if current < amount:
        return False
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        new_balance = current - amount
        
        c.execute('UPDATE credits SET balance = ?, total_spent = total_spent + ? WHERE user_id = ?',
                 (new_balance, amount, user_id))
        
        c.execute('INSERT INTO activity_log (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)',
                 (user_id, 'CREDIT_USE', f"{amount} - {description}", datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        user_credits[user_id] = new_balance
        return True

def init_user_credits(user_id):
    """Give 2 free credits to new users"""
    if user_id not in user_credits and user_id not in admin_ids:
        add_credits(user_id, FREE_CREDITS, "Welcome bonus - 2 free credits")
        return True
    return False

# ==================== PAYMENT SYSTEM ====================

def generate_payment_qr(user_id, amount, package_name):
    """Generate UPI QR code for payment"""
    payment_id = str(uuid.uuid4())[:8]
    
    # UPI payment URL
    upi_url = f"upi://pay?pa={UPI_ID}&pn=DevOps Credits&am={amount}&cu=INR&tn=Credits-{payment_id}"
    
    # Generate QR
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(upi_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    qr_path = os.path.join(PAYMENT_QR_DIR, f"{payment_id}.png")
    img.save(qr_path)
    
    # Store payment info
    package = CREDIT_PACKAGES[str(amount)]
    pending_payments[payment_id] = {
        'user_id': user_id,
        'amount': amount,
        'credits': package['credits'],
        'status': 'pending',
        'created_at': datetime.now().isoformat(),
        'package_name': package_name
    }
    
    # Save to DB
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('''INSERT INTO payments 
                    (id, user_id, amount, credits, status, payment_method, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (payment_id, user_id, amount, package['credits'], 'pending', 'UPI', 
                  datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    return payment_id, qr_path

def verify_payment(payment_id, transaction_id):
    """Verify and complete payment (Manual verification for now)"""
    if payment_id not in pending_payments:
        return False, "Invalid payment ID"
    
    payment = pending_payments[payment_id]
    
    if payment['status'] == 'completed':
        return False, "Already processed"
    
    # Add credits
    user_id = payment['user_id']
    credits = payment['credits']
    
    add_credits(user_id, credits, f"Purchase: {payment['package_name']}")
    
    # Update payment status
    payment['status'] = 'completed'
    payment['transaction_id'] = transaction_id
    payment['completed_at'] = datetime.now().isoformat()
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('''UPDATE payments 
                    SET status = ?, transaction_id = ?, completed_at = ?
                    WHERE id = ?''',
                 ('completed', transaction_id, datetime.now().isoformat(), payment_id))
        conn.commit()
        conn.close()
    
    return True, f"✅ Added {credits} credits!"

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
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('''INSERT INTO deployments 
                    (id, user_id, name, type, status, port, created_at, updated_at, 
                     repo_url, branch, build_cmd, start_cmd, logs, dependencies_installed, install_log)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (deploy_id, user_id, name, deploy_type, 'pending', port,
                  datetime.now().isoformat(), datetime.now().isoformat(),
                  kwargs.get('repo_url', ''), kwargs.get('branch', 'main'),
                  kwargs.get('build_cmd', ''), kwargs.get('start_cmd', ''), '', '', ''))
        
        c.execute('UPDATE users SET total_deployments = total_deployments + 1 WHERE user_id = ?', (user_id,))
        conn.commit()
        conn.close()
    
    if user_id not in active_deployments:
        active_deployments[user_id] = []
    
    active_deployments[user_id].append({
        'id': deploy_id,
        'name': name,
        'type': deploy_type,
        'status': 'pending',
        'port': port,
        'pid': None,
        'repo_url': kwargs.get('repo_url', ''),
        'branch': kwargs.get('branch', 'main')
    })
    
    return deploy_id, port

def update_deployment(deploy_id, status=None, logs=None, pid=None, deps=None, install_log=None):
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        updates = ['updated_at = ?']
        values = [datetime.now().isoformat()]
        
        if status:
            updates.append('status = ?')
            values.append(status)
        
        if logs:
            updates.append('logs = logs || ?')
            values.append(f"\n{logs}")
            if deploy_id not in deployment_logs:
                deployment_logs[deploy_id] = []
            deployment_logs[deploy_id].append(logs)
        
        if pid:
            updates.append('pid = ?')
            values.append(pid)
        
        if deps:
            updates.append('dependencies_installed = ?')
            values.append(deps)
        
        if install_log:
            updates.append('install_log = ?')
            values.append(install_log)
        
        values.append(deploy_id)
        
        c.execute(f'UPDATE deployments SET {", ".join(updates)} WHERE id = ?', values)
        conn.commit()
        conn.close()
    
    for user_deploys in active_deployments.values():
        for deploy in user_deploys:
            if deploy['id'] == deploy_id:
                if status:
                    deploy['status'] = status
                if pid:
                    deploy['pid'] = pid
                break

def deploy_from_file(user_id, file_path, filename):
    try:
        cost = CREDIT_COSTS['file_upload']
        if not deduct_credits(user_id, cost, f"File deploy: {filename}"):
            return None, f"❌ Need {cost} credits"
        
        deploy_id, port = create_deployment(user_id, filename, 'file_upload')
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        if filename.endswith('.zip'):
            update_deployment(deploy_id, 'extracting', '📦 Extracting ZIP...')
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(deploy_dir)
            
            main_file = None
            for root, dirs, files in os.walk(deploy_dir):
                for file in files:
                    if file in ['main.py', 'app.py', 'bot.py', 'index.js']:
                        main_file = os.path.join(root, file)
                        break
                if main_file:
                    break
            
            if not main_file:
                update_deployment(deploy_id, 'failed', '❌ No entry point')
                add_credits(user_id, cost, "Refund")
                return None, "❌ No main file found"
            
            file_path = main_file
        else:
            shutil.copy(file_path, os.path.join(deploy_dir, filename))
            file_path = os.path.join(deploy_dir, filename)
        
        update_deployment(deploy_id, 'installing', '🤖 AI analyzing...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        if installed_deps:
            update_deployment(deploy_id, deps=', '.join(installed_deps), install_log=install_log)
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        if user_id in user_env_vars:
            env.update(user_env_vars[user_id])
        
        update_deployment(deploy_id, 'starting', f'🚀 Starting port {port}...')
        
        if file_path.endswith('.py'):
            process = subprocess.Popen(
                [sys.executable, file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=os.path.dirname(file_path),
                env=env
            )
        elif file_path.endswith('.js'):
            process = subprocess.Popen(
                ['node', file_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=os.path.dirname(file_path),
                env=env
            )
        else:
            update_deployment(deploy_id, 'failed', '❌ Unsupported')
            add_credits(user_id, cost, "Refund")
            return None, "❌ Unsupported type"
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, 'running', f'✅ Live on {port}!', process.pid)
        
        def log_monitor():
            for line in iter(process.stdout.readline, b''):
                if line:
                    update_deployment(deploy_id, logs=line.decode().strip())
            process.wait()
            update_deployment(deploy_id, 'completed' if process.returncode == 0 else 'failed')
        
        Thread(target=log_monitor, daemon=True).start()
        
        return deploy_id, f"🎉 Deployed! Port {port}"
    
    except Exception as e:
        logger.error(f"Deploy error: {e}")
        if 'deploy_id' in locals():
            update_deployment(deploy_id, 'failed', str(e))
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
                                           build_cmd=build_cmd, start_cmd=start_cmd)
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        update_deployment(deploy_id, 'cloning', f'🔄 Cloning...')
        
        clone_cmd = ['git', 'clone', '-b', branch, '--depth', '1', repo_url, deploy_dir]
        result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0:
            update_deployment(deploy_id, 'failed', f'❌ Clone failed')
            add_credits(user_id, cost, "Refund")
            return None, "❌ Clone failed"
        
        update_deployment(deploy_id, 'installing', '🤖 AI analyzing...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        if installed_deps:
            update_deployment(deploy_id, deps=', '.join(installed_deps), install_log=install_log)
        
        if build_cmd:
            update_deployment(deploy_id, 'building', f'🔨 Building...')
            subprocess.run(build_cmd, shell=True, cwd=deploy_dir, timeout=600)
        
        if not start_cmd:
            main_files = {
                'main.py': f'{sys.executable} main.py',
                'app.py': f'{sys.executable} app.py',
                'bot.py': f'{sys.executable} bot.py',
                'index.js': 'node index.js',
                'package.json': 'npm start'
            }
            
            start_cmd = None
            for file, cmd in main_files.items():
                if os.path.exists(os.path.join(deploy_dir, file)):
                    start_cmd = cmd
                    break
            
            if not start_cmd:
                update_deployment(deploy_id, 'failed', '❌ No start cmd')
                add_credits(user_id, cost, "Refund")
                return None, "❌ No start command"
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        if user_id in user_env_vars:
            env.update(user_env_vars[user_id])
        
        update_deployment(deploy_id, 'starting', f'🚀 Starting...')
        
        process = subprocess.Popen(
            start_cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=deploy_dir,
            env=env
        )
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, 'running', f'✅ Live {port}!', process.pid)
        
        def log_monitor():
            for line in iter(process.stdout.readline, b''):
                if line:
                    update_deployment(deploy_id, logs=line.decode().strip())
            process.wait()
            update_deployment(deploy_id, 'completed' if process.returncode == 0 else 'failed')
        
        Thread(target=log_monitor, daemon=True).start()
        
        return deploy_id, f"🎉 Deployed! Port {port}"
    
    except Exception as e:
        logger.error(f"GitHub error: {e}")
        if 'deploy_id' in locals():
            update_deployment(deploy_id, 'failed', str(e))
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
            update_deployment(deploy_id, 'stopped', '🛑 Stopped')
            return True, "Stopped"
        return False, "Not running"
    except Exception as e:
        return False, str(e)

def get_deployment_logs(deploy_id):
    if deploy_id in deployment_logs:
        return "\n".join(deployment_logs[deploy_id][-300:])
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT logs, install_log FROM deployments WHERE id = ?', (deploy_id,))
        result = c.fetchone()
        conn.close()
        
        if result:
            logs = result[0] or ""
            install = result[1] or ""
            return f"{install}\n\n=== Runtime ===\n{logs}" if install else logs or "No logs"
        return "Not found"

# ==================== ENHANCED WEB DASHBOARD WITH PAYMENT ====================

ENHANCED_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevOps Pro v9.0</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --primary: #6366f1;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
        }
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding-bottom: 70px;
        }
        .header {
            background: rgba(255,255,255,0.98);
            backdrop-filter: blur(20px);
            padding: 12px 16px;
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }
        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .logo {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .logo-icon {
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, var(--primary), #ec4899);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 18px;
        }
        .logo-text h1 {
            font-size: 15px;
            font-weight: 800;
            color: #0f172a;
        }
        .credit-badge {
            background: linear-gradient(135deg, rgba(99,102,241,0.1), rgba(236,72,153,0.1));
            border: 1px solid rgba(99,102,241,0.2);
            padding: 6px 12px;
            border-radius: 20px;
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            font-weight: 700;
            color: var(--primary);
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 16px;
        }
        .tab-nav {
            background: white;
            border-radius: 14px;
            padding: 5px;
            margin-bottom: 16px;
            display: flex;
            gap: 4px;
            overflow-x: auto;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }
        .tab-btn {
            flex: 1;
            min-width: 70px;
            padding: 8px 12px;
            border: none;
            background: transparent;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 700;
            color: #6b7280;
            cursor: pointer;
            transition: all 0.3s;
        }
        .tab-btn.active {
            background: linear-gradient(135deg, var(--primary), #4f46e5);
            color: white;
            box-shadow: 0 2px 8px rgba(99,102,241,0.3);
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .card {
            background: white;
            border-radius: 16px;
            padding: 18px;
            margin-bottom: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
            padding-bottom: 10px;
            border-bottom: 1px solid #f3f4f6;
        }
        .card-title {
            font-size: 15px;
            font-weight: 800;
            color: #0f172a;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .upload-zone {
            border: 2px dashed var(--primary);
            border-radius: 14px;
            padding: 30px 16px;
            text-align: center;
            background: linear-gradient(135deg, rgba(99,102,241,0.03), rgba(236,72,153,0.03));
            cursor: pointer;
        }
        .upload-icon {
            font-size: 36px;
            background: linear-gradient(135deg, var(--primary), #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 12px;
        }
        .btn {
            background: linear-gradient(135deg, var(--primary), #4f46e5);
            color: white;
            border: none;
            padding: 12px 18px;
            border-radius: 10px;
            font-size: 12px;
            font-weight: 700;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            cursor: pointer;
            box-shadow: 0 2px 8px rgba(99,102,241,0.3);
        }
        .input-group {
            margin-bottom: 14px;
        }
        .input-label {
            display: block;
            margin-bottom: 6px;
            font-weight: 700;
            color: #0f172a;
            font-size: 11px;
            text-transform: uppercase;
        }
        .input-field {
            width: 100%;
            padding: 10px 12px;
            border: 1.5px solid #e5e7eb;
            border-radius: 10px;
            font-size: 13px;
            font-family: inherit;
        }
        .input-field:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99,102,241,0.1);
        }
        .deploy-item {
            background: #ffffff;
            border-radius: 14px;
            padding: 14px;
            margin-bottom: 10px;
            border: 1px solid #f3f4f6;
        }
        .status-badge {
            padding: 4px 8px;
            border-radius: 10px;
            font-size: 9px;
            font-weight: 800;
            text-transform: uppercase;
        }
        .status-running { background: #d1fae5; color: #065f46; }
        .status-pending { background: #fef3c7; color: #92400e; }
        .status-stopped { background: #fee2e2; color: #991b1b; }
        .action-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 6px;
            margin-top: 10px;
        }
        .action-btn {
            padding: 7px;
            border: none;
            border-radius: 8px;
            font-size: 10px;
            font-weight: 700;
            color: white;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 3px;
        }
        .pricing-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-top: 16px;
        }
        .price-card {
            background: white;
            border-radius: 16px;
            padding: 24px;
            text-align: center;
            border: 2px solid #e5e7eb;
            transition: all 0.3s;
        }
        .price-card:hover {
            border-color: var(--primary);
            transform: translateY(-4px);
            box-shadow: 0 8px 24px rgba(99,102,241,0.2);
        }
        .price-card.popular {
            border-color: var(--primary);
            position: relative;
            box-shadow: 0 4px 16px rgba(99,102,241,0.15);
        }
        .popular-badge {
            position: absolute;
            top: -10px;
            right: 20px;
            background: linear-gradient(135deg, var(--primary), #ec4899);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 10px;
            font-weight: 800;
        }
        .price-amount {
            font-size: 36px;
            font-weight: 900;
            background: linear-gradient(135deg, var(--primary), #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 16px 0;
        }
        .price-credits {
            font-size: 18px;
            font-weight: 700;
            color: #6b7280;
            margin-bottom: 20px;
        }
        .toast {
            position: fixed;
            top: 70px;
            left: 50%;
            transform: translateX(-50%) translateY(-100px);
            background: white;
            padding: 12px 18px;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            display: flex;
            align-items: center;
            gap: 8px;
            z-index: 9999;
            transition: all 0.4s;
        }
        .toast.show {
            transform: translateX(-50%) translateY(0);
        }
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            backdrop-filter: blur(4px);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 10000;
            padding: 20px;
        }
        .modal.show {
            display: flex;
        }
        .modal-content {
            background: white;
            border-radius: 18px;
            padding: 22px;
            max-width: 500px;
            width: 100%;
            max-height: 80vh;
            overflow-y: auto;
        }
        .qr-container {
            text-align: center;
            padding: 20px;
        }
        .qr-code {
            max-width: 300px;
            margin: 20px auto;
        }
        .bottom-nav {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(255,255,255,0.98);
            backdrop-filter: blur(20px);
            display: flex;
            justify-content: space-around;
            padding: 8px 0;
            box-shadow: 0 -2px 10px rgba(0,0,0,0.05);
            z-index: 999;
        }
        .nav-item {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 3px;
            color: #9ca3af;
            font-size: 10px;
            font-weight: 700;
            cursor: pointer;
            padding: 6px;
        }
        .nav-item.active {
            color: var(--primary);
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">
                <div class="logo-icon"><i class="fas fa-rocket"></i></div>
                <div class="logo-text"><h1> naroxbot </h1></div>
            </div>
            <div class="credit-badge">
                <i class="fas fa-gem"></i>
                <span id="creditBalance">{{ credits }}</span>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="tab-nav">
            <button class="tab-btn active" onclick="showTab('deploy')">
                <i class="fas fa-rocket"></i> Deploy
            </button>
            <button class="tab-btn" onclick="showTab('apps')">
                <i class="fas fa-list"></i> Apps
            </button>
            <button class="tab-btn" onclick="showTab('github')">
                <i class="fab fa-github"></i> GitHub
            </button>
            <button class="tab-btn" onclick="showTab('env')">
                <i class="fas fa-key"></i> ENV
            </button>
            <button class="tab-btn" onclick="showTab('credits')">
                <i class="fas fa-shopping-cart"></i> Buy
            </button>
        </div>
        
        <div id="deploy-tab" class="tab-content active">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-cloud-upload-alt"></i> Smart Deploy</h3>
                </div>
                <div class="upload-zone" onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon"><i class="fas fa-cloud-upload-alt"></i></div>
                    <div style="font-size: 14px; font-weight: 800; margin-bottom: 4px;">Tap to Upload</div>
                    <div style="color: #6b7280; font-size: 11px;">Python • JavaScript • ZIP</div>
                    <input type="file" id="fileInput" hidden accept=".py,.js,.zip" onchange="handleFileUpload(this)">
                </div>
            </div>
        </div>
        
        <div id="apps-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-server"></i> Your Apps</h3>
                    <button onclick="loadDeployments()" style="background: transparent; border: none; cursor: pointer;">
                        <i class="fas fa-sync"></i>
                    </button>
                </div>
                <div id="deploymentsList"></div>
            </div>
        </div>
        
        <div id="github-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fab fa-github"></i> GitHub Deploy</h3>
                </div>
                <div class="input-group">
                    <label class="input-label">Repository URL</label>
                    <input type="url" class="input-field" id="repoUrl" placeholder="https://github.com/user/repo.git">
                </div>
                <div class="input-group">
                    <label class="input-label">Branch</label>
                    <input type="text" class="input-field" id="repoBranch" value="main">
                </div>
                <button class="btn" onclick="deployGithub()">
                    <i class="fab fa-github"></i> Deploy Now
                </button>
            </div>
        </div>
        
        <div id="env-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-lock"></i> Environment</h3>
                    <button onclick="showAddEnv()" style="background: transparent; border: none; cursor: pointer;">
                        <i class="fas fa-plus"></i>
                    </button>
                </div>
                <div id="envList"></div>
            </div>
        </div>
        
        <div id="credits-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title"><i class="fas fa-shopping-cart"></i> Buy Credits</h3>
                </div>
                <div class="pricing-grid">
                    <div class="price-card">
                        <h3 style="font-weight: 800; margin-bottom: 8px;">Starter</h3>
                        <div class="price-amount">₹99</div>
                        <div class="price-credits">10 Credits</div>
                        <button class="btn" onclick="buyCredits(99)">
                            <i class="fas fa-shopping-cart"></i> Buy Now
                        </button>
                    </div>
                    <div class="price-card popular">
                        <div class="popular-badge">POPULAR</div>
                        <h3 style="font-weight: 800; margin-bottom: 8px;">Pro</h3>
                        <div class="price-amount">₹399</div>
                        <div class="price-credits">50 Credits</div>
                        <button class="btn" onclick="buyCredits(399)">
                            <i class="fas fa-shopping-cart"></i> Buy Now
                        </button>
                    </div>
                    <div class="price-card">
                        <h3 style="font-weight: 800; margin-bottom: 8px;">Ultimate</h3>
                        <div class="price-amount">₹699</div>
                        <div class="price-credits">100 Credits</div>
                        <button class="btn" onclick="buyCredits(699)">
                            <i class="fas fa-shopping-cart"></i> Buy Now
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="bottom-nav">
        <div class="nav-item active" onclick="showTab('deploy')">
            <i class="fas fa-rocket"></i>
            <span>Deploy</span>
        </div>
        <div class="nav-item" onclick="showTab('apps')">
            <i class="fas fa-list"></i>
            <span>Apps</span>
        </div>
        <div class="nav-item" onclick="showTab('github')">
            <i class="fab fa-github"></i>
            <span>GitHub</span>
        </div>
        <div class="nav-item" onclick="showTab('credits')">
            <i class="fas fa-shopping-cart"></i>
            <span>Buy</span>
        </div>
    </div>
    
    <div id="toast" class="toast"></div>
    <div id="modal" class="modal"></div>

    <script>
        function showTab(tab) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.getElementById(tab + '-tab').classList.add('active');
            document.querySelectorAll('.tab-btn, .nav-item').forEach(b => b.classList.remove('active'));
            event.target.closest('.tab-btn, .nav-item')?.classList.add('active');
            if (tab === 'apps') loadDeployments();
            if (tab === 'env') loadEnv();
        }
        
        async function handleFileUpload(input) {
            const file = input.files[0];
            if (!file) return;
            const formData = new FormData();
            formData.append('file', file);
            showToast('🤖 AI analyzing...', 'info');
            try {
                const res = await fetch('/api/deploy/upload', {method: 'POST', body: formData});
                const data = await res.json();
                if (data.success) {
                    showToast('✅ ' + data.message, 'success');
                    setTimeout(() => {
                        updateCredits();
                        loadDeployments();
                        showTab('apps');
                    }, 1500);
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Deploy failed', 'error');
            }
            input.value = '';
        }
        
        async function deployGithub() {
            const url = document.getElementById('repoUrl').value;
            const branch = document.getElementById('repoBranch').value;
            if (!url) return showToast('⚠️ Enter repo URL', 'warning');
            showToast('🤖 AI cloning...', 'info');
            try {
                const res = await fetch('/api/deploy/github', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url, branch})
                });
                const data = await res.json();
                if (data.success) {
                    showToast('✅ ' + data.message, 'success');
                    document.getElementById('repoUrl').value = '';
                    setTimeout(() => {
                        updateCredits();
                        loadDeployments();
                        showTab('apps');
                    }, 1500);
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Deploy failed', 'error');
            }
        }
        
        async function loadDeployments() {
            try {
                const res = await fetch('/api/deployments');
                const data = await res.json();
                const list = document.getElementById('deploymentsList');
                if (!data.deployments || !data.deployments.length) {
                    list.innerHTML = '<div style="text-align:center;padding:40px;color:#9ca3af;">No deployments yet</div>';
                    return;
                }
                list.innerHTML = data.deployments.map(d => `
                    <div class="deploy-item">
                        <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
                            <div>
                                <div style="font-weight:800;font-size:13px;">${d.name}</div>
                                <div style="color:#9ca3af;font-size:10px;">ID: ${d.id} • Port: ${d.port || 'N/A'}</div>
                            </div>
                            <span class="status-badge status-${d.status}">${d.status}</span>
                        </div>
                        <div class="action-grid">
                            <button class="action-btn" style="background:#3b82f6;" onclick="viewLogs('${d.id}')">
                                <i class="fas fa-terminal"></i> Logs
                            </button>
                            ${d.status === 'running' ? `
                                <button class="action-btn" style="background:#ef4444;" onclick="stopDeploy('${d.id}')">
                                    <i class="fas fa-stop"></i> Stop
                                </button>
                            ` : ''}
                            <button class="action-btn" style="background:#f59e0b;" onclick="deleteDeploy('${d.id}')">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        </div>
                    </div>
                `).join('');
            } catch (err) {
                console.error(err);
            }
        }
        
        async function viewLogs(deployId) {
            try {
                const res = await fetch('/api/deployment/' + deployId + '/logs');
                const data = await res.json();
                showModal(`
                    <h3 style="font-weight:800;margin-bottom:16px;"><i class="fas fa-terminal"></i> Logs</h3>
                    <div style="background:#1f2937;color:#10b981;font-family:monospace;font-size:11px;padding:12px;border-radius:10px;max-height:400px;overflow-y:auto;white-space:pre-wrap;">${data.logs || 'No logs'}</div>
                    <button class="btn" onclick="closeModal()" style="margin-top:14px;background:#ef4444;">
                        <i class="fas fa-times"></i> Close
                    </button>
                `);
            } catch (err) {
                showToast('❌ Failed to load logs', 'error');
            }
        }
        
        async function stopDeploy(deployId) {
            if (!confirm('Stop this deployment?')) return;
            try {
                const res = await fetch('/api/deployment/' + deployId + '/stop', {method: 'POST'});
                const data = await res.json();
                if (data.success) {
                    showToast('✅ Stopped', 'success');
                    loadDeployments();
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Stop failed', 'error');
            }
        }
        
        async function deleteDeploy(deployId) {
            if (!confirm('Delete permanently?')) return;
            try {
                const res = await fetch('/api/deployment/' + deployId, {method: 'DELETE'});
                const data = await res.json();
                if (data.success) {
                    showToast('✅ Deleted', 'success');
                    loadDeployments();
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Delete failed', 'error');
            }
        }
        
        function showAddEnv() {
            showModal(`
                <h3 style="font-weight:800;margin-bottom:16px;"><i class="fas fa-plus"></i> Add Variable</h3>
                <div class="input-group">
                    <label class="input-label">Variable Name</label>
                    <input type="text" class="input-field" id="envKey" placeholder="API_KEY">
                </div>
                <div class="input-group">
                    <label class="input-label">Variable Value</label>
                    <input type="text" class="input-field" id="envValue" placeholder="your_secret_value">
                </div>
                <button class="btn" onclick="addEnv()" style="background:#10b981;">
                    <i class="fas fa-save"></i> Add Variable
                </button>
                <button class="btn" onclick="closeModal()" style="margin-top:8px;background:#ef4444;">
                    <i class="fas fa-times"></i> Cancel
                </button>
            `);
        }
        
        async function addEnv() {
            const key = document.getElementById('envKey').value;
            const value = document.getElementById('envValue').value;
            if (!key || !value) return showToast('⚠️ Fill all fields', 'warning');
            try {
                const res = await fetch('/api/env/add', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key, value})
                });
                const data = await res.json();
                if (data.success) {
                    showToast('✅ Added', 'success');
                    closeModal();
                    loadEnv();
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Failed', 'error');
            }
        }
        
        async function loadEnv() {
            try {
                const res = await fetch('/api/env/list');
                const data = await res.json();
                const list = document.getElementById('envList');
                if (!data.variables || !Object.keys(data.variables).length) {
                    list.innerHTML = '<div style="text-align:center;padding:40px;color:#9ca3af;">No variables</div>';
                    return;
                }
                list.innerHTML = Object.entries(data.variables).map(([key, value]) => `
                    <div class="deploy-item">
                        <div style="display:flex;justify-content:space-between;align-items:center;">
                            <div style="flex:1;min-width:0;">
                                <div style="font-weight:800;font-size:13px;">${key}</div>
                                <p style="color:#9ca3af;font-size:11px;margin-top:4px;overflow:hidden;text-overflow:ellipsis;font-family:monospace;">
                                    ${value.substring(0, 30)}${value.length > 30 ? '...' : ''}
                                </p>
                            </div>
                            <button onclick="deleteEnv('${key}')" style="background:#fee2e2;color:#ef4444;border:none;padding:8px;border-radius:8px;cursor:pointer;">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    </div>
                `).join('');
            } catch (err) {
                console.error(err);
            }
        }
        
        async function deleteEnv(key) {
            if (!confirm('Delete "' + key + '"?')) return;
            try {
                const res = await fetch('/api/env/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key})
                });
                const data = await res.json();
                if (data.success) {
                    showToast('✅ Deleted', 'success');
                    loadEnv();
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Failed', 'error');
            }
        }
        
        async function buyCredits(amount) {
            try {
                const res = await fetch('/api/payment/create', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({amount})
                });
                const data = await res.json();
                if (data.success) {
                    showModal(`
                        <div class="qr-container">
                            <h3 style="font-weight:800;margin-bottom:16px;">
                                <i class="fas fa-qrcode"></i> Scan to Pay
                            </h3>
                            <p style="color:#6b7280;margin-bottom:20px;">Payment ID: <strong>${data.payment_id}</strong></p>
                            <img src="${data.qr_url}" class="qr-code" alt="QR Code">
                            <div style="background:#f3f4f6;padding:16px;border-radius:10px;margin:20px 0;">
                                <p style="font-weight:700;margin-bottom:8px;">Amount: ₹${amount}</p>
                                <p style="font-weight:700;color:#10b981;">Credits: ${data.credits}</p>
                            </div>
                            <p style="color:#6b7280;font-size:12px;margin-bottom:16px;">
                                Scan QR or pay to UPI: <strong>${data.upi_id}</strong><br>
                                After payment, send screenshot to <a href="${data.telegram_link}" target="_blank">${data.telegram_username}</a>
                            </p>
                            <button class="btn" onclick="closeModal()">
                                <i class="fas fa-times"></i> Close
                            </button>
                        </div>
                    `);
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Failed to create payment', 'error');
            }
        }
        
        async function updateCredits() {
            try {
                const res = await fetch('/api/credits');
                const data = await res.json();
                document.getElementById('creditBalance').textContent = 
                    data.credits === Infinity ? '∞' : data.credits.toFixed(1);
            } catch (err) {
                console.error(err);
            }
        }
        
        function showModal(html) {
            const modal = document.getElementById('modal');
            modal.innerHTML = `<div class="modal-content">${html}</div>`;
            modal.classList.add('show');
        }
        
        function closeModal() {
            document.getElementById('modal').classList.remove('show');
        }
        
        function showToast(msg, type = 'info') {
            const toast = document.getElementById('toast');
            const icons = {
                info: '<i class="fas fa-info-circle" style="color:#3b82f6;"></i>',
                success: '<i class="fas fa-check-circle" style="color:#10b981;"></i>',
                warning: '<i class="fas fa-exclamation-triangle" style="color:#f59e0b;"></i>',
                error: '<i class="fas fa-times-circle" style="color:#ef4444;"></i>'
            };
            toast.innerHTML = (icons[type] || icons.info) + `<div style="font-size:12px;font-weight:600;">${msg}</div>`;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 3500);
        }
        
        setInterval(updateCredits, 15000);
        loadDeployments();
        
        document.getElementById('modal').addEventListener('click', (e) => {
            if (e.target.id === 'modal') closeModal();
        });
    </script>
</body>
</html>
"""

# ==================== FLASK ROUTES ====================

@app.route('/')
def index():
    user_id = session.get('user_id', 999999)
    session['user_id'] = user_id
    
    if user_id not in user_credits and user_id not in admin_ids:
        init_user_credits(user_id)
    
    credits = get_credits(user_id)
    
    return render_template_string(
        ENHANCED_DASHBOARD,
        credits=f"{credits:.1f}" if credits != float('inf') else "∞"
    )

@app.route('/api/credits')
def api_credits():
    user_id = session.get('user_id', 999999)
    return jsonify({'success': True, 'credits': get_credits(user_id)})

@app.route('/api/deploy/upload', methods=['POST'])
def api_deploy_upload():
    user_id = session.get('user_id', 999999)
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'})
    
    file = request.files['file']
    if not file.filename:
        return jsonify({'success': False, 'error': 'Empty filename'})
    
    try:
        user_dir = os.path.join(UPLOADS_DIR, str(user_id))
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
    user_id = session.get('user_id', 999999)
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

@app.route('/api/deployments')
def api_deployments():
    user_id = session.get('user_id', 999999)
    deployments = active_deployments.get(user_id, [])
    return jsonify({'success': True, 'deployments': deployments})

@app.route('/api/deployment/<deploy_id>/logs')
def api_deployment_logs(deploy_id):
    logs = get_deployment_logs(deploy_id)
    return jsonify({'success': True, 'logs': logs})

@app.route('/api/deployment/<deploy_id>/stop', methods=['POST'])
def api_stop_deployment(deploy_id):
    success, msg = stop_deployment(deploy_id)
    return jsonify({'success': success, 'message': msg})

@app.route('/api/deployment/<deploy_id>', methods=['DELETE'])
def api_delete_deployment(deploy_id):
    try:
        stop_deployment(deploy_id)
        
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('UPDATE deployments SET status = ? WHERE id = ?', ('deleted', deploy_id))
            conn.commit()
            conn.close()
        
        user_id = session.get('user_id', 999999)
        if user_id in active_deployments:
            active_deployments[user_id] = [d for d in active_deployments[user_id] if d['id'] != deploy_id]
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/env/add', methods=['POST'])
def api_add_env():
    user_id = session.get('user_id', 999999)
    data = request.get_json()
    
    key = data.get('key')
    value = data.get('value')
    
    if not key or not value:
        return jsonify({'success': False, 'error': 'Missing key or value'})
    
    try:
        env_id = str(uuid.uuid4())[:8]
        value_encrypted = fernet.encrypt(value.encode()).decode()
        
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO env_vars 
                        (id, user_id, key, value_encrypted, created_at)
                        VALUES (?, ?, ?, ?, ?)''',
                     (env_id, user_id, key, value_encrypted, datetime.now().isoformat()))
            conn.commit()
            conn.close()
        
        if user_id not in user_env_vars:
            user_env_vars[user_id] = {}
        user_env_vars[user_id][key] = value
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/env/list')
def api_list_env():
    user_id = session.get('user_id', 999999)
    variables = user_env_vars.get(user_id, {})
    return jsonify({'success': True, 'variables': variables})

@app.route('/api/env/delete', methods=['POST'])
def api_delete_env():
    user_id = session.get('user_id', 999999)
    data = request.get_json()
    key = data.get('key')
    
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('DELETE FROM env_vars WHERE user_id = ? AND key = ?', (user_id, key))
            conn.commit()
            conn.close()
        
        if user_id in user_env_vars and key in user_env_vars[user_id]:
            del user_env_vars[user_id][key]
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/payment/create', methods=['POST'])
def api_create_payment():
    user_id = session.get('user_id', 999999)
    data = request.get_json()
    amount = data.get('amount')
    
    if str(amount) not in CREDIT_PACKAGES:
        return jsonify({'success': False, 'error': 'Invalid package'})
    
    package = CREDIT_PACKAGES[str(amount)]
    payment_id, qr_path = generate_payment_qr(user_id, amount, package['name'])
    
    return jsonify({
        'success': True,
        'payment_id': payment_id,
        'qr_url': f'/payment/qr/{payment_id}',
        'upi_id': UPI_ID,
        'credits': package['credits'],
        'telegram_link': TELEGRAM_LINK,
        'telegram_username': YOUR_USERNAME
    })

@app.route('/payment/qr/<payment_id>')
def payment_qr(payment_id):
    qr_path = os.path.join(PAYMENT_QR_DIR, f"{payment_id}.png")
    if os.path.exists(qr_path):
        return send_file(qr_path, mimetype='image/png')
    return "QR not found", 404

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

def keep_alive():
    t = Thread(target=run_flask, daemon=True)
    t.start()
    logger.info(f"{Fore.GREEN}✅ Web Dashboard: http://localhost:{os.environ.get('PORT', 8080)}")

# ==================== TELEGRAM BOT - FULL INTEGRATION ====================

def create_main_menu(user_id):
    markup = types.InlineKeyboardMarkup(row_width=2)
    credits = get_credits(user_id)
    credit_text = "∞" if credits == float('inf') else f"{credits:.1f}"
    
    markup.add(types.InlineKeyboardButton(f'💎 {credit_text} Credits', callback_data='credits'))
    markup.add(
        types.InlineKeyboardButton('🚀 Deploy File', callback_data='deploy_file'),
        types.InlineKeyboardButton('📊 My Apps', callback_data='my_apps')
    )
    markup.add(
        types.InlineKeyboardButton('🔑 ENV Vars', callback_data='env_vars'),
        types.InlineKeyboardButton('🌐 Dashboard', callback_data='dashboard')
    )
    markup.add(
        types.InlineKeyboardButton('💰 Buy Credits', callback_data='buy_credits')
    )
    
    if user_id in admin_ids:
        markup.add(types.InlineKeyboardButton('👑 Admin', callback_data='admin'))
    
    return markup

@bot.message_handler(commands=['start'])
def start_cmd(message):
    user_id = message.from_user.id
    username = message.from_user.username
    first_name = message.from_user.first_name
    
    if user_id not in active_users:
        active_users.add(user_id)
        
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO users 
                        (user_id, username, first_name, joined_date, last_active, total_deployments, successful_deployments, total_api_calls, pro_member)
                        VALUES (?, ?, ?, ?, ?, 0, 0, 0, 0)''',
                     (user_id, username, first_name, 
                      datetime.now().isoformat(), datetime.now().isoformat()))
            conn.commit()
            conn.close()
        
        if init_user_credits(user_id):
            bot.send_message(user_id, 
                f"🎉 *Welcome Bonus!*\n\n"
                f"You received *{FREE_CREDITS} FREE credits*!\n\n"
                f"✨ _Your credits are separate from others_")
    
    credits = get_credits(user_id)
    
    bot.send_message(
        message.chat.id,
        f"🚀 * @narzoxbot PRO EDITION*\n\n"
        f"👤 *{first_name}*\n"
        f"💎 Credits: *{credits if credits != float('inf') else '∞'}*\n\n"
        f"*🆕 WHAT'S NEW:*\n\n"
        f"✅ *Per-User Credits* - Your balance is yours!\n"
        f"✅ *Buy Credits* - ₹99/399/699 packages\n"
        f"✅ *Bot + Web Sync* - Fully integrated\n"
        f"✅ *AI Auto-Install* - Zero config needed\n"
        f"✅ *Direct Deploy* - Send files here!\n\n"
        f"📤 *Send any .py, .js or .zip file to deploy!*\n"
        f"🌐 *Or use web dashboard for more features*",
        reply_markup=create_main_menu(user_id)
    )

@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    user_id = call.from_user.id
    
    try:
        if call.data == 'dashboard':
            port = os.environ.get('PORT', 8080)
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                f"📱 *Web Dashboard*\n\n"
                f"🔗 `http://localhost:{port}`\n\n"
                f"*Features:*\n"
                f"• Upload & deploy files\n"
                f"• GitHub integration\n"
                f"• Manage deployments\n"
                f"• ENV variables\n"
                f"• Buy credits with UPI\n"
                f"• Real-time monitoring")
        
        elif call.data == 'my_apps':
            deploys = active_deployments.get(user_id, [])
            if not deploys:
                bot.answer_callback_query(call.id)
                bot.send_message(call.message.chat.id, 
                    "📊 *No Deployments*\n\n"
                    "Send a file or use dashboard to deploy!")
            else:
                running = sum(1 for d in deploys if d['status'] == 'running')
                
                status_text = f"📊 *Your Apps*\n\n"
                status_text += f"📦 Total: *{len(deploys)}*\n"
                status_text += f"🟢 Running: *{running}*\n\n"
                
                for d in deploys[-5:]:
                    emoji = {'running': '🟢', 'pending': '🟡', 'stopped': '🔴'}
                    status_text += f"{emoji.get(d['status'], '⚪')} `{d['name'][:20]}` - _{d['status']}_\n"
                
                bot.answer_callback_query(call.id)
                bot.send_message(call.message.chat.id, status_text)
        
        elif call.data == 'credits':
            credits = get_credits(user_id)
            
            with DB_LOCK:
                conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                c = conn.cursor()
                c.execute('SELECT total_spent, total_earned FROM credits WHERE user_id = ?', (user_id,))
                result = c.fetchone()
                conn.close()
            
            spent = result[0] if result else 0
            earned = result[1] if result else FREE_CREDITS
            
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                f"💎 *Your Credits*\n\n"
                f"💰 Balance: *{credits if credits != float('inf') else '∞'}*\n"
                f"📈 Earned: *{earned}*\n"
                f"📉 Spent: *{spent}*\n\n"
                f"_Your credits are separate from other users!_")
        
        elif call.data == 'buy_credits':
            markup = types.InlineKeyboardMarkup()
            markup.add(
                types.InlineKeyboardButton('₹99 → 10 Credits', callback_data='buy_99'),
                types.InlineKeyboardButton('₹399 → 50 Credits ⭐', callback_data='buy_399')
            )
            markup.add(
                types.InlineKeyboardButton('₹699 → 100 Credits 🔥', callback_data='buy_699')
            )
            markup.add(types.InlineKeyboardButton('◀️ Back', callback_data='back_menu'))
            
            bot.answer_callback_query(call.id)
            bot.edit_message_text(
                f"💰 *Buy Credits*\n\n"
                f"*Choose a package:*\n\n"
                f"🥉 Starter: ₹99 = 10 credits\n"
                f"🥈 Pro: ₹399 = 50 credits\n"
                f"🥇 Ultimate: ₹699 = 100 credits\n\n"
                f"_Payment via UPI - Instant activation!_",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=markup
            )
        
        elif call.data.startswith('buy_'):
            amount = call.data.split('_')[1]
            package = CREDIT_PACKAGES[amount]
            
            payment_id, qr_path = generate_payment_qr(user_id, int(amount), package['name'])
            
            bot.answer_callback_query(call.id)
            
            with open(qr_path, 'rb') as qr_file:
                bot.send_photo(
                    call.message.chat.id,
                    qr_file,
                    caption=f"💳 *Payment Details*\n\n"
                            f"📦 Package: *{package['name']}*\n"
                            f"💰 Amount: *₹{amount}*\n"
                            f"💎 Credits: *{package['credits']}*\n\n"
                            f"🔑 Payment ID: `{payment_id}`\n\n"
                            f"*Scan QR or pay to:*\n"
                            f"UPI: `{UPI_ID}`\n\n"
                            f"📸 *After payment, send screenshot to {YOUR_USERNAME}*\n\n"
                            f"_Credits added within 5 minutes!_"
                )
        
        elif call.data == 'env_vars':
            env_vars = user_env_vars.get(user_id, {})
            
            text = f"🔑 *Environment Variables*\n\n"
            if env_vars:
                text += f"📝 You have *{len(env_vars)}* variables:\n\n"
                for key in list(env_vars.keys())[:5]:
                    text += f"• `{key}`\n"
                if len(env_vars) > 5:
                    text += f"\n_...and {len(env_vars) - 5} more_\n"
                text += f"\n_Use dashboard to manage variables_"
            else:
                text += "No variables set yet.\n\n_Use dashboard to add variables_"
            
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, text)
        
        elif call.data == 'deploy_file':
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                "📤 *Deploy File*\n\n"
                "Send me any of these:\n\n"
                "• Python file (.py)\n"
                "• JavaScript file (.js)\n"
                "• ZIP archive (.zip)\n\n"
                "🤖 *AI will auto-install dependencies!*")
        
        elif call.data == 'back_menu':
            bot.answer_callback_query(call.id)
            bot.edit_message_text(
                "🚀 *Main Menu*\n\nChoose an option:",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=create_main_menu(user_id)
            )
        
        else:
            bot.answer_callback_query(call.id, "Use dashboard for full features!")
    
    except Exception as e:
        logger.error(f"Callback error: {e}")
        bot.answer_callback_query(call.id, "Error")

@bot.message_handler(content_types=['document'])
def handle_document(message):
    user_id = message.from_user.id
    
    try:
        file_info = bot.get_file(message.document.file_id)
        filename = message.document.file_name
        
        if not filename.endswith(('.py', '.js', '.zip')):
            bot.reply_to(message, "❌ *Unsupported*\n\nUse: `.py`, `.js`, `.zip`")
            return
        
        file_content = bot.download_file(file_info.file_path)
        user_dir = os.path.join(UPLOADS_DIR, str(user_id))
        os.makedirs(user_dir, exist_ok=True)
        filepath = os.path.join(user_dir, secure_filename(filename))
        
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        msg = bot.reply_to(message, "🤖 *AI Analyzing...*\n\nPlease wait...")
        deploy_id, result = deploy_from_file(user_id, filepath, filename)
        
        if deploy_id:
            bot.edit_message_text(
                f"✅ *Deployed Successfully!*\n\n"
                f"🆔 ID: `{deploy_id}`\n"
                f"📦 AI auto-installed dependencies\n\n"
                f"{result}\n\n"
                f"💎 Credits: *{get_credits(user_id):.1f}*\n\n"
                f"_View in dashboard for more details!_",
                message.chat.id,
                msg.message_id
            )
        else:
            bot.edit_message_text(
                f"❌ *Deploy Failed*\n\n{result}",
                message.chat.id,
                msg.message_id
            )
    
    except Exception as e:
        logger.error(f"File error: {e}")
        bot.reply_to(message, f"❌ *Error:* {e}")

@bot.message_handler(func=lambda message: message.text and message.text.startswith('https://github.com'))
def handle_github_link(message):
    """Deploy directly from GitHub URL sent in chat"""
    user_id = message.from_user.id
    repo_url = message.text.strip()
    
    try:
        msg = bot.reply_to(message, "🤖 *GitHub Deploy Starting...*\n\nCloning repository...")
        deploy_id, result = deploy_from_github(user_id, repo_url)
        
        if deploy_id:
            bot.edit_message_text(
                f"✅ *GitHub Deployed!*\n\n"
                f"🆔 ID: `{deploy_id}`\n"
                f"📦 Repository: `{repo_url.split('/')[-1]}`\n"
                f"🤖 AI auto-installed dependencies\n\n"
                f"{result}\n\n"
                f"💎 Credits: *{get_credits(user_id):.1f}*",
                message.chat.id,
                msg.message_id
            )
        else:
            bot.edit_message_text(
                f"❌ *Deploy Failed*\n\n{result}",
                message.chat.id,
                msg.message_id
            )
    except Exception as e:
        logger.error(f"GitHub deploy error: {e}")
        bot.reply_to(message, f"❌ *Error:* {e}")

@bot.message_handler(commands=['addcredits'])
def addcredits_cmd(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin only")
        return
    
    try:
        parts = message.text.split()
        if len(parts) != 3:
            bot.reply_to(message, "*Usage:* `/addcredits USER_ID AMOUNT`")
            return
        
        target_user = int(parts[1])
        amount = float(parts[2])
        
        if add_credits(target_user, amount, "Admin bonus"):
            bot.reply_to(message, f"✅ Added *{amount}* credits to user `{target_user}`")
            try:
                bot.send_message(target_user, 
                    f"🎉 *Bonus Credits!*\n\n"
                    f"You received *{amount}* credits from admin!\n\n"
                    f"💎 New Balance: *{get_credits(target_user):.1f}*")
            except:
                pass
        else:
            bot.reply_to(message, "❌ Failed")
    except Exception as e:
        bot.reply_to(message, f"❌ *Error:* {e}")

@bot.message_handler(commands=['stats'])
def stats_cmd(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin only")
        return
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        c.execute('SELECT COUNT(*) FROM users')
        total_users = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM deployments WHERE status != "deleted"')
        total_deploys = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM deployments WHERE status="running"')
        running_deploys = c.fetchone()[0]
        
        c.execute('SELECT SUM(total_spent) FROM credits')
        total_spent = c.fetchone()[0] or 0
        
        c.execute('SELECT COUNT(*) FROM payments WHERE status="completed"')
        completed_payments = c.fetchone()[0]
        
        c.execute('SELECT SUM(amount) FROM payments WHERE status="completed"')
        total_revenue = c.fetchone()[0] or 0
        
        conn.close()
    
    stats_text = f"📊 *System Statistics*\n\n"
    stats_text += f"👥 Total Users: *{total_users}*\n"
    stats_text += f"🚀 Total Deploys: *{total_deploys}*\n"
    stats_text += f"🟢 Running Now: *{running_deploys}*\n"
    stats_text += f"💰 Credits Spent: *{total_spent:.1f}*\n"
    stats_text += f"💳 Payments: *{completed_payments}*\n"
    stats_text += f"💵 Revenue: *₹{total_revenue:.0f}*\n"
    stats_text += f"⚡ Active Processes: *{len(active_processes)}*"
    
    bot.reply_to(message, stats_text)

@bot.message_handler(commands=['verify'])
def verify_payment_cmd(message):
    """Admin command to verify payment"""
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin only")
        return
    
    try:
        parts = message.text.split()
        if len(parts) != 3:
            bot.reply_to(message, "*Usage:* `/verify PAYMENT_ID TRANSACTION_ID`")
            return
        
        payment_id = parts[1]
        transaction_id = parts[2]
        
        success, msg = verify_payment(payment_id, transaction_id)
        
        if success:
            payment = pending_payments[payment_id]
            user_id = payment['user_id']
            
            bot.reply_to(message, f"✅ Payment verified!\n\n{msg}")
            
            # Notify user
            try:
                bot.send_message(user_id,
                    f"✅ *Payment Confirmed!*\n\n"
                    f"💰 Amount: ₹{payment['amount']}\n"
                    f"💎 Credits Added: *{payment['credits']}*\n\n"
                    f"🎉 New Balance: *{get_credits(user_id):.1f}*\n\n"
                    f"Thank you for your purchase!")
            except:
                pass
        else:
            bot.reply_to(message, f"❌ {msg}")
    
    except Exception as e:
        bot.reply_to(message, f"❌ *Error:* {e}")

@bot.message_handler(commands=['myapps'])
def myapps_cmd(message):
    """Show user's deployments"""
    user_id = message.from_user.id
    deploys = active_deployments.get(user_id, [])
    
    if not deploys:
        bot.reply_to(message, "📊 *No Deployments*\n\nDeploy your first app!")
        return
    
    text = f"📊 *Your Deployments*\n\n"
    
    for d in deploys[:10]:
        emoji = {'running': '🟢', 'pending': '🟡', 'stopped': '🔴', 'failed': '❌'}
        text += f"{emoji.get(d['status'], '⚪')} *{d['name'][:30]}*\n"
        text += f"   ID: `{d['id']}` | Port: `{d['port']}` | {d['status']}\n\n"
    
    if len(deploys) > 10:
        text += f"_...and {len(deploys) - 10} more. Use dashboard for all._"
    
    bot.reply_to(message, text)

@bot.message_handler(commands=['balance'])
def balance_cmd(message):
    """Check credit balance"""
    user_id = message.from_user.id
    credits = get_credits(user_id)
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT total_spent, total_earned FROM credits WHERE user_id = ?', (user_id,))
        result = c.fetchone()
        conn.close()
    
    spent = result[0] if result else 0
    earned = result[1] if result else FREE_CREDITS
    
    bot.reply_to(message,
        f"💎 *Credit Balance*\n\n"
        f"💰 Current: *{credits if credits != float('inf') else '∞'}*\n"
        f"📈 Total Earned: *{earned:.1f}*\n"
        f"📉 Total Spent: *{spent:.1f}*\n\n"
        f"_Your credits are separate from other users!_")

# ==================== CLEANUP ====================

def cleanup_on_exit():
    logger.warning(f"{Fore.YELLOW}🛑 Shutting down...")
    
    for deploy_id, process in list(active_processes.items()):
        try:
            logger.info(f"Stopping {deploy_id}...")
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
    print(f"{Fore.CYAN}{'🚀 ULTRA ADVANCED DEVOPS BOT v9.0 - ULTIMATE EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}🐍 Python: {sys.version.split()[0]}")
    print(f"{Fore.GREEN}📁 Data: {DATA_DIR}")
    print(f"{Fore.GREEN}👑 Owner: {OWNER_ID}")
    print(f"{Fore.YELLOW}🎁 Free Credits Per User: {FREE_CREDITS}")
    print(f"{Fore.MAGENTA}💳 Payment: UPI {UPI_ID}")
    print("=" * 90)
    print(f"{Fore.MAGENTA}✨ REVOLUTIONARY FEATURES v9.0:")
    print(f"{Fore.CYAN}  💎 Per-User Credits System")
    print("     └ Each user gets separate 2 free credits")
    print("     └ Credits isolated per user")
    print("     └ No shared balance")
    print("")
    print(f"{Fore.CYAN}  💰 Integrated Payment Gateway")
    print("     └ ₹99 → 10 credits")
    print("     └ ₹399 → 50 credits (Popular)")
    print("     └ ₹699 → 100 credits (Ultimate)")
    print("     └ UPI QR code generation")
    print("     └ Instant credit addition")
    print("")
    print(f"{Fore.CYAN}  🤖 AI Auto-Install Dependencies")
    print("     └ Analyzes code for imports")
    print("     └ Auto-installs missing packages")
    print("     └ Python, Node.js, Ruby, PHP, Go")
    print("")
    print(f"{Fore.CYAN}  🔗 Bot + Web Full Integration")
    print("     └ Deploy from Telegram")
    print("     └ Manage from Web Dashboard")
    print("     └ Real-time sync")
    print("     └ All features in both")
    print("")
    print(f"{Fore.CYAN}  📤 Direct File Deploy in Bot")
    print("     └ Send .py, .js, .zip files")
    print("     └ Send GitHub URLs")
    print("     └ Instant deployment")
    print("")
    print(f"{Fore.CYAN}  🔐 Environment Variables")
    print("     └ Per-user ENV vars")
    print("     └ Encrypted storage")
    print("     └ Manage from bot or web")
    print("=" * 90)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 Web Dashboard: http://localhost:{port}")
    print(f"{Fore.CYAN}📱 Telegram: {TELEGRAM_LINK}")
    print(f"{Fore.MAGENTA}💳 Payment UPI: {UPI_ID}")
    print(f"{Fore.YELLOW}🤖 Starting bot with full integration...\n")
    print("=" * 90)
    print(f"{Fore.GREEN}{'🎉 SYSTEM READY - BOT + WEB FULLY INTEGRATED':^90}")
    print("=" * 90 + "\n")
    
    print(f"{Fore.CYAN}📋 QUICK COMMANDS:")
    print(f"{Fore.YELLOW}  User Commands:")
    print("    /start - Main menu")
    print("    /myapps - View deployments")
    print("    /balance - Check credits")
    print(f"{Fore.YELLOW}  Admin Commands:")
    print("    /stats - System statistics")
    print("    /addcredits USER_ID AMOUNT - Add credits")
    print("    /verify PAYMENT_ID TXN_ID - Verify payment")
    print(f"{Fore.YELLOW}  Deploy Methods:")
    print("    1. Send .py/.js/.zip file in chat")
    print("    2. Send GitHub URL in chat")
    print("    3. Use web dashboard")
    print("=" * 90 + "\n")
    
    while True:
        try:
            logger.info(f"{Fore.GREEN}🤖 Bot polling - Ready for deployments!")
            bot.infinity_polling(timeout=60, long_polling_timeout=30)
        except Exception as e:
            logger.error(f"{Fore.RED}Polling error: {e}")
            time.sleep(5)
