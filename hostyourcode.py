# -*- coding: utf-8 -*-
"""
🚀 ULTRA ADVANCED DEVOPS BOT v9.1 - MOBILE APP EDITION
Revolutionary AI-Powered Deployment Platform with Native App Design
Mobile-First | Selective Admin Auth | Bottom Nav | Payment Integration
"""

import sys
import subprocess
import os

# ==================== SMART DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 NEXT-GEN DEPENDENCY INSTALLER v9.1")
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
    'pillow': 'PIL'
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

# Admin credentials (ONLY for Admin Panel access)
ADMIN_EMAIL = 'Kvinit6421@gmail.com'
ADMIN_PASSWORD = '28@RajPapa'

# Enhanced credit system
FREE_CREDITS = 3.0
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
DATA_DIR = os.path.join(BASE_DIR, 'devops_data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
DEPLOYS_DIR = os.path.join(DATA_DIR, 'deployments')
BACKUPS_DIR = os.path.join(DATA_DIR, 'backups')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
DB_PATH = os.path.join(DATA_DIR, 'devops.db')
ANALYTICS_DIR = os.path.join(DATA_DIR, 'analytics')
DOCKER_DIR = os.path.join(DATA_DIR, 'docker')
PAYMENTS_DIR = os.path.join(DATA_DIR, 'payments')

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, BACKUPS_DIR, LOGS_DIR, ANALYTICS_DIR, DOCKER_DIR, PAYMENTS_DIR]:
    os.makedirs(d, exist_ok=True)

# Flask & Bot
app = Flask(__name__)
app.secret_key = WEB_SECRET_KEY
CORS(app)
bot = telebot.TeleBot(TOKEN, parse_mode='Markdown')

# Global state
user_credits = {}
active_users = set()
admin_ids = {ADMIN_ID, OWNER_ID}
active_deployments = {}
active_processes = {}
deployment_logs = {}
user_vps = {}
user_env_vars = {}
deployment_analytics = {}
user_sessions = {}
custom_domains = {}
ssl_certificates = {}
auto_scaling_configs = {}
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
        'jwt': 'pyjwt',
        'magic': 'python-magic',
        'dateutil': 'python-dateutil',
        'openai': 'openai',
        'anthropic': 'anthropic',
        'discord': 'discord.py',
    }
    return mapping.get(import_name, import_name)

def detect_and_install_deps(project_path):
    """🤖 AI-Powered dependency detection and installation"""
    installed = []
    install_log = []
    
    logger.info(f"{Fore.CYAN}🤖 AI DEPENDENCY ANALYZER v9.1 - STARTING...")
    install_log.append("🤖 AI DEPENDENCY ANALYZER v9.1 - ENTERPRISE")
    install_log.append("=" * 60)
    
    # Python requirements.txt
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
    
    # Smart code analysis
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
                     'threading', 'subprocess', 'socket', 'http', 'urllib', 'email',
                     'unittest', 'io', 'csv', 'sqlite3', 'pickle', 'base64', 'hashlib',
                     'uuid', 'typing', 'copy', 'tempfile', 'shutil', 'glob', 'zipfile'}
            
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
    
    # Node.js package.json
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
                logger.info(f"{Fore.GREEN}✅ Node.js packages installed")
            else:
                install_log.append(f"⚠️  npm install completed with warnings")
        except subprocess.TimeoutExpired:
            install_log.append("⚠️  npm install timeout (may still be running)")
        except FileNotFoundError:
            logger.warning(f"{Fore.YELLOW}⚠️  npm not found")
            install_log.append("⚠️  npm not available on system")
        except Exception as e:
            install_log.append(f"⚠️  npm error: {str(e)[:50]}")
    
    # Summary
    install_log.append("\n" + "=" * 60)
    install_log.append(f"🎉 AI ANALYSIS COMPLETE")
    install_log.append(f"📦 Total Packages Installed: {len(installed)}")
    if installed:
        install_log.append(f"✅ Installed: {', '.join(installed[:10])}")
        if len(installed) > 10:
            install_log.append(f"   ... and {len(installed) - 10} more")
    install_log.append("=" * 60)
    
    return installed, "\n".join(install_log)

# ==================== DATABASE ====================

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
            pro_member INTEGER DEFAULT 0,
            email TEXT,
            ip_address TEXT
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
            uptime INTEGER DEFAULT 0,
            custom_domain TEXT,
            ssl_enabled INTEGER DEFAULT 0,
            auto_scale INTEGER DEFAULT 0
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS env_vars (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            deployment_id TEXT,
            key TEXT,
            value_encrypted TEXT,
            created_at TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS domains (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            deployment_id TEXT,
            domain TEXT,
            ssl_cert TEXT,
            ssl_key TEXT,
            created_at TEXT,
            verified INTEGER DEFAULT 0
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS backups (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            deployment_id TEXT,
            backup_path TEXT,
            size_mb REAL,
            created_at TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS payment_requests (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            amount REAL,
            screenshot_path TEXT,
            status TEXT,
            created_at TEXT,
            processed_at TEXT
        )''')
        
        c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
                 (OWNER_ID, 'owner', 'Owner', datetime.now().isoformat(), 
                  datetime.now().isoformat(), 0, 0, 0, 1, None, None))
        
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
        
        c.execute('SELECT id, user_id, name, type, status, port, pid, repo_url, branch, cpu_usage, memory_usage, custom_domain FROM deployments WHERE status != "deleted"')
        for dep_id, user_id, name, dep_type, status, port, pid, repo_url, branch, cpu, mem, domain in c.fetchall():
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
                'branch': branch,
                'cpu_usage': cpu or 0,
                'memory_usage': mem or 0,
                'custom_domain': domain
            })
        
        c.execute('SELECT id, user_id, key, value_encrypted FROM env_vars')
        for env_id, user_id, key, value_enc in c.fetchall():
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

# ==================== CREDIT SYSTEM ====================

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
    if user_id not in user_credits and user_id not in admin_ids:
        add_credits(user_id, FREE_CREDITS, "Welcome bonus")
        return True
    return False

# ==================== DEPLOYMENT FUNCTIONS (Same as before) ====================

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
                     repo_url, branch, build_cmd, start_cmd, logs, dependencies_installed, install_log, custom_domain, ssl_enabled, auto_scale)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (deploy_id, user_id, name, deploy_type, 'pending', port,
                  datetime.now().isoformat(), datetime.now().isoformat(),
                  kwargs.get('repo_url', ''), kwargs.get('branch', 'main'),
                  kwargs.get('build_cmd', ''), kwargs.get('start_cmd', ''), '', '', '', None, 0, 0))
        
        c.execute('UPDATE users SET total_deployments = total_deployments + 1 WHERE user_id = ?', (user_id,))
        
        c.execute('INSERT INTO activity_log (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)',
                 (user_id, 'DEPLOYMENT_CREATE', f"{name} ({deploy_type})", datetime.now().isoformat()))
        
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
        'branch': kwargs.get('branch', 'main'),
        'cpu_usage': 0,
        'memory_usage': 0,
        'custom_domain': None
    })
    
    try:
        bot.send_message(OWNER_ID, 
            f"🚀 *New Deployment*\n\n"
            f"User: `{user_id}`\n"
            f"Name: *{name}*\n"
            f"Type: {deploy_type}\n"
            f"ID: `{deploy_id}`\n"
            f"Port: {port}")
    except:
        pass
    
    return deploy_id, port

def update_deployment(deploy_id, status=None, logs=None, pid=None, deps=None, install_log=None, cpu=None, mem=None):
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        updates = ['updated_at = ?']
        values = [datetime.now().isoformat()]
        
        if status:
            updates.append('status = ?')
            values.append(status)
            
            if status == 'running':
                c.execute('UPDATE users SET successful_deployments = successful_deployments + 1 WHERE user_id = (SELECT user_id FROM deployments WHERE id = ?)', (deploy_id,))
        
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
        
        if cpu is not None:
            updates.append('cpu_usage = ?')
            values.append(cpu)
        
        if mem is not None:
            updates.append('memory_usage = ?')
            values.append(mem)
        
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
                if cpu is not None:
                    deploy['cpu_usage'] = cpu
                if mem is not None:
                    deploy['memory_usage'] = mem
                break

def monitor_deployment(deploy_id, process):
    """Monitor deployment resources"""
    try:
        while process.poll() is None:
            try:
                proc = psutil.Process(process.pid)
                cpu = proc.cpu_percent(interval=1)
                mem = proc.memory_percent()
                
                update_deployment(deploy_id, cpu=cpu, mem=mem)
                time.sleep(5)
            except:
                break
    except:
        pass

def deploy_from_file(user_id, file_path, filename):
    try:
        cost = CREDIT_COSTS['file_upload']
        if not deduct_credits(user_id, cost, f"File deploy: {filename}"):
            return None, f"❌ Need {cost} credits"
        
        deploy_id, port = create_deployment(user_id, filename, 'file_upload')
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        if filename.endswith('.zip'):
            update_deployment(deploy_id, 'extracting', '📦 Extracting ZIP archive...')
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(deploy_dir)
            
            main_file = None
            for root, dirs, files in os.walk(deploy_dir):
                for file in files:
                    if file in ['main.py', 'app.py', 'bot.py', 'index.js', 'server.js', 'app.js']:
                        main_file = os.path.join(root, file)
                        break
                if main_file:
                    break
            
            if not main_file:
                update_deployment(deploy_id, 'failed', '❌ No entry point found')
                add_credits(user_id, cost, "Refund: No entry point")
                return None, "❌ No main file found in ZIP"
            
            file_path = main_file
        else:
            shutil.copy(file_path, os.path.join(deploy_dir, filename))
            file_path = os.path.join(deploy_dir, filename)
        
        update_deployment(deploy_id, 'installing', '🤖 AI analyzing project dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        if installed_deps:
            update_deployment(deploy_id, deps=', '.join(installed_deps), install_log=install_log)
            update_deployment(deploy_id, logs=f"✅ Auto-installed: {', '.join(installed_deps[:5])}")
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        if user_id in user_env_vars:
            env.update(user_env_vars[user_id])
        
        update_deployment(deploy_id, 'starting', f'🚀 Launching on port {port}...')
        
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
            update_deployment(deploy_id, 'failed', '❌ Unsupported file type')
            add_credits(user_id, cost, "Refund: Unsupported type")
            return None, "❌ Unsupported file type"
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, 'running', f'✅ Live on port {port}!', process.pid)
        
        Thread(target=monitor_deployment, args=(deploy_id, process), daemon=True).start()
        
        def log_monitor():
            for line in iter(process.stdout.readline, b''):
                if line:
                    log_line = line.decode().strip()
                    update_deployment(deploy_id, logs=log_line)
            
            process.wait()
            if process.returncode == 0:
                update_deployment(deploy_id, 'completed')
            else:
                update_deployment(deploy_id, 'failed', f'❌ Exit code: {process.returncode}')
        
        Thread(target=log_monitor, daemon=True).start()
        
        try:
            bot.send_message(OWNER_ID, 
                f"✅ *Deployment Success*\n\n"
                f"User: `{user_id}`\n"
                f"File: {filename}\n"
                f"ID: `{deploy_id}`\n"
                f"Port: {port}\n"
                f"AI Installed: {len(installed_deps)} packages")
        except:
            pass
        
        return deploy_id, f"🎉 Deployed! Port {port}"
    
    except Exception as e:
        logger.error(f"Deploy error: {e}")
        if 'deploy_id' in locals():
            update_deployment(deploy_id, 'failed', str(e))
            add_credits(user_id, cost, "Refund: Error")
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
        
        update_deployment(deploy_id, 'cloning', f'🔄 Cloning {repo_url}...')
        
        clone_cmd = ['git', 'clone', '-b', branch, '--depth', '1', repo_url, deploy_dir]
        result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=600)
        
        if result.returncode != 0:
            update_deployment(deploy_id, 'failed', f'❌ Clone failed: {result.stderr}')
            add_credits(user_id, cost, "Refund: Clone failed")
            return None, "❌ Clone failed"
        
        update_deployment(deploy_id, logs='✅ Repository cloned')
        
        update_deployment(deploy_id, 'installing', '🤖 AI analyzing dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        if installed_deps:
            update_deployment(deploy_id, deps=', '.join(installed_deps), install_log=install_log)
            update_deployment(deploy_id, logs=f"✅ Auto-installed: {', '.join(installed_deps[:5])}")
        
        if build_cmd:
            update_deployment(deploy_id, 'building', f'🔨 Building: {build_cmd}')
            build_result = subprocess.run(build_cmd, shell=True, cwd=deploy_dir,
                                        capture_output=True, text=True, timeout=600)
            update_deployment(deploy_id, logs=f"Build:\n{build_result.stdout}\n{build_result.stderr}")
        
        if start_cmd:
            start_command = start_cmd
        else:
            main_files = {
                'main.py': f'{sys.executable} main.py',
                'app.py': f'{sys.executable} app.py',
                'bot.py': f'{sys.executable} bot.py',
                'server.py': f'{sys.executable} server.py',
                'index.js': 'node index.js',
                'server.js': 'node server.js',
                'app.js': 'node app.js',
                'package.json': 'npm start'
            }
            
            start_command = None
            for file, cmd in main_files.items():
                if os.path.exists(os.path.join(deploy_dir, file)):
                    start_command = cmd
                    break
            
            if not start_command:
                update_deployment(deploy_id, 'failed', '❌ No start command')
                add_credits(user_id, cost, "Refund: No start cmd")
                return None, "❌ No start command found"
        
        update_deployment(deploy_id, 'starting', f'🚀 Starting: {start_command}')
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        if user_id in user_env_vars:
            env.update(user_env_vars[user_id])
        
        process = subprocess.Popen(
            start_command.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=deploy_dir,
            env=env
        )
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, 'running', f'✅ Running on port {port}!', process.pid)
        
        Thread(target=monitor_deployment, args=(deploy_id, process), daemon=True).start()
        
        def log_monitor():
            for line in iter(process.stdout.readline, b''):
                if line:
                    log_line = line.decode().strip()
                    update_deployment(deploy_id, logs=log_line)
            
            process.wait()
            if process.returncode == 0:
                update_deployment(deploy_id, 'completed')
            else:
                update_deployment(deploy_id, 'failed', f'❌ Exit: {process.returncode}')
        
        Thread(target=log_monitor, daemon=True).start()
        
        try:
            bot.send_message(OWNER_ID, 
                f"✅ *GitHub Deploy Success*\n\n"
                f"User: `{user_id}`\n"
                f"Repo: {repo_name}\n"
                f"Branch: {branch}\n"
                f"ID: `{deploy_id}`\n"
                f"Port: {port}\n"
                f"AI Installed: {len(installed_deps)} packages")
        except:
            pass
        
        return deploy_id, f"🎉 GitHub deployed! Port {port}"
    
    except Exception as e:
        logger.error(f"GitHub deploy error: {e}")
        if 'deploy_id' in locals():
            update_deployment(deploy_id, 'failed', str(e))
            add_credits(user_id, cost, "Refund: Error")
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
        
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('SELECT pid FROM deployments WHERE id = ?', (deploy_id,))
            result = c.fetchone()
            conn.close()
        
        if result and result[0]:
            try:
                process = psutil.Process(result[0])
                process.terminate()
                process.wait(5)
            except:
                pass
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
            return f"{install}\n\n=== Runtime Logs ===\n{logs}" if install else logs or "No logs"
        return "Deployment not found"

def create_backup(user_id, deploy_id):
    """Create backup of deployment"""
    try:
        cost = CREDIT_COSTS['backup']
        if not deduct_credits(user_id, cost, f"Backup: {deploy_id}"):
            return None, f"❌ Need {cost} credits"
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if not os.path.exists(deploy_dir):
            return None, "❌ Deployment not found"
        
        backup_id = str(uuid.uuid4())[:8]
        backup_name = f"{deploy_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        backup_path = os.path.join(BACKUPS_DIR, backup_name)
        
        shutil.make_archive(backup_path.replace('.zip', ''), 'zip', deploy_dir)
        
        size_mb = os.path.getsize(backup_path) / (1024 * 1024)
        
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('''INSERT INTO backups (id, user_id, deployment_id, backup_path, size_mb, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (backup_id, user_id, deploy_id, backup_path, size_mb, datetime.now().isoformat()))
            conn.commit()
            conn.close()
        
        return backup_id, f"✅ Backup created: {size_mb:.2f} MB"
    except Exception as e:
        return None, str(e)

# ==================== 📱 MOBILE APP HTML ====================

MOBILE_APP_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#1e293b">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>EliteHost - Mobile App</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        
        :root {
            --primary: #3b82f6;
            --primary-dark: #2563eb;
            --primary-light: #60a5fa;
            --secondary: #8b5cf6;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #06b6d4;
            --dark: #0f172a;
            --dark-lighter: #1e293b;
            --light: #f8fafc;
            --gray: #64748b;
            --border: #334155;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--dark);
            color: white;
            overflow-x: hidden;
            padding-bottom: 80px;
        }
        
        /* Admin Login Screen */
        .admin-login-screen {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, var(--dark) 0%, var(--dark-lighter) 100%);
            z-index: 10000;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .admin-login-screen.show {
            display: flex;
        }
        
        .login-box {
            max-width: 400px;
            width: 100%;
            background: rgba(30, 41, 59, 0.8);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 24px;
            padding: 40px 32px;
            animation: slideUp 0.5s ease;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .login-logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            margin: 0 auto 24px;
            box-shadow: 0 8px 24px rgba(59, 130, 246, 0.4);
        }
        
        .login-title {
            text-align: center;
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #fff, var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .login-subtitle {
            text-align: center;
            color: var(--gray);
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
            color: var(--gray);
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
        
        .btn-login {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
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
        
        .btn-login:active {
            transform: scale(0.98);
        }
        
        /* App Container */
        .app-container {
            display: block;
        }
        
        /* Top Bar */
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
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }
        
        .logo-text {
            font-size: 20px;
            font-weight: 900;
            background: linear-gradient(135deg, #fff, var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
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
            color: var(--primary-light);
        }
        
        /* Pages */
        .page {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        
        .page.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateX(10px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        .page-content {
            padding: 20px;
        }
        
        /* Stats Grid */
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
            color: var(--primary-light);
            margin-bottom: 4px;
        }
        
        .stat-label {
            font-size: 11px;
            color: var(--gray);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 600;
        }
        
        /* Deploy Cards */
        .deploy-card {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 12px;
        }
        
        .deploy-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 12px;
        }
        
        .deploy-name {
            font-size: 16px;
            font-weight: 800;
            margin-bottom: 6px;
        }
        
        .deploy-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            font-size: 11px;
            color: var(--gray);
            margin-bottom: 12px;
        }
        
        .meta-item {
            display: flex;
            align-items: center;
            gap: 4px;
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
            color: var(--warning);
        }
        
        .status-stopped {
            background: rgba(239, 68, 68, 0.2);
            color: var(--danger);
        }
        
        .deploy-actions {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 6px;
        }
        
        .action-btn-small {
            padding: 8px;
            border: none;
            border-radius: 8px;
            font-size: 11px;
            color: white;
            cursor: pointer;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 4px;
            transition: all 0.2s;
        }
        
        .action-btn-small:active {
            transform: scale(0.95);
        }
        
        /* Upload Zone */
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
            color: var(--primary-light);
            margin-bottom: 12px;
        }
        
        .upload-text {
            font-size: 15px;
            font-weight: 700;
            margin-bottom: 6px;
        }
        
        .upload-hint {
            font-size: 12px;
            color: var(--gray);
        }
        
        /* Input Fields */
        .input-group {
            margin-bottom: 16px;
        }
        
        .input-label {
            display: block;
            font-size: 12px;
            font-weight: 700;
            color: var(--gray);
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
        
        .input-field:focus {
            outline: none;
            border-color: var(--primary);
        }
        
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
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
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .btn:active {
            transform: scale(0.98);
        }
        
        /* Bottom Navigation - 5 items now */
        .bottom-nav {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(30, 41, 59, 0.98);
            backdrop-filter: blur(20px);
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            padding: 8px 0;
            z-index: 1000;
            box-shadow: 0 -4px 20px rgba(0, 0, 0, 0.3);
        }
        
        .nav-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 4px;
            padding: 8px;
            cursor: pointer;
            color: var(--gray);
            transition: all 0.2s;
            border: none;
            background: none;
        }
        
        .nav-item.active {
            color: var(--primary-light);
        }
        
        .nav-item:active {
            transform: scale(0.95);
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
        
        /* Admin Panel Styles */
        .admin-stats {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }
        
        .admin-stat-card {
            background: rgba(139, 92, 246, 0.1);
            border: 1px solid rgba(139, 92, 246, 0.3);
            border-radius: 12px;
            padding: 16px;
            text-align: center;
        }
        
        .admin-stat-value {
            font-size: 24px;
            font-weight: 900;
            color: var(--secondary);
            margin-bottom: 4px;
        }
        
        .admin-stat-label {
            font-size: 10px;
            color: var(--gray);
            text-transform: uppercase;
        }
        
        .admin-actions {
            display: grid;
            gap: 10px;
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
        
        /* Buy Credits Page */
        .qr-container {
            background: white;
            border-radius: 16px;
            padding: 20px;
            text-align: center;
            margin-bottom: 20px;
        }
        
        .qr-image {
            width: 200px;
            height: 200px;
            margin: 0 auto 16px;
            border: 4px solid var(--primary);
            border-radius: 12px;
        }
        
        .payment-info {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 20px;
        }
        
        .payment-info-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .payment-info-item:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }
        
        .payment-label {
            font-size: 12px;
            color: var(--gray);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .payment-value {
            font-size: 14px;
            font-weight: 700;
            color: white;
        }
        
        .screenshot-upload-zone {
            border: 2px dashed rgba(16, 185, 129, 0.5);
            border-radius: 16px;
            padding: 30px 20px;
            text-align: center;
            background: rgba(16, 185, 129, 0.05);
            cursor: pointer;
            margin-bottom: 16px;
        }
        
        .screenshot-preview {
            max-width: 100%;
            max-height: 300px;
            border-radius: 12px;
            margin-top: 16px;
        }
        
        /* Toast */
        .toast.show {
            transform: translateY(0);
        }
        
        .toast-icon {
            font-size: 18px;
        }
        
        .toast-message {
            flex: 1;
            font-size: 13px;
            font-weight: 600;
        }
        
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.85);
            z-index: 10000;
            align-items: flex-end;
            justify-content: center;
        }
        
        .modal.show {
            display: flex;
        }
        
        .modal-content {
            background: var(--dark-lighter);
            border-radius: 24px 24px 0 0;
            width: 100%;
            max-height: 80vh;
            overflow-y: auto;
            padding: 24px 20px 40px;
            animation: slideUpModal 0.3s ease;
        }
        
        @keyframes slideUpModal {
            from {
                transform: translateY(100%);
            }
            to {
                transform: translateY(0);
            }
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .modal-title {
            font-size: 20px;
            font-weight: 900;
        }
        
        .close-btn {
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: white;
            width: 32px;
            height: 32px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }
        
        /* Terminal */
        .terminal {
            background: #0a0f1e;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 16px;
            font-family: 'Courier New', monospace;
            font-size: 11px;
            color: #10b981;
            max-height: 300px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            line-height: 1.5;
        }
        
        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 40px 20px;
        }
        
        .empty-icon {
            font-size: 48px;
            margin-bottom: 12px;
            opacity: 0.3;
        }
        
        .empty-title {
            font-size: 16px;
            font-weight: 800;
            margin-bottom: 6px;
        }
        
        .empty-desc {
            font-size: 13px;
            color: var(--gray);
        }
        
        /* Loading */
        .loading {
            text-align: center;
            padding: 40px;
        }
        
        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid rgba(59, 130, 246, 0.2);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            margin: 0 auto 16px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        /* Pull to Refresh */
        .pull-refresh {
            position: absolute;
            top: 60px;
            left: 50%;
            transform: translateX(-50%) translateY(-100px);
            width: 40px;
            height: 40px;
            background: rgba(59, 130, 246, 0.2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.3s;
            z-index: 99;
        }
        
        .pull-refresh.active {
            transform: translateX(-50%) translateY(0);
        }
        
        /* Section Headers */
        .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }
        
        .section-title {
            font-size: 18px;
            font-weight: 900;
            color: white;
        }
        
        .section-action {
            background: rgba(59, 130, 246, 0.15);
            border: none;
            color: var(--primary-light);
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
        }
        
        /* Env Variables */
        .env-item {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.2);
            border-radius: 10px;
            padding: 12px;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .env-info {
            flex: 1;
            min-width: 0;
        }
        
        .env-key {
            font-weight: 700;
            font-size: 13px;
            margin-bottom: 4px;
        }
        
        .env-value {
            font-family: monospace;
            font-size: 11px;
            color: var(--gray);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        
        .env-delete {
            background: rgba(239, 68, 68, 0.2);
            border: none;
            color: var(--danger);
            width: 32px;
            height: 32px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            flex-shrink: 0;
        }
    </style>
</head>
<body>
    <!-- Admin Login Screen (Only for Admin Panel) -->
    <div class="admin-login-screen" id="adminLoginScreen">
        <div class="login-box">
            <div class="login-logo">
                <i class="fas fa-crown"></i>
            </div>
            <h1 class="login-title">Admin Panel</h1>
            <p class="login-subtitle">Secure Admin Access</p>
            
            <form onsubmit="handleAdminLogin(event)">
                <div class="form-group">
                    <label class="form-label">Email Address</label>
                    <input type="email" class="form-input" id="adminEmail" placeholder="admin@elitehost.com" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" class="form-input" id="adminPassword" placeholder="Enter password" required>
                </div>
                
                <button type="submit" class="btn-login">
                    <i class="fas fa-sign-in-alt"></i> Login to Admin Panel
                </button>
            </form>
        </div>
    </div>

    <!-- App Container (Accessible to all users) -->
    <div class="app-container" id="appContainer">
        <!-- Top Bar -->
        <div class="top-bar">
            <div class="top-bar-content">
                <div class="app-logo">
                    <div class="logo-icon">
                        <i class="fas fa-rocket"></i>
                    </div>
                    <div class="logo-text">EliteHost</div>
                </div>
                <div class="credit-badge">
                    <i class="fas fa-gem"></i>
                    <span id="creditBalance">{{ credits }}</span>
                </div>
            </div>
        </div>

        <!-- Pull to Refresh Indicator -->
        <div class="pull-refresh" id="pullRefresh">
            <i class="fas fa-sync"></i>
        </div>

        <!-- Pages -->
        <!-- Home Page -->
        <div class="page active" id="homePage">
            <div class="page-content">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-icon">🚀</div>
                        <div class="stat-value" id="totalDeploys">{{ total_deploys }}</div>
                        <div class="stat-label">Total</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">🟢</div>
                        <div class="stat-value" id="activeDeploys">{{ active_deploys }}</div>
                        <div class="stat-label">Active</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">💻</div>
                        <div class="stat-value" id="vpsCount">{{ vps_count }}</div>
                        <div class="stat-label">Servers</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">🤖</div>
                        <div class="stat-value">AI</div>
                        <div class="stat-label">Powered</div>
                    </div>
                </div>

                <div class="section-header">
                    <h2 class="section-title">Recent Deployments</h2>
                    <button class="section-action" onclick="switchPage('deploymentsPage')">
                        View All <i class="fas fa-arrow-right"></i>
                    </button>
                </div>

                <div id="recentDeployments"></div>
            </div>
        </div>

        <!-- Deployments Page -->
        <div class="page" id="deploymentsPage">
            <div class="page-content">
                <div class="section-header">
                    <h2 class="section-title">All Deployments</h2>
                    <button class="section-action" onclick="loadDeployments()">
                        <i class="fas fa-sync"></i> Refresh
                    </button>
                </div>
                <div id="deploymentsList"></div>
            </div>
        </div>

        <!-- Upload Page -->
        <div class="page" id="uploadPage">
            <div class="page-content">
                <h2 class="section-title" style="margin-bottom: 16px;">Deploy Your App</h2>
                
                <div class="upload-zone" onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <div class="upload-text">Tap to Upload</div>
                    <div class="upload-hint">Python • JavaScript • ZIP</div>
                    <input type="file" id="fileInput" hidden accept=".py,.js,.zip" onchange="handleFileUpload(this)">
                </div>

                <h3 style="font-size: 16px; font-weight: 800; margin-bottom: 16px;">
                    <i class="fab fa-github"></i> Deploy from GitHub
                </h3>

                <div class="input-group">
                    <label class="input-label">Repository URL</label>
                    <input type="url" class="input-field" id="repoUrl" placeholder="https://github.com/user/repo">
                </div>

                <div class="input-group">
                    <label class="input-label">Branch</label>
                    <input type="text" class="input-field" id="repoBranch" value="main">
                </div>

                <div class="input-group">
                    <label class="input-label">Build Command (Optional)</label>
                    <input type="text" class="input-field" id="buildCmd" placeholder="npm run build">
                </div>

                <div class="input-group">
                    <label class="input-label">Start Command (Optional)</label>
                    <input type="text" class="input-field" id="startCmd" placeholder="Auto-detect">
                </div>

                <button class="btn" onclick="deployGithub()">
                    <i class="fab fa-github"></i>
                    Deploy from GitHub
                </button>
            </div>
        </div>

        <!-- Buy Credits Page -->
        <div class="page" id="buyCreditsPage">
            <div class="page-content">
                <h2 class="section-title" style="margin-bottom: 16px;">
                    <i class="fas fa-coins"></i> Buy Credits
                </h2>

                <div class="payment-info">
                    <div class="payment-info-item">
                        <span class="payment-label">Credit Price</span>
                        <span class="payment-value">₹10 = 1 Credit</span>
                    </div>
                    <div class="payment-info-item">
                        <span class="payment-label">Min Purchase</span>
                        <span class="payment-value">5 Credits (₹50)</span>
                    </div>
                    <div class="payment-info-item">
                        <span class="payment-label">Payment Method</span>
                        <span class="payment-value">UPI / QR Code</span>
                    </div>
                </div>

                <div class="qr-container">
                    <img src="/qr.jpg" alt="Payment QR Code" class="qr-image" onerror="this.src='data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22200%22 height=%22200%22%3E%3Crect fill=%22%233b82f6%22 width=%22200%22 height=%22200%22/%3E%3Ctext x=%2250%25%22 y=%2250%25%22 text-anchor=%22middle%22 dy=%22.3em%22 fill=%22white%22 font-size=%2216%22 font-family=%22Arial%22%3EPayment QR%3C/text%3E%3C/svg%3E'">
                    <div style="color: var(--dark); font-size: 14px; font-weight: 700; margin-bottom: 8px;">Scan to Pay</div>
                    <div style="color: var(--gray); font-size: 12px;">After payment, upload screenshot below</div>
                </div>

                <div class="input-group">
                    <label class="input-label">Amount (Credits)</label>
                    <input type="number" class="input-field" id="creditAmount" placeholder="5" min="5" step="1">
                </div>

                <div class="screenshot-upload-zone" onclick="document.getElementById('screenshotInput').click()">
                    <div class="upload-icon" style="font-size: 36px; color: var(--success);">
                        <i class="fas fa-camera"></i>
                    </div>
                    <div class="upload-text">Upload Payment Screenshot</div>
                    <div class="upload-hint">Tap to select image</div>
                    <input type="file" id="screenshotInput" hidden accept="image/*" onchange="previewScreenshot(this)">
                    <img id="screenshotPreview" class="screenshot-preview" style="display: none;">
                </div>

                <button class="btn" onclick="submitPayment()" style="background: linear-gradient(135deg, var(--success), #059669);">
                    <i class="fas fa-paper-plane"></i>
                    Submit Payment Request
                </button>

                <div style="margin-top: 20px; padding: 16px; background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.3); border-radius: 12px;">
                    <div style="font-size: 12px; color: var(--warning); line-height: 1.6;">
                        <strong>⚠️ Important:</strong><br>
                        • Credits will be added after verification<br>
                        • Keep your payment screenshot safe<br>
                        • Processing time: 5-30 minutes<br>
                        • For issues, contact {{ username }}
                    </div>
                </div>
            </div>
        </div>

        <!-- Admin Page (Requires Login) -->
        <div class="page" id="adminPage">
            <div class="page-content">
                <h2 class="section-title" style="margin-bottom: 16px;">
                    <i class="fas fa-crown"></i> Admin Panel
                </h2>

                <div class="admin-stats">
                    <div class="admin-stat-card">
                        <div class="admin-stat-value" id="adminUsers">0</div>
                        <div class="admin-stat-label">Total Users</div>
                    </div>
                    <div class="admin-stat-card">
                        <div class="admin-stat-value" id="adminDeploys">0</div>
                        <div class="admin-stat-label">Deployments</div>
                    </div>
                    <div class="admin-stat-card">
                        <div class="admin-stat-value" id="adminProcesses">0</div>
                        <div class="admin-stat-label">Active</div>
                    </div>
                    <div class="admin-stat-card">
                        <div class="admin-stat-value" id="adminAI">0</div>
                        <div class="admin-stat-label">AI Installs</div>
                    </div>
                </div>

                <div class="admin-actions">
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--success), #059669);" onclick="showAddCreditsModal()">
                        <i class="fas fa-coins"></i> Add Credits to User
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--warning), #d97706);" onclick="viewPaymentRequests()">
                        <i class="fas fa-receipt"></i> Payment Requests
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--secondary), #7c3aed);" onclick="viewAllUsers()">
                        <i class="fas fa-users"></i> View All Users
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--primary), var(--primary-dark));" onclick="viewAllDeployments()">
                        <i class="fas fa-server"></i> All Deployments
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--danger), #dc2626);" onclick="viewActivityLog()">
                        <i class="fas fa-history"></i> Activity Log
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--info), #0e7490);" onclick="systemHealth()">
                        <i class="fas fa-heartbeat"></i> System Health
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, #64748b, #475569);" onclick="adminLogout()">
                        <i class="fas fa-sign-out-alt"></i> Logout
                    </button>
                </div>
            </div>
        </div>

        <!-- Profile Page -->
        <div class="page" id="profilePage">
            <div class="page-content">
                <h2 class="section-title" style="margin-bottom: 16px;">Environment Variables</h2>
                
                <div id="envList"></div>

                <button class="btn" onclick="showAddEnv()" style="margin-top: 16px;">
                    <i class="fas fa-plus"></i>
                    Add Variable
                </button>

                <div style="margin-top: 32px; padding-top: 32px; border-top: 1px solid rgba(255,255,255,0.1);">
                    <h2 class="section-title" style="margin-bottom: 16px;">About</h2>
                    <div style="background: rgba(30, 41, 59, 0.6); border-radius: 12px; padding: 16px; font-size: 13px; color: var(--gray); line-height: 1.6;">
                        <div style="margin-bottom: 8px;"><strong style="color: white;">EliteHost v9.1</strong></div>
                        <div>🤖 AI-Powered Deployment</div>
                        <div>🚀 Enterprise Edition</div>
                        <div>📱 Mobile First Design</div>
                        <div>💳 Integrated Payment System</div>
                        <div style="margin-top: 12px;">Contact: {{ username }}</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Bottom Navigation - 5 Items -->
        <div class="bottom-nav">
            <button class="nav-item active" onclick="switchPage('homePage', this)">
                <div class="nav-icon"><i class="fas fa-home"></i></div>
                <div class="nav-label">Home</div>
            </button>
            <button class="nav-item" onclick="switchPage('deploymentsPage', this)">
                <div class="nav-icon"><i class="fas fa-rocket"></i></div>
                <div class="nav-label">Deploys</div>
            </button>
            <button class="nav-item" onclick="switchPage('uploadPage', this)">
                <div class="nav-icon"><i class="fas fa-plus-circle"></i></div>
                <div class="nav-label">Upload</div>
            </button>
            <button class="nav-item" onclick="switchPage('buyCreditsPage', this)">
                <div class="nav-icon"><i class="fas fa-coins"></i></div>
                <div class="nav-label">Buy</div>
            </button>
            <button class="nav-item" onclick="checkAdminAccess(this)">
                <div class="nav-icon"><i class="fas fa-crown"></i></div>
                <div class="nav-label">Admin</div>
            </button>
        </div>
    </div>

    <!-- Toast -->
    <div id="toast" class="toast">
        <div class="toast-icon"></div>
        <div class="toast-message"></div>
    </div>

    <!-- Modal -->
    <div id="modal" class="modal" onclick="if(event.target === this) closeModal()">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title" id="modalTitle">Modal</h3>
                <button class="close-btn" onclick="closeModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div id="modalBody"></div>
        </div>
    </div>

    <script>
        let isAdminLoggedIn = false;
        let touchStartY = 0;
        let pulling = false;
        let currentScreenshotFile = null;

        // Check Admin Session
        window.addEventListener('load', () => {
            if (sessionStorage.getItem('elitehost_admin') === 'true') {
                isAdminLoggedIn = true;
            }
            loadData();
        });

        // Admin Login Handler
        function handleAdminLogin(event) {
            event.preventDefault();
            
            const email = document.getElementById('adminEmail').value;
            const password = document.getElementById('adminPassword').value;
            
            if (email === 'Kvinit6421@gmail.com' && password === '28@RajPapa') {
                isAdminLoggedIn = true;
                sessionStorage.setItem('elitehost_admin', 'true');
                document.getElementById('adminLoginScreen').classList.remove('show');
                showToast('success', '✅ Admin login successful!');
                switchPage('adminPage');
                loadAdminStats();
            } else {
                showToast('error', '❌ Invalid admin credentials');
            }
        }

        // Check Admin Access
        function checkAdminAccess(navBtn) {
            if (!isAdminLoggedIn) {
                document.getElementById('adminLoginScreen').classList.add('show');
            } else {
                switchPage('adminPage', navBtn);
                loadAdminStats();
            }
        }

        // Admin Logout
        function adminLogout() {
            if (confirm('Logout from admin panel?')) {
                sessionStorage.removeItem('elitehost_admin');
                isAdminLoggedIn = false;
                showToast('info', '👋 Logged out from admin panel');
                switchPage('homePage');
            }
        }

        // Page Switching
        function switchPage(pageId, navBtn) {
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.getElementById(pageId).classList.add('active');
            
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            if (navBtn) navBtn.classList.add('active');
            
            window.scrollTo(0, 0);
        }

        // Pull to Refresh
        document.addEventListener('touchstart', (e) => {
            touchStartY = e.touches[0].clientY;
        });

        document.addEventListener('touchmove', (e) => {
            const touchY = e.touches[0].clientY;
            const pullDistance = touchY - touchStartY;
            
            if (window.scrollY === 0 && pullDistance > 0) {
                pulling = true;
                if (pullDistance > 80) {
                    document.getElementById('pullRefresh').classList.add('active');
                }
            }
        });

        document.addEventListener('touchend', () => {
            if (pulling && document.getElementById('pullRefresh').classList.contains('active')) {
                loadDeployments();
                updateCredits();
                if (document.getElementById('adminPage').classList.contains('active') && isAdminLoggedIn) {
                    loadAdminStats();
                }
            }
            document.getElementById('pullRefresh').classList.remove('active');
            pulling = false;
        });

        // Screenshot Preview
        function previewScreenshot(input) {
            const file = input.files[0];
            if (!file) return;
            
            currentScreenshotFile = file;
            const reader = new FileReader();
            reader.onload = function(e) {
                const preview = document.getElementById('screenshotPreview');
                preview.src = e.target.result;
                preview.style.display = 'block';
            };
            reader.readAsDataURL(file);
        }

        // Submit Payment
        async function submitPayment() {
            const amount = document.getElementById('creditAmount').value;
            
            if (!amount || amount < 5) {
                showToast('warning', '⚠️ Minimum 5 credits');
                return;
            }
            
            if (!currentScreenshotFile) {
                showToast('warning', '⚠️ Upload payment screenshot');
                return;
            }
            
            const formData = new FormData();
            formData.append('amount', amount);
            formData.append('screenshot', currentScreenshotFile);
            
            showToast('info', '📤 Submitting payment request...');
            
            try {
                const res = await fetch('/api/payment/submit', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                
                if (data.success) {
                    const deployments = data.deployments;
                    const listHtml = deployments.map(d => `
                        <div class="deploy-card">
                            <div class="deploy-header">
                                <div>
                                    <div class="deploy-name">${d.name}</div>
                                    <div class="deploy-meta">
                                        <span class="meta-item"><i class="fas fa-fingerprint"></i> ${d.id}</span>
                                        <span class="meta-item"><i class="fas fa-network-wired"></i> Port ${d.port || 'N/A'}</span>
                                    </div>
                                </div>
                                <span class="status-badge status-${d.status}">${d.status}</span>
                            </div>
                            <div class="deploy-actions">
                                <button class="action-btn-small" style="background: var(--info);" onclick="viewLogs('${d.id}')">
                                    <i class="fas fa-terminal"></i>
                                    <span>Logs</span>
                                </button>
                                <button class="action-btn-small" style="background: var(--warning);" onclick="stopDeploy('${d.id}')">
                                    <i class="fas fa-stop"></i>
                                    <span>Stop</span>
                                </button>
                                <button class="action-btn-small" style="background: var(--success);" onclick="backupDeploy('${d.id}')">
                                    <i class="fas fa-save"></i>
                                    <span>Backup</span>
                                </button>
                                <button class="action-btn-small" style="background: var(--danger);" onclick="deleteDeploy('${d.id}')">
                                    <i class="fas fa-trash"></i>
                                    <span>Delete</span>
                                </button>
                            </div>
                        </div>
                    `).join('');
                    
                    document.getElementById('deploymentsList').innerHTML = listHtml || '<div class="empty-state"><div class="empty-icon">🚀</div><div class="empty-desc">No deployments yet</div></div>';
                    document.getElementById('recentDeployments').innerHTML = deployments.slice(0, 3).map(d => `
                        <div class="deploy-card" style="margin-bottom: 8px; padding: 12px;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <div style="font-weight: 700; font-size: 14px; margin-bottom: 4px;">${d.name}</div>
                                    <div style="font-size: 11px; color: var(--gray);">Port ${d.port || 'N/A'}</div>
                                </div>
                                <span class="status-badge status-${d.status}">${d.status}</span>
                            </div>
                        </div>
                    `).join('') || '<div class="empty-desc" style="padding: 20px; text-align: center;">No recent deployments</div>';
                    
                    document.getElementById('totalDeploys').textContent = deployments.length;
                    document.getElementById('activeDeploys').textContent = deployments.filter(d => d.status === 'running').length;
                }
            } catch (err) {
                console.error(err);
            }
        }

        // View Logs
        async function viewLogs(deployId) {
            try {
                const res = await fetch(`/api/deployment/${deployId}/logs`);
                const data = await res.json();
                
                if (data.success) {
                    showModal('Deployment Logs', `<div class="terminal">${data.logs || 'No logs available'}</div>`);
                }
            } catch (err) {
                showToast('error', '❌ Failed to load logs');
            }
        }

        // Stop Deployment
        async function stopDeploy(deployId) {
            if (!confirm('Stop this deployment?')) return;
            
            try {
                const res = await fetch(`/api/deployment/${deployId}/stop`, {method: 'POST'});
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Deployment stopped');
                    loadDeployments();
                } else {
                    showToast('error', '❌ ' + data.message);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        // Backup Deployment
        async function backupDeploy(deployId) {
            if (!confirm('Create backup of this deployment?')) return;
            
            showToast('info', '📦 Creating backup...');
            
            try {
                const res = await fetch(`/api/deployment/${deployId}/backup`, {method: 'POST'});
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ ' + data.message);
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        // Delete Deployment
        async function deleteDeploy(deployId) {
            if (!confirm('Delete this deployment permanently?')) return;
            
            try {
                const res = await fetch(`/api/deployment/${deployId}`, {method: 'DELETE'});
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Deployment deleted');
                    loadDeployments();
                } else {
                    showToast('error', '❌ Failed');
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        // Load Environment Variables
        async function loadEnv() {
            try {
                const res = await fetch('/api/env/list');
                const data = await res.json();
                const list = document.getElementById('envList');
                
                if (!data.variables || !Object.keys(data.variables).length) {
                    list.innerHTML = '<div class="empty-state" style="padding: 20px;"><div class="empty-desc">No environment variables</div></div>';
                    return;
                }
                
                list.innerHTML = Object.entries(data.variables).map(([key, value]) => `
                    <div class="env-item">
                        <div class="env-info">
                            <div class="env-key">${key}</div>
                            <div class="env-value">${value.substring(0, 30)}${value.length > 30 ? '...' : ''}</div>
                        </div>
                        <button class="env-delete" onclick="deleteEnv('${key}')">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                `).join('');
            } catch (err) {
                console.error(err);
            }
        }

        // Show Add Env Modal
        function showAddEnv() {
            showModal('Add Environment Variable', `
                <div class="input-group">
                    <label class="input-label">Variable Name</label>
                    <input type="text" class="input-field" id="envKey" placeholder="API_KEY">
                </div>
                <div class="input-group">
                    <label class="input-label">Variable Value</label>
                    <input type="text" class="input-field" id="envValue" placeholder="your-secret-value">
                </div>
                <button class="btn" onclick="addEnv()">
                    <i class="fas fa-plus"></i> Add Variable
                </button>
            `);
        }

        // Add Environment Variable
        async function addEnv() {
            const key = document.getElementById('envKey').value;
            const value = document.getElementById('envValue').value;
            
            if (!key || !value) {
                showToast('warning', '⚠️ Fill all fields');
                return;
            }
            
            try {
                const res = await fetch('/api/env/add', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key, value})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Variable added');
                    closeModal();
                    loadEnv();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        // Delete Environment Variable
        async function deleteEnv(key) {
            if (!confirm(`Delete "${key}"?`)) return;
            
            try {
                const res = await fetch('/api/env/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Deleted');
                    loadEnv();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        // Admin Functions
        async function loadAdminStats() {
            try {
                const res = await fetch('/api/admin/stats');
                const data = await res.json();
                
                if (data.success) {
                    document.getElementById('adminUsers').textContent = data.stats.total_users;
                    document.getElementById('adminDeploys').textContent = data.stats.total_deployments;
                    document.getElementById('adminProcesses').textContent = data.stats.active_processes;
                    document.getElementById('adminAI').textContent = data.stats.ai_installs;
                }
            } catch (err) {
                console.error(err);
            }
        }

        function showAddCreditsModal() {
            showModal('Add Credits to User', `
                <div class="input-group">
                    <label class="input-label">User ID</label>
                    <input type="number" class="input-field" id="targetUserId" placeholder="123456789">
                </div>
                <div class="input-group">
                    <label class="input-label">Amount</label>
                    <input type="number" class="input-field" id="creditAmountAdmin" placeholder="10.0" step="0.5">
                </div>
                <button class="btn" onclick="adminAddCredits()" style="background: var(--success);">
                    <i class="fas fa-coins"></i> Add Credits
                </button>
            `);
        }

        async function adminAddCredits() {
            const userId = document.getElementById('targetUserId').value;
            const amount = document.getElementById('creditAmountAdmin').value;
            
            if (!userId || !amount) {
                showToast('warning', '⚠️ Fill all fields');
                return;
            }
            
            try {
                const res = await fetch('/api/admin/add-credits', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({user_id: parseInt(userId), amount: parseFloat(amount)})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Credits added');
                    closeModal();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        async function viewPaymentRequests() {
            try {
                const res = await fetch('/api/admin/payment-requests');
                const data = await res.json();
                
                if (data.success) {
                    const requestsHtml = data.requests.map(r => `
                        <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 14px; margin-bottom: 10px;">
                            <div style="font-weight: 800; font-size: 14px; margin-bottom: 6px;">User ID: ${r.user_id}</div>
                            <div style="font-size: 11px; color: var(--gray); line-height: 1.6; margin-bottom: 12px;">
                                <div>Amount: ${r.amount} Credits (₹${r.amount * 10})</div>
                                <div>Status: <span class="status-badge status-${r.status}">${r.status}</span></div>
                                <div>Date: ${new Date(r.created_at).toLocaleString()}</div>
                            </div>
                            ${r.status === 'pending' ? `
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px;">
                                    <button class="btn" onclick="approvePayment('${r.id}', ${r.user_id}, ${r.amount})" style="background: var(--success); padding: 10px; font-size: 12px;">
                                        <i class="fas fa-check"></i> Approve
                                    </button>
                                    <button class="btn" onclick="rejectPayment('${r.id}')" style="background: var(--danger); padding: 10px; font-size: 12px;">
                                        <i class="fas fa-times"></i> Reject
                                    </button>
                                </div>
                            ` : ''}
                        </div>
                    `).join('');
                    
                    showModal(`Payment Requests (${data.requests.length})`, requestsHtml || '<div class="empty-desc">No payment requests</div>');
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        async function approvePayment(requestId, userId, amount) {
            try {
                const res = await fetch('/api/admin/approve-payment', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({request_id: requestId, user_id: userId, amount: amount})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Payment approved!');
                    closeModal();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        async function rejectPayment(requestId) {
            if (!confirm('Reject this payment request?')) return;
            
            try {
                const res = await fetch('/api/admin/reject-payment', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({request_id: requestId})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Payment rejected');
                    closeModal();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        async function viewAllUsers() {
            try {
                const res = await fetch('/api/admin/users');
                const data = await res.json();
                
                if (data.success) {
                    const usersHtml = data.users.map(u => `
                        <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 14px; margin-bottom: 10px;">
                            <div style="font-weight: 800; font-size: 14px; margin-bottom: 6px;">${u.first_name}</div>
                            <div style="font-size: 11px; color: var(--gray); line-height: 1.6;">
                                <div>ID: ${u.user_id}</div>
                                <div>@${u.username || 'N/A'}</div>
                                <div>Deploys: ${u.total_deployments}</div>
                                <div>${new Date(u.joined_date).toLocaleDateString()}</div>
                            </div>
                        </div>
                    `).join('');
                    
                    showModal(`Users (${data.users.length})`, usersHtml);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        async function viewAllDeployments() {
            try {
                const res = await fetch('/api/admin/deployments');
                const data = await res.json();
                
                if (data.success) {
                    const deploysHtml = data.deployments.map(d => `
                        <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 14px; margin-bottom: 10px;">
                            <div style="font-weight: 800; margin-bottom: 6px;">${d.name}</div>
                            <div style="font-size: 11px; color: var(--gray); line-height: 1.6;">
                                <div>ID: ${d.id}</div>
                                <div>User: ${d.user_id}</div>
                                <div>Status: <span class="status-badge status-${d.status}">${d.status}</span></div>
                                <div>Port: ${d.port || 'N/A'}</div>
                            </div>
                        </div>
                    `).join('');
                    
                    showModal(`Deployments (${data.deployments.length})`, deploysHtml);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        async function viewActivityLog() {
            try {
                const res = await fetch('/api/admin/activity');
                const data = await res.json();
                
                if (data.success) {
                    const activityHtml = data.activity.map(a => `
                        <div style="background: rgba(30, 41, 59, 0.6); border-left: 3px solid var(--primary); padding: 12px; margin-bottom: 8px; border-radius: 8px;">
                            <div style="font-weight: 700; font-size: 12px; margin-bottom: 4px;">${a.action}</div>
                            <div style="font-size: 10px; color: var(--gray);">
                                <div>User: ${a.user_id}</div>
                                <div>${a.details}</div>
                                <div>${new Date(a.timestamp).toLocaleString()}</div>
                            </div>
                        </div>
                    `).join('');
                    
                    showModal(`Activity Log (${data.activity.length})`, activityHtml);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        async function systemHealth() {
            try {
                const res = await fetch('/api/admin/health');
                const data = await res.json();
                
                if (data.success) {
                    const health = data.health;
                    const healthHtml = `
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin-bottom: 16px;">
                            <div class="admin-stat-card">
                                <div class="admin-stat-value">${health.cpu_percent.toFixed(1)}%</div>
                                <div class="admin-stat-label">CPU</div>
                            </div>
                            <div class="admin-stat-card">
                                <div class="admin-stat-value">${health.memory_percent.toFixed(1)}%</div>
                                <div class="admin-stat-label">Memory</div>
                            </div>
                            <div class="admin-stat-card">
                                <div class="admin-stat-value">${health.disk_percent.toFixed(1)}%</div>
                                <div class="admin-stat-label">Disk</div>
                            </div>
                            <div class="admin-stat-card">
                                <div class="admin-stat-value">${health.active_processes}</div>
                                <div class="admin-stat-label">Processes</div>
                            </div>
                        </div>
                        <div style="padding: 14px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 12px;">
                            <div style="font-weight: 800; margin-bottom: 6px;">System: <span style="color: var(--success);">Healthy</span></div>
                            <div style="font-size: 11px; color: var(--gray);">Uptime: ${health.uptime}</div>
                        </div>
                    `;
                    
                    showModal('System Health', healthHtml);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        // Utility Functions
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

        function showModal(title, body) {
            document.getElementById('modalTitle').textContent = title;
            document.getElementById('modalBody').innerHTML = body;
            document.getElementById('modal').classList.add('show');
        }

        function closeModal() {
            document.getElementById('modal').classList.remove('show');
        }

        function showToast(type, message) {
            const toast = document.getElementById('toast');
            const icons = {
                info: '<i class="fas fa-info-circle" style="color: var(--info);"></i>',
                success: '<i class="fas fa-check-circle" style="color: var(--success);"></i>',
                warning: '<i class="fas fa-exclamation-triangle" style="color: var(--warning);"></i>',
                error: '<i class="fas fa-times-circle" style="color: var(--danger);"></i>'
            };
            
            toast.querySelector('.toast-icon').innerHTML = icons[type] || icons.info;
            toast.querySelector('.toast-message').textContent = message;
            toast.classList.add('show');
            
            setTimeout(() => toast.classList.remove('show'), 3500);
        }

        // Load initial data
        function loadData() {
            loadDeployments();
            loadEnv();
            updateCredits();
        }

        // Auto-refresh
        setInterval(updateCredits, 15000);
        setInterval(() => {
            loadDeployments();
            if (document.getElementById('adminPage').classList.contains('active') && isAdminLoggedIn) {
                loadAdminStats();
            }
        }, 10000);
    </script>
</body>
</html>
"""

# ==================== FLASK ROUTES (continued) ====================

@app.route('/')
def index():
    user_id = request.args.get('user_id', session.get('user_id', OWNER_ID))
    user_id = int(user_id)
    session['user_id'] = user_id
    
    if user_id not in user_credits and user_id not in admin_ids:
        init_user_credits(user_id)
    
    credits = get_credits(user_id)
    total_deploys = len(active_deployments.get(user_id, []))
    active_count = len([d for d in active_deployments.get(user_id, []) if d['status'] == 'running'])
    vps_count = len(user_vps.get(user_id, []))
    
    return render_template_string(
        MOBILE_APP_HTML,
        credits=f"{credits:.1f}" if credits != float('inf') else "∞",
        total_deploys=total_deploys,
        active_deploys=active_count,
        vps_count=vps_count,
        username=YOUR_USERNAME
    )

@app.route('/qr.jpg')
def serve_qr():
    """Serve QR code image"""
    qr_path = os.path.join(BASE_DIR, 'qr.jpg')
    if os.path.exists(qr_path):
        return send_file(qr_path, mimetype='image/jpeg')
    else:
        # Return placeholder if QR not found
        return "QR Code not found. Please add qr.jpg to the project directory.", 404

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
        logger.error(f"Upload error: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deploy/github', methods=['POST'])
def api_deploy_github():
    user_id = session.get('user_id', 999999)
    data = request.get_json()
    
    repo_url = data.get('url')
    branch = data.get('branch', 'main')
    build_cmd = data.get('build_cmd', '')
    start_cmd = data.get('start_cmd', '')
    
    if not repo_url:
        return jsonify({'success': False, 'error': 'Repository URL required'})
    
    deploy_id, msg = deploy_from_github(user_id, repo_url, branch, build_cmd, start_cmd)
    
    if deploy_id:
        return jsonify({'success': True, 'deployment_id': deploy_id, 'message': msg})
    else:
        return jsonify({'success': False, 'error': msg})

@app.route('/api/payment/submit', methods=['POST'])
def api_payment_submit():
    user_id = session.get('user_id', 999999)
    
    try:
        amount = float(request.form.get('amount'))
        screenshot = request.files.get('screenshot')
        
        if not amount or amount < 5:
            return jsonify({'success': False, 'error': 'Minimum 5 credits required'})
        
        if not screenshot:
            return jsonify({'success': False, 'error': 'Screenshot required'})
        
        # Save screenshot
        payment_id = str(uuid.uuid4())[:8]
        screenshot_filename = f"{payment_id}_{user_id}.jpg"
        screenshot_path = os.path.join(PAYMENTS_DIR, screenshot_filename)
        screenshot.save(screenshot_path)
        
        # Store payment request
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('''INSERT INTO payment_requests 
                        (id, user_id, amount, screenshot_path, status, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (payment_id, user_id, amount, screenshot_path, 'pending', datetime.now().isoformat()))
            conn.commit()
            conn.close()
        
        # Notify admin via bot
        try:
            bot.send_photo(
                OWNER_ID,
                photo=open(screenshot_path, 'rb'),
                caption=f"💳 *New Payment Request*\n\n"
                       f"User ID: `{user_id}`\n"
                       f"Amount: *{amount} Credits* (₹{amount * 10})\n"
                       f"Request ID: `{payment_id}`\n\n"
                       f"Check admin panel to approve/reject"
            )
        except Exception as e:
            logger.error(f"Failed to send payment notification: {e}")
        
        return jsonify({'success': True, 'request_id': payment_id})
    except Exception as e:
        logger.error(f"Payment submit error: {e}")
        return jsonify({'success': False, 'error': str(e)})

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

@app.route('/api/deployment/<deploy_id>/backup', methods=['POST'])
def api_create_backup(deploy_id):
    user_id = session.get('user_id', 999999)
    backup_id, msg = create_backup(user_id, deploy_id)
    
    if backup_id:
        return jsonify({'success': True, 'backup_id': backup_id, 'message': msg})
    else:
        return jsonify({'success': False, 'error': msg})

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

@app.route('/api/admin/stats')
def api_admin_stats():
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            
            c.execute('SELECT COUNT(*) FROM users')
            total_users = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM deployments WHERE status != "deleted"')
            total_deployments = c.fetchone()[0]
            
            c.execute('SELECT SUM(total_spent) FROM credits')
            total_spent = c.fetchone()[0] or 0
            
            c.execute('SELECT COUNT(*) FROM deployments WHERE dependencies_installed IS NOT NULL AND dependencies_installed != ""')
            ai_installs = c.fetchone()[0]
            
            conn.close()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_users': total_users,
                'total_deployments': total_deployments,
                'active_processes': len(active_processes),
                'total_spent': total_spent,
                'ai_installs': ai_installs
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/users')
def api_admin_users():
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('SELECT user_id, username, first_name, joined_date, total_deployments, pro_member FROM users ORDER BY joined_date DESC LIMIT 100')
            users = [{'user_id': r[0], 'username': r[1], 'first_name': r[2], 'joined_date': r[3], 'total_deployments': r[4], 'pro_member': r[5]} for r in c.fetchall()]
            conn.close()
        
        return jsonify({'success': True, 'users': users})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/deployments')
def api_admin_deployments():
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('SELECT id, user_id, name, status, port, created_at FROM deployments WHERE status != "deleted" ORDER BY created_at DESC LIMIT 100')
            deployments = [{'id': r[0], 'user_id': r[1], 'name': r[2], 'status': r[3], 'port': r[4], 'created_at': r[5]} for r in c.fetchall()]
            conn.close()
        
        return jsonify({'success': True, 'deployments': deployments})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/activity')
def api_admin_activity():
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('SELECT user_id, action, details, timestamp FROM activity_log ORDER BY timestamp DESC LIMIT 50')
            activity = [{'user_id': r[0], 'action': r[1], 'details': r[2], 'timestamp': r[3]} for r in c.fetchall()]
            conn.close()
        
        return jsonify({'success': True, 'activity': activity})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/health')
def api_admin_health():
    try:
        cpu = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
        
        return jsonify({
            'success': True,
            'health': {
                'cpu_percent': cpu,
                'memory_percent': memory,
                'disk_percent': disk,
                'active_processes': len(active_processes),
                'uptime': str(uptime).split('.')[0]
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/add-credits', methods=['POST'])
def api_admin_add_credits():
    data = request.get_json()
    target_user = data.get('user_id')
    amount = data.get('amount')
    
    if not target_user or not amount:
        return jsonify({'success': False, 'error': 'Missing parameters'})
    
    if add_credits(target_user, amount, "Admin bonus"):
        try:
            bot.send_message(target_user, f"🎉 *Bonus Credits!*\n\nYou received *{amount}* credits from admin!")
        except:
            pass
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to add credits'})

@app.route('/api/admin/payment-requests')
def api_admin_payment_requests():
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('SELECT id, user_id, amount, screenshot_path, status, created_at FROM payment_requests ORDER BY created_at DESC LIMIT 50')
            requests = [{'id': r[0], 'user_id': r[1], 'amount': r[2], 'screenshot_path': r[3], 'status': r[4], 'created_at': r[5]} for r in c.fetchall()]
            conn.close()
        
        return jsonify({'success': True, 'requests': requests})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/approve-payment', methods=['POST'])
def api_admin_approve_payment():
    data = request.get_json()
    request_id = data.get('request_id')
    user_id = data.get('user_id')
    amount = data.get('amount')
    
    try:
        # Add credits to user
        add_credits(user_id, amount, f"Payment approved: {request_id}")
        
        # Update payment request status
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('UPDATE payment_requests SET status = ?, processed_at = ? WHERE id = ?',
                     ('approved', datetime.now().isoformat(), request_id))
            conn.commit()
            conn.close()
        
        # Notify user via bot
        try:
            bot.send_message(user_id, 
                f"✅ *Payment Approved!*\n\n"
                f"Your payment has been verified.\n"
                f"*{amount} credits* added to your account!\n\n"
                f"Current Balance: *{get_credits(user_id):.1f}* credits")
        except:
            pass
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/admin/reject-payment', methods=['POST'])
def api_admin_reject_payment():
    data = request.get_json()
    request_id = data.get('request_id')
    
    try:
        # Get user_id before rejecting
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('SELECT user_id FROM payment_requests WHERE id = ?', (request_id,))
            result = c.fetchone()
            user_id = result[0] if result else None
            
            c.execute('UPDATE payment_requests SET status = ?, processed_at = ? WHERE id = ?',
                     ('rejected', datetime.now().isoformat(), request_id))
            conn.commit()
            conn.close()
        
        # Notify user via bot
        if user_id:
            try:
                bot.send_message(user_id, 
                    f"❌ *Payment Rejected*\n\n"
                    f"Your payment request was not approved.\n"
                    f"Please contact {YOUR_USERNAME} for details.")
            except:
                pass
        
        return jsonify({'success': True})
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

def create_main_menu(user_id):
    markup = types.InlineKeyboardMarkup(row_width=2)
    credits = get_credits(user_id)
    credit_text = "∞" if credits == float('inf') else f"{credits:.1f}"
    
    markup.add(types.InlineKeyboardButton(f'💎 {credit_text} Credits', callback_data='credits'))
    markup.add(
        types.InlineKeyboardButton('🚀 Deploy', callback_data='deploy'),
        types.InlineKeyboardButton('📊 Status', callback_data='status')
    )
    markup.add(
        types.InlineKeyboardButton('📱 Mobile App', callback_data='dashboard'),
        types.InlineKeyboardButton('💰 Buy Credits', callback_data='buy_credits')
    )
    
    if user_id in admin_ids:
        markup.add(types.InlineKeyboardButton('👑 Admin Panel', callback_data='admin'))
    
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
            bot.send_message(user_id, f"🎉 *Welcome Bonus!*\n\nYou received *{FREE_CREDITS} FREE credits*!")
    
    credits = get_credits(user_id)
    
    bot.send_message(
        message.chat.id,
        f"📱 *EliteHost Mobile App v9.1*\n\n"
        f"👤 *{first_name}*\n"
        f"💎 Credits: *{credits if credits != float('inf') else '∞'}*\n\n"
        f"*🎨 NEW FEATURES:*\n"
        f"✓ Buy Credits via QR Payment\n"
        f"✓ Admin login for panel only\n"
        f"✓ Normal users can use freely\n"
        f"✓ Payment screenshot to bot\n"
        f"✓ Auto credit addition\n\n"
        f"*🤖 AI Features:*\n"
        f"• Smart dependency detection\n"
        f"• Auto package installation\n"
        f"• Multi-language support\n\n"
        f"*📱 Open mobile app for full experience!*",
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
                f"📱 *EliteHost Mobile App*\n\n"
                f"🔗 Access: `http://localhost:{port}`\n\n"
                f"*✨ NEW v9.1 FEATURES:*\n"
                f"✓ Buy credits with QR payment\n"
                f"✓ Upload payment screenshot\n"
                f"✓ Admin approval system\n"
                f"✓ Auto credit addition\n"
                f"✓ Bottom navigation with Buy button\n\n"
                f"*🔐 Admin Panel Login:*\n"
                f"(Only for Admin Panel access)\n"
                f"Email: `Kvinit6421@gmail.com`\n"
                f"Password: `28@RajPapa`\n\n"
                f"*👥 Normal users can use all features without login!*")
        
        elif call.data == 'buy_credits':
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                f"💰 *Buy Credits*\n\n"
                f"*💎 Pricing:*\n"
                f"₹10 = 1 Credit\n"
                f"Minimum: 5 Credits (₹50)\n\n"
                f"*📱 How to Buy:*\n"
                f"1. Open mobile app\n"
                f"2. Go to 'Buy' tab\n"
                f"3. Scan QR code and pay\n"
                f"4. Upload payment screenshot\n"
                f"5. Wait for approval (5-30 min)\n\n"
                f"*⚡ Credits will be added automatically after verification!*\n\n"
                f"For instant credits, contact: {YOUR_USERNAME}")
        
        elif call.data == 'admin':
            if user_id not in admin_ids:
                bot.answer_callback_query(call.id, "⚠️ Admin only", show_alert=True)
                return
            
            with DB_LOCK:
                conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                c = conn.cursor()
                
                c.execute('SELECT COUNT(*) FROM users')
                total_users = c.fetchone()[0]
                
                c.execute('SELECT COUNT(*) FROM deployments WHERE status != "deleted"')
                total_deploys = c.fetchone()[0]
                
                c.execute('SELECT COUNT(*) FROM deployments WHERE status="running"')
                running = c.fetchone()[0]
                
                c.execute('SELECT COUNT(*) FROM payment_requests WHERE status="pending"')
                pending_payments = c.fetchone()[0]
                
                conn.close()
            
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                f"👑 *Admin Control Panel*\n\n"
                f"📊 *System Statistics:*\n"
                f"👥 Total Users: *{total_users}*\n"
                f"🚀 Total Deployments: *{total_deploys}*\n"
                f"🟢 Active Now: *{running}*\n"
                f"💳 Pending Payments: *{pending_payments}*\n"
                f"⚡ Active Processes: *{len(active_processes)}*\n\n"
                f"*Use mobile app for full admin panel!*")
        
        elif call.data == 'status':
            deploys = active_deployments.get(user_id, [])
            if not deploys:
                bot.answer_callback_query(call.id)
                bot.send_message(call.message.chat.id, 
                    "📊 *No Deployments*\n\nDeploy your first app!")
            else:
                running = sum(1 for d in deploys if d['status'] == 'running')
                
                status_text = f"📊 *Your Deployments*\n\n"
                status_text += f"📦 Total: *{len(deploys)}*\n"
                status_text += f"🟢 Running: *{running}*\n\n"
                status_text += "*📋 Recent Apps:*\n"
                
                for d in deploys[-5:]:
                    emoji = {
                        'running': '🟢', 'pending': '🟡', 'stopped': '🔴',
                        'installing': '📦', 'building': '🔨', 'failed': '❌'
                    }
                    status_text += f"{emoji.get(d['status'], '⚪')} `{d['name']}` - _{d['status']}_\n"
                
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
                f"💎 *Credit Balance*\n\n"
                f"Current: *{credits if credits != float('inf') else '∞'}*\n"
                f"Earned: *{earned}*\n"
                f"Spent: *{spent}*\n\n"
                f"*💰 Get More Credits*\n"
                f"Use 'Buy Credits' in mobile app!\n"
                f"Or contact: {YOUR_USERNAME}")
        
        else:
            bot.answer_callback_query(call.id, "Use mobile app!", show_alert=True)
    
    except Exception as e:
        logger.error(f"Callback error: {e}")
        bot.answer_callback_query(call.id, "Error")

@bot.message_handler(content_types=['document', 'photo'])
def handle_file(message):
    user_id = message.from_user.id
    
    try:
        # Handle document
        if message.document:
            file_info = bot.get_file(message.document.file_id)
            filename = message.document.file_name
            
            if not filename.endswith(('.py', '.js', '.zip')):
                bot.reply_to(message, "❌ *Unsupported File*\n\nSupported: `.py`, `.js`, `.zip`")
                return
            
            file_content = bot.download_file(file_info.file_path)
            user_dir = os.path.join(UPLOADS_DIR, str(user_id))
            os.makedirs(user_dir, exist_ok=True)
            filepath = os.path.join(user_dir, secure_filename(filename))
            
            with open(filepath, 'wb') as f:
                f.write(file_content)
            
            bot.reply_to(message, "🤖 *AI Analyzing Project...*\n\nPlease wait...")
            deploy_id, msg = deploy_from_file(user_id, filepath, filename)
            
            if deploy_id:
                bot.send_message(message.chat.id,
                    f"✅ *Deployment Successful!*\n\n"
                    f"🆔 ID: `{deploy_id}`\n"
                    f"🤖 AI auto-installed dependencies\n"
                    f"📦 Project optimized\n\n"
                    f"{msg}\n\n"
                    f"*View in mobile app!* 📱")
            else:
                bot.send_message(message.chat.id, f"❌ *Deployment Failed*\n\n{msg}")
        
        # Handle photo (payment screenshot)
        elif message.photo:
            bot.reply_to(message, 
                "📸 *Payment Screenshot Received!*\n\n"
                "To submit payment:\n"
                "1. Open mobile app\n"
                "2. Go to 'Buy' tab\n"
                "3. Upload screenshot there\n\n"
                "Or use /buy command for manual submission")
    
    except Exception as e:
        logger.error(f"File error: {e}")
        bot.reply_to(message, f"❌ *Error:* {e}")

@bot.message_handler(commands=['addcredits'])
def addcredits_cmd(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ *Admin Only*")
        return
    
    try:
        parts = message.text.split()
        if len(parts) != 3:
            bot.reply_to(message, "*Usage:* `/addcredits USER_ID AMOUNT`")
            return
        
        target_user = int(parts[1])
        amount = float(parts[2])
        
        if add_credits(target_user, amount, "Admin bonus"):
            bot.reply_to(message, f"✅ *Success*\n\nAdded *{amount}* credits to user `{target_user}`")
            try:
                bot.send_message(target_user, f"🎉 *Bonus Credits!*\n\nYou received *{amount}* credits from admin!")
            except:
                pass
        else:
            bot.reply_to(message, "❌ *Failed to add credits*")
    except Exception as e:
        bot.reply_to(message, f"❌ *Error:* {e}")

@bot.message_handler(commands=['stats'])
def stats_cmd(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ *Admin Only*")
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
        
        c.execute('SELECT COUNT(*) FROM payment_requests WHERE status="pending"')
        pending_payments = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM deployments WHERE dependencies_installed IS NOT NULL AND dependencies_installed != ""')
        auto_installed = c.fetchone()[0]
        
        conn.close()
    
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    
    stats_text = f"📊 *EliteHost System Statistics*\n\n"
    stats_text += f"*👥 Users & Deployments:*\n"
    stats_text += f"• Total Users: *{total_users}*\n"
    stats_text += f"• Total Deploys: *{total_deploys}*\n"
    stats_text += f"• Running Now: *{running_deploys}*\n"
    stats_text += f"• Active Processes: *{len(active_processes)}*\n\n"
    stats_text += f"*💰 Payments:*\n"
    stats_text += f"• Pending Requests: *{pending_payments}*\n"
    stats_text += f"• Total Spent: *{total_spent:.1f}*\n\n"
    stats_text += f"*🤖 AI Features:*\n"
    stats_text += f"• AI Auto-Installs: *{auto_installed}*\n\n"
    stats_text += f"*⚡ System Health:*\n"
    stats_text += f"• CPU Usage: *{cpu:.1f}%*\n"
    stats_text += f"• Memory: *{memory:.1f}%*\n"
    stats_text += f"• Disk: *{disk:.1f}%*"
    
    bot.reply_to(message, stats_text)

@bot.message_handler(commands=['backup'])
def backup_cmd(message):
    user_id = message.from_user.id
    
    try:
        parts = message.text.split()
        if len(parts) != 2:
            bot.reply_to(message, "*Usage:* `/backup DEPLOYMENT_ID`")
            return
        
        deploy_id = parts[1]
        
        user_deploys = active_deployments.get(user_id, [])
        if not any(d['id'] == deploy_id for d in user_deploys) and user_id not in admin_ids:
            bot.reply_to(message, "❌ *Deployment not found*")
            return
        
        bot.reply_to(message, "⏳ *Creating backup...*")
        backup_id, msg = create_backup(user_id, deploy_id)
        
        if backup_id:
            bot.send_message(message.chat.id, f"✅ *Backup Created!*\n\n{msg}\n\nBackup ID: `{backup_id}`")
        else:
            bot.send_message(message.chat.id, f"❌ *Backup Failed*\n\n{msg}")
    except Exception as e:
        bot.reply_to(message, f"❌ *Error:* {e}")

@bot.message_handler(commands=['help'])
def help_cmd(message):
    user_id = message.from_user.id
    is_admin = user_id in admin_ids
    
    help_text = f"📱 *EliteHost Mobile App - Help*\n\n"
    help_text += f"*📱 Basic Commands:*\n"
    help_text += f"/start - Start the bot\n"
    help_text += f"/help - Show this help\n"
    help_text += f"/backup DEPLOY_ID - Create backup\n\n"
    help_text += f"*🎯 Features:*\n"
    help_text += f"• Upload files (.py, .js, .zip)\n"
    help_text += f"• AI auto-installs dependencies\n"
    help_text += f"• GitHub/GitLab integration\n"
    help_text += f"• Real-time monitoring\n"
    help_text += f"• Buy credits via QR payment\n"
    help_text += f"• Environment variables\n"
    help_text += f"• Mobile app interface\n\n"
    
    if is_admin:
        help_text += f"*👑 Admin Commands:*\n"
        help_text += f"/addcredits USER_ID AMOUNT\n"
        help_text += f"/stats - System statistics\n\n"
    
    help_text += f"*📱 Mobile App:*\n"
    help_text += f"Open the mobile app for full features!\n"
    help_text += f"URL: `http://localhost:{os.environ.get('PORT', 8080)}`\n\n"
    help_text += f"*💰 Buy Credits:*\n"
    help_text += f"1. Open mobile app\n"
    help_text += f"2. Click 'Buy' tab in bottom nav\n"
    help_text += f"3. Scan QR code and pay\n"
    help_text += f"4. Upload screenshot\n"
    help_text += f"5. Wait for approval!\n\n"
    help_text += f"Contact: {YOUR_USERNAME}"
    
    bot.reply_to(message, help_text)

# ==================== CLEANUP ====================

def cleanup_on_exit():
    logger.warning(f"{Fore.YELLOW}🛑 Shutting down EliteHost...")
    
    for deploy_id, process in list(active_processes.items()):
        try:
            logger.info(f"Stopping deployment {deploy_id}...")
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
    print(f"{Fore.CYAN}{'📱 ELITEHOST MOBILE APP v9.1 - ENHANCED EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}🐍 Python: {sys.version.split()[0]}")
    print(f"{Fore.GREEN}📁 Data Directory: {DATA_DIR}")
    print(f"{Fore.GREEN}👑 Owner ID: {OWNER_ID}")
    print(f"{Fore.GREEN}👨‍💼 Admin ID: {ADMIN_ID}")
    print(f"{Fore.YELLOW}🎁 Free Credits: {FREE_CREDITS}")
    print("=" * 90)
    print(f"{Fore.MAGENTA}📱 MOBILE APP v9.1 FEATURES:")
    print("")
    print(f"{Fore.CYAN}🎨 Native App Design")
    print("   └ Bottom navigation bar (5 items)")
    print("   └ Pull-to-refresh functionality")
    print("   └ Slide-up modals & panels")
    print("   └ Touch-optimized controls")
    print("   └ App-like transitions")
    print("")
    print(f"{Fore.CYAN}🔐 Selective Admin Authentication")
    print("   └ Admin login ONLY for Admin Panel")
    print("   └ Normal users can use all features freely")
    print("   └ Email: Kvinit6421@gmail.com")
    print("   └ Password: 28@RajPapa")
    print("")
    print(f"{Fore.CYAN}💰 Integrated Payment System")
    print("   └ Buy Credits tab in bottom nav")
    print("   └ QR code payment (qr.jpg)")
    print("   └ Screenshot upload from app")
    print("   └ Auto-send to bot for approval")
    print("   └ Admin approve/reject payments")
    print("   └ Auto credit addition after approval")
    print("")
    print(f"{Fore.CYAN}🤖 AI-Powered Auto-Install")
    print("   └ Smart dependency detection")
    print("   └ Auto package installation")
    print("   └ Multi-language support")
    print("   └ Code analysis")
    print("")
    print(f"{Fore.CYAN}🔄 Real-Time Bot Sync")
    print("   └ All deployments sync to bot")
    print("   └ Payment screenshots to admin bot")
    print("   └ Telegram notifications")
    print("   └ Unified tracking")
    print("")
    print(f"{Fore.CYAN}📊 Advanced Features")
    print("   └ Real-time monitoring")
    print("   └ Environment variables")
    print("   └ GitHub integration")
    print("   └ Backup system")
    print("   └ Payment management")
    print("")
    print("=" * 90)
    print(f"{Fore.YELLOW}💡 IMPORTANT NOTES:")
    print(f"{Fore.CYAN}   • Add 'qr.jpg' to project root for QR payment")
    print(f"{Fore.CYAN}   • Admin panel requires login (secure)")
    print(f"{Fore.CYAN}   • Normal users can use without login")
    print(f"{Fore.CYAN}   • Payment screenshots auto-forward to bot")
    print(f"{Fore.CYAN}   • 5 bottom nav items: Home, Deploys, Upload, Buy, Admin")
    print("=" * 90)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}📱 Mobile App: http://localhost:{port}")
    print(f"{Fore.CYAN}📱 Telegram Bot: {TELEGRAM_LINK}")
    print(f"{Fore.MAGENTA}🔐 Admin Panel Login: Kvinit6421@gmail.com / 28@RajPapa")
    print(f"{Fore.YELLOW}💰 Add qr.jpg for payment QR code")
    print(f"{Fore.YELLOW}🤖 Starting Telegram bot...\n")
    print("=" * 90)
    print(f"{Fore.GREEN}{'🎉 ELITEHOST v9.1 READY - BUY CREDITS ENABLED':^90}")
    print("=" * 90 + "\n")
    
    while True:
        try:
            logger.info(f"{Fore.GREEN}🤖 EliteHost bot polling - Payment system active!")
            bot.infinity_polling(timeout=60, long_polling_timeout=30)
        except Exception as e:
            logger.error(f"{Fore.RED}Polling error: {e}")
            time.sleep(5)
                                
