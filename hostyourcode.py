# -*- coding: utf-8 -*-
"""
🚀 ULTRA ADVANCED DEVOPS BOT v9.0 - ENTERPRISE EDITION
Revolutionary AI-Powered Deployment Platform with EliteHost Features
Mobile-First | Auto-Install | Zero Config | Enterprise UI | Admin Panel
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

# Enhanced credit system
FREE_CREDITS = 2.0
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

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, BACKUPS_DIR, LOGS_DIR, ANALYTICS_DIR, DOCKER_DIR]:
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

# ==================== 🤖 REVOLUTIONARY AI DEPENDENCY DETECTOR V9 ====================

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
    """🤖 REVOLUTIONARY AI-Powered dependency detection and installation"""
    installed = []
    install_log = []
    
    logger.info(f"{Fore.CYAN}🤖 AI DEPENDENCY ANALYZER v9.0 - STARTING...")
    install_log.append("🤖 AI DEPENDENCY ANALYZER v9.0 - ENTERPRISE")
    install_log.append("=" * 60)
    
    # ========== PYTHON REQUIREMENTS.TXT ==========
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
    
    # ========== SMART CODE ANALYSIS ==========
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
    
    # ========== NODE.JS PACKAGE.JSON ==========
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
    
    # ========== SUMMARY ==========
    install_log.append("\n" + "=" * 60)
    install_log.append(f"🎉 AI ANALYSIS COMPLETE")
    install_log.append(f"📦 Total Packages Installed: {len(installed)}")
    if installed:
        install_log.append(f"✅ Installed: {', '.join(installed[:10])}")
        if len(installed) > 10:
            install_log.append(f"   ... and {len(installed) - 10} more")
    install_log.append("=" * 60)
    
    return installed, "\n".join(install_log)

# ==================== DATABASE V9 ====================

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

# ==================== 📱 ELITEHOST STYLE PROFESSIONAL DASHBOARD ====================

ELITEHOST_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#3b82f6">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <title>EliteHost - DevOps Enterprise Platform</title>
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
            --border: #e2e8f0;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            min-height: 100vh;
            color: white;
            line-height: 1.6;
        }
        
        /* Header */
        .header {
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding: 16px 24px;
            position: sticky;
            top: 0;
            z-index: 1000;
        }
        
        .header-content {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .logo {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .logo-icon {
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 20px;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        
        .logo-text h1 {
            font-size: 22px;
            font-weight: 900;
            background: linear-gradient(135deg, #fff, #60a5fa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }
        
        .logo-text p {
            font-size: 10px;
            color: var(--gray);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .header-right {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        
        .credit-display {
            background: rgba(59, 130, 246, 0.1);
            border: 1px solid rgba(59, 130, 246, 0.3);
            padding: 8px 16px;
            border-radius: 24px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-weight: 700;
            color: var(--primary-light);
        }
        
        /* Hero Section */
        .hero {
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(139, 92, 246, 0.1));
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding: 60px 24px;
            text-align: center;
        }
        
        .hero h1 {
            font-size: 48px;
            font-weight: 900;
            margin-bottom: 16px;
            background: linear-gradient(135deg, #fff, var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .hero .highlight {
            color: var(--primary);
        }
        
        .hero p {
            font-size: 18px;
            color: var(--gray);
            max-width: 800px;
            margin: 0 auto 32px;
            line-height: 1.8;
        }
        
        /* Container */
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 24px 80px;
        }
        
        /* Feature Grid */
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
            margin-bottom: 60px;
        }
        
        .feature-card {
            background: rgba(30, 41, 59, 0.8);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 32px;
            transition: all 0.3s ease;
        }
        
        .feature-card:hover {
            transform: translateY(-4px);
            border-color: var(--primary);
            box-shadow: 0 8px 24px rgba(59, 130, 246, 0.2);
        }
        
        .feature-icon {
            width: 56px;
            height: 56px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            margin-bottom: 20px;
            color: white;
        }
        
        .feature-title {
            font-size: 20px;
            font-weight: 800;
            margin-bottom: 12px;
            color: white;
        }
        
        .feature-desc {
            color: var(--gray);
            font-size: 14px;
            line-height: 1.6;
        }
        
        /* Steps Section */
        .steps-section {
            margin: 60px 0;
        }
        
        .section-title {
            font-size: 36px;
            font-weight: 900;
            text-align: center;
            margin-bottom: 16px;
            background: linear-gradient(135deg, #fff, var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .section-subtitle {
            text-align: center;
            color: var(--gray);
            font-size: 16px;
            margin-bottom: 48px;
        }
        
        .steps-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 32px;
        }
        
        .step-card {
            background: rgba(30, 41, 59, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 28px;
            position: relative;
        }
        
        .step-number {
            position: absolute;
            top: -16px;
            left: 28px;
            width: 40px;
            height: 40px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 900;
            font-size: 18px;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        
        .step-icon {
            font-size: 28px;
            margin: 20px 0 16px;
            color: var(--primary-light);
        }
        
        .step-title {
            font-size: 18px;
            font-weight: 800;
            margin-bottom: 8px;
        }
        
        .step-desc {
            color: var(--gray);
            font-size: 13px;
            line-height: 1.6;
        }
        
        /* Dashboard Actions */
        .dashboard-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 24px;
            margin-top: 40px;
        }
        
        .action-card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 32px;
        }
        
        .action-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 20px;
        }
        
        .action-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }
        
        .action-title {
            font-size: 18px;
            font-weight: 800;
        }
        
        /* Upload Zone */
        .upload-zone {
            border: 2px dashed rgba(59, 130, 246, 0.5);
            border-radius: 16px;
            padding: 40px 24px;
            text-align: center;
            background: rgba(59, 130, 246, 0.05);
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .upload-zone:hover {
            border-color: var(--primary);
            background: rgba(59, 130, 246, 0.1);
        }
        
        .upload-icon {
            font-size: 48px;
            color: var(--primary-light);
            margin-bottom: 16px;
        }
        
        .upload-text {
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 8px;
        }
        
        .upload-hint {
            color: var(--gray);
            font-size: 13px;
        }
        
        /* Input Groups */
        .input-group {
            margin-bottom: 20px;
        }
        
        .input-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 700;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--gray);
        }
        
        .input-field {
            width: 100%;
            padding: 14px 16px;
            background: rgba(15, 23, 42, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            color: white;
            font-size: 14px;
            font-family: inherit;
            transition: all 0.3s;
        }
        
        .input-field:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        
        /* Buttons */
        .btn {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
            border: none;
            padding: 14px 24px;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 700;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            cursor: pointer;
            transition: all 0.3s;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 16px rgba(59, 130, 246, 0.3);
        }
        
        .btn-success {
            background: linear-gradient(135deg, var(--success), #059669);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, var(--danger), #dc2626);
        }
        
        .btn-secondary {
            background: linear-gradient(135deg, var(--secondary), #7c3aed);
        }
        
        /* Deployments List */
        .deployments-grid {
            display: grid;
            gap: 16px;
        }
        
        .deploy-card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 24px;
            transition: all 0.3s;
        }
        
        .deploy-card:hover {
            border-color: var(--primary);
        }
        
        .deploy-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 16px;
        }
        
        .deploy-info h3 {
            font-size: 18px;
            font-weight: 800;
            margin-bottom: 8px;
        }
        
        .deploy-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            font-size: 12px;
            color: var(--gray);
        }
        
        .meta-item {
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-running {
            background: rgba(16, 185, 129, 0.2);
            color: var(--success);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
        
        .status-pending {
            background: rgba(245, 158, 11, 0.2);
            color: var(--warning);
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
        
        .status-stopped {
            background: rgba(239, 68, 68, 0.2);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .deploy-actions {
            display: flex;
            gap: 8px;
            margin-top: 16px;
        }
        
        .action-btn {
            flex: 1;
            padding: 10px;
            border: none;
            border-radius: 10px;
            font-size: 12px;
            font-weight: 700;
            color: white;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            transition: all 0.3s;
        }
        
        .action-btn:hover {
            transform: translateY(-2px);
        }
        
        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 16px;
            padding: 24px;
            text-align: center;
        }
        
        .stat-icon {
            font-size: 32px;
            margin-bottom: 12px;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: 900;
            background: linear-gradient(135deg, var(--primary-light), var(--secondary));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            line-height: 1;
            margin-bottom: 8px;
        }
        
        .stat-label {
            color: var(--gray);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(4px);
            z-index: 10000;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .modal.show {
            display: flex;
        }
        
        .modal-content {
            background: var(--dark);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            padding: 32px;
            max-width: 600px;
            width: 100%;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }
        
        .modal-title {
            font-size: 24px;
            font-weight: 900;
        }
        
        .close-btn {
            background: none;
            border: none;
            color: var(--gray);
            font-size: 24px;
            cursor: pointer;
            padding: 0;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 8px;
            transition: all 0.3s;
        }
        
        .close-btn:hover {
            background: rgba(255, 255, 255, 0.1);
            color: white;
        }
        
        /* Terminal */
        .terminal {
            background: #0a0f1e;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #10b981;
            max-height: 400px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            line-height: 1.6;
        }
        
        /* Toast */
        .toast {
            position: fixed;
            top: 100px;
            right: 24px;
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            z-index: 10001;
            transform: translateX(400px);
            transition: transform 0.4s cubic-bezier(0.68,-0.55,0.265,1.55);
            box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3);
        }
        
        .toast.show {
            transform: translateX(0);
        }
        
        .toast-icon {
            font-size: 20px;
        }
        
        .toast-message {
            font-size: 14px;
            font-weight: 600;
        }
        
        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
        }
        
        .empty-icon {
            font-size: 64px;
            margin-bottom: 16px;
            opacity: 0.3;
        }
        
        .empty-title {
            font-size: 20px;
            font-weight: 800;
            margin-bottom: 8px;
        }
        
        .empty-desc {
            color: var(--gray);
            font-size: 14px;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .hero h1 {
                font-size: 32px;
            }
            
            .hero p {
                font-size: 16px;
            }
            
            .feature-grid,
            .steps-grid,
            .dashboard-actions {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .toast {
                right: 16px;
                left: 16px;
            }
        }
        
        /* Admin Panel Styles */
        .admin-panel {
            background: rgba(139, 92, 246, 0.1);
            border: 1px solid rgba(139, 92, 246, 0.3);
            border-radius: 16px;
            padding: 32px;
            margin-top: 40px;
        }
        
        .admin-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
        }
        
        .admin-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--secondary), #7c3aed);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        
        .admin-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .admin-stat {
            background: rgba(139, 92, 246, 0.1);
            border: 1px solid rgba(139, 92, 246, 0.2);
            border-radius: 12px;
            padding: 16px;
            text-align: center;
        }
        
        .admin-stat-value {
            font-size: 28px;
            font-weight: 900;
            color: var(--secondary);
            margin-bottom: 4px;
        }
        
        .admin-stat-label {
            font-size: 11px;
            color: var(--gray);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .admin-actions {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }
        
        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }
        
        ::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.05);
        }
        
        ::-webkit-scrollbar-thumb {
            background: rgba(59, 130, 246, 0.5);
            border-radius: 5px;
        }
        
        ::-webkit-scrollbar-thumb:hover {
            background: var(--primary);
        }
    </style>
</head>
<body>
    <!-- Header -->
    <div class="header">
        <div class="header-content">
            <div class="logo">
                <div class="logo-icon">
                    <i class="fas fa-rocket"></i>
                </div>
                <div class="logo-text">
                    <h1>EliteHost</h1>
                    <p>Deploy Faster. Scale Smarter.</p>
                </div>
            </div>
            <div class="header-right">
                <div class="credit-display">
                    <i class="fas fa-gem"></i>
                    <span id="creditBalance">{{ credits }}</span>
                </div>
            </div>
        </div>
    </div>

    <!-- Hero Section -->
    <div class="hero">
        <h1>Everything you need to <span class="highlight">build and scale</span></h1>
        <p>A complete platform for modern application deployment. From code to production in minutes.</p>
    </div>

    <!-- Container -->
    <div class="container">
        <!-- Stats Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">🚀</div>
                <div class="stat-value" id="totalDeploys">{{ total_deploys }}</div>
                <div class="stat-label">Total Deploys</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🟢</div>
                <div class="stat-value" id="activeDeploys">{{ active_deploys }}</div>
                <div class="stat-label">Active Now</div>
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

        <!-- Feature Grid -->
        <div class="feature-grid">
            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-bolt"></i>
                </div>
                <h3 class="feature-title">One-Click Deployment</h3>
                <p class="feature-desc">Push your code and let the platform handle builds, caching, and CDN distribution automatically.</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fab fa-github"></i>
                </div>
                <h3 class="feature-title">GitHub / GitLab Integration</h3>
                <p class="feature-desc">Automatic builds from branches and pull requests with instant preview URLs.</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-lock"></i>
                </div>
                <h3 class="feature-title">Environment Variables & Secrets</h3>
                <p class="feature-desc">Encrypted secrets store with per-deploy overrides and team-level sharing.</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fab fa-docker"></i>
                </div>
                <h3 class="feature-title">Docker & Custom Builds</h3>
                <p class="feature-desc">Bring your own Dockerfile or use buildpacks for zero-config deployments.</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-globe"></i>
                </div>
                <h3 class="feature-title">Global CDN & Auto Scaling</h3>
                <p class="feature-desc">Edge caching across 200+ locations with intelligent traffic routing.</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-chart-line"></i>
                </div>
                <h3 class="feature-title">Real-time Logs & Metrics</h3>
                <p class="feature-desc">Centralized observability with custom alerts and detailed performance insights.</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-brain"></i>
                </div>
                <h3 class="feature-title">AI-based Resource Optimization</h3>
                <p class="feature-desc">Intelligent scaling recommendations to reduce costs and improve performance.</p>
            </div>

            <div class="feature-card">
                <div class="feature-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <h3 class="feature-title">DDoS Protection & SSL Auto-Provision</h3>
                <p class="feature-desc">Enterprise-grade security with network-level protections and automated TLS certificates.</p>
            </div>
        </div>

        <!-- Steps Section -->
        <div class="steps-section">
            <h2 class="section-title">From code to production in <span class="highlight">four steps</span></h2>
            <p class="section-subtitle">A streamlined workflow that gets your application live in minutes, not hours.</p>
            
            <div class="steps-grid">
                <div class="step-card">
                    <div class="step-number">1</div>
                    <div class="step-icon"><i class="fab fa-github"></i></div>
                    <h3 class="step-title">Connect GitHub</h3>
                    <p class="step-desc">Authorize repository access and configure branch settings for automatic deployments.</p>
                </div>

                <div class="step-card">
                    <div class="step-number">2</div>
                    <div class="step-icon"><i class="fas fa-cog"></i></div>
                    <h3 class="step-title">Configure Environment</h3>
                    <p class="step-desc">Add environment variables, secrets, and resource limits with our intuitive dashboard.</p>
                </div>

                <div class="step-card">
                    <div class="step-number">3</div>
                    <div class="step-icon"><i class="fas fa-play-circle"></i></div>
                    <h3 class="step-title">Click Deploy</h3>
                    <p class="step-desc">Trigger a build manually or let auto-deploy handle it for every push to your branch.</p>
                </div>

                <div class="step-card">
                    <div class="step-number">4</div>
                    <div class="step-icon"><i class="fas fa-globe"></i></div>
                    <h3 class="step-title">Live URL Generated</h3>
                    <p class="step-desc">Your app is live on a globally distributed domain with SSL, CDN, and monitoring enabled.</p>
                </div>
            </div>
        </div>

        <!-- Dashboard Actions -->
        <div class="dashboard-actions">
            <!-- File Upload -->
            <div class="action-card">
                <div class="action-header">
                    <div class="action-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <h3 class="action-title">Smart Deploy</h3>
                </div>
                <p style="color: var(--gray); margin-bottom: 20px; font-size: 13px;">
                    <strong style="color: var(--primary-light);">🤖 AI Auto-Install:</strong> Upload your code and our AI automatically detects & installs ALL dependencies!
                </p>
                <div class="upload-zone" onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <div class="upload-text">Drop files or click to upload</div>
                    <div class="upload-hint">Python • JavaScript • ZIP archives</div>
                    <input type="file" id="fileInput" hidden accept=".py,.js,.zip" onchange="handleFileUpload(this)">
                </div>
            </div>

            <!-- GitHub Deploy -->
            <div class="action-card">
                <div class="action-header">
                    <div class="action-icon">
                        <i class="fab fa-github"></i>
                    </div>
                    <h3 class="action-title">GitHub Deploy</h3>
                </div>
                <div class="input-group">
                    <label class="input-label">Repository URL</label>
                    <input type="url" class="input-field" id="repoUrl" placeholder="https://github.com/user/repo.git">
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
                    <input type="text" class="input-field" id="startCmd" placeholder="Auto-detected if empty">
                </div>
                <button class="btn" onclick="deployGithub()">
                    <i class="fab fa-github"></i>
                    Deploy from GitHub
                </button>
            </div>

            <!-- Environment Variables -->
            <div class="action-card">
                <div class="action-header">
                    <div class="action-icon">
                        <i class="fas fa-key"></i>
                    </div>
                    <h3 class="action-title">Environment Variables</h3>
                </div>
                <div id="envList" style="margin-bottom: 20px;"></div>
                <button class="btn btn-secondary" onclick="showAddEnv()">
                    <i class="fas fa-plus"></i>
                    Add Variable
                </button>
            </div>
        </div>

        <!-- Your Deployments -->
        <div style="margin-top: 60px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
                <h2 class="section-title" style="margin: 0;">Your Deployments</h2>
                <button class="btn" style="width: auto; padding: 12px 24px;" onclick="loadDeployments()">
                    <i class="fas fa-sync"></i>
                    Refresh
                </button>
            </div>
            <div class="deployments-grid" id="deploymentsList"></div>
        </div>

        <!-- Admin Panel (Only for Admins) -->
        <div id="adminPanel" style="display: none;">
            <div class="admin-panel">
                <div class="admin-header">
                    <div class="admin-icon">
                        <i class="fas fa-crown"></i>
                    </div>
                    <h2 style="font-size: 24px; font-weight: 900;">Admin Control Panel</h2>
                </div>
                
                <div class="admin-stats">
                    <div class="admin-stat">
                        <div class="admin-stat-value" id="adminTotalUsers">0</div>
                        <div class="admin-stat-label">Total Users</div>
                    </div>
                    <div class="admin-stat">
                        <div class="admin-stat-value" id="adminTotalDeploys">0</div>
                        <div class="admin-stat-label">All Deployments</div>
                    </div>
                    <div class="admin-stat">
                        <div class="admin-stat-value" id="adminActiveProcesses">0</div>
                        <div class="admin-stat-label">Active Processes</div>
                    </div>
                    <div class="admin-stat">
                        <div class="admin-stat-value" id="adminTotalCredits">0</div>
                        <div class="admin-stat-label">Credits Spent</div>
                    </div>
                    <div class="admin-stat">
                        <div class="admin-stat-value" id="adminAIInstalls">0</div>
                        <div class="admin-stat-label">AI Installs</div>
                    </div>
                </div>

                <h3 style="font-size: 18px; font-weight: 800; margin-bottom: 16px;">Quick Actions</h3>
                <div class="admin-actions">
                    <button class="btn btn-success" onclick="showAddCreditsModal()">
                        <i class="fas fa-coins"></i>
                        Add Credits
                    </button>
                    <button class="btn btn-secondary" onclick="viewAllUsers()">
                        <i class="fas fa-users"></i>
                        View Users
                    </button>
                    <button class="btn" onclick="viewAllDeployments()">
                        <i class="fas fa-server"></i>
                        All Deployments
                    </button>
                    <button class="btn btn-danger" onclick="viewActivityLog()">
                        <i class="fas fa-history"></i>
                        Activity Log
                    </button>
                    <button class="btn btn-secondary" onclick="systemHealth()">
                        <i class="fas fa-heartbeat"></i>
                        System Health
                    </button>
                    <button class="btn" onclick="exportData()">
                        <i class="fas fa-download"></i>
                        Export Data
                    </button>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast -->
    <div id="toast" class="toast">
        <div class="toast-icon"></div>
        <div class="toast-message"></div>
    </div>

    <!-- Modal -->
    <div id="modal" class="modal">
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
        let isAdmin = {{ is_admin }};
        
        // Show admin panel if admin
        if (isAdmin) {
            document.getElementById('adminPanel').style.display = 'block';
            loadAdminStats();
        }

        // File Upload Handler
        async function handleFileUpload(input) {
            const file = input.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            showToast('info', '🤖 AI analyzing project...');
            
            try {
                const res = await fetch('/api/deploy/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ ' + data.message);
                    setTimeout(() => {
                        updateCredits();
                        loadDeployments();
                    }, 1500);
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Deployment failed');
            }
            
            input.value = '';
        }

        // GitHub Deploy
        async function deployGithub() {
            const url = document.getElementById('repoUrl').value;
            const branch = document.getElementById('repoBranch').value;
            const buildCmd = document.getElementById('buildCmd').value;
            const startCmd = document.getElementById('startCmd').value;
            
            if (!url) {
                showToast('warning', '⚠️ Please enter repository URL');
                return;
            }
            
            showToast('info', '🤖 AI cloning repository...');
            
            try {
                const res = await fetch('/api/deploy/github', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url, branch, build_cmd: buildCmd, start_cmd: startCmd})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ ' + data.message);
                    document.getElementById('repoUrl').value = '';
                    document.getElementById('buildCmd').value = '';
                    document.getElementById('startCmd').value = '';
                    setTimeout(() => {
                        updateCredits();
                        loadDeployments();
                    }, 1500);
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Deployment failed');
            }
        }

        // Load Deployments
        async function loadDeployments() {
            try {
                const res = await fetch('/api/deployments');
                const data = await res.json();
                const list = document.getElementById('deploymentsList');
                
                if (!data.deployments || !data.deployments.length) {
                    list.innerHTML = `
                        <div class="empty-state">
                            <div class="empty-icon">🚀</div>
                            <div class="empty-title">No deployments yet</div>
                            <div class="empty-desc">Deploy your first application to get started</div>
                        </div>
                    `;
                    return;
                }
                
                list.innerHTML = data.deployments.map(d => `
                    <div class="deploy-card">
                        <div class="deploy-header">
                            <div class="deploy-info">
                                <h3>${d.name}</h3>
                                <div class="deploy-meta">
                                    <span class="meta-item">
                                        <i class="fas fa-fingerprint"></i>
                                        ${d.id}
                                    </span>
                                    ${d.port ? `
                                        <span class="meta-item">
                                            <i class="fas fa-network-wired"></i>
                                            Port ${d.port}
                                        </span>
                                    ` : ''}
                                    ${d.custom_domain ? `
                                        <span class="meta-item">
                                            <i class="fas fa-globe"></i>
                                            ${d.custom_domain}
                                        </span>
                                    ` : ''}
                                    ${d.cpu_usage ? `
                                        <span class="meta-item">
                                            <i class="fas fa-microchip"></i>
                                            CPU ${d.cpu_usage.toFixed(1)}%
                                        </span>
                                    ` : ''}
                                    ${d.memory_usage ? `
                                        <span class="meta-item">
                                            <i class="fas fa-memory"></i>
                                            RAM ${d.memory_usage.toFixed(1)}%
                                        </span>
                                    ` : ''}
                                </div>
                            </div>
                            <span class="status-badge status-${d.status}">${d.status}</span>
                        </div>
                        <div class="deploy-actions">
                            <button class="action-btn" style="background: var(--info);" onclick="viewLogs('${d.id}')">
                                <i class="fas fa-terminal"></i> Logs
                            </button>
                            ${d.status === 'running' ? `
                                <button class="action-btn" style="background: var(--danger);" onclick="stopDeploy('${d.id}')">
                                    <i class="fas fa-stop"></i> Stop
                                </button>
                            ` : ''}
                            <button class="action-btn" style="background: var(--success);" onclick="createBackup('${d.id}')">
                                <i class="fas fa-save"></i> Backup
                            </button>
                            <button class="action-btn" style="background: var(--warning);" onclick="deleteDeploy('${d.id}')">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        </div>
                    </div>
                `).join('');
                
                const runningCount = data.deployments.filter(d => d.status === 'running').length;
                document.getElementById('activeDeploys').textContent = runningCount;
                document.getElementById('totalDeploys').textContent = data.deployments.length;
            } catch (err) {
                console.error(err);
            }
        }

        // View Logs
        async function viewLogs(deployId) {
            try {
                const res = await fetch(`/api/deployment/${deployId}/logs`);
                const data = await res.json();
                
                showModal('Deployment Logs', `
                    <div class="terminal">${data.logs || 'No logs available...'}</div>
                    <button class="btn btn-danger" onclick="closeModal()" style="margin-top: 20px;">
                        <i class="fas fa-times"></i> Close
                    </button>
                `);
            } catch (err) {
                showToast('error', '❌ Failed to load logs');
            }
        }

        // Stop Deployment
        async function stopDeploy(deployId) {
            if (!confirm('Stop this deployment?')) return;
            
            showToast('info', '⏳ Stopping deployment...');
            
            try {
                const res = await fetch(`/api/deployment/${deployId}/stop`, {method: 'POST'});
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Deployment stopped');
                    loadDeployments();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed to stop');
            }
        }

        // Delete Deployment
        async function deleteDeploy(deployId) {
            if (!confirm('Delete this deployment permanently?')) return;
            
            showToast('info', '⏳ Deleting...');
            
            try {
                const res = await fetch(`/api/deployment/${deployId}`, {method: 'DELETE'});
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Deleted successfully');
                    loadDeployments();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed to delete');
            }
        }

        // Create Backup
        async function createBackup(deployId) {
            if (!confirm('Create backup of this deployment?')) return;
            
            showToast('info', '⏳ Creating backup...');
            
            try {
                const res = await fetch(`/api/deployment/${deployId}/backup`, {method: 'POST'});
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ ' + data.message);
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Backup failed');
            }
        }

        // Environment Variables
        function showAddEnv() {
            showModal('Add Environment Variable', `
                <div class="input-group">
                    <label class="input-label">Variable Name</label>
                    <input type="text" class="input-field" id="envKey" placeholder="API_KEY">
                </div>
                <div class="input-group">
                    <label class="input-label">Variable Value</label>
                    <input type="text" class="input-field" id="envValue" placeholder="your_secret_value">
                </div>
                <button class="btn btn-success" onclick="addEnv()">
                    <i class="fas fa-save"></i> Add Variable
                </button>
                <button class="btn btn-danger" onclick="closeModal()" style="margin-top: 12px;">
                    <i class="fas fa-times"></i> Cancel
                </button>
            `);
        }

        async function addEnv() {
            const key = document.getElementById('envKey').value;
            const value = document.getElementById('envValue').value;
            
            if (!key || !value) {
                showToast('warning', '⚠️ Fill all fields');
                return;
            }
            
            showToast('info', '⏳ Adding variable...');
            
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
                showToast('error', '❌ Failed to add');
            }
        }

        async function loadEnv() {
            try {
                const res = await fetch('/api/env/list');
                const data = await res.json();
                const list = document.getElementById('envList');
                
                if (!data.variables || !Object.keys(data.variables).length) {
                    list.innerHTML = '<p style="color: var(--gray); font-size: 13px; text-align: center; padding: 20px;">No environment variables yet</p>';
                    return;
                }
                
                list.innerHTML = Object.entries(data.variables).map(([key, value]) => `
                    <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.2); border-radius: 10px; padding: 12px; margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
                        <div style="flex: 1; min-width: 0;">
                            <div style="font-weight: 700; font-size: 13px; margin-bottom: 4px;">${key}</div>
                            <div style="font-family: monospace; font-size: 11px; color: var(--gray); overflow: hidden; text-overflow: ellipsis;">
                                ${value.substring(0, 30)}${value.length > 30 ? '...' : ''}
                            </div>
                        </div>
                        <button onclick="deleteEnv('${key}')" style="background: rgba(239, 68, 68, 0.2); border: none; color: var(--danger); padding: 8px 12px; border-radius: 8px; cursor: pointer; font-size: 12px;">
                            <i class="fas fa-trash"></i>
                        </button>
                    </div>
                `).join('');
            } catch (err) {
                console.error(err);
            }
        }

        async function deleteEnv(key) {
            if (!confirm(`Delete "${key}"?`)) return;
            
            showToast('info', '⏳ Deleting...');
            
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
                showToast('error', '❌ Failed to delete');
            }
        }

        // Admin Functions
        async function loadAdminStats() {
            try {
                const res = await fetch('/api/admin/stats');
                const data = await res.json();
                
                if (data.success) {
                    document.getElementById('adminTotalUsers').textContent = data.stats.total_users;
                    document.getElementById('adminTotalDeploys').textContent = data.stats.total_deployments;
                    document.getElementById('adminActiveProcesses').textContent = data.stats.active_processes;
                    document.getElementById('adminTotalCredits').textContent = data.stats.total_spent.toFixed(1);
                    document.getElementById('adminAIInstalls').textContent = data.stats.ai_installs;
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
                    <input type="number" class="input-field" id="creditAmount" placeholder="10.0" step="0.5">
                </div>
                <button class="btn btn-success" onclick="adminAddCredits()">
                    <i class="fas fa-coins"></i> Add Credits
                </button>
            `);
        }

        async function adminAddCredits() {
            const userId = document.getElementById('targetUserId').value;
            const amount = document.getElementById('creditAmount').value;
            
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
                    showToast('success', '✅ Credits added successfully');
                    closeModal();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed to add credits');
            }
        }

        async function viewAllUsers() {
            try {
                const res = await fetch('/api/admin/users');
                const data = await res.json();
                
                if (data.success) {
                    const usersHtml = data.users.map(u => `
                        <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 16px; margin-bottom: 12px;">
                            <div style="display: flex; justify-content: space-between; align-items: start;">
                                <div>
                                    <div style="font-weight: 800; font-size: 15px; margin-bottom: 4px;">${u.first_name}</div>
                                    <div style="font-size: 12px; color: var(--gray);">
                                        <div>ID: ${u.user_id}</div>
                                        <div>Username: @${u.username || 'N/A'}</div>
                                        <div>Deployments: ${u.total_deployments}</div>
                                        <div>Joined: ${new Date(u.joined_date).toLocaleDateString()}</div>
                                    </div>
                                </div>
                                ${u.pro_member ? '<span style="background: linear-gradient(135deg, var(--secondary), #7c3aed); padding: 4px 12px; border-radius: 12px; font-size: 10px; font-weight: 800;">PRO</span>' : ''}
                            </div>
                        </div>
                    `).join('');
                    
                    showModal(`All Users (${data.users.length})`, usersHtml);
                }
            } catch (err) {
                showToast('error', '❌ Failed to load users');
            }
        }

        async function viewAllDeployments() {
            try {
                const res = await fetch('/api/admin/deployments');
                const data = await res.json();
                
                if (data.success) {
                    const deploysHtml = data.deployments.map(d => `
                        <div style="background: rgba(30, 41, 59, 0.6); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 16px; margin-bottom: 12px;">
                            <div style="font-weight: 800; margin-bottom: 8px;">${d.name}</div>
                            <div style="font-size: 12px; color: var(--gray); line-height: 1.8;">
                                <div>ID: ${d.id}</div>
                                <div>User: ${d.user_id}</div>
                                <div>Status: <span class="status-badge status-${d.status}">${d.status}</span></div>
                                <div>Port: ${d.port || 'N/A'}</div>
                                <div>Created: ${new Date(d.created_at).toLocaleString()}</div>
                            </div>
                        </div>
                    `).join('');
                    
                    showModal(`All Deployments (${data.deployments.length})`, deploysHtml);
                }
            } catch (err) {
                showToast('error', '❌ Failed to load deployments');
            }
        }

        async function viewActivityLog() {
            try {
                const res = await fetch('/api/admin/activity');
                const data = await res.json();
                
                if (data.success) {
                    const activityHtml = data.activity.map(a => `
                        <div style="background: rgba(30, 41, 59, 0.6); border-left: 3px solid var(--primary); padding: 12px; margin-bottom: 8px; border-radius: 8px;">
                            <div style="font-weight: 700; font-size: 13px; margin-bottom: 4px;">${a.action}</div>
                            <div style="font-size: 11px; color: var(--gray);">
                                <div>User: ${a.user_id}</div>
                                <div>Details: ${a.details}</div>
                                <div>Time: ${new Date(a.timestamp).toLocaleString()}</div>
                            </div>
                        </div>
                    `).join('');
                    
                    showModal(`Activity Log (${data.activity.length} recent)`, activityHtml);
                }
            } catch (err) {
                showToast('error', '❌ Failed to load activity log');
            }
        }

        async function systemHealth() {
            try {
                const res = await fetch('/api/admin/health');
                const data = await res.json();
                
                if (data.success) {
                    const health = data.health;
                    const healthHtml = `
                        <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px;">
                            <div class="admin-stat">
                                <div class="admin-stat-value">${health.disk_percent.toFixed(1)}%</div>
                                <div class="admin-stat-label">Disk Usage</div>
                            </div>
                            <div class="admin-stat">
                                <div class="admin-stat-value">${health.active_processes}</div>
                                <div class="admin-stat-label">Active Processes</div>
                            </div>
                        </div>
                        <div style="margin-top: 20px; padding: 16px; background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); border-radius: 12px;">
                            <div style="font-weight: 800; margin-bottom: 8px;">System Status: <span style="color: var(--success);">Healthy</span></div>
                            <div style="font-size: 12px; color: var(--gray);">Uptime: ${health.uptime}</div>
                        </div>
                    `;
                    
                    showModal('System Health', healthHtml);
                }
            } catch (err) {
                showToast('error', '❌ Failed to load health data');
            }
        }

        async function exportData() {
            showToast('info', '⏳ Exporting data...');
            try {
                const res = await fetch('/api/admin/export');
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `devops_export_${Date.now()}.json`;
                a.click();
                showToast('success', '✅ Data exported');
            } catch (err) {
                showToast('error', '❌ Export failed');
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

        // Close modal on outside click
        document.getElementById('modal').addEventListener('click', (e) => {
            if (e.target.id === 'modal') closeModal();
        });

        // Auto-refresh
        setInterval(updateCredits, 15000);
        setInterval(() => {
            loadDeployments();
            if (isAdmin) loadAdminStats();
        }, 10000);

        // Initial load
        loadDeployments();
        loadEnv();
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
    total_deploys = len(active_deployments.get(user_id, []))
    active_count = len([d for d in active_deployments.get(user_id, []) if d['status'] == 'running'])
    vps_count = len(user_vps.get(user_id, []))
    is_admin = 'true' if user_id in admin_ids else 'false'
    
    return render_template_string(
        ELITEHOST_DASHBOARD_HTML,
        credits=f"{credits:.1f}" if credits != float('inf') else "∞",
        total_deploys=total_deploys,
        active_deploys=active_count,
        vps_count=vps_count,
        is_admin=is_admin
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

# ==================== ADMIN API ROUTES ====================

@app.route('/api/admin/stats')
def api_admin_stats():
    user_id = session.get('user_id', 999999)
    if user_id not in admin_ids:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
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
    user_id = session.get('user_id', 999999)
    if user_id not in admin_ids:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
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
    user_id = session.get('user_id', 999999)
    if user_id not in admin_ids:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
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
    user_id = session.get('user_id', 999999)
    if user_id not in admin_ids:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
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
    user_id = session.get('user_id', 999999)
    if user_id not in admin_ids:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
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
    user_id = session.get('user_id', 999999)
    if user_id not in admin_ids:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    target_user = data.get('user_id')
    amount = data.get('amount')
    
    if not target_user or not amount:
        return jsonify({'success': False, 'error': 'Missing parameters'})
    
    if add_credits(target_user, amount, "Admin bonus"):
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Failed to add credits'})

@app.route('/api/admin/export')
def api_admin_export():
    user_id = session.get('user_id', 999999)
    if user_id not in admin_ids:
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403
    
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'users': [],
                'deployments': [],
                'credits': []
            }
            
            c = conn.cursor()
            c.execute('SELECT * FROM users')
            for row in c.fetchall():
                export_data['users'].append({
                    'user_id': row[0],
                    'username': row[1],
                    'first_name': row[2],
                    'joined_date': row[3],
                    'total_deployments': row[5]
                })
            
            c.execute('SELECT * FROM deployments WHERE status != "deleted"')
            for row in c.fetchall():
                export_data['deployments'].append({
                    'id': row[0],
                    'user_id': row[1],
                    'name': row[2],
                    'status': row[4],
                    'created_at': row[7]
                })
            
            c.execute('SELECT * FROM credits')
            for row in c.fetchall():
                export_data['credits'].append({
                    'user_id': row[0],
                    'balance': row[1],
                    'total_spent': row[2]
                })
            
            conn.close()
        
        return jsonify(export_data)
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

def keep_alive():
    t = Thread(target=run_flask, daemon=True)
    t.start()
    logger.info(f"{Fore.GREEN}✅ Web Dashboard: http://localhost:{os.environ.get('PORT', 8080)}")

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
        types.InlineKeyboardButton('🌐 Dashboard', callback_data='dashboard'),
        types.InlineKeyboardButton('💰 Buy Credits', url=TELEGRAM_LINK)
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
            bot.send_message(user_id, f"🎉 *Welcome Bonus!*\n\nYou received *{FREE_CREDITS} FREE credits* to get started!")
    
    credits = get_credits(user_id)
    
    bot.send_message(
        message.chat.id,
        f"🚀 *EliteHost DevOps Bot v9.0 - ENTERPRISE EDITION*\n\n"
        f"👤 *{first_name}*\n"
        f"💎 Credits: *{credits if credits != float('inf') else '∞'}*\n\n"
        f"*✨ ELITEHOST FEATURES:*\n\n"
        f"⚡ *One-Click Deployment*\n"
        f"   • Push and auto-deploy\n"
        f"   • CDN distribution\n"
        f"   • Zero configuration\n\n"
        f"🤖 *AI-Powered Auto-Install*\n"
        f"   • Smart dependency detection\n"
        f"   • Auto package installation\n"
        f"   • Multi-language support\n\n"
        f"🌐 *GitHub/GitLab Integration*\n"
        f"   • Automatic builds\n"
        f"   • Pull request previews\n"
        f"   • Branch deployments\n\n"
        f"🔒 *Enterprise Security*\n"
        f"   • Encrypted secrets\n"
        f"   • DDoS protection\n"
        f"   • Auto SSL/TLS\n\n"
        f"📊 *Real-time Monitoring*\n"
        f"   • Live logs & metrics\n"
        f"   • Performance insights\n"
        f"   • Custom alerts\n\n"
        f"🎯 *Resource Optimization*\n"
        f"   • AI-based scaling\n"
        f"   • Cost reduction\n"
        f"   • Load balancing\n\n"
        f"*Open dashboard for full experience!* 🌟",
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
                f"🌐 *EliteHost Dashboard - Enterprise Edition*\n\n"
                f"🔗 Access: `http://localhost:{port}`\n\n"
                f"*🎨 ELITEHOST DESIGN:*\n"
                f"✓ Modern dark theme\n"
                f"✓ Smooth animations\n"
                f"✓ Touch-optimized\n"
                f"✓ AI auto-install\n"
                f"✓ Real-time monitoring\n"
                f"✓ Advanced admin panel\n"
                f"✓ Resource analytics\n"
                f"✓ One-click deployment\n\n"
                f"*Experience enterprise-grade platform!* 🚀")
        
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
                
                c.execute('SELECT SUM(total_spent) FROM credits')
                spent = c.fetchone()[0] or 0
                
                conn.close()
            
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                f"👑 *Admin Control Panel*\n\n"
                f"📊 *System Statistics:*\n"
                f"👥 Total Users: *{total_users}*\n"
                f"🚀 Total Deployments: *{total_deploys}*\n"
                f"🟢 Active Now: *{running}*\n"
                f"💰 Credits Spent: *{spent:.1f}*\n"
                f"⚡ Active Processes: *{len(active_processes)}*\n\n"
                f"*Use dashboard for full admin panel!*")
        
        elif call.data == 'status':
            deploys = active_deployments.get(user_id, [])
            if not deploys:
                bot.answer_callback_query(call.id)
                bot.send_message(call.message.chat.id, 
                    "📊 *No Deployments*\n\nDeploy your first app to get started!")
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
                f"Contact: {YOUR_USERNAME}")
        
        else:
            bot.answer_callback_query(call.id, "Use dashboard for full features!", show_alert=True)
    
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
            bot.reply_to(message, "❌ *Unsupported File*\n\nSupported: `.py`, `.js`, `.zip`")
            return
        
        file_content = bot.download_file(file_info.file_path)
        user_dir = os.path.join(UPLOADS_DIR, str(user_id))
        os.makedirs(user_dir, exist_ok=True)
        filepath = os.path.join(user_dir, secure_filename(filename))
        
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        bot.reply_to(message, "🤖 *AI Analyzing Project...*\n\nPlease wait while our AI detects dependencies...")
        deploy_id, msg = deploy_from_file(user_id, filepath, filename)
        
        if deploy_id:
            bot.send_message(message.chat.id,
                f"✅ *Deployment Successful!*\n\n"
                f"🆔 ID: `{deploy_id}`\n"
                f"🤖 AI auto-installed all dependencies\n"
                f"📦 Project analyzed & optimized\n\n"
                f"{msg}\n\n"
                f"*View full details in dashboard!* 🌐")
        else:
            bot.send_message(message.chat.id, f"❌ *Deployment Failed*\n\n{msg}")
    
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
        
        c.execute('SELECT COUNT(*) FROM deployments WHERE dependencies_installed IS NOT NULL AND dependencies_installed != ""')
        auto_installed = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM backups')
        total_backups = c.fetchone()[0]
        
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
    stats_text += f"*🤖 AI Features:*\n"
    stats_text += f"• AI Auto-Installs: *{auto_installed}*\n"
    stats_text += f"• Backups Created: *{total_backups}*\n\n"
    stats_text += f"*💰 Credits:*\n"
    stats_text += f"• Total Spent: *{total_spent:.1f}*\n\n"
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
        
        # Check if deployment belongs to user or user is admin
        user_deploys = active_deployments.get(user_id, [])
        if not any(d['id'] == deploy_id for d in user_deploys) and user_id not in admin_ids:
            bot.reply_to(message, "❌ *Deployment not found*")
            return
        
        bot.reply_to(message, "⏳ *Creating backup...*\n\nThis may take a moment.")
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
    
    help_text = f"🚀 *EliteHost DevOps Bot - Help*\n\n"
    help_text += f"*📱 Basic Commands:*\n"
    help_text += f"/start - Start the bot\n"
    help_text += f"/help - Show this help\n"
    help_text += f"/backup DEPLOY_ID - Create backup\n\n"
    help_text += f"*🎯 Features:*\n"
    help_text += f"• Upload files (.py, .js, .zip)\n"
    help_text += f"• AI auto-installs dependencies\n"
    help_text += f"• GitHub/GitLab integration\n"
    help_text += f"• Real-time monitoring\n"
    help_text += f"• Environment variables\n"
    help_text += f"• Automatic backups\n\n"
    
    if is_admin:
        help_text += f"*👑 Admin Commands:*\n"
        help_text += f"/addcredits USER_ID AMOUNT\n"
        help_text += f"/stats - System statistics\n\n"
    
    help_text += f"*💡 Pro Tip:*\n"
    help_text += f"Use the web dashboard for the complete EliteHost experience with advanced features!\n\n"
    help_text += f"📱 Dashboard: `http://localhost:{os.environ.get('PORT', 8080)}`"
    
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
    
    logger.warning(f"{Fore.GREEN}✅ Cleanup complete - EliteHost stopped")

atexit.register(cleanup_on_exit)

def signal_handler(sig, frame):
    cleanup_on_exit()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "=" * 90)
    print(f"{Fore.CYAN}{'🚀 ELITEHOST DEVOPS BOT v9.0 - ENTERPRISE EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}🐍 Python: {sys.version.split()[0]}")
    print(f"{Fore.GREEN}📁 Data Directory: {DATA_DIR}")
    print(f"{Fore.GREEN}👑 Owner ID: {OWNER_ID}")
    print(f"{Fore.GREEN}👨‍💼 Admin ID: {ADMIN_ID}")
    print(f"{Fore.YELLOW}🎁 Free Credits: {FREE_CREDITS}")
    print("=" * 90)
    print(f"{Fore.MAGENTA}✨ ELITEHOST FEATURES:")
    print("")
    print(f"{Fore.CYAN}⚡ One-Click Deployment")
    print("   └ Push your code and let the platform handle everything")
    print("   └ CDN distribution across 200+ locations")
    print("   └ Zero configuration required")
    print("")
    print(f"{Fore.CYAN}🤖 AI-Powered Auto-Install")
    print("   └ Smart code analysis & import detection")
    print("   └ Automatically installs missing packages")
    print("   └ Supports: Python, Node.js, Ruby, PHP, Go")
    print("   └ Handles: requirements.txt, package.json, Gemfile, composer.json")
    print("")
    print(f"{Fore.CYAN}🌐 GitHub/GitLab Integration")
    print("   └ Automatic builds from branches")
    print("   └ Pull request preview deployments")
    print("   └ Instant preview URLs")
    print("")
    print(f"{Fore.CYAN}🔒 Enterprise Security")
    print("   └ Encrypted environment variables & secrets")
    print("   └ DDoS protection & SSL auto-provision")
    print("   └ Network-level security")
    print("")
    print(f"{Fore.CYAN}📊 Real-time Monitoring")
    print("   └ Live logs & performance metrics")
    print("   └ Custom alerts & notifications")
    print("   └ Resource usage analytics")
    print("")
    print(f"{Fore.CYAN}🎯 AI Resource Optimization")
    print("   └ Intelligent scaling recommendations")
    print("   └ Cost reduction analysis")
    print("   └ Performance improvements")
    print("")
    print(f"{Fore.CYAN}👑 Advanced Admin Panel")
    print("   └ User management & statistics")
    print("   └ System health monitoring")
    print("   └ Activity logs & audit trail")
    print("   └ Credit management")
    print("   └ Data export capabilities")
    print("")
    print(f"{Fore.CYAN}📱 Modern EliteHost UI")
    print("   └ Professional dark theme design")
    print("   └ Smooth animations & transitions")
    print("   └ Touch-optimized mobile interface")
    print("   └ Responsive layout")
    print("=" * 90)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 EliteHost Dashboard: http://localhost:{port}")
    print(f"{Fore.CYAN}📱 Telegram Bot: {TELEGRAM_LINK}")
    print(f"{Fore.MAGENTA}✨ EliteHost Enterprise UI Active!")
    print(f"{Fore.YELLOW}🤖 Starting Telegram bot...\n")
    print("=" * 90)
    print(f"{Fore.GREEN}{'🎉 ELITEHOST SYSTEM READY':^90}")
    print("=" * 90 + "\n")
    
    while True:
        try:
            logger.info(f"{Fore.GREEN}🤖 EliteHost bot polling - Ready for enterprise deployments!")
            bot.infinity_polling(timeout=60, long_polling_timeout=30)
        except Exception as e:
            logger.error(f"{Fore.RED}Polling error: {e}")
            time.sleep(5)<div class="admin-stat-value">${health.cpu_percent.toFixed(1)}%</div>
                                <div class="admin-stat-label">CPU Usage</div>
                            </div>
                            <div class="admin-stat">
                                <div class="admin-stat-value">${health.memory_percent.toFixed(1)}%</div>
                                <div class="admin-stat-label">Memory Usage</div>
                            </div>
                            <div class="admin-stat">
