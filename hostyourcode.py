# -*- coding: utf-8 -*-
"""
🚀 ULTRA ADVANCED DEVOPS BOT v8.0 - ULTIMATE EDITION
Revolutionary AI-Powered Deployment Platform
Mobile-First | Auto-Install | Zero Config
"""

import sys
import subprocess
import os

# ==================== SMART DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 NEXT-GEN DEPENDENCY INSTALLER v8.0")
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
TOKEN = '7991988270:AAFsl-uDsVcf2tl7L5sZgl9Eq9U2nnW3bps'
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

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, BACKUPS_DIR, LOGS_DIR, ANALYTICS_DIR]:
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

# ==================== 🤖 REVOLUTIONARY AI DEPENDENCY DETECTOR V8 ====================

def extract_imports_from_code(code_content):
    """Extract all import statements from Python code"""
    imports = set()
    
    # Standard import patterns
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
    
    logger.info(f"{Fore.CYAN}🤖 AI DEPENDENCY ANALYZER v8.0 - STARTING...")
    install_log.append("🤖 AI DEPENDENCY ANALYZER v8.0")
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
        
        for py_file in python_files[:20]:  # Analyze max 20 files
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
            
            # Filter out standard library modules
            stdlib = {'os', 'sys', 'time', 'json', 're', 'math', 'random', 'datetime', 
                     'collections', 'itertools', 'functools', 'pathlib', 'logging', 
                     'threading', 'subprocess', 'socket', 'http', 'urllib', 'email',
                     'unittest', 'io', 'csv', 'sqlite3', 'pickle', 'base64', 'hashlib',
                     'uuid', 'typing', 'copy', 'tempfile', 'shutil', 'glob', 'zipfile'}
            
            third_party = all_imports - stdlib
            
            for imp in third_party:
                pkg = get_package_name(imp)
                try:
                    # Check if already installed
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
    
    # ========== RUBY GEMFILE ==========
    gem_file = os.path.join(project_path, 'Gemfile')
    if os.path.exists(gem_file):
        logger.info(f"{Fore.CYAN}📦 Found Gemfile")
        install_log.append("\n📦 RUBY GEMFILE DETECTED")
        try:
            subprocess.run(['bundle', '--version'], check=True, capture_output=True)
            subprocess.run(['bundle', 'install'], cwd=project_path, 
                         check=True, capture_output=True, timeout=600)
            installed.append('Ruby gems')
            install_log.append("✅ Ruby gems installed")
            logger.info(f"{Fore.GREEN}✅ Ruby gems installed")
        except:
            logger.warning(f"{Fore.YELLOW}⚠️  bundler not found")
            install_log.append("⚠️  bundler not available")
    
    # ========== PHP COMPOSER.JSON ==========
    composer_file = os.path.join(project_path, 'composer.json')
    if os.path.exists(composer_file):
        logger.info(f"{Fore.CYAN}📦 Found composer.json")
        install_log.append("\n📦 PHP COMPOSER.JSON DETECTED")
        try:
            subprocess.run(['composer', '--version'], check=True, capture_output=True)
            subprocess.run(['composer', 'install'], cwd=project_path, 
                         check=True, capture_output=True, timeout=600)
            installed.append('PHP packages')
            install_log.append("✅ PHP packages installed")
            logger.info(f"{Fore.GREEN}✅ PHP packages installed")
        except:
            logger.warning(f"{Fore.YELLOW}⚠️  composer not found")
            install_log.append("⚠️  composer not available")
    
    # ========== GO MODULES ==========
    go_mod = os.path.join(project_path, 'go.mod')
    if os.path.exists(go_mod):
        logger.info(f"{Fore.CYAN}📦 Found go.mod")
        install_log.append("\n📦 GO MODULES DETECTED")
        try:
            subprocess.run(['go', 'version'], check=True, capture_output=True)
            subprocess.run(['go', 'mod', 'download'], cwd=project_path, 
                         check=True, capture_output=True, timeout=600)
            installed.append('Go modules')
            install_log.append("✅ Go modules downloaded")
            logger.info(f"{Fore.GREEN}✅ Go modules downloaded")
        except:
            install_log.append("⚠️  Go not available")
    
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

# ==================== DATABASE V8 ====================

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
        
        c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT
        )''')
        
        c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', 
                 (OWNER_ID, 'owner', 'Owner', datetime.now().isoformat(), 
                  datetime.now().isoformat(), 0, 0, 0, 1))
        
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
        
        c.execute('SELECT id, user_id, name, type, status, port, pid, repo_url, branch, cpu_usage, memory_usage FROM deployments WHERE status != "deleted"')
        for dep_id, user_id, name, dep_type, status, port, pid, repo_url, branch, cpu, mem in c.fetchall():
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
                'memory_usage': mem or 0
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
                     repo_url, branch, build_cmd, start_cmd, logs, dependencies_installed, install_log)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (deploy_id, user_id, name, deploy_type, 'pending', port,
                  datetime.now().isoformat(), datetime.now().isoformat(),
                  kwargs.get('repo_url', ''), kwargs.get('branch', 'main'),
                  kwargs.get('build_cmd', ''), kwargs.get('start_cmd', ''), '', '', ''))
        
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
        'memory_usage': 0
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
        
        # 🤖 AI-POWERED DEPENDENCY INSTALLATION
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
        
        # 🤖 AI-POWERED DEPENDENCY INSTALLATION
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

# ==================== 📱 ULTIMATE MOBILE-FIRST DASHBOARD ====================

ULTIMATE_MOBILE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#8B5CF6">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>🚀 DevOps Bot v8.0</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>


/* ============================================================
   ENHANCED — Compact Header + Single-line Compact Stats
   Full stylesheet (replace your existing CSS with this).
   Notes:
   - Header is intentionally very small (compact, single row).
   - Stats (Total / Active / Servers / AI) are forced into a single compact line.
   - On very narrow screens the stats row will horizontally scroll.
   ============================================================ */

/* --------------------------
   Theme variables (tweak here)
   -------------------------- */
:root{
  --primary: #8B5CF6;
  --primary-2: #7C3AED;
  --secondary: #EC4899;
  --accent: linear-gradient(90deg,#8B5CF6,#EC4899);
  --success: #10B981;
  --danger: #EF4444;
  --warning: #F59E0B;
  --info: #3B82F6;

  --bg-a: #0b1020;
  --bg-b: #2b2140;
  --card-bg: rgba(255,255,255,0.98);
  --glass: rgba(255,255,255,0.08);
  --glass-strong: rgba(255,255,255,0.14);
  --glass-border: rgba(255,255,255,0.18);

  --text-dark: #0f1720;
  --muted: #6B7280;
  --surface: #F9FAFB;

  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 20px;

  --shadow-xs: 0 2px 8px rgba(2,6,23,0.06);
  --shadow-sm: 0 8px 24px rgba(2,6,23,0.08);
  --shadow-md: 0 12px 40px rgba(2,6,23,0.12);
  --shadow-lg: 0 24px 80px rgba(2,6,23,0.18);

  --max-width: 1100px;

  --transition-fast: 160ms;
  --transition: 280ms;
  --transition-slow: 420ms;
}

/* ----------------
   Global reset + base
   ---------------- */
*,
*::before,
*::after {
  box-sizing: border-box;
  -webkit-tap-highlight-color: transparent;
}
html,body { height:100%; }
body{
  margin:0;
  font-family: Inter, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background:
    radial-gradient(800px 320px at 10% 10%, rgba(139,92,246,0.06), transparent 8%),
    radial-gradient(700px 220px at 95% 90%, rgba(236,72,153,0.03), transparent 6%),
    linear-gradient(135deg,var(--bg-a) 0%, var(--bg-b) 100%);
  color: #0b1227;
  -webkit-font-smoothing:antialiased;
  -moz-osx-font-smoothing:grayscale;
  min-height:100vh;
  overflow-x:hidden;
  padding-bottom: calc(72px + env(safe-area-inset-bottom));
  line-height:1.45;
}

/* Focus improvements */
:focus { outline: none; box-shadow: 0 6px 24px rgba(99,102,241,0.12); border-radius: 8px; }

/* Helpers */
.hidden { display:none !important; }
.text-muted { color: var(--muted) !important; }
.center { display:flex; align-items:center; justify-content:center; }

/* Container */
.container {
  width: 100%;
  max-width: var(--max-width);
  margin: 10px auto;
  padding: 0 16px;
  animation: pop-in var(--transition) ease both;
}

/* -------------------------
   Compact header (single row)
   ------------------------- */
.header {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  padding:8px 14px;           /* very small padding */
  height:52px;                /* compact height */
  background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03));
  backdrop-filter: blur(12px) saturate(140%);
  -webkit-backdrop-filter: blur(12px) saturate(140%);
  border-bottom: 1px solid var(--glass-border);
  box-shadow: var(--shadow-sm);
  position: sticky;
  top: 0;
  z-index: 1100;
}

/* small logo */
.logo {
  display:flex;
  align-items:center;
  gap:10px;
  color:white;
  font-size:15px;             /* smaller text */
  font-weight:900;
  margin-bottom:0;
}
.logo i {
  font-size:18px;
  animation: float-y 3.6s ease-in-out infinite;
  color:white;
  text-shadow: 0 6px 20px rgba(99,102,241,0.10);
}
.version-badge {
  padding:4px 8px;
  border-radius:999px;
  font-size:10px;
  font-weight:800;
  color:white;
  background: linear-gradient(90deg,var(--primary),var(--primary-2));
  box-shadow: 0 8px 26px rgba(139,92,246,0.10);
}

/* compact credit card */
.credit-card {
  display:flex;
  align-items:center;
  gap:10px;
  padding:6px 10px;
  border-radius:12px;
  background: linear-gradient(135deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03));
  border: 1px solid var(--glass-border);
  box-shadow: 0 8px 22px rgba(0,0,0,0.08);
  color:white;
  min-width:160px;
}
.credit-info { display:flex; flex-direction:column; gap:4px; }
.credit-label { font-size:11px; font-weight:700; opacity:0.95; display:flex; gap:6px; align-items:center; }
.credit-value { font-size:16px; font-weight:900; line-height:1; }

/* small buy button in header */
.buy-btn {
  padding:8px 10px;
  font-size:12px;
  border-radius:10px;
  display:inline-flex;
  align-items:center;
  gap:8px;
  background: linear-gradient(90deg, rgba(255,255,255,0.06), rgba(255,255,255,0.03));
  color:white;
  border:1px solid rgba(255,255,255,0.06);
  text-decoration:none;
  cursor:pointer;
  transition: transform var(--transition-fast), box-shadow var(--transition-fast);
}
.buy-btn:hover { transform: translateY(-3px); box-shadow: 0 10px 30px rgba(99,102,241,0.06); }

/* smaller header layout on wide screens stays single row (we always use compact single row) */

/* -------------------------
   Stats — single-line compact
   ------------------------- */
/* Force stats into a single compact line using flex.
   They will equally distribute; on extremely small screens the row scrolls horizontally. */
.stats-grid {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:10px;
  width:100%;
  padding:6px 0;
  margin-bottom:12px;
  overflow-x:auto;                 /* allow horizontal scroll on very narrow devices */
  -webkit-overflow-scrolling: touch;
  scrollbar-width: none;
}
.stats-grid::-webkit-scrollbar { display:none; }

/* Compact stat cards — pill-like, small */
.stat-card {
  flex: 0 0 auto;                  /* do not grow beyond intrinsic width */
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  min-width:86px;                  /* compact consistent width */
  max-width:160px;
  padding:8px 10px;                /* small padding */
  border-radius:12px;
  background: var(--card-bg);
  box-shadow: 0 8px 20px rgba(2,6,23,0.06);
  border:1px solid rgba(2,6,23,0.03);
  text-align:center;
  transition: transform var(--transition-fast), box-shadow var(--transition-fast);
}
.stat-card:hover { transform: translateY(-4px); box-shadow: 0 12px 34px rgba(124,58,237,0.06); }

/* smaller stat visuals */
.stat-icon { font-size:16px; margin-bottom:6px; display:inline-block; }
.stat-value {
  font-size:15px;                  /* smaller number */
  font-weight:900;
  background: linear-gradient(90deg,var(--primary),var(--secondary));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  margin:4px 0;
}
.stat-label {
  font-size:10px;
  color: var(--muted);
  font-weight:800;
  text-transform:uppercase;
  letter-spacing:0.4px;
}

/* ensure the four main stats look balanced */
.stats-grid > .stat-card:nth-child(1),
.stats-grid > .stat-card:nth-child(2),
.stats-grid > .stat-card:nth-child(3),
.stats-grid > .stat-card:nth-child(4) {
  min-width: 76px;
  flex-basis: 1;
}

/* on very small screens keep cards slightly smaller */
@media (max-width:420px){
  .stat-card { min-width:72px; padding:6px 8px; }
  .stat-value { font-size:14px; }
  .logo { font-size:14px; }
  .credit-card { min-width:140px; padding:6px 8px; }
}

/* ---------- Minor adjustments to match compact header ---------- */
/* Reduce tab-bar top spacing so layout feels tight under compact header */
.tab-bar {
  padding:8px 12px;
  gap:8px;
  margin: 0 -12px 12px -12px;
  border-radius:10px;
}

/* Slightly smaller cards and buttons across the UI to keep compact look */
.card { padding:14px; border-radius:12px; }
.card-title { font-size:15px; margin-bottom:10px; }
.btn { padding:10px 14px; font-size:13px; border-radius:12px; }

/* Keep rest of the enhanced stylesheet intact (copied/kept minimal here) */
/* Upload zone (small adjustments) */
.upload-zone {
  border: 2px dashed rgba(139,92,246,0.16);
  border-radius: 14px;
  padding: 22px 14px;
  text-align:center;
  background: linear-gradient(180deg, rgba(139,92,246,0.03), rgba(236,72,153,0.02));
  transition: transform var(--transition-fast), box-shadow var(--transition-fast);
}
.upload-icon { font-size:38px; margin-bottom:10px; animation: float-y 3.6s infinite; }

/* Deployment item compact adjustments */
.deployment-item { padding:12px; border-radius:12px; border-left-width:5px; }
.deployment-name { font-size:15px; }

/* Keep progress bars smaller to match compact style */
.progress-bar { height:6px; }
.progress-fill { transition: width 0.45s ease; }

/* Notifications & Modal (unchanged but slightly smaller padding) */
.notification { padding:10px 14px; border-radius:10px; }
.modal-content { padding:18px; border-radius:14px; max-width:640px; }

/* Bottom nav unchanged (still hidden on desktop) */
@media(min-width:768px){
  .bottom-nav { display:none; }
}

/* Utility */
.mt-6 { margin-top:6px !important; }
.mb-6 { margin-bottom:6px !important; }
.w-100 { width:100%; }
.kicker { text-transform:uppercase; font-weight:900; letter-spacing:0.6px; font-size:11px; color:var(--muted); }

/* End of compact-enhanced stylesheet */
  
                
    </style>
</head>
<body>
    <!-- 🎨 Header -->
    <div class="header">
        <div class="logo">
            <i class="fas fa-rocket"></i>
            <div>
                <div>DevOps Bot v8.0</div>
                <span class="version-badge">ULTIMATE</span>
            </div>
        </div>
        <div class="credit-card">
            <div class="credit-info">
                <div class="credit-label">
                    <i class="fas fa-gem"></i> CREDITS
                </div>
                <div class="credit-value" id="creditBalance">{{ credits }}</div>
            </div>
            <a href="{{ telegram_link }}" target="_blank" class="buy-btn">
                <i class="fab fa-telegram"></i> Buy
            </a>
        </div>
    </div>
    
    <div class="container">
        <!-- 📊 Stats -->
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
        
        <!-- 🎯 Tabs -->
        <div class="tab-bar">
            <button class="tab active" onclick="showTab('deploy')">
                <i class="fas fa-rocket"></i> Deploy
            </button>
            <button class="tab" onclick="showTab('apps')">
                <i class="fas fa-list"></i> Apps
            </button>
            <button class="tab" onclick="showTab('github')">
                <i class="fab fa-github"></i> GitHub
            </button>
            <button class="tab" onclick="showTab('env')">
                <i class="fas fa-key"></i> ENV
            </button>
            <button class="tab" onclick="showTab('pricing')">
                <i class="fas fa-crown"></i> Pro
            </button>
        </div>
        
        <!-- 📤 Deploy Tab -->
        <div id="deploy-tab" class="tab-content active">
            <div class="card">
                <h3 class="card-title">
                    <i class="fas fa-cloud-upload-alt"></i> Smart Deploy
                </h3>
                <p style="color: #6B7280; margin-bottom: 20px; font-size: 14px; line-height: 1.8; font-weight: 600;">
                    <strong style="color: var(--primary);">🤖 AI Auto-Install:</strong> Upload any project and our AI automatically detects & installs ALL dependencies. Zero config needed!
                </p>
                
                <div class="upload-zone" onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <div class="upload-title">Tap to Upload</div>
                    <div class="upload-desc">Python • JavaScript • ZIP</div>
                    <div class="upload-hint">
                        ✨ Auto-detects:<br>
                        requirements.txt • package.json<br>
                        Gemfile • composer.json • go.mod
                    </div>
                    <input type="file" id="fileInput" hidden accept=".py,.js,.zip" onchange="handleFileUpload(this)">
                </div>
            </div>
        </div>
        
        <!-- 📱 Apps Tab -->
        <div id="apps-tab" class="tab-content">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h3 class="card-title" style="margin: 0;">
                        <i class="fas fa-server"></i> Your Apps
                    </h3>
                    <button onclick="loadDeployments()" style="background: linear-gradient(135deg, var(--primary), var(--secondary)); border: none; color: white; font-size: 20px; padding: 10px; cursor: pointer; border-radius: 10px; width: 40px; height: 40px; box-shadow: 0 4px 15px rgba(139, 92, 246, 0.4);">
                        <i class="fas fa-sync"></i>
                    </button>
                </div>
                <div id="deploymentsList"></div>
            </div>
        </div>
        
        <!-- 🐙 GitHub Tab -->
        <div id="github-tab" class="tab-content">
            <div class="card">
                <h3 class="card-title">
                    <i class="fab fa-github"></i> GitHub Deploy
                </h3>
                <p style="color: #6B7280; margin-bottom: 20px; font-size: 14px; font-weight: 600;">
                    Deploy from any GitHub repo with AI-powered dependency detection
                </p>
                
                <div class="input-group">
                    <label><i class="fab fa-github"></i> Repository URL</label>
                    <input type="url" id="repoUrl" placeholder="https://github.com/user/repo.git">
                </div>
                
                <div class="input-group">
                    <label><i class="fas fa-code-branch"></i> Branch</label>
                    <input type="text" id="repoBranch" value="main" placeholder="main">
                </div>
                
                <div class="input-group">
                    <label><i class="fas fa-hammer"></i> Build Command (Optional)</label>
                    <input type="text" id="buildCmd" placeholder="npm run build">
                </div>
                
                <div class="input-group">
                    <label><i class="fas fa-play"></i> Start Command (Optional)</label>
                    <input type="text" id="startCmd" placeholder="Auto-detected if empty">
                </div>
                
                <button class="btn" onclick="deployGithub()">
                    <i class="fab fa-github"></i> Deploy Now
                </button>
            </div>
        </div>
        
        <!-- 🔐 ENV Tab -->
        <div id="env-tab" class="tab-content">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h3 class="card-title" style="margin: 0;">
                        <i class="fas fa-lock"></i> Environment
                    </h3>
                    <button onclick="showAddEnv()" style="background: linear-gradient(135deg, var(--success), #059669); border: none; color: white; font-size: 20px; padding: 10px; cursor: pointer; border-radius: 10px; width: 40px; height: 40px; box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4);">
                        <i class="fas fa-plus"></i>
                    </button>
                </div>
                <div id="envList"></div>
            </div>
        </div>
        
        <!-- 👑 Pricing Tab -->
        <div id="pricing-tab" class="tab-content">
            <div class="card">
                <h3 class="card-title" style="text-align: center; font-size: 24px;">
                    <i class="fas fa-crown"></i> Premium Plans
                </h3>
                
                <div class="pricing-card">
                    <div class="pricing-type">STARTER</div>
                    <div class="pricing-amount">₹99</div>
                    <div class="pricing-credits">10 Credits</div>
                    <div class="feature-list">
                        <div class="feature-item"><i class="fas fa-check-circle"></i> 20 Deployments</div>
                        <div class="feature-item"><i class="fas fa-check-circle"></i> GitHub Integration</div>
                        <div class="feature-item"><i class="fas fa-check-circle"></i> AI Auto-Install</div>
                    </div>
                    <a href="{{ telegram_link }}" target="_blank" class="btn">
                        <i class="fab fa-telegram"></i> Buy Now
                    </a>
                </div>
                
                <div class="pricing-card featured">
                    <div class="pricing-badge">⭐ POPULAR</div>
                    <div class="pricing-type">PRO</div>
                    <div class="pricing-amount">₹399</div>
                    <div class="pricing-credits">50 Credits</div>
                    <div class="feature-list">
                        <div class="feature-item"><i class="fas fa-check-circle"></i> 100 Deployments</div>
                        <div class="feature-item"><i class="fas fa-check-circle"></i> Priority Support</div>
                        <div class="feature-item"><i class="fas fa-check-circle"></i> Analytics</div>
                        <div class="feature-item"><i class="fas fa-check-circle"></i> Auto Backups</div>
                    </div>
                    <a href="{{ telegram_link }}" target="_blank" class="btn">
                        <i class="fab fa-telegram"></i> Get Pro
                    </a>
                </div>
                
                <div class="pricing-card" style="background: linear-gradient(135deg, #f093fb, #f5576c); color: white;">
                    <div class="pricing-type" style="color: white;">UNLIMITED</div>
                    <div class="pricing-amount" style="color: white; background: none; -webkit-background-clip: initial; -webkit-text-fill-color: white;">₹2999</div>
                    <div class="pricing-credits" style="color: white;">∞ Unlimited</div>
                    <div class="feature-list">
                        <div class="feature-item" style="color: white;"><i class="fas fa-check-circle"></i> Everything Unlimited</div>
                        <div class="feature-item" style="color: white;"><i class="fas fa-check-circle"></i> Dedicated Support</div>
                        <div class="feature-item" style="color: white;"><i class="fas fa-check-circle"></i> Custom Features</div>
                        <div class="feature-item" style="color: white;"><i class="fas fa-check-circle"></i> White Label</div>
                    </div>
                    <a href="{{ telegram_link }}" target="_blank" class="btn" style="background: white; color: #f5576c; box-shadow: 0 6px 20px rgba(0,0,0,0.2);">
                        <i class="fab fa-telegram"></i> Go Unlimited
                    </a>
                </div>
            </div>
        </div>
    </div>
    
    <!-- 📱 Bottom Nav -->
    <div class="bottom-nav">
        <a class="nav-item active" onclick="showTab('deploy')">
            <i class="fas fa-rocket"></i>
            <span>Deploy</span>
        </a>
        <a class="nav-item" onclick="showTab('apps')">
            <div style="position: relative;">
                <i class="fas fa-list"></i>
                <span class="badge" id="runningBadge" style="display: none;">0</span>
            </div>
            <span>Apps</span>
        </a>
        <a class="nav-item" onclick="showTab('github')">
            <i class="fab fa-github"></i>
            <span>GitHub</span>
        </a>
        <a class="nav-item" onclick="showTab('env')">
            <i class="fas fa-key"></i>
            <span>ENV</span>
        </a>
        <a class="nav-item" onclick="showTab('pricing')">
            <i class="fas fa-crown"></i>
            <span>Pro</span>
        </a>
    </div>
    
    <div id="notification" class="notification"></div>
    <div id="modal" class="modal"></div>

    <script>
        function showTab(tab) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.getElementById(tab + '-tab').classList.add('active');
            document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            
            event.target.closest('.tab')?.classList.add('active');
            event.target.closest('.nav-item')?.classList.add('active');
            
            if (tab === 'apps') loadDeployments();
            if (tab === 'env') loadEnv();
        }
        
        async function handleFileUpload(input) {
            const file = input.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            showNotification('🤖 AI analyzing...', 'info');
            
            try {
                const res = await fetch('/api/deploy/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ ' + data.message, 'success');
                    setTimeout(() => {
                        updateCredits();
                        loadDeployments();
                        showTab('apps');
                    }, 1500);
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Deploy failed', 'error');
            }
            
            input.value = '';
        }
        
        async function deployGithub() {
            const url = document.getElementById('repoUrl').value;
            const branch = document.getElementById('repoBranch').value;
            const buildCmd = document.getElementById('buildCmd').value;
            const startCmd = document.getElementById('startCmd').value;
            
            if (!url) return showNotification('⚠️ Enter repo URL', 'warning');
            
            showNotification('🤖 AI cloning...', 'info');
            
            try {
                const res = await fetch('/api/deploy/github', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url, branch, build_cmd: buildCmd, start_cmd: startCmd})
                });
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ ' + data.message, 'success');
                    document.getElementById('repoUrl').value = '';
                    document.getElementById('buildCmd').value = '';
                    document.getElementById('startCmd').value = '';
                    setTimeout(() => {
                        updateCredits();
                        loadDeployments();
                        showTab('apps');
                    }, 1500);
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Deploy failed', 'error');
            }
        }
        
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
                            <div class="empty-desc">Deploy your first app to get started!</div>
                        </div>
                    `;
                    return;
                }
                
                list.innerHTML = data.deployments.map(d => `
                    <div class="deployment-item">
                        <div class="deployment-header">
                            <div style="flex: 1;">
                                <div class="deployment-name">${d.name}</div>
                                <div class="deployment-meta">
                                    <span class="meta-item"><i class="fas fa-fingerprint"></i> ${d.id}</span>
                                    ${d.port ? `<span class="meta-item"><i class="fas fa-network-wired"></i> :${d.port}</span>` : ''}
                                    ${d.pid ? `<span class="meta-item"><i class="fas fa-microchip"></i> ${d.pid}</span>` : ''}
                                </div>
                                ${d.repo_url ? `<p style="color:#8B5CF6;font-size:12px;margin-top:8px;font-weight:700;"><i class="fab fa-github"></i> ${d.repo_url.split('/').slice(-2).join('/')}</p>` : ''}
                            </div>
                            <span class="status-badge status-${d.status}">${d.status}</span>
                        </div>
                        ${d.status === 'running' ? `
                        <div class="resource-usage">
                            <div class="resource-bar">
                                <div class="resource-label">CPU ${(d.cpu_usage || 0).toFixed(1)}%</div>
                                <div class="progress-bar">
                                    <div class="progress-fill" style="width: ${Math.min(d.cpu_usage || 0, 100)}%"></div>
                                </div>
                            </div>
                            <div class="resource-bar">
                                <div class="resource-label">RAM ${(d.memory_usage || 0).toFixed(1)}%</div>
                                <div class="progress-bar">
                                    <div class="progress-fill" style="width: ${Math.min(d.memory_usage || 0, 100)}%"></div>
                                </div>
                            </div>
                        </div>
                        ` : ''}
                        <div class="action-btns">
                            <button class="action-btn" style="background: var(--info);" onclick="viewLogs('${d.id}')">
                                <i class="fas fa-terminal"></i> Logs
                            </button>
                            ${d.status === 'running' ? `
                                <button class="action-btn" style="background: var(--danger);" onclick="stopDeploy('${d.id}')">
                                    <i class="fas fa-stop"></i> Stop
                                </button>
                            ` : ''}
                            <button class="action-btn" style="background: var(--warning);" onclick="deleteDeploy('${d.id}')">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        </div>
                    </div>
                `).join('');
                
                const runningCount = data.deployments.filter(d => d.status === 'running').length;
                document.getElementById('activeDeploys').textContent = runningCount;
                document.getElementById('totalDeploys').textContent = data.deployments.length;
                
                const badge = document.getElementById('runningBadge');
                if (runningCount > 0) {
                    badge.textContent = runningCount;
                    badge.style.display = 'block';
                } else {
                    badge.style.display = 'none';
                }
            } catch (err) {
                console.error(err);
            }
        }
        
        async function viewLogs(deployId) {
            try {
                const res = await fetch('/api/deployment/' + deployId + '/logs');
                const data = await res.json();
                
                showModal(`
                    <h3 style="margin-bottom: 24px; font-size: 22px; font-weight: 900;">
                        <i class="fas fa-terminal"></i> Deployment Logs
                    </h3>
                    <div class="terminal">${data.logs || 'No logs available...'}</div>
                    <button class="btn btn-danger" onclick="closeModal()" style="margin-top: 20px;">
                        <i class="fas fa-times"></i> Close
                    </button>
                `);
            } catch (err) {
                showNotification('❌ Failed to load logs', 'error');
            }
        }
        
        async function stopDeploy(deployId) {
            if (!confirm('Stop this deployment?')) return;
            
            showNotification('⏳ Stopping...', 'info');
            
            try {
                const res = await fetch('/api/deployment/' + deployId + '/stop', {method: 'POST'});
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Stopped', 'success');
                    loadDeployments();
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Stop failed', 'error');
            }
        }
        
        async function deleteDeploy(deployId) {
            if (!confirm('Delete permanently?')) return;
            
            showNotification('⏳ Deleting...', 'info');
            
            try {
                const res = await fetch('/api/deployment/' + deployId, {method: 'DELETE'});
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Deleted', 'success');
                    loadDeployments();
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Delete failed', 'error');
            }
        }
        
        function showAddEnv() {
            showModal(`
                <h3 style="margin-bottom: 24px; font-size: 22px; font-weight: 900;">
                    <i class="fas fa-plus"></i> Add Variable
                </h3>
                <div class="input-group">
                    <label>Variable Name</label>
                    <input type="text" id="envKey" placeholder="API_KEY">
                </div>
                <div class="input-group">
                    <label>Variable Value</label>
                    <input type="text" id="envValue" placeholder="your_secret_value">
                </div>
                <button class="btn btn-success" onclick="addEnv()">
                    <i class="fas fa-save"></i> Add Variable
                </button>
                <button class="btn btn-danger" onclick="closeModal()">
                    <i class="fas fa-times"></i> Cancel
                </button>
            `);
        }
        
        async function addEnv() {
            const key = document.getElementById('envKey').value;
            const value = document.getElementById('envValue').value;
            
            if (!key || !value) {
                return showNotification('⚠️ Fill all fields', 'warning');
            }
            
            showNotification('⏳ Adding...', 'info');
            
            try {
                const res = await fetch('/api/env/add', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key, value})
                });
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Added', 'success');
                    closeModal();
                    loadEnv();
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Failed to add', 'error');
            }
        }
        
        async function loadEnv() {
            try {
                const res = await fetch('/api/env/list');
                const data = await res.json();
                
                const list = document.getElementById('envList');
                
                if (!data.variables || !Object.keys(data.variables).length) {
                    list.innerHTML = `
                        <div class="empty-state">
                            <div class="empty-icon">🔐</div>
                            <div class="empty-title">No variables</div>
                            <div class="empty-desc">Add environment variables for your apps</div>
                        </div>
                    `;
                    return;
                }
                
                list.innerHTML = Object.entries(data.variables).map(([key, value]) => `
                    <div class="deployment-item">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="flex: 1; min-width: 0;">
                                <div class="deployment-name">${key}</div>
                                <p style="color:#6B7280;font-size:13px;margin-top:8px;overflow:hidden;text-overflow:ellipsis;font-family:monospace;font-weight:600;">
                                    ${value.substring(0, 40)}${value.length > 40 ? '...' : ''}
                                </p>
                            </div>
                            <button class="action-btn" style="background: var(--danger); margin: 0; padding: 10px 16px;" onclick="deleteEnv('${key}')">
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
            
            showNotification('⏳ Deleting...', 'info');
            
            try {
                const res = await fetch('/api/env/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key})
                });
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Deleted', 'success');
                    loadEnv();
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Delete failed', 'error');
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
        
        function showNotification(msg, type = 'info') {
            const notif = document.getElementById('notification');
            const icons = {
                info: '<i class="fas fa-info-circle notification-icon" style="color: #3B82F6;"></i>',
                success: '<i class="fas fa-check-circle notification-icon" style="color: #10B981;"></i>',
                warning: '<i class="fas fa-exclamation-triangle notification-icon" style="color: #F59E0B;"></i>',
                error: '<i class="fas fa-times-circle notification-icon" style="color: #EF4444;"></i>'
            };
            
            notif.innerHTML = (icons[type] || icons.info) + `<div style="flex: 1; font-weight: 700;">${msg}</div>`;
            notif.classList.add('show');
            setTimeout(() => notif.classList.remove('show'), 4000);
        }
        
        // Auto refresh
        setInterval(updateCredits, 15000);
        setInterval(() => {
            if (document.getElementById('apps-tab').classList.contains('active')) {
                loadDeployments();
            }
        }, 10000);
        
        // Initial load
        loadDeployments();
        
        // Modal click outside to close
        document.getElementById('modal').addEventListener('click', (e) => {
            if (e.target.id === 'modal') closeModal();
        });
        
        // Drag & drop
        const uploadZone = document.getElementById('uploadZone');
        if (uploadZone) {
            ['dragover', 'drop'].forEach(evt => {
                uploadZone.addEventListener(evt, e => e.preventDefault());
            });
            uploadZone.addEventListener('drop', e => {
                const files = e.dataTransfer.files;
                if (files.length > 0) {
                    document.getElementById('fileInput').files = files;
                    handleFileUpload(document.getElementById('fileInput'));
                }
            });
        }
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
    
    return render_template_string(
        ULTIMATE_MOBILE_HTML,
        credits=f"{credits:.1f}" if credits != float('inf') else "∞",
        total_deploys=total_deploys,
        active_deploys=active_count,
        vps_count=vps_count,
        telegram_link=TELEGRAM_LINK
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
            bot.send_message(user_id, f"🎉 *Welcome Bonus!*\n\nYou received *{FREE_CREDITS} FREE credits* to get started!")
    
    credits = get_credits(user_id)
    
    bot.send_message(
        message.chat.id,
        f"🚀 *DevOps Bot v8.0 - ULTIMATE EDITION*\n\n"
        f"👤 *{first_name}*\n"
        f"💎 Credits: *{credits if credits != float('inf') else '∞'}*\n\n"
        f"*✨ REVOLUTIONARY FEATURES:*\n\n"
        f"🤖 *AI-Powered Auto-Install*\n"
        f"   └ Scans your code for imports\n"
        f"   └ Auto-installs ALL dependencies\n"
        f"   └ Supports 5+ package managers\n"
        f"   └ Zero configuration needed\n\n"
        f"⚡ *Smart Deployment*\n"
        f"   • File Upload (.py, .js, .zip)\n"
        f"   • GitHub Integration\n"
        f"   • Real-time Monitoring\n"
        f"   • Resource Analytics\n"
        f"   • Auto Port Allocation\n\n"
        f"📱 *Ultimate Mobile Dashboard*\n"
        f"   • Instagram-level UI\n"
        f"   • Smooth Animations\n"
        f"   • Touch Optimized\n"
        f"   • Glassmorphism Design\n"
        f"   • Real-time Updates\n\n"
        f"*Just upload & deploy. AI does the rest!* 🎯",
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
                f"📱 *Ultimate Mobile Dashboard*\n\n"
                f"🔗 Access: `http://localhost:{port}`\n\n"
                f"*🎨 REVOLUTIONARY FEATURES:*\n"
                f"✓ Glassmorphism design\n"
                f"✓ Smooth animations\n"
                f"✓ Touch-optimized UI\n"
                f"✓ AI auto-install\n"
                f"✓ Real-time monitoring\n"
                f"✓ Drag & drop upload\n"
                f"✓ GitHub one-click\n"
                f"✓ Mobile-first design\n\n"
                f"*Experience the future!* 🚀")
        
        elif call.data == 'status':
            deploys = active_deployments.get(user_id, [])
            if not deploys:
                bot.answer_callback_query(call.id)
                bot.send_message(call.message.chat.id, 
                    "📊 *No Deployments*\n\nDeploy your first app!")
            else:
                running = sum(1 for d in deploys if d['status'] == 'running')
                installing = sum(1 for d in deploys if d['status'] in ['installing', 'building'])
                
                avg_cpu = sum(d.get('cpu_usage', 0) for d in deploys if d['status'] == 'running') / max(running, 1)
                avg_mem = sum(d.get('memory_usage', 0) for d in deploys if d['status'] == 'running') / max(running, 1)
                
                status_text = f"📊 *Deployment Analytics*\n\n"
                status_text += f"📦 Total: *{len(deploys)}*\n"
                status_text += f"🟢 Running: *{running}*\n"
                status_text += f"⚡ Installing: *{installing}*\n"
                status_text += f"💻 Avg CPU: *{avg_cpu:.1f}%*\n"
                status_text += f"🧠 Avg RAM: *{avg_mem:.1f}%*\n\n"
                status_text += "*📋 Recent:*\n"
                
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
                f"*💰 Get More*\n"
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
            bot.reply_to(message, "❌ Unsupported\n\nUse: `.py`, `.js`, `.zip`")
            return
        
        file_content = bot.download_file(file_info.file_path)
        user_dir = os.path.join(UPLOADS_DIR, str(user_id))
        os.makedirs(user_dir, exist_ok=True)
        filepath = os.path.join(user_dir, secure_filename(filename))
        
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        bot.reply_to(message, "🤖 *AI Analyzing...*\n\nPlease wait...")
        deploy_id, msg = deploy_from_file(user_id, filepath, filename)
        
        if deploy_id:
            bot.send_message(message.chat.id,
                f"✅ *Success!*\n\n"
                f"🆔 ID: `{deploy_id}`\n"
                f"📦 AI auto-installed dependencies\n\n"
                f"{msg}\n\n"
                f"View in dashboard!")
        else:
            bot.send_message(message.chat.id, f"❌ *Failed*\n\n{msg}")
    
    except Exception as e:
        logger.error(f"File error: {e}")
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
            bot.reply_to(message, f"✅ Added *{amount}* to `{target_user}`")
            try:
                bot.send_message(target_user, f"🎉 *Bonus!*\n\nYou got *{amount}* credits!")
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
        
        c.execute('SELECT COUNT(*) FROM deployments WHERE dependencies_installed IS NOT NULL AND dependencies_installed != ""')
        auto_installed = c.fetchone()[0]
        
        conn.close()
    
    stats_text = f"📊 *System Stats*\n\n"
    stats_text += f"👥 Users: *{total_users}*\n"
    stats_text += f"🚀 Deploys: *{total_deploys}*\n"
    stats_text += f"🟢 Running: *{running_deploys}*\n"
    stats_text += f"💰 Spent: *{total_spent:.1f}*\n"
    stats_text += f"📦 AI Installs: *{auto_installed}*\n"
    stats_text += f"⚡ Active: *{len(active_processes)}*"
    
    bot.reply_to(message, stats_text)

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
    print(f"{Fore.CYAN}{'🚀 ULTRA ADVANCED DEVOPS BOT v8.0 - ULTIMATE EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}🐍 Python: {sys.version.split()[0]}")
    print(f"{Fore.GREEN}📁 Data: {DATA_DIR}")
    print(f"{Fore.GREEN}👑 Owner: {OWNER_ID}")
    print(f"{Fore.YELLOW}🎁 Free Credits: {FREE_CREDITS}")
    print("=" * 90)
    print(f"{Fore.MAGENTA}✨ REVOLUTIONARY FEATURES:")
    print(f"{Fore.CYAN}  🤖 AI-Powered Auto-Install")
    print("     └ Code analysis & import detection")
    print("     └ Auto-installs missing packages")
    print("     └ Supports: Python, Node.js, Ruby, PHP, Go")
    print("")
    print(f"{Fore.CYAN}  📱 Ultimate Mobile Dashboard")
    print("     └ Glassmorphism design")
    print("     └ Smooth animations")
    print("     └ Touch-optimized UI")
    print("     └ Real-time updates")
    print("")
    print(f"{Fore.CYAN}  🚀 Smart Deployment")
    print("     └ File upload & GitHub")
    print("     └ Resource monitoring")
    print("     └ Auto port allocation")
    print("     └ Environment variables")
    print("=" * 90)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}📱 Dashboard: http://localhost:{port}")
    print(f"{Fore.CYAN}📱 Telegram: {TELEGRAM_LINK}")
    print(f"{Fore.MAGENTA}✨ Ultimate Mobile UI Active!")
    print(f"{Fore.YELLOW}🤖 Starting bot...\n")
    print("=" * 90)
    print(f"{Fore.GREEN}{'🎉 SYSTEM READY':^90}")
    print("=" * 90 + "\n")
    
    while True:
        try:
            logger.info(f"{Fore.GREEN}🤖 Bot polling - Ready to deploy!")
            bot.infinity_polling(timeout=60, long_polling_timeout=30)
        except Exception as e:
            logger.error(f"{Fore.RED}Polling error: {e}")
            time.sleep(5)
