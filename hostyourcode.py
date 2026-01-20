# -*- coding: utf-8 -*-
"""
ULTRA ADVANCED DEVOPS BOT v7.0 - REVOLUTIONARY EDITION
Next-Generation AI-Powered Deployment Platform
"""

import sys
import subprocess
import os

# ==================== SMART DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 NEXT-GEN DEPENDENCY INSTALLER v7.0")
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
    'qrcode': 'qrcode',
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
import qrcode
from io import BytesIO
import base64

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

# ==================== ENHANCED DEPENDENCY DETECTOR V3 ====================

def detect_and_install_deps(project_path):
    """Revolutionary AI-Powered dependency detection and installation"""
    installed = []
    install_log = []
    
    # Python requirements.txt
    req_file = os.path.join(project_path, 'requirements.txt')
    if os.path.exists(req_file):
        logger.info(f"{Fore.CYAN}📦 Detected requirements.txt")
        install_log.append("📦 Python requirements.txt detected")
        try:
            with open(req_file, 'r') as f:
                packages = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if packages:
                logger.info(f"{Fore.YELLOW}⚡ Installing {len(packages)} Python packages...")
                install_log.append(f"⚡ Installing {len(packages)} packages...")
                subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '-r', req_file, '--quiet'],
                    check=True,
                    capture_output=True
                )
                installed.extend(packages)
                install_log.append(f"✅ Installed: {', '.join(packages[:5])}{'...' if len(packages) > 5 else ''}")
                logger.info(f"{Fore.GREEN}✅ Python packages installed")
        except Exception as e:
            logger.error(f"{Fore.RED}❌ Python install failed: {e}")
            install_log.append(f"❌ Error: {str(e)[:100]}")
    
    # Node.js package.json
    pkg_file = os.path.join(project_path, 'package.json')
    if os.path.exists(pkg_file):
        logger.info(f"{Fore.CYAN}📦 Detected package.json")
        install_log.append("📦 Node.js package.json detected")
        try:
            subprocess.run(['npm', '--version'], check=True, capture_output=True)
            logger.info(f"{Fore.YELLOW}⚡ Installing Node.js packages...")
            install_log.append("⚡ Running npm install...")
            subprocess.run(
                ['npm', 'install', '--silent'],
                cwd=project_path,
                check=True,
                capture_output=True
            )
            installed.append('npm packages')
            install_log.append("✅ Node.js packages installed")
            logger.info(f"{Fore.GREEN}✅ Node.js packages installed")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning(f"{Fore.YELLOW}⚠️  npm not found")
            install_log.append("⚠️  npm not available, skipped")
    
    # Gemfile for Ruby
    gem_file = os.path.join(project_path, 'Gemfile')
    if os.path.exists(gem_file):
        logger.info(f"{Fore.CYAN}📦 Detected Gemfile")
        install_log.append("📦 Ruby Gemfile detected")
        try:
            subprocess.run(['bundle', '--version'], check=True, capture_output=True)
            subprocess.run(['bundle', 'install'], cwd=project_path, check=True, capture_output=True)
            installed.append('Ruby gems')
            install_log.append("✅ Ruby gems installed")
            logger.info(f"{Fore.GREEN}✅ Ruby gems installed")
        except:
            logger.warning(f"{Fore.YELLOW}⚠️  bundler not found")
            install_log.append("⚠️  bundler not available")
    
    # composer.json for PHP
    composer_file = os.path.join(project_path, 'composer.json')
    if os.path.exists(composer_file):
        logger.info(f"{Fore.CYAN}📦 Detected composer.json")
        install_log.append("📦 PHP composer.json detected")
        try:
            subprocess.run(['composer', '--version'], check=True, capture_output=True)
            subprocess.run(['composer', 'install'], cwd=project_path, check=True, capture_output=True)
            installed.append('PHP packages')
            install_log.append("✅ PHP packages installed")
            logger.info(f"{Fore.GREEN}✅ PHP packages installed")
        except:
            logger.warning(f"{Fore.YELLOW}⚠️  composer not found")
            install_log.append("⚠️  composer not available")
    
    # Go modules
    go_mod = os.path.join(project_path, 'go.mod')
    if os.path.exists(go_mod):
        logger.info(f"{Fore.CYAN}📦 Detected go.mod")
        install_log.append("📦 Go modules detected")
        try:
            subprocess.run(['go', 'version'], check=True, capture_output=True)
            subprocess.run(['go', 'mod', 'download'], cwd=project_path, check=True, capture_output=True)
            installed.append('Go modules')
            install_log.append("✅ Go modules downloaded")
            logger.info(f"{Fore.GREEN}✅ Go modules downloaded")
        except:
            install_log.append("⚠️  Go not available")
    
    return installed, "\n".join(install_log)

# ==================== DATABASE V3 ====================

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
        
        c.execute('''CREATE TABLE IF NOT EXISTS vps_servers (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            name TEXT,
            host TEXT,
            port INTEGER,
            username TEXT,
            password_encrypted TEXT,
            created_at TEXT,
            last_connected TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS env_vars (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            deployment_id TEXT,
            key TEXT,
            value_encrypted TEXT,
            created_at TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS backups (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            deployment_id TEXT,
            file_path TEXT,
            size INTEGER,
            created_at TEXT,
            auto_backup INTEGER DEFAULT 0
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            timestamp TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS analytics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            deployment_id TEXT,
            timestamp TEXT,
            cpu REAL,
            memory REAL,
            network_in INTEGER,
            network_out INTEGER
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
        
        c.execute('SELECT id, user_id, name, host, port, username, password_encrypted FROM vps_servers')
        for vps_id, user_id, name, host, port, username, password_enc in c.fetchall():
            if user_id not in user_vps:
                user_vps[user_id] = []
            try:
                password = fernet.decrypt(password_enc.encode()).decode() if password_enc else None
            except:
                password = None
            user_vps[user_id].append({
                'id': vps_id,
                'name': name,
                'host': host,
                'port': port,
                'username': username,
                'password': password
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

# ==================== CREDIT SYSTEM V3 ====================

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

# ==================== DEPLOYMENT FUNCTIONS V3 ====================

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
                
                with DB_LOCK:
                    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                    c = conn.cursor()
                    c.execute('''INSERT INTO analytics 
                                (deployment_id, timestamp, cpu, memory, network_in, network_out)
                                VALUES (?, ?, ?, ?, ?, ?)''',
                             (deploy_id, datetime.now().isoformat(), cpu, mem, 0, 0))
                    conn.commit()
                    conn.close()
                
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
        
        # AI-POWERED DEPENDENCY INSTALLATION
        update_deployment(deploy_id, 'installing', '🤖 AI analyzing project dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        if installed_deps:
            update_deployment(deploy_id, deps=', '.join(installed_deps), install_log=install_log)
            update_deployment(deploy_id, logs=f"✅ Auto-installed: {', '.join(installed_deps)}")
        
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
        result = subprocess.run(clone_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            update_deployment(deploy_id, 'failed', f'❌ Clone failed: {result.stderr}')
            add_credits(user_id, cost, "Refund: Clone failed")
            return None, "❌ Clone failed"
        
        update_deployment(deploy_id, logs='✅ Repository cloned')
        
        # AI-POWERED DEPENDENCY INSTALLATION
        update_deployment(deploy_id, 'installing', '🤖 AI analyzing dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        
        if installed_deps:
            update_deployment(deploy_id, deps=', '.join(installed_deps), install_log=install_log)
            update_deployment(deploy_id, logs=f"✅ Auto-installed: {', '.join(installed_deps)}")
        
        if build_cmd:
            update_deployment(deploy_id, 'building', f'🔨 Building: {build_cmd}')
            build_result = subprocess.run(build_cmd, shell=True, cwd=deploy_dir,
                                        capture_output=True, text=True)
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

# ==================== REVOLUTIONARY WEB DASHBOARD V3 ====================

REVOLUTIONARY_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#6366f1">
    <title>🚀 DevOps Bot v7.0 - Revolutionary Platform</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --secondary: #8b5cf6;
            --accent: #ec4899;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #3b82f6;
            --dark: #0f172a;
            --light: #f8fafc;
            --gradient-main: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            --gradient-glow: radial-gradient(circle at 50% 50%, rgba(102, 126, 234, 0.3), transparent 70%);
        }
        
        @keyframes gradientShift {
            0%, 100% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.8; transform: scale(1.05); }
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-15px); }
        }
        
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--gradient-main);
            background-size: 400% 400%;
            animation: gradientShift 20s ease infinite;
            min-height: 100vh;
            padding-bottom: 90px;
            position: relative;
            overflow-x: hidden;
        }
        
        body::before {
            content: '';
            position: fixed;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 1px, transparent 1px);
            background-size: 60px 60px;
            animation: float 25s ease-in-out infinite;
            pointer-events: none;
            z-index: 0;
        }
        
        .header {
            background: rgba(255,255,255,0.98);
            backdrop-filter: blur(25px);
            padding: 28px 24px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.12);
            position: sticky;
            top: 0;
            z-index: 100;
            border-bottom: 4px solid var(--primary);
        }
        
        .logo {
            font-size: 32px;
            font-weight: 900;
            background: var(--gradient-main);
            background-size: 200% 200%;
            animation: gradientShift 4s ease infinite;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 18px;
            letter-spacing: -1.5px;
            display: flex;
            align-items: center;
            gap: 14px;
        }
        
        .logo i {
            background: var(--gradient-main);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: float 3.5s ease-in-out infinite;
        }
        
        .version-badge {
            background: var(--gradient-main);
            color: white;
            padding: 5px 14px;
            border-radius: 24px;
            font-size: 11px;
            font-weight: 900;
            letter-spacing: 1.2px;
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.5);
            animation: pulse 2.5s ease-in-out infinite;
        }
        
        .credit-display {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--gradient-main);
            background-size: 200% 200%;
            animation: gradientShift 6s ease infinite;
            color: white;
            padding: 26px 28px;
            border-radius: 24px;
            margin-top: 18px;
            box-shadow: 0 14px 36px rgba(102, 126, 234, 0.45);
            position: relative;
            overflow: hidden;
        }
        
        .credit-display::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.15) 10%, transparent 70%);
            animation: float 12s ease-in-out infinite;
        }
        
        .credit-badge {
            background: rgba(255,255,255,0.28);
            padding: 7px 16px;
            border-radius: 24px;
            font-size: 12px;
            font-weight: 800;
            margin-bottom: 10px;
            backdrop-filter: blur(12px);
        }
        
        .credit-value {
            font-size: 42px;
            font-weight: 900;
            text-shadow: 0 3px 12px rgba(0,0,0,0.25);
        }
        
        .buy-btn {
            background: rgba(255,255,255,0.32);
            color: white;
            padding: 16px 32px;
            border: 2px solid rgba(255,255,255,0.5);
            border-radius: 16px;
            font-weight: 900;
            backdrop-filter: blur(12px);
            cursor: pointer;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.25);
        }
        
        .buy-btn:hover {
            background: rgba(255,255,255,0.45);
            transform: translateY(-3px) scale(1.05);
            box-shadow: 0 8px 25px rgba(0,0,0,0.35);
        }
        
        .container {
            padding: 28px 24px;
            max-width: 1400px;
            margin: 0 auto;
            position: relative;
            z-index: 1;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 18px;
            margin-bottom: 28px;
        }
        
        .stat-card {
            background: rgba(255,255,255,0.96);
            backdrop-filter: blur(12px);
            border-radius: 24px;
            padding: 28px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0,0,0,0.12);
            transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
            border: 2px solid transparent;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: var(--gradient-main);
        }
        
        .stat-card:hover {
            transform: translateY(-5px) scale(1.02);
            box-shadow: 0 15px 45px rgba(0,0,0,0.18);
            border-color: var(--primary);
        }
        
        .stat-icon {
            font-size: 38px;
            margin-bottom: 14px;
            filter: drop-shadow(0 3px 6px rgba(0,0,0,0.15));
            animation: float 4s ease-in-out infinite;
        }
        
        .stat-value {
            font-size: 42px;
            font-weight: 900;
            background: var(--gradient-main);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 12px 0;
        }
        
        .stat-label {
            color: #64748b;
            font-size: 14px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        
        .tab-bar {
            display: flex;
            overflow-x: auto;
            gap: 12px;
            padding: 18px 24px;
            background: rgba(255,255,255,0.96);
            backdrop-filter: blur(12px);
            margin: 0 -24px 28px -24px;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
            -webkit-overflow-scrolling: touch;
        }
        
        .tab-bar::-webkit-scrollbar { display: none; }
        
        .tab {
            flex: 0 0 auto;
            padding: 16px 28px;
            border-radius: 16px;
            background: transparent;
            border: none;
            font-size: 15px;
            font-weight: 900;
            color: #64748b;
            white-space: nowrap;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            position: relative;
        }
        
        .tab.active {
            background: var(--gradient-main);
            color: white;
            box-shadow: 0 8px 24px rgba(102, 126, 234, 0.45);
            transform: translateY(-3px);
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.5s ease-out;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .card {
            background: rgba(255,255,255,0.96);
            backdrop-filter: blur(12px);
            border-radius: 28px;
            padding: 32px;
            margin-bottom: 24px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.12);
            position: relative;
            overflow: hidden;
            border: 2px solid transparent;
            transition: all 0.4s;
        }
        
        .card:hover {
            border-color: rgba(102, 126, 234, 0.3);
            box-shadow: 0 15px 50px rgba(0,0,0,0.15);
        }
        
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 6px;
            background: var(--gradient-main);
        }
        
        .card-title {
            font-size: 26px;
            font-weight: 900;
            margin-bottom: 24px;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 14px;
        }
        
        .btn {
            background: var(--gradient-main);
            color: white;
            border: none;
            padding: 20px 32px;
            border-radius: 18px;
            cursor: pointer;
            font-size: 17px;
            font-weight: 900;
            width: 100%;
            margin: 14px 0;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 14px;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 8px 28px rgba(102, 126, 234, 0.45);
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        
        .btn:hover {
            transform: translateY(-3px) scale(1.02);
            box-shadow: 0 12px 38px rgba(102, 126, 234, 0.55);
        }
        
        .btn:active {
            transform: translateY(0) scale(0.98);
        }
        
        .btn-success { background: linear-gradient(135deg, #10b981, #059669); }
        .btn-danger { background: linear-gradient(135deg, #ef4444, #dc2626); }
        .btn-warning { background: linear-gradient(135deg, #f59e0b, #d97706); }
        .btn-info { background: linear-gradient(135deg, #3b82f6, #2563eb); }
        
        .input-group {
            margin-bottom: 24px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 12px;
            font-weight: 900;
            color: var(--dark);
            font-size: 15px;
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        
        .input-group input, .input-group select, .input-group textarea {
            width: 100%;
            padding: 18px 20px;
            border: 3px solid #e2e8f0;
            border-radius: 16px;
            font-size: 16px;
            font-family: inherit;
            transition: all 0.4s;
            background: white;
        }
        
        .input-group input:focus, .input-group select:focus, .input-group textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 5px rgba(102,126,234,0.18);
            transform: translateY(-2px);
        }
        
        .upload-zone {
            border: 4px dashed var(--primary);
            border-radius: 28px;
            padding: 70px 28px;
            text-align: center;
            cursor: pointer;
            transition: all 0.4s;
            background: linear-gradient(135deg, rgba(102,126,234,0.06), rgba(118,75,162,0.06));
            position: relative;
            overflow: hidden;
        }
        
        .upload-zone::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 350px;
            height: 350px;
            background: radial-gradient(circle, rgba(102,126,234,0.12) 0%, transparent 70%);
            transform: translate(-50%, -50%);
            animation: pulse 4s ease-in-out infinite;
        }
        
        .upload-zone:hover {
            background: linear-gradient(135deg, rgba(102,126,234,0.12), rgba(118,75,162,0.12));
            border-color: var(--secondary);
            transform: scale(1.03);
            box-shadow: 0 15px 40px rgba(102,126,234,0.25);
        }
        
        .upload-icon {
            font-size: 64px;
            background: var(--gradient-main);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 24px;
            animation: float 3.5s ease-in-out infinite;
        }
        
        .deployment-item {
            background: linear-gradient(135deg, #ffffff, #f8fafc);
            border-radius: 24px;
            padding: 26px;
            margin-bottom: 20px;
            border-left: 7px solid var(--primary);
            transition: all 0.4s;
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }
        
        .deployment-item:hover {
            box-shadow: 0 12px 40px rgba(0,0,0,0.15);
            transform: translateX(8px);
        }
        
        .deployment-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 16px;
        }
        
        .deployment-name {
            font-size: 20px;
            font-weight: 900;
            color: var(--dark);
            margin-bottom: 10px;
        }
        
        .deployment-meta {
            color: #64748b;
            font-size: 13px;
            font-weight: 700;
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            margin-top: 10px;
        }
        
        .meta-item {
            display: flex;
            align-items: center;
            gap: 7px;
        }
        
        .resource-usage {
            display: flex;
            gap: 18px;
            margin-top: 14px;
            padding-top: 14px;
            border-top: 2px solid #e2e8f0;
        }
        
        .resource-bar {
            flex: 1;
        }
        
        .resource-label {
            font-size: 12px;
            font-weight: 800;
            color: #64748b;
            margin-bottom: 8px;
            text-transform: uppercase;
        }
        
        .progress-bar {
            height: 10px;
            background: #e2e8f0;
            border-radius: 12px;
            overflow: hidden;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--gradient-main);
            border-radius: 12px;
            transition: width 0.6s ease;
        }
        
        .status-badge {
            padding: 10px 18px;
            border-radius: 28px;
            font-size: 12px;
            font-weight: 900;
            text-transform: uppercase;
            letter-spacing: 1.2px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.12);
        }
        
        .status-running { background: linear-gradient(135deg, #d1fae5, #a7f3d0); color: #065f46; }
        .status-pending { background: linear-gradient(135deg, #fef3c7, #fde68a); color: #92400e; }
        .status-building, .status-installing { background: linear-gradient(135deg, #dbeafe, #bfdbfe); color: #1e40af; }
        .status-cloning, .status-extracting { background: linear-gradient(135deg, #e0e7ff, #c7d2fe); color: #3730a3; }
        .status-starting { background: linear-gradient(135deg, #fce7f3, #fbcfe8); color: #9f1239; }
        .status-stopped { background: linear-gradient(135deg, #fee2e2, #fecaca); color: #991b1b; }
        .status-failed { background: linear-gradient(135deg, #fecaca, #fca5a5); color: #7f1d1d; }
        .status-completed { background: linear-gradient(135deg, #d1fae5, #a7f3d0); color: #065f46; }
        
        .action-btns {
            display: flex;
            gap: 12px;
            margin-top: 18px;
            flex-wrap: wrap;
        }
        
        .action-btn {
            flex: 1;
            min-width: 110px;
            padding: 14px 18px;
            border: none;
            border-radius: 14px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 900;
            color: white;
            transition: all 0.4s;
            text-transform: uppercase;
            letter-spacing: 0.6px;
        }
        
        .nav-item.active {
            color: var(--primary);
            transform: translateY(-4px);
        }
        
        .nav-item i {
            font-size: 26px;
        }
        
        .badge {
            position: absolute;
            top: -8px;
            right: -8px;
            background: var(--danger);
            color: white;
            font-size: 11px;
            font-weight: 900;
            padding: 4px 8px;
            border-radius: 14px;
            box-shadow: 0 3px 10px rgba(239, 68, 68, 0.5);
        }
        
        .pricing-card {
            background: linear-gradient(135deg, #ffffff, #f8fafc);
            border-radius: 28px;
            padding: 38px;
            margin: 24px 0;
            text-align: center;
            position: relative;
            box-shadow: 0 10px 30px rgba(0,0,0,0.12);
            transition: all 0.5s;
            border: 3px solid transparent;
        }
        
        .pricing-card:hover {
            transform: translateY(-10px);
            box-shadow: 0 20px 60px rgba(0,0,0,0.18);
        }
        
        .pricing-card.featured {
            border-color: var(--primary);
            background: linear-gradient(135deg, rgba(102,126,234,0.08), rgba(118,75,162,0.08));
        }
        
        .pricing-badge {
            position: absolute;
            top: -16px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--gradient-main);
            color: white;
            padding: 10px 28px;
            border-radius: 28px;
            font-size: 12px;
            font-weight: 900;
            letter-spacing: 1.2px;
            box-shadow: 0 8px 24px rgba(102, 126, 234, 0.5);
        }
        
        .pricing-type {
            font-size: 15px;
            color: #64748b;
            font-weight: 900;
            margin-top: 14px;
            text-transform: uppercase;
            letter-spacing: 1.2px;
        }
        
        .pricing-amount {
            font-size: 64px;
            font-weight: 900;
            background: var(--gradient-main);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 18px 0;
        }
        
        .pricing-credits {
            font-size: 22px;
            color: #64748b;
            margin-bottom: 28px;
            font-weight: 800;
        }
        
        .feature-list {
            text-align: left;
            margin: 28px 0;
            padding: 0 14px;
        }
        
        .feature-item {
            display: flex;
            align-items: center;
            gap: 14px;
            margin: 14px 0;
            font-size: 15px;
            font-weight: 700;
            color: #475569;
        }
        
        .feature-item i {
            color: var(--success);
            font-size: 20px;
        }
        
        @media (min-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(4, 1fr);
            }
            
            .bottom-nav {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">
            <i class="fas fa-rocket"></i> 
            DevOps Bot v7.0
            <span class="version-badge">REVOLUTIONARY</span>
        </div>
        <div class="credit-display">
            <div style="position: relative; z-index: 1;">
                <div class="credit-badge">💎 CREDITS BALANCE</div>
                <div class="credit-value" id="creditBalance">{{ credits }}</div>
            </div>
            <a href="{{ telegram_link }}" target="_blank" class="buy-btn">
                <i class="fab fa-telegram"></i> Buy Credits
            </a>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">🚀</div>
                <div class="stat-value" id="totalDeploys">{{ total_deploys }}</div>
                <div class="stat-label">Deployments</div>
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
                <div class="stat-icon">💾</div>
                <div class="stat-value" id="backupCount">{{ backup_count }}</div>
                <div class="stat-label">Backups</div>
            </div>
        </div>
        
        <div class="tab-bar">
            <button class="tab active" onclick="showTab('deploy')">
                <i class="fas fa-rocket"></i> Deploy
            </button>
            <button class="tab" onclick="showTab('deployments')">
                <i class="fas fa-list"></i> Apps
            </button>
            <button class="tab" onclick="showTab('github')">
                <i class="fab fa-github"></i> GitHub
            </button>
            <button class="tab" onclick="showTab('env')">
                <i class="fas fa-key"></i> ENV
            </button>
            <button class="tab" onclick="showTab('pricing')">
                <i class="fas fa-shopping-cart"></i> Pricing
            </button>
        </div>
        
        <!-- Deploy Tab -->
        <div id="deploy-tab" class="tab-content active">
            <div class="card">
                <h3 class="card-title"><i class="fas fa-cloud-upload-alt"></i> Revolutionary Deploy</h3>
                <p style="color: #64748b; margin-bottom: 28px; font-size: 16px; line-height: 1.9; font-weight: 700;">
                    <strong style="color: var(--primary);">🤖 AI-Powered Auto-Install:</strong> Upload any project and watch as our revolutionary system automatically detects and installs all dependencies. Zero configuration needed!
                </p>
                
                <div class="upload-zone" id="uploadZone" onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <h3 style="font-size: 26px; font-weight: 900; margin-bottom: 14px; color: var(--dark);">Drop or Click to Upload</h3>
                    <p style="color: #64748b; font-size: 15px; font-weight: 700;">Python, JavaScript, ZIP archives</p>
                    <p style="color: var(--primary); font-size: 14px; margin-top: 14px; font-weight: 900;">
                        ✨ Auto-detects: requirements.txt • package.json • Gemfile • composer.json • go.mod
                    </p>
                    <input type="file" id="fileInput" hidden accept=".py,.js,.zip" onchange="handleFileUpload(this)">
                </div>
            </div>
        </div>
        
        <!-- GitHub Deploy Tab -->
        <div id="github-tab" class="tab-content">
            <div class="card">
                <h3 class="card-title"><i class="fab fa-github"></i> GitHub Deploy</h3>
                <p style="color: #64748b; margin-bottom: 28px; font-size: 16px; font-weight: 700;">
                    Deploy from any GitHub repository with intelligent dependency detection
                </p>
                
                <div class="input-group">
                    <label><i class="fab fa-github"></i> Repository URL</label>
                    <input type="url" id="repoUrl" placeholder="https://github.com/username/repo.git">
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
                    <i class="fab fa-github"></i> Deploy Repository
                </button>
            </div>
        </div>
        
        <!-- Deployments Tab -->
        <div id="deployments-tab" class="tab-content">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 28px;">
                    <h3 class="card-title" style="margin: 0;"><i class="fas fa-server"></i> Your Applications</h3>
                    <button onclick="loadDeployments()" style="background: var(--gradient-main); border: none; color: white; font-size: 26px; padding: 14px; cursor: pointer; border-radius: 14px; width: 52px; height: 52px; box-shadow: 0 5px 15px rgba(102,126,234,0.35);">
                        <i class="fas fa-sync"></i>
                    </button>
                </div>
                <div id="deploymentsList"></div>
            </div>
        </div>
        
        <!-- Environment Tab -->
        <div id="env-tab" class="tab-content">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 28px;">
                    <h3 class="card-title" style="margin: 0;"><i class="fas fa-lock"></i> Environment Variables</h3>
                    <button onclick="showAddEnv()" style="background: var(--gradient-main); border: none; color: white; font-size: 26px; padding: 14px; cursor: pointer; border-radius: 14px; width: 52px; height: 52px; box-shadow: 0 5px 15px rgba(102,126,234,0.35);">
                        <i class="fas fa-plus"></i>
                    </button>
                </div>
                <div id="envList"></div>
            </div>
        </div>
        
        <!-- Pricing Tab -->
        <div id="pricing-tab" class="tab-content">
            <div class="card">
                <h3 class="card-title" style="text-align: center; font-size: 32px;"><i class="fas fa-crown"></i> Premium Plans</h3>
                
                <div class="pricing-card">
                    <div class="pricing-type">STARTER</div>
                    <div class="pricing-amount">₹99</div>
                    <div class="pricing-credits">10 Credits</div>
                    <div class="feature-list">
                        <div class="feature-item"><i class="fas fa-check-circle"></i> 20 Deployments</div>
                        <div class="feature-item"><i class="fas fa-check-circle"></i> GitHub Integration</div>
                        <div class="feature-item"><i class="fas fa-check-circle"></i> Auto Dependencies</div>
                    </div>
                    <a href="{{ telegram_link }}" target="_blank" class="btn">
                        <i class="fab fa-telegram"></i> Buy Now
                    </a>
                </div>
                
                <div class="pricing-card featured">
                    <div class="pricing-badge">⭐ MOST POPULAR</div>
                    <div class="pricing-type">PRO</div>
                    <div class="pricing-amount">₹399</div>
                    <div class="pricing-credits">50 Credits</div>
                    <div class="feature-list">
                        <div class="feature-item"><i class="fas fa-check-circle"></i> 100 Deployments</div>
                        <div class="feature-item"><i class="fas fa-check-circle"></i> Priority Support</div>
                        <div class="feature-item"><i class="fas fa-check-circle"></i> Advanced Analytics</div>
                        <div class="feature-item"><i class="fas fa-check-circle"></i> Auto Backups</div>
                    </div>
                    <a href="{{ telegram_link }}" target="_blank" class="btn">
                        <i class="fab fa-telegram"></i> Get Pro Now
                    </a>
                </div>
                
                <div class="pricing-card" style="background: linear-gradient(135deg, #f093fb, #f5576c); color: white;">
                    <div class="pricing-type" style="color: white;">UNLIMITED</div>
                    <div class="pricing-amount" style="color: white; background: none; -webkit-background-clip: initial; -webkit-text-fill-color: white;">₹2999</div>
                    <div class="pricing-credits" style="color: white;">∞ Unlimited Credits</div>
                    <div class="feature-list">
                        <div class="feature-item" style="color: white;"><i class="fas fa-check-circle"></i> Unlimited Everything</div>
                        <div class="feature-item" style="color: white;"><i class="fas fa-check-circle"></i> Dedicated Support</div>
                        <div class="feature-item" style="color: white;"><i class="fas fa-check-circle"></i> Custom Integrations</div>
                        <div class="feature-item" style="color: white;"><i class="fas fa-check-circle"></i> White Label Option</div>
                    </div>
                    <a href="{{ telegram_link }}" target="_blank" class="btn" style="background: white; color: #f5576c; box-shadow: 0 8px 28px rgba(0,0,0,0.25);">
                        <i class="fab fa-telegram"></i> Go Unlimited
                    </a>
                </div>
            </div>
        </div>
    </div>
    
    <div class="bottom-nav">
        <a class="nav-item active" onclick="showTab('deploy')">
            <i class="fas fa-rocket"></i>
            <span>Deploy</span>
        </a>
        <a class="nav-item" onclick="showTab('deployments')">
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
            <span>Pricing</span>
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
            
            if (tab === 'deployments') loadDeployments();
            if (tab === 'env') loadEnv();
        }
        
        async function handleFileUpload(input) {
            const file = input.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            showNotification('🤖 AI analyzing and deploying...', 'info');
            
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
                        showTab('deployments');
                    }, 1500);
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Deployment failed', 'error');
            }
            
            input.value = '';
        }
        
        async function deployGithub() {
            const url = document.getElementById('repoUrl').value;
            const branch = document.getElementById('repoBranch').value;
            const buildCmd = document.getElementById('buildCmd').value;
            const startCmd = document.getElementById('startCmd').value;
            
            if (!url) return showNotification('⚠️ Enter repository URL', 'warning');
            
            showNotification('🤖 AI cloning and analyzing...', 'info');
            
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
                        showTab('deployments');
                    }, 1500);
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Deployment failed', 'error');
            }
        }
        
        async function loadDeployments() {
            try {
                const res = await fetch('/api/deployments');
                const data = await res.json();
                
                const list = document.getElementById('deploymentsList');
                
                if (!data.deployments || !data.deployments.length) {
                    list.innerHTML = '<div style="text-align:center;padding:70px 24px;"><div style="font-size:72px;margin-bottom:24px;">🚀</div><p style="color:#64748b;font-size:20px;font-weight:800;">No deployments yet</p><p style="color:#94a3b8;font-size:16px;margin-top:14px;font-weight:700;">Deploy your first application to get started!</p></div>';
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
                                    ${d.pid ? `<span class="meta-item"><i class="fas fa-microchip"></i> PID ${d.pid}</span>` : ''}
                                </div>
                                ${d.repo_url ? `<p style="color:#6366f1;font-size:13px;margin-top:10px;font-weight:800;"><i class="fab fa-github"></i> ${d.repo_url.split('/').slice(-2).join('/')}</p>` : ''}
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
                    <h3 style="margin-bottom: 28px; font-size: 28px; font-weight: 900;"><i class="fas fa-terminal"></i> Deployment Logs</h3>
                    <div class="terminal">${data.logs || 'No logs available...'}</div>
                    <button class="btn btn-danger" onclick="closeModal()" style="margin-top: 24px;">
                        <i class="fas fa-times"></i> Close
                    </button>
                `);
            } catch (err) {
                showNotification('❌ Failed to load logs', 'error');
            }
        }
        
        async function stopDeploy(deployId) {
            if (!confirm('Stop this deployment?')) return;
            
            showNotification('⏳ Stopping deployment...', 'info');
            
            try {
                const res = await fetch('/api/deployment/' + deployId + '/stop', {method: 'POST'});
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Deployment stopped', 'success');
                    loadDeployments();
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Stop failed', 'error');
            }
        }
        
        async function deleteDeploy(deployId) {
            if (!confirm('Delete this deployment permanently?')) return;
            
            showNotification('⏳ Deleting deployment...', 'info');
            
            try {
                const res = await fetch('/api/deployment/' + deployId, {method: 'DELETE'});
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Deployment deleted', 'success');
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
                <h3 style="margin-bottom: 28px; font-size: 28px; font-weight: 900;"><i class="fas fa-plus"></i> Add Environment Variable</h3>
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
            
            showNotification('⏳ Adding variable...', 'info');
            
            try {
                const res = await fetch('/api/env/add', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key, value})
                });
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Variable added', 'success');
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
                    list.innerHTML = '<div style="text-align:center;padding:70px 24px;"><div style="font-size:72px;margin-bottom:24px;">🔐</div><p style="color:#64748b;font-size:20px;font-weight:800;">No environment variables</p><p style="color:#94a3b8;font-size:16px;margin-top:14px;font-weight:700;">Add variables for your deployments</p></div>';
                    return;
                }
                
                list.innerHTML = Object.entries(data.variables).map(([key, value]) => `
                    <div class="deployment-item">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="flex: 1; min-width: 0;">
                                <div class="deployment-name">${key}</div>
                                <p style="color:#64748b;font-size:14px;margin-top:10px;overflow:hidden;text-overflow:ellipsis;font-family:monospace;font-weight:700;">
                                    ${value.substring(0, 50)}${value.length > 50 ? '...' : ''}
                                </p>
                            </div>
                            <button class="action-btn" style="background: var(--danger); margin: 0; min-width: auto; flex: 0;" onclick="deleteEnv('${key}')">
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
            if (!confirm('Delete variable "' + key + '"?')) return;
            
            showNotification('⏳ Deleting variable...', 'info');
            
            try {
                const res = await fetch('/api/env/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key})
                });
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Variable deleted', 'success');
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
                info: '<i class="fas fa-info-circle notification-icon" style="color: #3b82f6;"></i>',
                success: '<i class="fas fa-check-circle notification-icon" style="color: #10b981;"></i>',
                warning: '<i class="fas fa-exclamation-triangle notification-icon" style="color: #f59e0b;"></i>',
                error: '<i class="fas fa-times-circle notification-icon" style="color: #ef4444;"></i>'
            };
            
            notif.innerHTML = (icons[type] || icons.info) + `<div style="flex: 1; font-weight: 800;"><strong>${msg}</strong></div>`;
            notif.classList.add('show');
            setTimeout(() => notif.classList.remove('show'), 4500);
        }
        
        setInterval(updateCredits, 15000);
        setInterval(() => {
            if (document.getElementById('deployments-tab').classList.contains('active')) {
                loadDeployments();
            }
        }, 10000);
        
        loadDeployments();
        
        document.getElementById('modal').addEventListener('click', (e) => {
            if (e.target.id === 'modal') closeModal();
        });
        
        const uploadZone = document.getElementById('uploadZone');
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
    </script>
</body>
</html>
"""

# ==================== FLASK ROUTES V3 ====================

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
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM backups WHERE user_id = ?', (user_id,))
        backup_count = c.fetchone()[0]
        conn.close()
    
    return render_template_string(
        REVOLUTIONARY_HTML,
        credits=f"{credits:.1f}" if credits != float('inf') else "∞",
        total_deploys=total_deploys,
        active_deploys=active_count,
        vps_count=vps_count,
        backup_count=backup_count,
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

# ==================== REVOLUTIONARY TELEGRAM BOT ====================

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
        f"🚀 *DevOps Bot v7.0 - REVOLUTIONARY EDITION*\n\n"
        f"👤 *{first_name}*\n"
        f"💎 Credits: *{credits if credits != float('inf') else '∞'}*\n\n"
        f"*✨ REVOLUTIONARY FEATURES:*\n\n"
        f"🤖 *AI-Powered Auto-Install*\n"
        f"   └ Python (requirements.txt)\n"
        f"   └ Node.js (package.json)\n"
        f"   └ Ruby (Gemfile)\n"
        f"   └ PHP (composer.json)\n"
        f"   └ Go (go.mod)\n\n"
        f"⚡ *Advanced Capabilities*\n"
        f"   • One-Click File Deploy\n"
        f"   • GitHub Integration\n"
        f"   • Real-time Monitoring\n"
        f"   • Resource Analytics\n"
        f"   • Auto Backup System\n"
        f"   • Environment Manager\n"
        f"   • VPS Management\n\n"
        f"🎨 *Revolutionary Dashboard*\n"
        f"   • Beautiful Gradient UI\n"
        f"   • Smooth Animations\n"
        f"   • Mobile Optimized\n"
        f"   • Real-time Updates\n\n"
        f"*Zero configuration. Just deploy!* 🎯",
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
                f"🌐 *Revolutionary Web Dashboard*\n\n"
                f"🔗 Access: `http://localhost:{port}`\n\n"
                f"*🎨 REVOLUTIONARY FEATURES:*\n"
                f"✓ Stunning gradient animations\n"
                f"✓ AI-powered auto-install\n"
                f"✓ Real-time resource monitoring\n"
                f"✓ Interactive deployment logs\n"
                f"✓ Drag & drop file upload\n"
                f"✓ GitHub one-click deploy\n"
                f"✓ Secure environment manager\n"
                f"✓ Mobile-first responsive\n\n"
                f"*Experience the future of DevOps!* 🚀")
        
        elif call.data == 'status':
            deploys = active_deployments.get(user_id, [])
            if not deploys:
                bot.answer_callback_query(call.id)
                bot.send_message(call.message.chat.id, 
                    "📊 *No Deployments*\n\nDeploy your first app to see stats!")
            else:
                running = sum(1 for d in deploys if d['status'] == 'running')
                installing = sum(1 for d in deploys if d['status'] in ['installing', 'building'])
                
                avg_cpu = sum(d.get('cpu_usage', 0) for d in deploys if d['status'] == 'running') / max(running, 1)
                avg_mem = sum(d.get('memory_usage', 0) for d in deploys if d['status'] == 'running') / max(running, 1)
                
                status_text = f"📊 *Deployment Analytics*\n\n"
                status_text += f"📦 Total Deployments: *{len(deploys)}*\n"
                status_text += f"🟢 Running: *{running}*\n"
                status_text += f"⚡ Installing: *{installing}*\n"
                status_text += f"💻 Avg CPU: *{avg_cpu:.1f}%*\n"
                status_text += f"🧠 Avg RAM: *{avg_mem:.1f}%*\n\n"
                status_text += "*📋 Recent Deployments:*\n"
                
                for d in deploys[-5:]:
                    emoji = {
                        'running': '🟢', 
                        'pending': '🟡', 
                        'stopped': '🔴',
                        'installing': '📦',
                        'building': '🔨',
                        'failed': '❌'
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
                f"Current: *{credits if credits != float('inf') else '∞'}* credits\n"
                f"Total Earned: *{earned}* credits\n"
                f"Total Spent: *{spent}* credits\n\n"
                f"*💰 Get More Credits*\n"
                f"Contact: {YOUR_USERNAME}\n"
                f"Link: {TELEGRAM_LINK}")
        
        else:
            bot.answer_callback_query(call.id, "Use web dashboard for full features!", show_alert=True)
    
    except Exception as e:
        logger.error(f"Callback error: {e}")
        bot.answer_callback_query(call.id, "Error occurred")

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
        
        bot.reply_to(message, "🤖 *AI Analyzing & Deploying...*\n\nPlease wait...")
        deploy_id, msg = deploy_from_file(user_id, filepath, filename)
        
        if deploy_id:
            bot.send_message(message.chat.id,
                f"✅ *Deployment Successful!*\n\n"
                f"🆔 ID: `{deploy_id}`\n"
                f"📦 AI auto-installed dependencies\n\n"
                f"{msg}\n\n"
                f"View in dashboard for real-time monitoring!")
        else:
            bot.send_message(message.chat.id, f"❌ *Deployment Failed*\n\n{msg}")
    
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
            bot.reply_to(message, f"✅ Added *{amount}* credits to `{target_user}`")
            try:
                bot.send_message(target_user, f"🎉 *Bonus Credits!*\n\nYou received *{amount}* credits from admin!")
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
    
    stats_text = f"📊 *System Analytics*\n\n"
    stats_text += f"👥 Users: *{total_users}*\n"
    stats_text += f"🚀 Deployments: *{total_deploys}*\n"
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
    print(f"{Fore.CYAN}{'🚀 ULTRA ADVANCED DEVOPS BOT v7.0 - REVOLUTIONARY EDITION':^90}")
    print("=" * 90)
    print(f"{Fore.GREEN}🐍 Python: {sys.version.split()[0]}")
    print(f"{Fore.GREEN}📁 Data: {DATA_DIR}")
    print(f"{Fore.GREEN}👑 Owner: {OWNER_ID}")
    print(f"{Fore.YELLOW}🎁 Free Credits: {FREE_CREDITS}")
    print("=" * 90)
    print(f"{Fore.MAGENTA}✨ REVOLUTIONARY FEATURES:")
    print(f"{Fore.CYAN}  🤖 AI-Powered Auto-Install")
    print("     └ Python requirements.txt ✓")
    print("     └ Node.js package.json ✓")
    print("     └ Ruby Gemfile ✓")
    print("     └ PHP composer.json ✓")
    print("     └ Go go.mod ✓")
    print("")
    print(f"{Fore.CYAN}  🚀 Advanced Deployment")
    print("     └ File Upload (.py, .js, .zip)")
    print("     └ GitHub Integration")
    print("     └ Custom Build Commands")
    print("     └ Auto Port Allocation")
    print("     └ Real-time Monitoring")
    print("     └ Resource Analytics")
    print("")
    print(f"{Fore.CYAN}  🎨 Revolutionary Dashboard")
    print("     └ Stunning Gradient UI")
    print("     └ Smooth Animations")
    print("     └ Mobile-First Design")
    print("     └ Touch Optimized")
    print("     └ Real-time Updates")
    print("     └ Interactive Modals")
    print("     └ Resource Graphs")
    print("")
    print(f"{Fore.CYAN}  📱 Advanced Telegram Bot")
    print("     └ File Upload Deploy")
    print("     └ Status Analytics")
    print("     └ Credit Management")
    print("     └ Admin Commands")
    print("")
    print(f"{Fore.CYAN}  🔐 Enterprise Security")
    print("     └ Encrypted ENV Variables")
    print("     └ Encrypted VPS Credentials")
    print("     └ Activity Logging")
    print("     └ Transaction History")
    print("=" * 90)
    print(f"{Fore.YELLOW}📊 CAPABILITIES:")
    print(f"  ✓ {len(REQUIRED_PACKAGES)} Dependencies")
    print("  ✓ 5 Package Managers")
    print("  ✓ Unlimited Deployments")
    print("  ✓ Real-time Logs")
    print("  ✓ Auto Detection")
    print("  ✓ Zero Config")
    print("=" * 90)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 Dashboard: http://localhost:{port}")
    print(f"{Fore.CYAN}📱 Telegram: {TELEGRAM_LINK}")
    print(f"{Fore.MAGENTA}✨ Revolutionary UI Active!")
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
