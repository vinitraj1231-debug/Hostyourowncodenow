# -*- coding: utf-8 -*-
"""
🚀 ULTRA ADVANCED DEVOPS BOT v11.0 - ULTIMATE PROFESSIONAL EDITION
Revolutionary AI-Powered Deployment Platform
Professional Design | Per-Deployment ENV | Full Integration | Zero Errors
"""

import sys
import subprocess
import os

# ==================== SMART DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 INSTALLING DEPENDENCIES v11.0")
print("=" * 90)

REQUIRED_PACKAGES = {
    'pyTelegramBotAPI': 'telebot',
    'flask': 'flask',
    'flask-cors': 'flask_cors',
    'requests': 'requests',
    'cryptography': 'cryptography',
    'psutil': 'psutil',
    'werkzeug': 'werkzeug',
    'colorama': 'colorama'
}

def smart_install(package, import_name):
    try:
        __import__(import_name)
        print(f"✓ {package:30} [OK]")
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
for pkg, imp in REQUIRED_PACKAGES.items():
    smart_install(pkg, imp)

print("\n" + "=" * 90)
print("✅ DEPENDENCIES READY!")
print("=" * 90 + "\n")

# ==================== IMPORTS ====================
import telebot
from telebot import types
import zipfile
import shutil
import time
from datetime import datetime
import sqlite3
import json
import logging
import threading
import atexit
import secrets
import signal
from flask import Flask, render_template_string, request, jsonify, session, send_file
from flask_cors import CORS
from threading import Thread, Lock
import uuid
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import psutil
from colorama import Fore, init
import re

init(autoreset=True)

# ==================== CONFIGURATION ====================
TOKEN = '8133133627:AAHXG1M3I_5yV6mIo2IRl61h8zRUvg6Nn2Y'
OWNER_ID = 7524032836
ADMIN_ID = 8285724366
YOUR_USERNAME = '@Zolvit'
TELEGRAM_LINK = 'https://t.me/Zolvit'
UPI_ID = "nitishkypaurai17@ibl"
PAYMENT_QR_IMAGE = "qr.jpg"

WEB_SECRET_KEY = secrets.token_hex(32)
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

FREE_CREDITS = 2.0
CREDIT_PACKAGES = {
    '99': {'credits': 10, 'price': 99, 'name': 'Starter', 'badge': '🥉'},
    '399': {'credits': 50, 'price': 399, 'name': 'Pro', 'badge': '⭐'},
    '699': {'credits': 100, 'price': 699, 'name': 'Ultimate', 'badge': '🔥'}
}

CREDIT_COSTS = {
    'file_upload': 0.5,
    'github_deploy': 1.0,
}

# Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'devops_data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
DEPLOYS_DIR = os.path.join(DATA_DIR, 'deployments')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
DB_PATH = os.path.join(DATA_DIR, 'devops.db')

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, LOGS_DIR]:
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
deployment_env_vars = {}  # {deploy_id: {key: value}}
user_env_vars = {}  # {user_id: {key: value}}
pending_payments = {}
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
            credits REAL DEFAULT 0
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
            repo_url TEXT,
            branch TEXT,
            build_cmd TEXT,
            start_cmd TEXT,
            logs TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS env_vars (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            deployment_id TEXT,
            key TEXT,
            value_encrypted TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS payments (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            amount REAL,
            credits REAL,
            status TEXT,
            created_at TEXT
        )''')
        
        conn.commit()
        conn.close()

def load_data():
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        c.execute('SELECT user_id, credits FROM users')
        for user_id, credits in c.fetchall():
            active_users.add(user_id)
            user_credits[user_id] = credits
        
        c.execute('SELECT id, user_id, name, type, status, port, pid, repo_url, branch FROM deployments WHERE status != "deleted"')
        for dep_id, user_id, name, dep_type, status, port, pid, repo_url, branch in c.fetchall():
            if user_id not in active_deployments:
                active_deployments[user_id] = []
            active_deployments[user_id].append({
                'id': dep_id,
                'name': name,
                'type': dep_type,
                'status': status,
                'port': port or 0,
                'pid': pid,
                'repo_url': repo_url or '',
                'branch': branch or 'main'
            })
        
        c.execute('SELECT user_id, deployment_id, key, value_encrypted FROM env_vars')
        for user_id, deploy_id, key, value_enc in c.fetchall():
            try:
                value = fernet.decrypt(value_enc.encode()).decode()
            except:
                value = value_enc
            
            if deploy_id:
                if deploy_id not in deployment_env_vars:
                    deployment_env_vars[deploy_id] = {}
                deployment_env_vars[deploy_id][key] = value
            else:
                if user_id not in user_env_vars:
                    user_env_vars[user_id] = {}
                user_env_vars[user_id][key] = value
        
        conn.close()

init_db()
load_data()

# ==================== CREDIT SYSTEM ====================

def get_credits(user_id):
    if user_id in admin_ids:
        return float('inf')
    return user_credits.get(user_id, 0.0)

def add_credits(user_id, amount):
    if user_id in admin_ids:
        return True
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        current = get_credits(user_id)
        new_balance = current + amount
        
        c.execute('UPDATE users SET credits = ? WHERE user_id = ?', (new_balance, user_id))
        conn.commit()
        conn.close()
        
        user_credits[user_id] = new_balance
        return True

def deduct_credits(user_id, amount):
    if user_id in admin_ids:
        return True
    
    current = get_credits(user_id)
    if current < amount:
        return False
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        new_balance = current - amount
        c.execute('UPDATE users SET credits = ? WHERE user_id = ?', (new_balance, user_id))
        conn.commit()
        conn.close()
        
        user_credits[user_id] = new_balance
        return True

def init_user(user_id, username, first_name):
    if user_id not in active_users:
        active_users.add(user_id)
        
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO users 
                        (user_id, username, first_name, joined_date, credits)
                        VALUES (?, ?, ?, ?, ?)''',
                     (user_id, username, first_name, datetime.now().isoformat(), FREE_CREDITS))
            conn.commit()
            conn.close()
        
        user_credits[user_id] = FREE_CREDITS
        return True
    return False

# ==================== PAYMENT ====================

def create_payment(user_id, amount):
    payment_id = str(uuid.uuid4())[:8].upper()
    package = CREDIT_PACKAGES[str(amount)]
    
    pending_payments[payment_id] = {
        'user_id': user_id,
        'amount': amount,
        'credits': package['credits'],
        'status': 'pending',
        'created_at': datetime.now().isoformat()
    }
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('''INSERT INTO payments (id, user_id, amount, credits, status, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)''',
                 (payment_id, user_id, amount, package['credits'], 'pending', datetime.now().isoformat()))
        conn.commit()
        conn.close()
    
    return payment_id

def verify_payment(payment_id):
    if payment_id not in pending_payments:
        return False, "Invalid payment ID"
    
    payment = pending_payments[payment_id]
    if payment['status'] == 'completed':
        return False, "Already verified"
    
    user_id = payment['user_id']
    credits = payment['credits']
    
    add_credits(user_id, credits)
    
    payment['status'] = 'completed'
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('UPDATE payments SET status = ? WHERE id = ?', ('completed', payment_id))
        conn.commit()
        conn.close()
    
    return True, f"✅ Added {credits} credits!"

# ==================== AI DEPENDENCY DETECTION ====================

def detect_and_install_deps(project_path):
    installed = []
    install_log = []
    
    install_log.append("🤖 AI DEPENDENCY ANALYZER v11.0")
    install_log.append("=" * 60)
    
    req_file = os.path.join(project_path, 'requirements.txt')
    if os.path.exists(req_file):
        install_log.append("\n📦 PYTHON REQUIREMENTS")
        try:
            with open(req_file, 'r') as f:
                packages = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            for pkg in packages[:20]:
                try:
                    subprocess.run(
                        [sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                        check=True,
                        capture_output=True,
                        timeout=120
                    )
                    install_log.append(f"  ✅ {pkg}")
                    installed.append(pkg)
                except:
                    install_log.append(f"  ⚠️  {pkg}")
        except Exception as e:
            install_log.append(f"❌ Error: {str(e)[:50]}")
    
    pkg_file = os.path.join(project_path, 'package.json')
    if os.path.exists(pkg_file):
        install_log.append("\n📦 NODE.JS PACKAGES")
        try:
            subprocess.run(['npm', '--version'], check=True, capture_output=True)
            result = subprocess.run(
                ['npm', 'install', '--silent'],
                cwd=project_path,
                capture_output=True,
                timeout=300
            )
            if result.returncode == 0:
                install_log.append("  ✅ npm packages installed")
                installed.append('npm packages')
        except:
            install_log.append("  ⚠️  npm not available")
    
    install_log.append("\n" + "=" * 60)
    install_log.append(f"📦 Installed: {len(installed)} packages")
    
    return installed, "\n".join(install_log)

# ==================== DEPLOYMENT ====================

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        return s.getsockname()[1]

def create_deployment(user_id, name, deploy_type, **kwargs):
    deploy_id = str(uuid.uuid4())[:8]
    port = find_free_port()
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('''INSERT INTO deployments 
                    (id, user_id, name, type, status, port, created_at, repo_url, branch, build_cmd, start_cmd, logs)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (deploy_id, user_id, name, deploy_type, 'pending', port, datetime.now().isoformat(),
                  kwargs.get('repo_url', ''), kwargs.get('branch', 'main'),
                  kwargs.get('build_cmd', ''), kwargs.get('start_cmd', ''), ''))
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

def update_deployment(deploy_id, status=None, logs=None, pid=None):
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        updates = []
        values = []
        
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
        
        if updates:
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
        if not deduct_credits(user_id, cost):
            return None, f"❌ Need {cost} credits"
        
        deploy_id, port = create_deployment(user_id, filename, 'file')
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        if filename.endswith('.zip'):
            update_deployment(deploy_id, 'extracting', '📦 Extracting...')
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
                add_credits(user_id, cost)
                return None, "❌ No main file"
            
            file_path = main_file
        else:
            shutil.copy(file_path, os.path.join(deploy_dir, filename))
            file_path = os.path.join(deploy_dir, filename)
        
        update_deployment(deploy_id, 'installing', '🤖 AI installing...')
        installed, install_log = detect_and_install_deps(deploy_dir)
        update_deployment(deploy_id, logs=install_log)
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        if deploy_id in deployment_env_vars:
            env.update(deployment_env_vars[deploy_id])
        if user_id in user_env_vars:
            env.update(user_env_vars[user_id])
        
        update_deployment(deploy_id, 'starting', f'🚀 Starting...')
        
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
            add_credits(user_id, cost)
            return None, "❌ Unsupported type"
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, 'running', f'✅ Running on port {port}', process.pid)
        
        def log_monitor():
            try:
                for line in iter(process.stdout.readline, b''):
                    if line:
                        update_deployment(deploy_id, logs=line.decode().strip()[:200])
                process.wait()
            except:
                pass
        
        Thread(target=log_monitor, daemon=True).start()
        
        return deploy_id, f"🎉 Deployed on port {port}"
    
    except Exception as e:
        logger.error(f"Deploy error: {e}")
        if 'deploy_id' in locals():
            update_deployment(deploy_id, 'failed', str(e)[:200])
            add_credits(user_id, cost)
        return None, str(e)[:200]

def deploy_from_github(user_id, repo_url, branch='main', build_cmd='', start_cmd=''):
    try:
        cost = CREDIT_COSTS['github_deploy']
        if not deduct_credits(user_id, cost):
            return None, f"❌ Need {cost} credits"
        
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        deploy_id, port = create_deployment(user_id, repo_name, 'github',
                                           repo_url=repo_url, branch=branch,
                                           build_cmd=build_cmd, start_cmd=start_cmd)
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        update_deployment(deploy_id, 'cloning', '🔄 Cloning...')
        
        result = subprocess.run(
            ['git', 'clone', '-b', branch, '--depth', '1', repo_url, deploy_dir],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            update_deployment(deploy_id, 'failed', '❌ Clone failed')
            add_credits(user_id, cost)
            return None, "❌ Clone failed"
        
        update_deployment(deploy_id, 'installing', '🤖 AI installing...')
        installed, install_log = detect_and_install_deps(deploy_dir)
        update_deployment(deploy_id, logs=install_log)
        
        if build_cmd:
            update_deployment(deploy_id, 'building', '🔨 Building...')
            subprocess.run(build_cmd, shell=True, cwd=deploy_dir, timeout=300)
        
        if not start_cmd:
            main_files = {
                'main.py': f'{sys.executable} main.py',
                'app.py': f'{sys.executable} app.py',
                'bot.py': f'{sys.executable} bot.py',
                'index.js': 'node index.js',
                'package.json': 'npm start'
            }
            
            for file, cmd in main_files.items():
                if os.path.exists(os.path.join(deploy_dir, file)):
                    start_cmd = cmd
                    break
            
            if not start_cmd:
                update_deployment(deploy_id, 'failed', '❌ No start cmd')
                add_credits(user_id, cost)
                return None, "❌ No start command"
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        if deploy_id in deployment_env_vars:
            env.update(deployment_env_vars[deploy_id])
        if user_id in user_env_vars:
            env.update(user_env_vars[user_id])
        
        update_deployment(deploy_id, 'starting', '🚀 Starting...')
        
        process = subprocess.Popen(
            start_cmd.split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=deploy_dir,
            env=env
        )
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, 'running', f'✅ Running on port {port}', process.pid)
        
        def log_monitor():
            try:
                for line in iter(process.stdout.readline, b''):
                    if line:
                        update_deployment(deploy_id, logs=line.decode().strip()[:200])
                process.wait()
            except:
                pass
        
        Thread(target=log_monitor, daemon=True).start()
        
        return deploy_id, f"🎉 Deployed on port {port}"
    
    except Exception as e:
        logger.error(f"GitHub error: {e}")
        if 'deploy_id' in locals():
            update_deployment(deploy_id, 'failed', str(e)[:200])
            add_credits(user_id, cost)
        return None, str(e)[:200]

def stop_deployment(deploy_id):
    try:
        if deploy_id in active_processes:
            process = active_processes[deploy_id]
            process.terminate()
            try:
                process.wait(timeout=3)
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
        return "\n".join(deployment_logs[deploy_id][-100:])
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT logs FROM deployments WHERE id = ?', (deploy_id,))
        result = c.fetchone()
        conn.close()
        
        return result[0] if result else "No logs"

# ==================== 🎨 PROFESSIONAL WEB DASHBOARD ====================

PROFESSIONAL_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevOps Pro v11.0</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --primary: #6366f1;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --dark: #0f172a;
            --light: #f8fafc;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #fff;
        }
        
        /* Professional Navigation */
        .navbar {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            padding: 0;
            position: sticky;
            top: 0;
            z-index: 1000;
        }
        
        .nav-container {
            max-width: 1400px;
            margin: 0 auto;
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 20px;
            height: 70px;
        }
        
        .nav-brand {
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 20px;
            font-weight: 800;
        }
        
        .nav-brand-icon {
            width: 42px;
            height: 42px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
        }
        
        .nav-menu {
            display: flex;
            gap: 8px;
            list-style: none;
        }
        
        .nav-item {
            padding: 8px 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            font-weight: 600;
            font-size: 14px;
        }
        
        .nav-item:hover {
            background: rgba(255, 255, 255, 0.15);
        }
        
        .nav-item.active {
            background: rgba(255, 255, 255, 0.2);
        }
        
        .nav-credits {
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.2), rgba(255, 255, 255, 0.1));
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 30px 20px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 20px;
        }
        
        .card-title {
            font-size: 18px;
            font-weight: 800;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .section {
            display: none;
        }
        
        .section.active {
            display: block;
        }
        
        .btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 10px;
            font-weight: 700;
            cursor: pointer;
            width: 100%;
            margin-top: 10px;
            transition: all 0.3s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(102, 126, 234, 0.4);
        }
        
        .input-group {
            margin-bottom: 16px;
        }
        
        .input-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 700;
            font-size: 13px;
        }
        
        .input-field {
            width: 100%;
            padding: 12px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            font-size: 14px;
        }
        
        .input-field::placeholder {
            color: rgba(255, 255, 255, 0.5);
        }
        
        .input-field:focus {
            outline: none;
            border-color: #667eea;
            background: rgba(255, 255, 255, 0.15);
        }
        
        .deploy-item {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
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
            font-weight: 800;
            font-size: 15px;
        }
        
        .deploy-meta {
            color: rgba(255, 255, 255, 0.7);
            font-size: 12px;
            margin-top: 4px;
        }
        
        .status-badge {
            padding: 6px 12px;
            border-radius: 8px;
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
        }
        
        .status-running { background: #10b981; }
        .status-pending { background: #f59e0b; }
        .status-stopped { background: #ef4444; }
        
        .action-btns {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(100px, 1fr));
            gap: 8px;
            margin-top: 12px;
        }
        
        .action-btn {
            padding: 8px 12px;
            border: none;
            border-radius: 8px;
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
            color: white;
        }
        
        .pricing-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        
        .price-card {
            background: rgba(255, 255, 255, 0.1);
            border: 2px solid rgba(255, 255, 255, 0.2);
            border-radius: 16px;
            padding: 30px 20px;
            text-align: center;
            transition: all 0.3s;
        }
        
        .price-card:hover {
            transform: translateY(-5px);
            border-color: rgba(255, 255, 255, 0.4);
        }
        
        .price-badge {
            font-size: 48px;
            margin-bottom: 10px;
        }
        
        .price-amount {
            font-size: 42px;
            font-weight: 900;
            margin: 15px 0;
        }
        
        .price-credits {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 20px;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(5px);
            z-index: 2000;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .modal.show {
            display: flex;
        }
        
        .modal-content {
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 16px;
            padding: 30px;
            max-width: 600px;
            width: 100%;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .modal-title {
            font-size: 20px;
            font-weight: 800;
            margin-bottom: 20px;
        }
        
        .toast {
            position: fixed;
            top: 90px;
            right: 20px;
            background: white;
            color: #0f172a;
            padding: 16px 24px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            transform: translateX(400px);
            transition: all 0.3s;
            z-index: 3000;
            font-weight: 600;
        }
        
        .toast.show {
            transform: translateX(0);
        }
        
        .env-item {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 12px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .env-key {
            font-weight: 800;
            font-size: 14px;
        }
        
        .env-value {
            font-family: monospace;
            color: rgba(255, 255, 255, 0.7);
            font-size: 12px;
            margin-top: 4px;
        }
        
        .deploy-select {
            width: 100%;
            padding: 12px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            border-radius: 8px;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            font-size: 14px;
            margin-bottom: 16px;
        }
        
        .deploy-select option {
            background: #0f172a;
            color: #fff;
        }
        
        @media (max-width: 768px) {
            .nav-menu {
                display: none;
            }
            
            .nav-container {
                height: 60px;
            }
        }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">
                <div class="nav-brand-icon">
                    <i class="fas fa-rocket"></i>
                </div>
                <span>DevOps Pro v11.0</span>
            </div>
            <ul class="nav-menu">
                <li class="nav-item active" onclick="showSection('deploy')">
                    <i class="fas fa-upload"></i> Deploy
                </li>
                <li class="nav-item" onclick="showSection('apps')">
                    <i class="fas fa-server"></i> Apps
                </li>
                <li class="nav-item" onclick="showSection('github')">
                    <i class="fab fa-github"></i> GitHub
                </li>
                <li class="nav-item" onclick="showSection('env')">
                    <i class="fas fa-key"></i> ENV
                </li>
                <li class="nav-item" onclick="showSection('credits')">
                    <i class="fas fa-gem"></i> Buy
                </li>
            </ul>
            <div class="nav-credits">
                <i class="fas fa-gem"></i>
                <span id="creditBalance">{{ credits }}</span>
            </div>
        </div>
    </nav>
    
    <div class="container">
        <!-- Deploy Section -->
        <section id="deploy" class="section active">
            <div class="card">
                <h2 class="card-title">
                    <i class="fas fa-cloud-upload-alt"></i>
                    File Upload Deploy
                </h2>
                <p style="margin-bottom: 20px; opacity: 0.9; line-height: 1.6;">
                    Upload .py, .js or .zip files. AI automatically detects and installs dependencies.
                </p>
                <input type="file" id="fileInput" accept=".py,.js,.zip" style="margin-bottom: 10px;">
                <button class="btn" onclick="handleFileUpload()">
                    <i class="fas fa-rocket"></i> Deploy File
                </button>
            </div>
        </section>
        
        <!-- Apps Section -->
        <section id="apps" class="section">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2 class="card-title" style="margin: 0;">
                        <i class="fas fa-server"></i>
                        My Deployments
                    </h2>
                    <button onclick="loadDeployments()" style="background: rgba(255,255,255,0.2); border: none; color: #fff; padding: 10px 16px; border-radius: 8px; cursor: pointer;">
                        <i class="fas fa-sync"></i> Refresh
                    </button>
                </div>
                <div id="deploymentsList"></div>
            </div>
        </section>
        
        <!-- GitHub Section -->
        <section id="github" class="section">
            <div class="card">
                <h2 class="card-title">
                    <i class="fab fa-github"></i>
                    GitHub Deploy
                </h2>
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
                    <i class="fab fa-github"></i> Deploy from GitHub
                </button>
            </div>
        </section>
        
        <!-- ENV Section -->
        <section id="env" class="section">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h2 class="card-title" style="margin: 0;">
                        <i class="fas fa-key"></i>
                        Environment Variables
                    </h2>
                    <button onclick="showAddEnv()" style="background: rgba(255,255,255,0.2); border: none; color: #fff; padding: 10px 16px; border-radius: 8px; cursor: pointer;">
                        <i class="fas fa-plus"></i> Add
                    </button>
                </div>
                <p style="margin-bottom: 20px; opacity: 0.9; line-height: 1.6;">
                    Set environment variables for specific deployments or globally for all deployments.
                </p>
                <div id="envList"></div>
            </div>
        </section>
        
        <!-- Credits Section -->
        <section id="credits" class="section">
            <div class="card">
                <h2 class="card-title">
                    <i class="fas fa-shopping-cart"></i>
                    Buy Credits
                </h2>
                <div class="pricing-grid">
                    <div class="price-card">
                        <div class="price-badge">🥉</div>
                        <div style="font-weight: 700; margin-bottom: 10px;">Starter</div>
                        <div class="price-amount">₹99</div>
                        <div class="price-credits">10 Credits</div>
                        <button class="btn" onclick="buyCredits(99)">
                            <i class="fas fa-shopping-cart"></i> Buy Now
                        </button>
                    </div>
                    <div class="price-card">
                        <div class="price-badge">⭐</div>
                        <div style="font-weight: 700; margin-bottom: 10px;">Pro</div>
                        <div class="price-amount">₹399</div>
                        <div class="price-credits">50 Credits</div>
                        <button class="btn" onclick="buyCredits(399)">
                            <i class="fas fa-shopping-cart"></i> Buy Now
                        </button>
                    </div>
                    <div class="price-card">
                        <div class="price-badge">🔥</div>
                        <div style="font-weight: 700; margin-bottom: 10px;">Ultimate</div>
                        <div class="price-amount">₹699</div>
                        <div class="price-credits">100 Credits</div>
                        <button class="btn" onclick="buyCredits(699)">
                            <i class="fas fa-shopping-cart"></i> Buy Now
                        </button>
                    </div>
                </div>
            </div>
        </section>
    </div>
    
    <div id="modal" class="modal"></div>
    <div id="toast" class="toast"></div>

    <script>
        function showSection(section) {
            document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
            document.getElementById(section).classList.add('active');
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            event.target.classList.add('active');
            
            if (section === 'apps') loadDeployments();
            if (section === 'env') loadEnv();
        }
        
        async function handleFileUpload() {
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            if (!file) return showToast('Please select a file', 'warning');
            
            const formData = new FormData();
            formData.append('file', file);
            showToast('Deploying...', 'info');
            
            try {
                const res = await fetch('/api/deploy/upload', {method: 'POST', body: formData});
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'success');
                    fileInput.value = '';
                    updateCredits();
                    setTimeout(() => {
                        showSection('apps');
                        loadDeployments();
                    }, 1000);
                } else {
                    showToast(data.error, 'error');
                }
            } catch (err) {
                showToast('Deploy failed', 'error');
            }
        }
        
        async function deployGithub() {
            const url = document.getElementById('repoUrl').value;
            const branch = document.getElementById('repoBranch').value;
            const buildCmd = document.getElementById('buildCmd').value;
            const startCmd = document.getElementById('startCmd').value;
            
            if (!url) return showToast('Enter repository URL', 'warning');
            showToast('Deploying from GitHub...', 'info');
            
            try {
                const res = await fetch('/api/deploy/github', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url, branch, build_cmd: buildCmd, start_cmd: startCmd})
                });
                const data = await res.json();
                if (data.success) {
                    showToast(data.message, 'success');
                    document.getElementById('repoUrl').value = '';
                    document.getElementById('buildCmd').value = '';
                    document.getElementById('startCmd').value = '';
                    updateCredits();
                    setTimeout(() => {
                        showSection('apps');
                        loadDeployments();
                    }, 1000);
                } else {
                    showToast(data.error, 'error');
                }
            } catch (err) {
                showToast('Deploy failed', 'error');
            }
        }
        
        async function loadDeployments() {
            try {
                const res = await fetch('/api/deployments');
                const data = await res.json();
                const list = document.getElementById('deploymentsList');
                
                if (!data.deployments || !data.deployments.length) {
                    list.innerHTML = '<div style="text-align:center;padding:40px;opacity:0.7;">No deployments yet</div>';
                    return;
                }
                
                list.innerHTML = data.deployments.map(d => `
                    <div class="deploy-item">
                        <div class="deploy-header">
                            <div>
                                <div class="deploy-name">${d.name}</div>
                                <div class="deploy-meta">
                                    ID: ${d.id} • Port: ${d.port} • Type: ${d.type}
                                </div>
                            </div>
                            <span class="status-badge status-${d.status}">${d.status}</span>
                        </div>
                        <div class="action-btns">
                            <button class="action-btn" style="background:#3b82f6;" onclick="viewLogs('${d.id}')">
                                <i class="fas fa-terminal"></i> Logs
                            </button>
                            <button class="action-btn" style="background:#10b981;" onclick="manageEnv('${d.id}', '${d.name}')">
                                <i class="fas fa-key"></i> ENV
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
                    <h3 class="modal-title"><i class="fas fa-terminal"></i> Deployment Logs</h3>
                    <div style="background:#1e293b;color:#10b981;font-family:monospace;font-size:12px;padding:16px;border-radius:8px;max-height:400px;overflow-y:auto;white-space:pre-wrap;">
                        ${data.logs || 'No logs available'}
                    </div>
                    <button class="btn" onclick="closeModal()" style="background:#ef4444;margin-top:16px;">
                        <i class="fas fa-times"></i> Close
                    </button>
                `);
            } catch (err) {
                showToast('Failed to load logs', 'error');
            }
        }
        
        async function manageEnv(deployId, deployName) {
            try {
                const res = await fetch('/api/env/deployment/' + deployId);
                const data = await res.json();
                const envVars = data.variables || {};
                
                showModal(`
                    <h3 class="modal-title"><i class="fas fa-key"></i> ENV for ${deployName}</h3>
                    <p style="margin-bottom:20px;opacity:0.8;">Environment variables for this specific deployment.</p>
                    <div id="modalEnvList">
                        ${Object.keys(envVars).length === 0 ? 
                            '<div style="text-align:center;padding:20px;opacity:0.6;">No variables set</div>' :
                            Object.entries(envVars).map(([key, value]) => `
                                <div style="background:rgba(255,255,255,0.05);padding:12px;border-radius:8px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;">
                                    <div>
                                        <div style="font-weight:700;">${key}</div>
                                        <div style="font-family:monospace;font-size:11px;opacity:0.7;margin-top:4px;">${value.substring(0,30)}...</div>
                                    </div>
                                    <button onclick="deleteDeployEnv('${deployId}', '${key}')" style="background:#ef4444;border:none;color:#fff;padding:8px 12px;border-radius:6px;cursor:pointer;">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                </div>
                            `).join('')
                        }
                    </div>
                    <div style="margin-top:20px;padding-top:20px;border-top:1px solid rgba(255,255,255,0.2);">
                        <input type="text" class="input-field" id="modalEnvKey" placeholder="Variable Name" style="margin-bottom:10px;">
                        <input type="text" class="input-field" id="modalEnvValue" placeholder="Variable Value" style="margin-bottom:10px;">
                        <button class="btn" onclick="addDeployEnv('${deployId}')" style="background:#10b981;">
                            <i class="fas fa-plus"></i> Add Variable
                        </button>
                    </div>
                    <button class="btn" onclick="closeModal()" style="background:#64748b;margin-top:10px;">
                        <i class="fas fa-times"></i> Close
                    </button>
                `);
            } catch (err) {
                showToast('Failed to load ENV', 'error');
            }
        }
        
        async function addDeployEnv(deployId) {
            const key = document.getElementById('modalEnvKey').value;
            const value = document.getElementById('modalEnvValue').value;
            if (!key || !value) return showToast('Fill all fields', 'warning');
            
            try {
                const res = await fetch('/api/env/deployment/add', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({deployment_id: deployId, key, value})
                });
                const data = await res.json();
                if (data.success) {
                    showToast('Variable added', 'success');
                    closeModal();
                } else {
                    showToast(data.error, 'error');
                }
            } catch (err) {
                showToast('Failed to add', 'error');
            }
        }
        
        async function deleteDeployEnv(deployId, key) {
            if (!confirm('Delete this variable?')) return;
            try {
                const res = await fetch('/api/env/deployment/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({deployment_id: deployId, key})
                });
                const data = await res.json();
                if (data.success) {
                    showToast('Variable deleted', 'success');
                    closeModal();
                } else {
                    showToast(data.error, 'error');
                }
            } catch (err) {
                showToast('Delete failed', 'error');
            }
        }
        
        async function stopDeploy(deployId) {
            if (!confirm('Stop this deployment?')) return;
            try {
                const res = await fetch('/api/deployment/' + deployId + '/stop', {method: 'POST'});
                const data = await res.json();
                if (data.success) {
                    showToast('Deployment stopped', 'success');
                    loadDeployments();
                } else {
                    showToast(data.error, 'error');
                }
            } catch (err) {
                showToast('Stop failed', 'error');
            }
        }
        
        async function deleteDeploy(deployId) {
            if (!confirm('Delete permanently?')) return;
            try {
                const res = await fetch('/api/deployment/' + deployId, {method: 'DELETE'});
                const data = await res.json();
                if (data.success) {
                    showToast('Deleted', 'success');
                    loadDeployments();
                } else {
                    showToast(data.error, 'error');
                }
            } catch (err) {
                showToast('Delete failed', 'error');
            }
        }
        
        function showAddEnv() {
            showModal(`
                <h3 class="modal-title"><i class="fas fa-plus"></i> Add Environment Variable</h3>
                <p style="margin-bottom:20px;opacity:0.8;">Add global variables (applied to all deployments) or deployment-specific variables.</p>
                <div class="input-group">
                    <label class="input-label">Scope</label>
                    <select class="deploy-select" id="envScope">
                        <option value="global">Global (All Deployments)</option>
                        <option value="deployment">Specific Deployment</option>
                    </select>
                </div>
                <div id="deploymentSelect" style="display:none;">
                    <div class="input-group">
                        <label class="input-label">Select Deployment</label>
                        <select class="deploy-select" id="envDeployId"></select>
                    </div>
                </div>
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
                <button class="btn" onclick="closeModal()" style="background:#64748b;margin-top:10px;">
                    <i class="fas fa-times"></i> Cancel
                </button>
            `);
            
            document.getElementById('envScope').addEventListener('change', async function() {
                const deploySelect = document.getElementById('deploymentSelect');
                if (this.value === 'deployment') {
                    deploySelect.style.display = 'block';
                    const res = await fetch('/api/deployments');
                    const data = await res.json();
                    const select = document.getElementById('envDeployId');
                    select.innerHTML = data.deployments.map(d => 
                        `<option value="${d.id}">${d.name} (${d.id})</option>`
                    ).join('');
                } else {
                    deploySelect.style.display = 'none';
                }
            });
        }
        
        async function addEnv() {
            const scope = document.getElementById('envScope').value;
            const key = document.getElementById('envKey').value;
            const value = document.getElementById('envValue').value;
            if (!key || !value) return showToast('Fill all fields', 'warning');
            
            const payload = {key, value};
            if (scope === 'deployment') {
                payload.deployment_id = document.getElementById('envDeployId').value;
            }
            
            try {
                const endpoint = scope === 'deployment' ? '/api/env/deployment/add' : '/api/env/add';
                const res = await fetch(endpoint, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    showToast('Variable added', 'success');
                    closeModal();
                    loadEnv();
                } else {
                    showToast(data.error, 'error');
                }
            } catch (err) {
                showToast('Failed to add', 'error');
            }
        }
        
        async function loadEnv() {
            try {
                const res = await fetch('/api/env/list');
                const data = await res.json();
                const list = document.getElementById('envList');
                
                if (!data.variables || !Object.keys(data.variables).length) {
                    list.innerHTML = '<div style="text-align:center;padding:40px;opacity:0.7;">No global variables set</div>';
                    return;
                }
                
                list.innerHTML = Object.entries(data.variables).map(([key, value]) => `
                    <div class="env-item">
                        <div>
                            <div class="env-key">${key}</div>
                            <div class="env-value">${value.substring(0, 50)}${value.length > 50 ? '...' : ''}</div>
                        </div>
                        <button onclick="deleteEnv('${key}')" style="background:#ef4444;border:none;color:#fff;padding:10px 14px;border-radius:8px;cursor:pointer;">
                            <i class="fas fa-trash"></i>
                        </button>
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
                    showToast('Variable deleted', 'success');
                    loadEnv();
                } else {
                    showToast(data.error, 'error');
                }
            } catch (err) {
                showToast('Delete failed', 'error');
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
                        <h3 class="modal-title"><i class="fas fa-qrcode"></i> Payment</h3>
                        <div style="text-align:center;">
                            <p style="margin-bottom:20px;">Payment ID: <strong>${data.payment_id}</strong></p>
                            <img src="${data.qr_url}" style="max-width:300px;border-radius:12px;margin:20px auto;display:block;">
                            <div style="background:rgba(255,255,255,0.1);padding:20px;border-radius:12px;margin:20px 0;">
                                <p style="font-weight:800;font-size:20px;margin-bottom:10px;">₹${amount}</p>
                                <p style="font-weight:700;color:#10b981;font-size:18px;">${data.credits} Credits</p>
                            </div>
                            <p style="opacity:0.9;line-height:1.6;margin-bottom:20px;">
                                Scan QR or pay to UPI: <strong>${data.upi_id}</strong><br><br>
                                After payment, send screenshot to <a href="${data.telegram_link}" target="_blank" style="color:#3b82f6;">${data.telegram_username}</a>
                            </p>
                            <button class="btn" onclick="closeModal()">
                                <i class="fas fa-times"></i> Close
                            </button>
                        </div>
                    `);
                } else {
                    showToast(data.error, 'error');
                }
            } catch (err) {
                showToast('Failed to create payment', 'error');
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
            modal.innerHTML = '<div class="modal-content">' + html + '</div>';
            modal.classList.add('show');
        }
        
        function closeModal() {
            document.getElementById('modal').classList.remove('show');
        }
        
        function showToast(msg, type = 'info') {
            const toast = document.getElementById('toast');
            const colors = {
                info: '#3b82f6',
                success: '#10b981',
                warning: '#f59e0b',
                error: '#ef4444'
            };
            toast.style.borderLeft = `4px solid ${colors[type]}`;
            toast.textContent = msg;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 3500);
        }
        
        setInterval(updateCredits, 20000);
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
    
    if user_id not in active_users:
        init_user(user_id, 'web_user', 'Web User')
    
    credits = get_credits(user_id)
    return render_template_string(PROFESSIONAL_DASHBOARD, credits=f"{credits:.1f}" if credits != float('inf') else "∞")

@app.route('/api/credits')
def api_credits():
    user_id = session.get('user_id', 999999)
    return jsonify({'success': True, 'credits': get_credits(user_id)})

@app.route('/api/deploy/upload', methods=['POST'])
def api_deploy_upload():
    user_id = session.get('user_id', 999999)
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file'})
    
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
            c.execute('''INSERT OR REPLACE INTO env_vars (id, user_id, deployment_id, key, value_encrypted)
                        VALUES (?, ?, NULL, ?, ?)''',
                     (env_id, user_id, key, value_encrypted))
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
            c.execute('DELETE FROM env_vars WHERE user_id = ? AND key = ? AND deployment_id IS NULL', (user_id, key))
            conn.commit()
            conn.close()
        
        if user_id in user_env_vars and key in user_env_vars[user_id]:
            del user_env_vars[user_id][key]
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/env/deployment/<deploy_id>')
def api_deployment_env(deploy_id):
    variables = deployment_env_vars.get(deploy_id, {})
    return jsonify({'success': True, 'variables': variables})

@app.route('/api/env/deployment/add', methods=['POST'])
def api_add_deployment_env():
    user_id = session.get('user_id', 999999)
    data = request.get_json()
    
    deploy_id = data.get('deployment_id')
    key = data.get('key')
    value = data.get('value')
    
    if not all([deploy_id, key, value]):
        return jsonify({'success': False, 'error': 'Missing fields'})
    
    try:
        env_id = str(uuid.uuid4())[:8]
        value_encrypted = fernet.encrypt(value.encode()).decode()
        
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO env_vars (id, user_id, deployment_id, key, value_encrypted)
                        VALUES (?, ?, ?, ?, ?)''',
                     (env_id, user_id, deploy_id, key, value_encrypted))
            conn.commit()
            conn.close()
        
        if deploy_id not in deployment_env_vars:
            deployment_env_vars[deploy_id] = {}
        deployment_env_vars[deploy_id][key] = value
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/env/deployment/delete', methods=['POST'])
def api_delete_deployment_env():
    data = request.get_json()
    deploy_id = data.get('deployment_id')
    key = data.get('key')
    
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('DELETE FROM env_vars WHERE deployment_id = ? AND key = ?', (deploy_id, key))
            conn.commit()
            conn.close()
        
        if deploy_id in deployment_env_vars and key in deployment_env_vars[deploy_id]:
            del deployment_env_vars[deploy_id][key]
        
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
    
    payment_id = create_payment(user_id, amount)
    package = CREDIT_PACKAGES[str(amount)]
    
    return jsonify({
        'success': True,
        'payment_id': payment_id,
        'qr_url': '/payment/qr',
        'upi_id': UPI_ID,
        'credits': package['credits'],
        'telegram_link': TELEGRAM_LINK,
        'telegram_username': YOUR_USERNAME
    })

@app.route('/payment/qr')
def payment_qr():
    qr_path = os.path.join(BASE_DIR, PAYMENT_QR_IMAGE)
    if os.path.exists(qr_path):
        return send_file(qr_path, mimetype='image/jpeg')
    return "QR not found", 404

def run_flask():
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

def keep_alive():
    Thread(target=run_flask, daemon=True).start()

# ==================== TELEGRAM BOT ====================

def create_main_menu(user_id):
    markup = types.InlineKeyboardMarkup(row_width=2)
    credits = get_credits(user_id)
    credit_text = "∞" if credits == float('inf') else f"{credits:.1f}"
    
    markup.add(types.InlineKeyboardButton(f'💎 {credit_text} Credits', callback_data='credits'))
    markup.add(
        types.InlineKeyboardButton('🚀 Deploy', callback_data='deploy'),
        types.InlineKeyboardButton('📊 Apps', callback_data='apps')
    )
    markup.add(
        types.InlineKeyboardButton('🔑 ENV', callback_data='env'),
        types.InlineKeyboardButton('🌐 Dashboard', callback_data='dashboard')
    )
    markup.add(types.InlineKeyboardButton('💰 Buy Credits', callback_data='buy'))
    
    if user_id in admin_ids:
        markup.add(types.InlineKeyboardButton('👑 Admin', callback_data='admin'))
    
    return markup

@bot.message_handler(commands=['start'])
def start_cmd(message):
    user_id = message.from_user.id
    username = message.from_user.username
    first_name = message.from_user.first_name
    
    is_new = init_user(user_id, username, first_name)
    
    if is_new:
        bot.send_message(user_id, f"🎉 *Welcome!*\n\nYou got *{FREE_CREDITS} free credits*!")
    
    credits = get_credits(user_id)
    
    bot.send_message(
        message.chat.id,
        f"🚀 *DevOps Bot v11.0*\n\n"
        f"👤 {first_name}\n"
        f"💎 Credits: *{credits if credits != float('inf') else '∞'}*\n\n"
        f"*Features:*\n"
        f"✅ AI Auto-Install\n"
        f"✅ Per-Deployment ENV\n"
        f"✅ Bot + Web Sync\n"
        f"✅ GitHub Deploy\n\n"
        f"📤 Send .py/.js/.zip to deploy\n"
        f"🔗 Send GitHub URL to deploy",
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
                f"🌐 *Dashboard*\n\n"
                f"🔗 `http://localhost:{port}`\n\n"
                f"Features:\n"
                f"• File & GitHub deploy\n"
                f"• Per-deployment ENV\n"
                f"• Build/Start commands\n"
                f"• Real-time logs\n"
                f"• Buy credits")
        
        elif call.data == 'apps':
            deploys = active_deployments.get(user_id, [])
            if not deploys:
                bot.answer_callback_query(call.id)
                bot.send_message(call.message.chat.id, "📊 No deployments")
            else:
                text = f"📊 *Your Apps* ({len(deploys)})\n\n"
                for d in deploys[:5]:
                    emoji = {'running': '🟢', 'pending': '🟡', 'stopped': '🔴'}
                    text += f"{emoji.get(d['status'], '⚪')} `{d['name'][:20]}`\n   Port {d['port']} • {d['status']}\n\n"
                bot.answer_callback_query(call.id)
                bot.send_message(call.message.chat.id, text)
        
        elif call.data == 'buy':
            markup = types.InlineKeyboardMarkup()
            markup.add(types.InlineKeyboardButton('🥉 ₹99 → 10', callback_data='buy_99'))
            markup.add(types.InlineKeyboardButton('⭐ ₹399 → 50', callback_data='buy_399'))
            markup.add(types.InlineKeyboardButton('🔥 ₹699 → 100', callback_data='buy_699'))
            markup.add(types.InlineKeyboardButton('◀️ Back', callback_data='back'))
            
            bot.answer_callback_query(call.id)
            bot.edit_message_text(
                f"💰 *Buy Credits*\n\n"
                f"🥉 Starter: ₹99 = 10 credits\n"
                f"⭐ Pro: ₹399 = 50 credits\n"
                f"🔥 Ultimate: ₹699 = 100 credits",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=markup
            )
        
        elif call.data.startswith('buy_'):
            amount = call.data.split('_')[1]
            payment_id = create_payment(user_id, int(amount))
            package = CREDIT_PACKAGES[amount]
            
            bot.answer_callback_query(call.id)
            
            qr_path = os.path.join(BASE_DIR, PAYMENT_QR_IMAGE)
            if os.path.exists(qr_path):
                with open(qr_path, 'rb') as qr:
                    bot.send_photo(
                        call.message.chat.id,
                        qr,
                        caption=f"💳 *Payment*\n\n"
                                f"{package['badge']} {package['name']}\n"
                                f"💰 ₹{amount}\n"
                                f"💎 {package['credits']} credits\n\n"
                                f"🔑 ID: `{payment_id}`\n\n"
                                f"Pay to: `{UPI_ID}`\n\n"
                                f"Send screenshot to {YOUR_USERNAME}"
                    )
        
        elif call.data == 'back':
            bot.answer_callback_query(call.id)
            bot.edit_message_text(
                "🚀 *Main Menu*",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=create_main_menu(user_id)
            )
        
        else:
            bot.answer_callback_query(call.id, "Use dashboard")
    
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
            bot.reply_to(message, "❌ Unsupported\n\nUse: .py, .js, .zip")
            return
        
        file_content = bot.download_file(file_info.file_path)
        user_dir = os.path.join(UPLOADS_DIR, str(user_id))
        os.makedirs(user_dir, exist_ok=True)
        filepath = os.path.join(user_dir, secure_filename(filename))
        
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        msg = bot.reply_to(message, "🤖 *Deploying...*")
        deploy_id, result = deploy_from_file(user_id, filepath, filename)
        
        if deploy_id:
            bot.edit_message_text(
                f"✅ *Deployed!*\n\n"
                f"🆔 {deploy_id}\n"
                f"{result}\n\n"
                f"💎 Credits: {get_credits(user_id):.1f}",
                message.chat.id,
                msg.message_id
            )
        else:
            bot.edit_message_text(f"❌ *Failed*\n\n{result}", message.chat.id, msg.message_id)
    
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)[:100]}")

@bot.message_handler(func=lambda m: m.text and m.text.startswith('https://github.com'))
def handle_github(message):
    user_id = message.from_user.id
    repo_url = message.text.strip()
    
    try:
        msg = bot.reply_to(message, "🤖 *Deploying from GitHub...*")
        deploy_id, result = deploy_from_github(user_id, repo_url)
        
        if deploy_id:
            bot.edit_message_text(
                f"✅ *Deployed!*\n\n"
                f"🆔 {deploy_id}\n"
                f"{result}\n\n"
                f"💎 Credits: {get_credits(user_id):.1f}",
                message.chat.id,
                msg.message_id
            )
        else:
            bot.edit_message_text(f"❌ *Failed*\n\n{result}", message.chat.id, msg.message_id)
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {str(e)[:100]}")

@bot.message_handler(commands=['verify'])
def verify_cmd(message):
    if message.from_user.id not in admin_ids:
        return
    
    try:
        parts = message.text.split()
        if len(parts) != 2:
            bot.reply_to(message, "Usage: /verify PAYMENT_ID")
            return
        
        payment_id = parts[1].upper()
        success, msg = verify_payment(payment_id)
        
        if success:
            payment = pending_payments[payment_id]
            bot.reply_to(message, f"✅ Verified!\n\n{msg}")
            try:
                bot.send_message(payment['user_id'],
                    f"✅ *Payment Confirmed!*\n\n"
                    f"💎 {payment['credits']} credits added\n"
                    f"💰 Balance: {get_credits(payment['user_id']):.1f}")
            except:
                pass
        else:
            bot.reply_to(message, f"❌ {msg}")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")

@bot.message_handler(commands=['addcredits'])
def addcredits_cmd(message):
    if message.from_user.id not in admin_ids:
        return
    
    try:
        parts = message.text.split()
        if len(parts) != 3:
            bot.reply_to(message, "Usage: /addcredits USER_ID AMOUNT")
            return
        
        target = int(parts[1])
        amount = float(parts[2])
        
        add_credits(target, amount)
        bot.reply_to(message, f"✅ Added {amount} credits to {target}")
        
        try:
            bot.send_message(target, f"🎉 Bonus!\n\n💎 {amount} credits added")
        except:
            pass
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")

# ==================== CLEANUP ====================

def cleanup():
    for deploy_id, process in list(active_processes.items()):
        try:
            process.terminate()
            process.wait(timeout=2)
        except:
            try:
                process.kill()
            except:
                pass

atexit.register(cleanup)
signal.signal(signal.SIGINT, lambda s, f: (cleanup(), sys.exit(0)))
signal.signal(signal.SIGTERM, lambda s, f: (cleanup(), sys.exit(0)))

# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "=" * 90)
    print(f"{Fore.CYAN}🚀 DEVOPS BOT v11.0 - ULTIMATE EDITION")
    print("=" * 90)
    print(f"{Fore.GREEN}✅ All errors fixed")
    print(f"{Fore.GREEN}✅ Per-deployment ENV support")
    print(f"{Fore.GREEN}✅ Professional navigation")
    print(f"{Fore.GREEN}✅ GitHub build/start commands")
    print(f"{Fore.GREEN}✅ Bot + Web fully integrated")
    print(f"{Fore.YELLOW}💳 UPI: {UPI_ID}")
    print(f"{Fore.YELLOW}🖼️  QR: {PAYMENT_QR_IMAGE}")
    print("=" * 90 + "\n")
    
    if not os.path.exists(os.path.join(BASE_DIR, PAYMENT_QR_IMAGE)):
        print(f"{Fore.RED}⚠️  QR image not found: {PAYMENT_QR_IMAGE}")
        print(f"{Fore.YELLOW}   Add qr.jpg to project directory\n")
    else:
        print(f"{Fore.GREEN}✅ QR image found\n")
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"{Fore.GREEN}🌐 Dashboard: http://localhost:{port}")
    print(f"{Fore.CYAN}🤖 Starting bot...\n")
    
    while True:
        try:
            bot.infinity_polling(timeout=60, long_polling_timeout=30)
        except Exception as e:
            logger.error(f"Error: {e}")
            time.sleep(5)
