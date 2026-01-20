# -*- coding: utf-8 -*-
"""
ULTRA ADVANCED DEVOPS BOT v5.0 - REVOLUTIONARY EDITION
Auto Dependencies Install + Enhanced UI + Advanced Features
"""

import sys
import subprocess
import os

# ==================== AUTO-INSTALL SYSTEM ====================
print("=" * 80)
print("🔧 SMART DEPENDENCY INSTALLER v5.0")
print("=" * 80)

REQUIRED_PACKAGES = {
    'pyTelegramBotAPI': 'telebot',
    'flask': 'flask',
    'flask-cors': 'flask_cors',
    'requests': 'requests',
    'cryptography': 'cryptography',
    'psutil': 'psutil',
    'werkzeug': 'werkzeug',
    'python-dotenv': 'dotenv'
}

def smart_install(package, import_name):
    try:
        __import__(import_name)
        print(f"✓ {package:25} [INSTALLED]")
        return True
    except ImportError:
        print(f"⚡ {package:25} [INSTALLING...]", end=' ')
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
    print(f"\n❌ Failed to install: {', '.join(failed)}")
    print("Please install manually: pip install " + ' '.join(failed))
    sys.exit(1)

print("\n" + "=" * 80)
print("✅ ALL DEPENDENCIES READY!")
print("=" * 80 + "\n")

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
from flask import Flask, render_template_string, request, jsonify, session, send_file, redirect
from flask_cors import CORS
from threading import Thread, Lock
import uuid
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import psutil

# ==================== CONFIGURATION ====================
TOKEN = '8451737127:AAGRbO0CygbnYuqMCBolTP8_EG7NLrh5d04'
OWNER_ID = 7524032836
ADMIN_ID = 8285724366
YOUR_USERNAME = '@Zolvit'
WEB_SECRET_KEY = secrets.token_hex(32)
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

FREE_CREDITS = 3.0
CREDIT_COSTS = {
    'file_upload': 1.0,
    'github_deploy': 2.0,
    'vps_command': 0.5,
    'backup': 1.0,
}

# Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'devops_data')
UPLOADS_DIR = os.path.join(DATA_DIR, 'uploads')
DEPLOYS_DIR = os.path.join(DATA_DIR, 'deployments')
BACKUPS_DIR = os.path.join(DATA_DIR, 'backups')
LOGS_DIR = os.path.join(DATA_DIR, 'logs')
DB_PATH = os.path.join(DATA_DIR, 'devops.db')

for d in [DATA_DIR, UPLOADS_DIR, DEPLOYS_DIR, BACKUPS_DIR, LOGS_DIR]:
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

# ==================== SMART DEPENDENCY DETECTOR ====================

def detect_and_install_deps(project_path):
    """Auto-detect and install project dependencies"""
    installed = []
    
    # Python requirements.txt
    req_file = os.path.join(project_path, 'requirements.txt')
    if os.path.exists(req_file):
        logger.info(f"📦 Found requirements.txt")
        try:
            with open(req_file, 'r') as f:
                packages = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            if packages:
                logger.info(f"⚡ Installing {len(packages)} Python packages...")
                subprocess.run(
                    [sys.executable, '-m', 'pip', 'install', '-r', req_file, '--quiet'],
                    check=True,
                    capture_output=True
                )
                installed.extend(packages)
                logger.info(f"✅ Python packages installed: {', '.join(packages[:3])}{'...' if len(packages) > 3 else ''}")
        except Exception as e:
            logger.error(f"❌ Python install failed: {e}")
    
    # Node.js package.json
    pkg_file = os.path.join(project_path, 'package.json')
    if os.path.exists(pkg_file):
        logger.info(f"📦 Found package.json")
        try:
            subprocess.run(['npm', '--version'], check=True, capture_output=True)
            logger.info(f"⚡ Installing Node.js packages...")
            subprocess.run(
                ['npm', 'install', '--silent'],
                cwd=project_path,
                check=True,
                capture_output=True
            )
            installed.append('npm packages')
            logger.info(f"✅ Node.js packages installed")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.warning("⚠️  npm not found, skipping Node.js deps")
    
    # Gemfile for Ruby
    gem_file = os.path.join(project_path, 'Gemfile')
    if os.path.exists(gem_file):
        logger.info(f"📦 Found Gemfile")
        try:
            subprocess.run(['bundle', '--version'], check=True, capture_output=True)
            subprocess.run(['bundle', 'install'], cwd=project_path, check=True, capture_output=True)
            installed.append('Ruby gems')
            logger.info(f"✅ Ruby gems installed")
        except:
            logger.warning("⚠️  bundle not found")
    
    # composer.json for PHP
    composer_file = os.path.join(project_path, 'composer.json')
    if os.path.exists(composer_file):
        logger.info(f"📦 Found composer.json")
        try:
            subprocess.run(['composer', '--version'], check=True, capture_output=True)
            subprocess.run(['composer', 'install'], cwd=project_path, check=True, capture_output=True)
            installed.append('PHP packages')
            logger.info(f"✅ PHP packages installed")
        except:
            logger.warning("⚠️  composer not found")
    
    return installed

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
            successful_deployments INTEGER DEFAULT 0
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS credits (
            user_id INTEGER PRIMARY KEY,
            balance REAL DEFAULT 0,
            total_spent REAL DEFAULT 0,
            total_earned REAL DEFAULT 0
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
            dependencies_installed TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS vps_servers (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            name TEXT,
            host TEXT,
            port INTEGER,
            username TEXT,
            password_encrypted TEXT,
            created_at TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS env_vars (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
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
            created_at TEXT
        )''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            details TEXT,
            timestamp TEXT
        )''')
        
        c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?, ?, ?, ?)', 
                 (OWNER_ID, 'owner', 'Owner', datetime.now().isoformat(), 
                  datetime.now().isoformat(), 0, 0))
        
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
        
        c.execute('INSERT OR REPLACE INTO credits (user_id, balance, total_earned) VALUES (?, ?, COALESCE((SELECT total_earned FROM credits WHERE user_id = ?), 0) + ?)',
                 (user_id, new_balance, user_id, amount))
        
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
                     repo_url, branch, build_cmd, start_cmd, logs, dependencies_installed)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                 (deploy_id, user_id, name, deploy_type, 'pending', port,
                  datetime.now().isoformat(), datetime.now().isoformat(),
                  kwargs.get('repo_url', ''), kwargs.get('branch', 'main'),
                  kwargs.get('build_cmd', ''), kwargs.get('start_cmd', ''), '', ''))
        
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
        'branch': kwargs.get('branch', 'main')
    })
    
    return deploy_id, port

def update_deployment(deploy_id, status=None, logs=None, pid=None, deps=None):
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
            return None, f"Need {cost} credits"
        
        deploy_id, port = create_deployment(user_id, filename, 'file_upload')
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        if filename.endswith('.zip'):
            update_deployment(deploy_id, 'extracting', '📦 Extracting ZIP file...')
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
                update_deployment(deploy_id, 'failed', '❌ No main file found')
                add_credits(user_id, cost, "Refund")
                return None, "No main file found in ZIP"
            
            file_path = main_file
        else:
            shutil.copy(file_path, os.path.join(deploy_dir, filename))
            file_path = os.path.join(deploy_dir, filename)
        
        # SMART DEPENDENCY INSTALLATION
        update_deployment(deploy_id, 'installing', '⚡ Auto-detecting and installing dependencies...')
        installed_deps = detect_and_install_deps(os.path.dirname(file_path))
        
        if installed_deps:
            update_deployment(deploy_id, deps=', '.join(installed_deps))
            update_deployment(deploy_id, logs=f"✅ Installed: {', '.join(installed_deps)}")
        
        env = os.environ.copy()
        env['PORT'] = str(port)
        
        if user_id in user_env_vars:
            env.update(user_env_vars[user_id])
        
        update_deployment(deploy_id, 'starting', f'🚀 Starting application on port {port}...')
        
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
            add_credits(user_id, cost, "Refund")
            return None, "Unsupported file type"
        
        active_processes[deploy_id] = process
        update_deployment(deploy_id, 'running', f'✅ Successfully deployed on port {port}!', process.pid)
        
        def monitor():
            for line in iter(process.stdout.readline, b''):
                if line:
                    log_line = line.decode().strip()
                    update_deployment(deploy_id, logs=log_line)
            
            process.wait()
            if process.returncode == 0:
                update_deployment(deploy_id, 'completed')
            else:
                update_deployment(deploy_id, 'failed', f'Process exited with code: {process.returncode}')
        
        Thread(target=monitor, daemon=True).start()
        
        return deploy_id, f"🎉 Deployed successfully on port {port}!"
    
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
            return None, f"Need {cost} credits"
        
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        deploy_id, port = create_deployment(user_id, repo_name, 'github',
                                           repo_url=repo_url, branch=branch,
                                           build_cmd=build_cmd, start_cmd=start_cmd)
        
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        os.makedirs(deploy_dir, exist_ok=True)
        
        update_deployment(deploy_id, 'cloning', f'🔄 Cloning {repo_url} (branch: {branch})...')
        
        clone_cmd = ['git', 'clone', '-b', branch, '--depth', '1', repo_url, deploy_dir]
        result = subprocess.run(clone_cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            update_deployment(deploy_id, 'failed', f'Clone failed: {result.stderr}')
            add_credits(user_id, cost, "Refund")
            return None, f"Clone failed: {result.stderr}"
        
        update_deployment(deploy_id, logs='✅ Repository cloned successfully')
        
        # SMART DEPENDENCY INSTALLATION
        update_deployment(deploy_id, 'installing', '⚡ Auto-detecting and installing dependencies...')
        installed_deps = detect_and_install_deps(deploy_dir)
        
        if installed_deps:
            update_deployment(deploy_id, deps=', '.join(installed_deps))
            update_deployment(deploy_id, logs=f"✅ Installed: {', '.join(installed_deps)}")
        
        if build_cmd:
            update_deployment(deploy_id, 'building', f'🔨 Running custom build: {build_cmd}')
            build_result = subprocess.run(build_cmd, shell=True, cwd=deploy_dir,
                                        capture_output=True, text=True)
            update_deployment(deploy_id, logs=f"Build output:\n{build_result.stdout}\n{build_result.stderr}")
        
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
                update_deployment(deploy_id, 'failed', '❌ No start command found')
                add_credits(user_id, cost, "Refund")
                return None, "No start command found. Please specify start command."
        
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
        update_deployment(deploy_id, 'running', f'✅ Successfully running on port {port}!', process.pid)
        
        def monitor():
            for line in iter(process.stdout.readline, b''):
                if line:
                    log_line = line.decode().strip()
                    update_deployment(deploy_id, logs=log_line)
            
            process.wait()
            if process.returncode == 0:
                update_deployment(deploy_id, 'completed')
            else:
                update_deployment(deploy_id, 'failed', f'Process exited: {process.returncode}')
        
        Thread(target=monitor, daemon=True).start()
        
        return deploy_id, f"🎉 GitHub deployment successful on port {port}!"
    
    except Exception as e:
        logger.error(f"GitHub deploy error: {e}")
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
            update_deployment(deploy_id, 'stopped', '🛑 Manually stopped')
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
            update_deployment(deploy_id, 'stopped', '🛑 Stopped by PID')
            return True, "Stopped"
        
        return False, "Not running"
    except Exception as e:
        return False, str(e)

def get_deployment_logs(deploy_id):
    if deploy_id in deployment_logs:
        return "\n".join(deployment_logs[deploy_id][-200:])
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT logs FROM deployments WHERE id = ?', (deploy_id,))
        result = c.fetchone()
        conn.close()
        
        if result:
            return result[0] or "No logs yet"
        return "Deployment not found"

# ==================== ENHANCED WEB DASHBOARD ====================

ENHANCED_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#6366f1">
    <title>DevOps Bot v5.0 - Revolutionary</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --secondary: #8b5cf6;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #3b82f6;
            --dark: #1e293b;
            --light: #f8fafc;
            --gradient: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%);
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--gradient);
            min-height: 100vh;
            padding-bottom: 80px;
        }
        
        .header {
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(10px);
            padding: 20px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .logo {
            font-size: 22px;
            font-weight: 800;
            background: var(--gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }
        
        .credit-display {
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: var(--gradient);
            color: white;
            padding: 18px 20px;
            border-radius: 16px;
            margin-top: 12px;
            box-shadow: 0 8px 24px rgba(99,102,241,0.3);
        }
        
        .credit-badge {
            background: rgba(255,255,255,0.2);
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
            margin-bottom: 6px;
        }
        
        .container {
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
            margin-bottom: 20px;
        }
        
        .stat-card {
            background: white;
            border-radius: 16px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: transform 0.3s;
        }
        
        .stat-card:active {
            transform: scale(0.98);
        }
        
        .stat-icon {
            font-size: 28px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: 800;
            background: var(--gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 8px 0;
        }
        
        .stat-label {
            color: #64748b;
            font-size: 13px;
            font-weight: 600;
        }
        
        .tab-bar {
            display: flex;
            overflow-x: auto;
            gap: 8px;
            padding: 12px;
            background: white;
            margin: 0 -20px 20px -20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            -webkit-overflow-scrolling: touch;
        }
        
        .tab-bar::-webkit-scrollbar { display: none; }
        
        .tab {
            flex: 0 0 auto;
            padding: 12px 20px;
            border-radius: 12px;
            background: transparent;
            border: 2px solid transparent;
            font-size: 14px;
            font-weight: 700;
            color: #64748b;
            white-space: nowrap;
            transition: all 0.3s;
        }
        
        .tab.active {
            background: var(--gradient);
            color: white;
            box-shadow: 0 4px 12px rgba(99,102,241,0.3);
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.3s;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .card {
            background: white;
            border-radius: 20px;
            padding: 24px;
            margin-bottom: 16px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        }
        
        .card-title {
            font-size: 20px;
            font-weight: 800;
            margin-bottom: 16px;
            color: var(--dark);
        }
        
        .btn {
            background: var(--gradient);
            color: white;
            border: none;
            padding: 16px 24px;
            border-radius: 14px;
            cursor: pointer;
            font-size: 15px;
            font-weight: 700;
            width: 100%;
            margin: 10px 0;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(99,102,241,0.3);
        }
        
        .btn:active {
            transform: translateY(2px);
            box-shadow: 0 2px 8px rgba(99,102,241,0.2);
        }
        
        .btn-success { background: var(--success); box-shadow: 0 4px 15px rgba(16,185,129,0.3); }
        .btn-danger { background: var(--danger); box-shadow: 0 4px 15px rgba(239,68,68,0.3); }
        .btn-warning { background: var(--warning); box-shadow: 0 4px 15px rgba(245,158,11,0.3); }
        .btn-info { background: var(--info); box-shadow: 0 4px 15px rgba(59,130,246,0.3); }
        
        .input-group {
            margin-bottom: 16px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 700;
            color: var(--dark);
            font-size: 14px;
        }
        
        .input-group input, .input-group select, .input-group textarea {
            width: 100%;
            padding: 14px 16px;
            border: 2px solid #e2e8f0;
            border-radius: 12px;
            font-size: 15px;
            font-family: inherit;
            transition: all 0.3s;
        }
        
        .input-group input:focus, .input-group select:focus, .input-group textarea:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 4px rgba(99,102,241,0.1);
        }
        
        .upload-zone {
            border: 3px dashed var(--primary);
            border-radius: 20px;
            padding: 50px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            background: linear-gradient(135deg, rgba(99,102,241,0.05), rgba(139,92,246,0.05));
        }
        
        .upload-zone:hover {
            background: linear-gradient(135deg, rgba(99,102,241,0.1), rgba(139,92,246,0.1));
            border-color: var(--secondary);
        }
        
        .upload-icon {
            font-size: 48px;
            color: var(--primary);
            margin-bottom: 16px;
        }
        
        .deployment-item {
            background: linear-gradient(135deg, #f8fafc, #f1f5f9);
            border-radius: 16px;
            padding: 18px;
            margin-bottom: 14px;
            border-left: 5px solid var(--primary);
            transition: all 0.3s;
        }
        
        .deployment-item:hover {
            box-shadow: 0 4px 16px rgba(0,0,0,0.1);
            transform: translateX(4px);
        }
        
        .deployment-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 12px;
        }
        
        .status-badge {
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-running { background: #d1fae5; color: #065f46; }
        .status-pending { background: #fef3c7; color: #92400e; }
        .status-building, .status-installing { background: #dbeafe; color: #1e40af; }
        .status-cloning, .status-extracting { background: #e0e7ff; color: #3730a3; }
        .status-starting { background: #fce7f3; color: #9f1239; }
        .status-stopped { background: #fee2e2; color: #991b1b; }
        .status-failed { background: #fecaca; color: #7f1d1d; }
        .status-completed { background: #d1fae5; color: #065f46; }
        
        .action-btns {
            display: flex;
            gap: 8px;
            margin-top: 12px;
            flex-wrap: wrap;
        }
        
        .action-btn {
            flex: 1;
            min-width: 90px;
            padding: 10px 14px;
            border: none;
            border-radius: 10px;
            cursor: pointer;
            font-size: 12px;
            font-weight: 700;
            color: white;
            transition: all 0.2s;
        }
        
        .action-btn:active {
            transform: scale(0.95);
        }
        
        .terminal {
            background: #0f172a;
            color: #22c55e;
            padding: 20px;
            border-radius: 12px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 12px;
            max-height: 400px;
            overflow-y: auto;
            margin-top: 12px;
            white-space: pre-wrap;
            word-wrap: break-word;
            box-shadow: inset 0 2px 8px rgba(0,0,0,0.3);
        }
        
        .terminal::-webkit-scrollbar {
            width: 8px;
        }
        
        .terminal::-webkit-scrollbar-thumb {
            background: #334155;
            border-radius: 4px;
        }
        
        .notification {
            position: fixed;
            top: 80px;
            left: 20px;
            right: 20px;
            background: white;
            padding: 18px 20px;
            border-radius: 16px;
            box-shadow: 0 12px 40px rgba(0,0,0,0.2);
            z-index: 1000;
            display: none;
            animation: slideDown 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
        }
        
        .notification.show {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .notification-icon {
            font-size: 24px;
        }
        
        @keyframes slideDown {
            from { transform: translateY(-120px) scale(0.8); opacity: 0; }
            to { transform: translateY(0) scale(1); opacity: 1; }
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.6);
            backdrop-filter: blur(4px);
            z-index: 2000;
            padding: 20px;
            overflow-y: auto;
            animation: fadeIn 0.3s;
        }
        
        .modal.show {
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .modal-content {
            background: white;
            border-radius: 24px;
            padding: 28px;
            max-width: 500px;
            width: 100%;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            animation: scaleIn 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
        }
        
        @keyframes scaleIn {
            from { transform: scale(0.8); opacity: 0; }
            to { transform: scale(1); opacity: 1; }
        }
        
        .bottom-nav {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: white;
            display: flex;
            justify-content: space-around;
            padding: 12px 0 16px 0;
            box-shadow: 0 -4px 20px rgba(0,0,0,0.1);
            z-index: 100;
        }
        
        .nav-item {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 4px;
            padding: 8px;
            color: #64748b;
            text-decoration: none;
            font-size: 11px;
            font-weight: 700;
            transition: all 0.3s;
        }
        
        .nav-item.active {
            color: var(--primary);
        }
        
        .nav-item i {
            font-size: 22px;
        }
        
        .badge {
            position: absolute;
            top: -4px;
            right: -4px;
            background: var(--danger);
            color: white;
            font-size: 10px;
            font-weight: 700;
            padding: 2px 6px;
            border-radius: 10px;
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
            <i class="fas fa-rocket"></i> @narzoxbot
            <span style="font-size: 11px; background: linear-gradient(135deg, #f59e0b, #ef4444); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-left: 8px;">AUTO-INSTALL</span>
        </div>
        <div class="credit-display">
            <div>
                <div class="credit-badge">CREDITS BALANCE</div>
                <div style="font-size: 28px; font-weight: 800;" id="creditBalance">{{ credits }}</div>
            </div>
            <button onclick="showTab('pricing')" style="background: rgba(255,255,255,0.25); color: white; padding: 12px 24px; border: 2px solid rgba(255,255,255,0.3); border-radius: 12px; font-weight: 700; backdrop-filter: blur(10px);">
                <i class="fas fa-plus"></i> Add
            </button>
        </div>
    </div>
    
    <div class="container">
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
                <div class="stat-icon">🖥️</div>
                <div class="stat-value" id="vpsCount">{{ vps_count }}</div>
                <div class="stat-label">VPS Servers</div>
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
                <i class="fas fa-key"></i> Env
            </button>
        </div>
        
        <!-- Deploy Tab -->
        <div id="deploy-tab" class="tab-content active">
            <div class="card">
                <h3 class="card-title">📤 Quick Deploy</h3>
                <p style="color: #64748b; margin-bottom: 20px; font-size: 14px; line-height: 1.6;">
                    <strong style="color: var(--primary);">✨ Auto-Install:</strong> Dependencies are automatically detected and installed! Just upload and deploy.
                </p>
                
                <div class="upload-zone" id="uploadZone" onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <h3 style="font-size: 18px; font-weight: 800; margin-bottom: 8px;">Tap to Upload</h3>
                    <p style="color: #64748b; font-size: 13px;">Python, JavaScript, ZIP files</p>
                    <p style="color: var(--primary); font-size: 12px; margin-top: 8px; font-weight: 700;">
                        📦 requirements.txt & package.json auto-detected!
                    </p>
                    <input type="file" id="fileInput" hidden accept=".py,.js,.zip" onchange="handleFileUpload(this)">
                </div>
            </div>
        </div>
        
        <!-- GitHub Deploy Tab -->
        <div id="github-tab" class="tab-content">
            <div class="card">
                <h3 class="card-title">🐙 GitHub Deploy</h3>
                <p style="color: #64748b; margin-bottom: 20px; font-size: 14px;">
                    Deploy from any repository with automatic dependency installation
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
                    <i class="fab fa-github"></i> Deploy from GitHub
                </button>
            </div>
        </div>
        
        <!-- Deployments Tab -->
        <div id="deployments-tab" class="tab-content">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h3 class="card-title" style="margin: 0;">📋 Your Deployments</h3>
                    <button onclick="loadDeployments()" style="background: none; border: none; color: var(--primary); font-size: 22px; padding: 8px; cursor: pointer;">
                        <i class="fas fa-sync"></i>
                    </button>
                </div>
                <div id="deploymentsList"></div>
            </div>
        </div>
        
        <!-- Environment Tab -->
        <div id="env-tab" class="tab-content">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                    <h3 class="card-title" style="margin: 0;">🔐 Environment Variables</h3>
                    <button onclick="showAddEnv()" style="background: none; border: none; color: var(--primary); font-size: 22px; padding: 8px; cursor: pointer;">
                        <i class="fas fa-plus"></i>
                    </button>
                </div>
                <div id="envList"></div>
            </div>
        </div>
        
        <!-- Pricing Tab -->
        <div id="pricing-tab" class="tab-content">
            <div class="card">
                <h3 class="card-title" style="text-align: center;">💰 Premium Plans</h3>
                
                <div style="background: var(--gradient); color: white; border-radius: 20px; padding: 28px; margin: 20px 0; text-align: center; box-shadow: 0 8px 24px rgba(99,102,241,0.3);">
                    <div style="font-size: 13px; opacity: 0.9; font-weight: 700;">STARTER</div>
                    <div style="font-size: 42px; font-weight: 900; margin: 12px 0;">₹99</div>
                    <div style="font-size: 18px; margin-bottom: 20px; opacity: 0.95;">10 Credits</div>
                    <button onclick="buyPlan('basic')" style="background: white; color: var(--primary); padding: 14px 32px; border: none; border-radius: 12px; font-weight: 800; width: 100%; font-size: 15px;">
                        Buy Now
                    </button>
                </div>
                
                <div style="border: 3px solid var(--primary); border-radius: 20px; padding: 28px; margin: 20px 0; text-align: center; position: relative;">
                    <div style="position: absolute; top: -14px; left: 50%; transform: translateX(-50%); background: var(--primary); color: white; padding: 6px 20px; border-radius: 20px; font-size: 11px; font-weight: 800;">MOST POPULAR</div>
                    <div style="font-size: 13px; color: #64748b; font-weight: 700; margin-top: 8px;">PRO</div>
                    <div style="font-size: 42px; font-weight: 900; color: var(--primary); margin: 12px 0;">₹399</div>
                    <div style="font-size: 18px; color: #64748b; margin-bottom: 20px;">50 Credits</div>
                    <button onclick="buyPlan('pro')" class="btn">
                        Get Pro
                    </button>
                </div>
                
                <div style="background: linear-gradient(135deg, #f59e0b, #ef4444); color: white; border-radius: 20px; padding: 28px; margin: 20px 0; text-align: center; box-shadow: 0 8px 24px rgba(245,158,11,0.3);">
                    <div style="font-size: 13px; opacity: 0.9; font-weight: 700;">UNLIMITED</div>
                    <div style="font-size: 42px; font-weight: 900; margin: 12px 0;">₹2999</div>
                    <div style="font-size: 18px; margin-bottom: 20px; opacity: 0.95;">∞ Credits</div>
                    <button onclick="buyPlan('unlimited')" style="background: white; color: #f59e0b; padding: 14px 32px; border: none; border-radius: 12px; font-weight: 800; width: 100%; font-size: 15px;">
                        Go Unlimited
                    </button>
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
            <span>Env</span>
        </a>
    </div>
    
    <div id="notification" class="notification"></div>
    <div id="modal" class="modal"></div>

    <script>
        // Tab switching
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
        
        // File upload
        async function handleFileUpload(input) {
            const file = input.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            showNotification('⏳ Uploading and deploying with auto-install...', 'info');
            
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
        }
        
        // Load deployments
        async function loadDeployments() {
            try {
                const res = await fetch('/api/deployments');
                const data = await res.json();
                
                const list = document.getElementById('deploymentsList');
                
                if (!data.deployments || !data.deployments.length) {
                    list.innerHTML = '<div style="text-align:center;padding:40px;"><div style="font-size:48px;margin-bottom:16px;">🚀</div><p style="color:#64748b;font-size:16px;font-weight:600;">No deployments yet</p><p style="color:#94a3b8;font-size:14px;margin-top:8px;">Deploy your first app to get started!</p></div>';
                    return;
                }
                
                list.innerHTML = data.deployments.map(d => `
                    <div class="deployment-item">
                        <div class="deployment-header">
                            <div style="flex: 1;">
                                <strong style="font-size: 16px; font-weight: 800;">${d.name}</strong>
                                <p style="color:#64748b;font-size:12px;margin-top:6px;font-weight:600;">
                                    <i class="fas fa-fingerprint"></i> ${d.id} ${d.port ? `• <i class="fas fa-network-wired"></i> Port ${d.port}` : ''}
                                </p>
                                ${d.repo_url ? `<p style="color:#6366f1;font-size:11px;margin-top:4px;font-weight:600;"><i class="fab fa-github"></i> ${d.repo_url.split('/').slice(-2).join('/')}</p>` : ''}
                            </div>
                            <span class="status-badge status-${d.status}">${d.status}</span>
                        </div>
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
        
        // View logs
        async function viewLogs(deployId) {
            try {
                const res = await fetch('/api/deployment/' + deployId + '/logs');
                const data = await res.json();
                
                showModal(`
                    <h3 style="margin-bottom: 20px; font-size: 20px; font-weight: 800;"><i class="fas fa-terminal"></i> Deployment Logs</h3>
                    <div class="terminal">${data.logs || 'No logs yet...'}</div>
                    <button class="btn" onclick="closeModal()" style="margin-top: 16px;">
                        <i class="fas fa-times"></i> Close
                    </button>
                `);
            } catch (err) {
                showNotification('❌ Failed to load logs', 'error');
            }
        }
        
        // Stop deployment
        async function stopDeploy(deployId) {
            if (!confirm('Stop this deployment?')) return;
            
            showNotification('⏳ Stopping deployment...', 'info');
            
            try {
                const res = await fetch('/api/deployment/' + deployId + '/stop', {method: 'POST'});
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Deployment stopped successfully', 'success');
                    loadDeployments();
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Stop failed', 'error');
            }
        }
        
        // Delete deployment
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
        
        // Environment functions
        function showAddEnv() {
            showModal(`
                <h3 style="margin-bottom: 20px; font-size: 20px; font-weight: 800;"><i class="fas fa-plus"></i> Add Environment Variable</h3>
                <div class="input-group">
                    <label>Variable Name</label>
                    <input type="text" id="envKey" placeholder="API_KEY">
                </div>
                <div class="input-group">
                    <label>Variable Value</label>
                    <input type="text" id="envValue" placeholder="your_secret_value">
                </div>
                <button class="btn" onclick="addEnv()">
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
                return showNotification('⚠️ Please fill all fields', 'warning');
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
                    showNotification('✅ Variable added successfully', 'success');
                    closeModal();
                    loadEnv();
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Failed to add variable', 'error');
            }
        }
        
        async function loadEnv() {
            try {
                const res = await fetch('/api/env/list');
                const data = await res.json();
                
                const list = document.getElementById('envList');
                
                if (!data.variables || !Object.keys(data.variables).length) {
                    list.innerHTML = '<div style="text-align:center;padding:40px;"><div style="font-size:48px;margin-bottom:16px;">🔐</div><p style="color:#64748b;font-size:16px;font-weight:600;">No environment variables</p><p style="color:#94a3b8;font-size:14px;margin-top:8px;">Add variables for your deployments</p></div>';
                    return;
                }
                
                list.innerHTML = Object.entries(data.variables).map(([key, value]) => `
                    <div class="deployment-item">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="flex: 1; min-width: 0;">
                                <strong style="font-size: 15px; font-weight: 800;">${key}</strong>
                                <p style="color:#64748b;font-size:12px;margin-top:6px;overflow:hidden;text-overflow:ellipsis;font-family:monospace;">
                                    ${value.substring(0, 40)}${value.length > 40 ? '...' : ''}
                                </p>
                            </div>
                            <button class="action-btn" style="background: var(--danger); margin: 0; min-width: auto;" onclick="deleteEnv('${key}')">
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
        
        // Buy plan
        function buyPlan(plan) {
            showNotification('💳 Contact @Zolvit to purchase credits!', 'info');
        }
        
        // Update credits
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
        
        // Modal
        function showModal(html) {
            const modal = document.getElementById('modal');
            modal.innerHTML = `<div class="modal-content">${html}</div>`;
            modal.classList.add('show');
        }
        
        function closeModal() {
            document.getElementById('modal').classList.remove('show');
        }
        
        // Notification
        function showNotification(msg, type = 'info') {
            const notif = document.getElementById('notification');
            const icons = {
                info: '<i class="fas fa-info-circle notification-icon" style="color: #3b82f6;"></i>',
                success: '<i class="fas fa-check-circle notification-icon" style="color: #10b981;"></i>',
                warning: '<i class="fas fa-exclamation-triangle notification-icon" style="color: #f59e0b;"></i>',
                error: '<i class="fas fa-times-circle notification-icon" style="color: #ef4444;"></i>'
            };
            
            notif.innerHTML = (icons[type] || icons.info) + `<div style="flex: 1;"><strong>${msg}</strong></div>`;
            notif.classList.add('show');
            setTimeout(() => notif.classList.remove('show'), 3500);
        }
        
        // Auto refresh
        setInterval(updateCredits, 10000);
        setInterval(() => {
            if (document.getElementById('deployments-tab').classList.contains('active')) {
                loadDeployments();
            }
        }, 15000);
        
        // Initial load
        loadDeployments();
        
        // Close modal on outside click
        document.getElementById('modal').addEventListener('click', (e) => {
            if (e.target.id === 'modal') closeModal();
        });
        
        // Drag & Drop
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
    
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM backups WHERE user_id = ?', (user_id,))
        backup_count = c.fetchone()[0]
        conn.close()
    
    return render_template_string(
        ENHANCED_HTML,
        credits=f"{credits:.1f}" if credits != float('inf') else "∞",
        total_deploys=total_deploys,
        active_deploys=active_count,
        vps_count=vps_count,
        backup_count=backup_count
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
    logger.info(f"✅ Web Dashboard: http://localhost:{os.environ.get('PORT', 8080)}")

# ==================== ENHANCED TELEGRAM BOT ====================

def create_main_menu(user_id):
    markup = types.InlineKeyboardMarkup(row_width=2)
    credits = get_credits(user_id)
    credit_text = "∞" if credits == float('inf') else f"{credits:.1f}"
    
    markup.add(types.InlineKeyboardButton(f'💳 {credit_text} Credits', callback_data='credits'))
    markup.add(
        types.InlineKeyboardButton('🚀 Deploy', callback_data='deploy'),
        types.InlineKeyboardButton('📊 Status', callback_data='status')
    )
    markup.add(
        types.InlineKeyboardButton('🌐 Dashboard', callback_data='dashboard'),
        types.InlineKeyboardButton('💰 Buy Credits', callback_data='buy')
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
                        (user_id, username, first_name, joined_date, last_active, total_deployments, successful_deployments)
                        VALUES (?, ?, ?, ?, ?, 0, 0)''',
                     (user_id, username, first_name, 
                      datetime.now().isoformat(), datetime.now().isoformat()))
            conn.commit()
            conn.close()
        
        if init_user_credits(user_id):
            bot.send_message(user_id, f"🎉 *Welcome Bonus!*\n\nYou received *{FREE_CREDITS} FREE credits* to get started!")
    
    credits = get_credits(user_id)
    
    bot.send_message(
        message.chat.id,
        f"🚀 *DevOps Bot v5.0 - REVOLUTIONARY*\n\n"
        f"👤 *{first_name}*\n"
        f"💳 Credits: *{credits if credits != float('inf') else '∞'}*\n\n"
        f"✨ *NEW: Auto-Install Dependencies!*\n"
        f"📦 Python `requirements.txt` auto-detected\n"
        f"📦 Node.js `package.json` auto-detected\n"
        f"📦 Ruby `Gemfile` auto-detected\n"
        f"📦 PHP `composer.json` auto-detected\n\n"
        f"*🎯 Features:*\n"
        f"• One-Click File Deploy\n"
        f"• GitHub Integration\n"
        f"• Mobile Dashboard\n"
        f"• Real-time Logs\n"
        f"• VPS Management\n"
        f"• Environment Variables\n\n"
        f"*Just upload and deploy - we handle the rest!* 🎉",
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
                f"🌐 *Enhanced Web Dashboard*\n\n"
                f"🔗 Access: `http://localhost:{port}`\n\n"
                f"*✨ Features:*\n"
                f"✓ Modern gradient UI\n"
                f"✓ Auto-install dependencies\n"
                f"✓ Real-time deployment logs\n"
                f"✓ One-tap file upload\n"
                f"✓ GitHub integration\n"
                f"✓ Environment manager\n"
                f"✓ Mobile optimized\n\n"
                f"*Zero configuration needed!*")
        
        elif call.data == 'status':
            deploys = active_deployments.get(user_id, [])
            if not deploys:
                bot.answer_callback_query(call.id)
                bot.send_message(call.message.chat.id, 
                    "📊 *No Deployments*\n\nDeploy your first app to see stats here!")
            else:
                running = sum(1 for d in deploys if d['status'] == 'running')
                installing = sum(1 for d in deploys if d['status'] in ['installing', 'building'])
                
                status_text = f"📊 *Deployment Status*\n\n"
                status_text += f"📦 Total: *{len(deploys)}*\n"
                status_text += f"🟢 Running: *{running}*\n"
                status_text += f"⚡ Installing: *{installing}*\n\n"
                status_text += "*Recent Deployments:*\n"
                
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
        
        elif call.data == 'buy':
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                f"💰 *Premium Credit Plans*\n\n"
                f"💎 *STARTER* - ₹99\n"
                f"   └ 10 Credits\n\n"
                f"🌟 *PRO* - ₹399\n"
                f"   └ 50 Credits\n\n"
                f"🚀 *UNLIMITED* - ₹2999\n"
                f"   └ ∞ Unlimited Credits\n\n"
                f"📞 Contact: {YOUR_USERNAME}\n"
                f"💳 Payment: UPI/Card")
        
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
            bot.reply_to(message, "❌ Unsupported file type\n\nSupported: `.py`, `.js`, `.zip`")
            return
        
        file_content = bot.download_file(file_info.file_path)
        user_dir = os.path.join(UPLOADS_DIR, str(user_id))
        os.makedirs(user_dir, exist_ok=True)
        filepath = os.path.join(user_dir, secure_filename(filename))
        
        with open(filepath, 'wb') as f:
            f.write(file_content)
        
        bot.reply_to(message, "⏳ *Deploying with auto-install...*\n\nPlease wait...")
        deploy_id, msg = deploy_from_file(user_id, filepath, filename)
        
        if deploy_id:
            bot.send_message(message.chat.id,
                f"✅ *Deployment Successful!*\n\n"
                f"🆔 ID: `{deploy_id}`\n"
                f"📦 Dependencies auto-installed\n\n"
                f"{msg}")
        else:
            bot.send_message(message.chat.id, f"❌ *Deployment Failed*\n\n{msg}")
    
    except Exception as e:
        logger.error(f"File error: {e}")
        bot.reply_to(message, f"❌ *Error:* {e}")

@bot.message_handler(commands=['addcredits'])
def addcredits_cmd(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin only command")
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
                bot.send_message(target_user, f"🎉 *Bonus Credits!*\n\nYou received *{amount}* credits from admin!")
            except:
                pass
        else:
            bot.reply_to(message, "❌ Failed to add credits")
    except Exception as e:
        bot.reply_to(message, f"❌ *Error:* {e}")

@bot.message_handler(commands=['stats'])
def stats_cmd(message):
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin only command")
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
    
    stats_text = f"📊 *System Statistics*\n\n"
    stats_text += f"👥 Total Users: *{total_users}*\n"
    stats_text += f"🚀 Total Deployments: *{total_deploys}*\n"
    stats_text += f"🟢 Currently Running: *{running_deploys}*\n"
    stats_text += f"💰 Credits Spent: *{total_spent:.1f}*\n"
    stats_text += f"📦 Auto-Installed: *{auto_installed}*\n"
    stats_text += f"⚡ Active Processes: *{len(active_processes)}*"
    
    bot.reply_to(message, stats_text)

# ==================== CLEANUP ====================

def cleanup_on_exit():
    logger.warning("🛑 Shutting down gracefully...")
    
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
    
    logger.warning("✅ All deployments stopped")
    logger.warning("✅ Cleanup complete")

atexit.register(cleanup_on_exit)

def signal_handler(sig, frame):
    cleanup_on_exit()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ==================== MAIN ====================

if __name__ == '__main__':
    print("\n" + "=" * 80)
    print("🚀 ULTRA ADVANCED DEVOPS BOT v5.0 - REVOLUTIONARY EDITION")
    print("=" * 80)
    print(f"🐍 Python: {sys.version.split()[0]}")
    print(f"📁 Data Directory: {DATA_DIR}")
    print(f"👑 Owner ID: {OWNER_ID}")
    print(f"🎁 Free Credits: {FREE_CREDITS}")
    print("=" * 80)
    print("✨ REVOLUTIONARY FEATURES:")
    print("  🤖 Smart Auto-Install System")
    print("     └ Python requirements.txt ✓")
    print("     └ Node.js package.json ✓")
    print("     └ Ruby Gemfile ✓")
    print("     └ PHP composer.json ✓")
    print("")
    print("  🚀 Advanced Deployment")
    print("     └ File Upload (.py, .js, .zip)")
    print("     └ GitHub Integration")
    print("     └ Custom Build Commands")
    print("     └ Auto Port Allocation")
    print("     └ Real-time Monitoring")
    print("")
    print("  🎨 Enhanced Web Dashboard")
    print("     └ Modern Gradient UI")
    print("     └ Mobile-First Design")
    print("     └ Touch Optimized")
    print("     └ Real-time Updates")
    print("     └ Interactive Modals")
    print("     └ Smooth Animations")
    print("")
    print("  📱 Telegram Bot")
    print("     └ File Upload Deploy")
    print("     └ Status Checking")
    print("     └ Credit Management")
    print("     └ Admin Commands")
    print("")
    print("  🔐 Security Features")
    print("     └ Encrypted Environment Variables")
    print("     └ Encrypted VPS Credentials")
    print("     └ User Activity Logging")
    print("     └ Credit Transaction History")
    print("")
    print("  🛠️ Management Tools")
    print("     └ VPS SSH Management")
    print("     └ Environment Variables")
    print("     └ Backup System")
    print("     └ Deployment Logs")
    print("     └ Process Monitoring")
    print("=" * 80)
    print("📊 CAPABILITIES:")
    print(f"  ✓ {len(REQUIRED_PACKAGES)} Core Dependencies")
    print("  ✓ 4 Language Package Managers")
    print("  ✓ Unlimited Concurrent Deployments")
    print("  ✓ Real-time Log Streaming")
    print("  ✓ Automatic Dependency Detection")
    print("  ✓ Zero Configuration Required")
    print("=" * 80)
    
    # Start Flask
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n🌐 Web Dashboard: http://localhost:{port}")
    print("📱 Mobile-optimized with modern gradient UI!")
    print("✨ Auto-install feature active!")
    print("🤖 Starting Telegram bot...\n")
    print("=" * 80)
    print("🎉 SYSTEM READY - WAITING FOR DEPLOYMENTS")
    print("=" * 80 + "\n")
    
    # Start bot
    while True:
        try:
            logger.info("🤖 Bot polling started - Ready to deploy!")
            bot.infinity_polling(timeout=60, long_polling_timeout=30)
        except Exception as e:
            logger.error(f"Polling error: {e}")
            time.sleep(5)

        
                    }, 1500);
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Upload failed', 'error');
            }
            
            input.value = '';
        }
        
        // GitHub deploy
        async function deployGithub() {
            const url = document.getElementById('repoUrl').value;
            const branch = document.getElementById('repoBranch').value;
            const buildCmd = document.getElementById('buildCmd').value;
            const startCmd = document.getElementById('startCmd').value;
            
            if (!url) return showNotification('⚠️ Enter repository URL', 'warning');
            
            showNotification('⏳ Cloning with auto-install...', 'info');
            
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
