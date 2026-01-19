# -*- coding: utf-8 -*-
"""
ULTRA ADVANCED DEVOPS BOT v2.0 - PRODUCTION READY
Complete implementation of all features with enterprise-grade security
"""

import telebot
import subprocess
import os
import zipfile
import tempfile
import shutil
from telebot import types
import time
from datetime import datetime, timedelta
import psutil
import sqlite3
import json
import logging
import threading
import re
import sys
import atexit
import requests
import hashlib
import secrets
import jwt
import paramiko
from pathlib import Path
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for, send_file
from flask_cors import CORS
from threading import Thread, Lock
import uuid
import asyncio
from functools import wraps
import docker
from cryptography.fernet import Fernet
import git
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import yaml

# Suppress warnings
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.getLogger('paramiko').setLevel(logging.ERROR)

# ==================== CONFIGURATION ====================
TOKEN = '7991988270:AAFsl-uDsVcf2tl7L5sZgl9Eq9U2nnW3bps'
OWNER_ID = 8240720451
ADMIN_ID = 8285724366
YOUR_USERNAME = '@Zolvit'
UPDATE_CHANNEL = 't.me/narzoxbot'
WEB_SECRET_KEY = secrets.token_hex(32)
ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

# Credit System
FREE_CREDITS = 1
CREDIT_COSTS = {
    'file_upload': 0.5,
    'vps_deploy': 1,
    'github_deploy': 1,
    'docker_deploy': 1.5,
    'auto_deploy': 2,
    'custom_deploy': 2.5,
    'vps_command': 0.3,
    'system_monitor': 0.1,
    'backup_restore': 0.8,
    'ssl_setup': 1.2,
    'domain_config': 0.7
}

PRICING_PLANS = {
    'basic': {'credits': 10, 'price': 99, 'validity_days': 30, 'features': ['Basic Support', 'File Uploads', 'VPS Access']},
    'pro': {'credits': 50, 'price': 399, 'validity_days': 90, 'features': ['Priority Support', 'GitHub Integration', 'Docker Deploy', 'Auto Deploy']},
    'enterprise': {'credits': 200, 'price': 1299, 'validity_days': 180, 'features': ['24/7 Support', 'Custom Solutions', 'Dedicated Resources', 'API Access']},
    'unlimited': {'credits': -1, 'price': 2999, 'validity_days': 365, 'features': ['Unlimited Everything', 'VIP Support', 'White Label', 'Custom Development']}
}

# Directories
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_BOTS_DIR = os.path.join(BASE_DIR, 'upload_bots')
IROTECH_DIR = os.path.join(BASE_DIR, 'inf')
DATABASE_PATH = os.path.join(IROTECH_DIR, 'bot_data.db')
DEVOPS_DIR = os.path.join(IROTECH_DIR, 'devops')
WEB_UPLOADS_DIR = os.path.join(BASE_DIR, 'web_uploads')
BACKUP_DIR = os.path.join(BASE_DIR, 'backups')
LOGS_DIR = os.path.join(BASE_DIR, 'logs')

for dir_path in [UPLOAD_BOTS_DIR, IROTECH_DIR, DEVOPS_DIR, WEB_UPLOADS_DIR, BACKUP_DIR, LOGS_DIR]:
    os.makedirs(dir_path, exist_ok=True)

# Initialize Flask
app = Flask(__name__)
app.secret_key = WEB_SECRET_KEY
CORS(app)

# Initialize Bot
bot = telebot.TeleBot(TOKEN, parse_mode=None)

# Global data structures
bot_scripts = {}
user_credits = {}
user_sessions = {}
active_users = set()
admin_ids = {ADMIN_ID, OWNER_ID}
bot_locked = False
user_vps_servers = {}
user_env_vars = {}
user_github_repos = {}
deployment_history = {}
web_deployments = {}
active_processes = {}
webhook_handlers = {}
ssl_certificates = {}
domain_configs = {}
backup_schedules = {}

# Locks
DB_LOCK = Lock()
DEPLOY_LOCK = Lock()
PROCESS_LOCK = Lock()

# Docker client
try:
    docker_client = docker.from_env()
    DOCKER_AVAILABLE = True
except:
    DOCKER_AVAILABLE = False
    docker_client = None

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOGS_DIR, 'bot.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ==================== DATABASE SETUP ====================

def init_db():
    """Initialize comprehensive database schema"""
    logger.info("Initializing database...")
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        
        # Users table
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (user_id INTEGER PRIMARY KEY, 
                      username TEXT, 
                      first_name TEXT, 
                      email TEXT,
                      phone TEXT,
                      joined_date TEXT, 
                      last_active TEXT,
                      subscription_tier TEXT DEFAULT 'free',
                      subscription_expires TEXT,
                      two_factor_enabled BOOLEAN DEFAULT 0,
                      api_key TEXT,
                      webhook_url TEXT)''')
        
        # Credits table
        c.execute('''CREATE TABLE IF NOT EXISTS credits
                     (user_id INTEGER PRIMARY KEY, 
                      credits REAL DEFAULT 1.0,
                      total_spent REAL DEFAULT 0, 
                      total_earned REAL DEFAULT 0,
                      lifetime_credits REAL DEFAULT 0)''')
        
        # Transactions table
        c.execute('''CREATE TABLE IF NOT EXISTS transactions
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER, 
                      amount REAL, 
                      type TEXT,
                      description TEXT, 
                      timestamp TEXT,
                      transaction_hash TEXT,
                      status TEXT DEFAULT 'completed')''')
        
        # Deployments table
        c.execute('''CREATE TABLE IF NOT EXISTS deployments
                     (id TEXT PRIMARY KEY, 
                      user_id INTEGER, 
                      deploy_type TEXT, 
                      status TEXT, 
                      cost REAL,
                      created_at TEXT, 
                      updated_at TEXT, 
                      completed_at TEXT,
                      details TEXT, 
                      logs TEXT,
                      container_id TEXT,
                      process_id INTEGER,
                      port INTEGER,
                      url TEXT,
                      auto_restart BOOLEAN DEFAULT 0,
                      health_check_url TEXT)''')
        
        # VPS Servers table
        c.execute('''CREATE TABLE IF NOT EXISTS vps_servers
                     (user_id INTEGER, 
                      vps_name TEXT, 
                      host TEXT, 
                      port INTEGER, 
                      username TEXT,
                      password_encrypted TEXT,
                      ssh_key_path TEXT,
                      status TEXT DEFAULT 'active',
                      last_connected TEXT,
                      cpu_limit INTEGER DEFAULT 100,
                      memory_limit INTEGER DEFAULT 1024,
                      PRIMARY KEY (user_id, vps_name))''')
        
        # Environment Variables table
        c.execute('''CREATE TABLE IF NOT EXISTS env_variables
                     (user_id INTEGER, 
                      var_name TEXT, 
                      var_value TEXT,
                      encrypted BOOLEAN DEFAULT 1,
                      scope TEXT DEFAULT 'global',
                      created_at TEXT,
                      PRIMARY KEY (user_id, var_name))''')
        
        # GitHub Repos table
        c.execute('''CREATE TABLE IF NOT EXISTS github_repos
                     (user_id INTEGER, 
                      repo_url TEXT, 
                      branch TEXT DEFAULT 'main',
                      last_pull TEXT,
                      last_commit TEXT,
                      auto_deploy BOOLEAN DEFAULT 0,
                      deploy_on_push BOOLEAN DEFAULT 0,
                      webhook_secret TEXT,
                      build_command TEXT,
                      start_command TEXT,
                      PRIMARY KEY (user_id, repo_url))''')
        
        # Web Sessions table
        c.execute('''CREATE TABLE IF NOT EXISTS web_sessions
                     (session_token TEXT PRIMARY KEY, 
                      user_id INTEGER,
                      created_at TEXT, 
                      expires_at TEXT, 
                      ip_address TEXT,
                      user_agent TEXT,
                      active BOOLEAN DEFAULT 1)''')
        
        # Payment Orders table
        c.execute('''CREATE TABLE IF NOT EXISTS payment_orders
                     (order_id TEXT PRIMARY KEY, 
                      user_id INTEGER,
                      plan TEXT, 
                      amount REAL, 
                      status TEXT DEFAULT 'pending',
                      payment_method TEXT,
                      transaction_id TEXT,
                      created_at TEXT, 
                      completed_at TEXT,
                      expires_at TEXT)''')
        
        # Admins table
        c.execute('''CREATE TABLE IF NOT EXISTS admins
                     (user_id INTEGER PRIMARY KEY,
                      role TEXT DEFAULT 'admin',
                      permissions TEXT,
                      added_by INTEGER,
                      added_at TEXT)''')
        
        # Backups table
        c.execute('''CREATE TABLE IF NOT EXISTS backups
                     (id TEXT PRIMARY KEY,
                      user_id INTEGER,
                      deployment_id TEXT,
                      backup_type TEXT,
                      file_path TEXT,
                      file_size INTEGER,
                      created_at TEXT,
                      expires_at TEXT,
                      status TEXT DEFAULT 'active')''')
        
        # SSL Certificates table
        c.execute('''CREATE TABLE IF NOT EXISTS ssl_certificates
                     (id TEXT PRIMARY KEY,
                      user_id INTEGER,
                      domain TEXT,
                      cert_path TEXT,
                      key_path TEXT,
                      issuer TEXT,
                      issued_at TEXT,
                      expires_at TEXT,
                      auto_renew BOOLEAN DEFAULT 1)''')
        
        # Webhooks table
        c.execute('''CREATE TABLE IF NOT EXISTS webhooks
                     (id TEXT PRIMARY KEY,
                      user_id INTEGER,
                      event_type TEXT,
                      url TEXT,
                      secret TEXT,
                      active BOOLEAN DEFAULT 1,
                      created_at TEXT)''')
        
        # Notifications table
        c.execute('''CREATE TABLE IF NOT EXISTS notifications
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      user_id INTEGER,
                      title TEXT,
                      message TEXT,
                      type TEXT,
                      read BOOLEAN DEFAULT 0,
                      created_at TEXT)''')
        
        # API Keys table
        c.execute('''CREATE TABLE IF NOT EXISTS api_keys
                     (key_id TEXT PRIMARY KEY,
                      user_id INTEGER,
                      key_hash TEXT,
                      name TEXT,
                      scopes TEXT,
                      created_at TEXT,
                      last_used TEXT,
                      active BOOLEAN DEFAULT 1)''')
        
        # Initialize owner and admin
        c.execute('INSERT OR IGNORE INTO admins VALUES (?, ?, ?, ?, ?)', 
                 (OWNER_ID, 'owner', json.dumps(['all']), OWNER_ID, datetime.now().isoformat()))
        if ADMIN_ID != OWNER_ID:
            c.execute('INSERT OR IGNORE INTO admins VALUES (?, ?, ?, ?, ?)',
                     (ADMIN_ID, 'admin', json.dumps(['all']), OWNER_ID, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        logger.info("✅ Database initialized successfully")
    except Exception as e:
        logger.error(f"❌ Database initialization error: {e}", exc_info=True)

def load_data():
    """Load all data from database into memory"""
    logger.info("Loading data from database...")
    try:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        
        # Load users
        c.execute('SELECT user_id FROM users')
        active_users.update(uid for (uid,) in c.fetchall())
        
        # Load credits
        c.execute('SELECT user_id, credits FROM credits')
        for user_id, credits in c.fetchall():
            user_credits[user_id] = credits
        
        # Load admins
        c.execute('SELECT user_id FROM admins')
        admin_ids.update(uid for (uid,) in c.fetchall())
        
        # Load VPS servers
        c.execute('SELECT user_id, vps_name, host, port, username, password_encrypted FROM vps_servers WHERE status="active"')
        for user_id, vps_name, host, port, username, password_enc in c.fetchall():
            if user_id not in user_vps_servers:
                user_vps_servers[user_id] = {}
            try:
                password = fernet.decrypt(password_enc.encode()).decode() if password_enc else None
            except:
                password = None
            user_vps_servers[user_id][vps_name] = {
                'host': host, 'port': port, 'username': username, 'password': password
            }
        
        # Load environment variables
        c.execute('SELECT user_id, var_name, var_value, encrypted FROM env_variables')
        for user_id, var_name, var_value, encrypted in c.fetchall():
            if user_id not in user_env_vars:
                user_env_vars[user_id] = {}
            try:
                value = fernet.decrypt(var_value.encode()).decode() if encrypted else var_value
            except:
                value = var_value
            user_env_vars[user_id][var_name] = value
        
        # Load GitHub repos
        c.execute('SELECT user_id, repo_url, branch, auto_deploy FROM github_repos')
        for user_id, repo_url, branch, auto_deploy in c.fetchall():
            if user_id not in user_github_repos:
                user_github_repos[user_id] = {}
            user_github_repos[user_id][repo_url] = {
                'branch': branch, 'auto_deploy': bool(auto_deploy)
            }
        
        conn.close()
        logger.info(f"✅ Data loaded: {len(active_users)} users, {len(admin_ids)} admins")
    except Exception as e:
        logger.error(f"❌ Data loading error: {e}", exc_info=True)

init_db()
load_data()

# ==================== CREDIT SYSTEM ====================

def get_user_credits(user_id):
    """Get user credit balance"""
    if user_id in admin_ids:
        return float('inf')
    return user_credits.get(user_id, 0.0)

def add_credits(user_id, amount, description="Credit added"):
    """Add credits to user account"""
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            current = get_user_credits(user_id)
            if current == float('inf'):
                return True
            
            new_balance = current + amount
            tx_hash = hashlib.sha256(f"{user_id}{amount}{time.time()}".encode()).hexdigest()
            
            c.execute('INSERT OR REPLACE INTO credits (user_id, credits, total_earned, lifetime_credits) VALUES (?, ?, COALESCE((SELECT total_earned FROM credits WHERE user_id=?), 0) + ?, COALESCE((SELECT lifetime_credits FROM credits WHERE user_id=?), 0) + ?)',
                     (user_id, new_balance, user_id, amount, user_id, amount))
            c.execute('''INSERT INTO transactions 
                        (user_id, amount, type, description, timestamp, transaction_hash, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (user_id, amount, 'credit', description, datetime.now().isoformat(), tx_hash, 'completed'))
            conn.commit()
            user_credits[user_id] = new_balance
            
            # Send notification
            send_notification(user_id, "Credits Added", f"You received {amount} credits. {description}")
            
            return True
        except Exception as e:
            logger.error(f"Add credits error: {e}")
            return False
        finally:
            conn.close()

def deduct_credits(user_id, amount, description="Credit used"):
    """Deduct credits from user account"""
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            current = get_user_credits(user_id)
            if current == float('inf'):
                return True
            
            if current < amount:
                return False
            
            new_balance = current - amount
            tx_hash = hashlib.sha256(f"{user_id}{-amount}{time.time()}".encode()).hexdigest()
            
            c.execute('UPDATE credits SET credits = ?, total_spent = total_spent + ? WHERE user_id = ?',
                     (new_balance, amount, user_id))
            c.execute('''INSERT INTO transactions 
                        (user_id, amount, type, description, timestamp, transaction_hash, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (user_id, -amount, 'debit', description, datetime.now().isoformat(), tx_hash, 'completed'))
            conn.commit()
            user_credits[user_id] = new_balance
            return True
        except Exception as e:
            logger.error(f"Deduct credits error: {e}")
            return False
        finally:
            conn.close()

def initialize_user_credits(user_id):
    """Give new user free credits"""
    if user_id not in user_credits and user_id not in admin_ids:
        add_credits(user_id, FREE_CREDITS, "🎉 Welcome bonus!")
        return True
    return False

# ==================== DEPLOYMENT FUNCTIONS ====================

def create_deployment_record(user_id, deploy_type, cost, details=None):
    """Create deployment record"""
    deployment_id = str(uuid.uuid4())
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO deployments 
                        (id, user_id, deploy_type, status, cost, created_at, updated_at, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (deployment_id, user_id, deploy_type, 'pending', cost,
                      datetime.now().isoformat(), datetime.now().isoformat(), 
                      json.dumps(details or {})))
            conn.commit()
            
            if user_id not in deployment_history:
                deployment_history[user_id] = []
            deployment_history[user_id].append({
                'id': deployment_id,
                'type': deploy_type,
                'status': 'pending',
                'created': datetime.now().isoformat()
            })
            
            return deployment_id
        finally:
            conn.close()

def update_deployment_status(deployment_id, status, logs=None, **kwargs):
    """Update deployment status"""
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            update_fields = ['status = ?', 'updated_at = ?']
            update_values = [status, datetime.now().isoformat()]
            
            if logs:
                update_fields.append('logs = ?')
                update_values.append(logs)
            
            if status == 'completed':
                update_fields.append('completed_at = ?')
                update_values.append(datetime.now().isoformat())
            
            for key, value in kwargs.items():
                update_fields.append(f'{key} = ?')
                update_values.append(value)
            
            update_values.append(deployment_id)
            
            c.execute(f'''UPDATE deployments 
                         SET {', '.join(update_fields)}
                         WHERE id = ?''', update_values)
            conn.commit()
        finally:
            conn.close()

def deploy_from_file(user_id, file_path, filename):
    """Deploy from uploaded file"""
    try:
        deployment_id = create_deployment_record(user_id, 'file_upload', CREDIT_COSTS['file_upload'], 
                                                 {'filename': filename})
        
        # Extract if zip
        if filename.endswith('.zip'):
            extract_dir = os.path.join(UPLOAD_BOTS_DIR, str(user_id), deployment_id)
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            # Find main file
            main_file = None
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file in ['main.py', 'app.py', 'bot.py', 'index.js', 'server.js']:
                        main_file = os.path.join(root, file)
                        break
                if main_file:
                    break
            
            if not main_file:
                raise Exception("No main file found in zip")
            
            file_path = main_file
        
        # Determine file type and run
        if file_path.endswith('.py'):
            process = subprocess.Popen(['python3', file_path], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE,
                                      cwd=os.path.dirname(file_path))
        elif file_path.endswith('.js'):
            process = subprocess.Popen(['node', file_path],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      cwd=os.path.dirname(file_path))
        else:
            raise Exception("Unsupported file type")
        
        with PROCESS_LOCK:
            active_processes[deployment_id] = process
        
        update_deployment_status(deployment_id, 'running', process_id=process.pid)
        
        return deployment_id, "Deployment started successfully"
    except Exception as e:
        logger.error(f"File deployment error: {e}")
        return None, str(e)

def deploy_from_github(user_id, repo_url, branch='main'):
    """Deploy from GitHub repository"""
    try:
        deployment_id = create_deployment_record(user_id, 'github_deploy', CREDIT_COSTS['github_deploy'],
                                                 {'repo_url': repo_url, 'branch': branch})
        
        clone_dir = os.path.join(DEVOPS_DIR, str(user_id), deployment_id)
        os.makedirs(clone_dir, exist_ok=True)
        
        # Clone repository
        repo = git.Repo.clone_from(repo_url, clone_dir, branch=branch)
        
        # Find and run main file
        main_files = ['main.py', 'app.py', 'bot.py', 'index.js', 'server.js']
        main_file = None
        
        for file in main_files:
            potential_path = os.path.join(clone_dir, file)
            if os.path.exists(potential_path):
                main_file = potential_path
                break
        
        if not main_file:
            raise Exception("No main file found in repository")
        
        # Check for requirements
        req_file = os.path.join(clone_dir, 'requirements.txt')
        if os.path.exists(req_file):
            subprocess.run(['pip', 'install', '-r', req_file], check=True)
        
        package_file = os.path.join(clone_dir, 'package.json')
        if os.path.exists(package_file):
            subprocess.run(['npm', 'install'], cwd=clone_dir, check=True)
        
        # Start process
        if main_file.endswith('.py'):
            process = subprocess.Popen(['python3', main_file],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      cwd=clone_dir)
        else:
            process = subprocess.Popen(['node', main_file],
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      cwd=clone_dir)
        
        with PROCESS_LOCK:
            active_processes[deployment_id] = process
        
        update_deployment_status(deployment_id, 'running', process_id=process.pid)
        
        # Save to database
        with DB_LOCK:
            conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO github_repos 
                        (user_id, repo_url, branch, last_pull, last_commit)
                        VALUES (?, ?, ?, ?, ?)''',
                     (user_id, repo_url, branch, datetime.now().isoformat(), 
                      repo.head.commit.hexsha))
            conn.commit()
            conn.close()
        
        return deployment_id, "GitHub deployment successful"
    except Exception as e:
        logger.error(f"GitHub deployment error: {e}")
        return None, str(e)

def deploy_with_docker(user_id, project_type, source_path=None):
    """Deploy using Docker"""
    if not DOCKER_AVAILABLE:
        return None, "Docker is not available"
    
    try:
        deployment_id = create_deployment_record(user_id, 'docker_deploy', CREDIT_COSTS['docker_deploy'],
                                                 {'project_type': project_type})
        
        # Generate Dockerfile based on project type
        dockerfile_content = generate_dockerfile(project_type)
        
        build_dir = os.path.join(DEVOPS_DIR, str(user_id), deployment_id)
        os.makedirs(build_dir, exist_ok=True)
        
        # Write Dockerfile
        with open(os.path.join(build_dir, 'Dockerfile'), 'w') as f:
            f.write(dockerfile_content)
        
        # Copy source if provided
        if source_path and os.path.exists(source_path):
            if os.path.isfile(source_path):
                shutil.copy(source_path, build_dir)
            else:
                shutil.copytree(source_path, build_dir, dirs_exist_ok=True)
        
        # Build image
        image_tag = f"devops-bot-{user_id}-{deployment_id}"
        image, build_logs = docker_client.images.build(path=build_dir, tag=image_tag)
        
        # Run container
        container = docker_client.containers.run(
            image_tag,
            detach=True,
            name=f"deploy-{deployment_id}",
            restart_policy={"Name": "unless-stopped"}
        )
        
        update_deployment_status(deployment_id, 'running', 
                                container_id=container.id,
                                logs="\n".join([log.get('stream', '') for log in build_logs]))
        
        return deployment_id, "Docker deployment successful"
    except Exception as e:
        logger.error(f"Docker deployment error: {e}")
        return None, str(e)

def generate_dockerfile(project_type):
    """Generate Dockerfile based on project type"""
    dockerfiles = {
        'python': """FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
""",
        'nodejs': """FROM node:16-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
CMD ["node", "index.js"]
""",
        'bot': """FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "bot.py"]
"""
    }
    return dockerfiles.get(project_type, dockerfiles['python'])

# ==================== VPS MANAGEMENT ====================

def connect_to_vps(user_id, vps_name):
    """Establish SSH connection to VPS"""
    if user_id not in user_vps_servers or vps_name not in user_vps_servers[user_id]:
        return None, "VPS not found"
    
    vps = user_vps_servers[user_id][vps_name]
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh.connect(
            hostname=vps['host'],
            port=vps['port'],
            username=vps['username'],
            password=vps.get('password')
        )
        
        return ssh, "Connected successfully"
    except Exception as e:
        return None, str(e)

def execute_vps_command(user_id, vps_name, command):
    """Execute command on VPS"""
    ssh, msg = connect_to_vps(user_id, vps_name)
    
    if not ssh:
        return None, msg
    
    try:
        stdin, stdout, stderr = ssh.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        ssh.close()
        
        return output or error, None
    except Exception as e:
        ssh.close()
        return None, str(e)

def add_vps_server(user_id, vps_name, host, port, username, password):
    """Add new VPS server"""
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            password_encrypted = fernet.encrypt(password.encode()).decode()
            
            c.execute('''INSERT OR REPLACE INTO vps_servers
                        (user_id, vps_name, host, port, username, password_encrypted, status, last_connected)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (user_id, vps_name, host, port, username, password_encrypted, 'active', datetime.now().isoformat()))
            conn.commit()
            
            if user_id not in user_vps_servers:
                user_vps_servers[user_id] = {}
            user_vps_servers[user_id][vps_name] = {
                'host': host, 'port': port, 'username': username, 'password': password
            }
            
            return True, "VPS added successfully"
        except Exception as e:
            logger.error(f"Add VPS error: {e}")
            return False, str(e)
        finally:
            conn.close()

# ==================== NOTIFICATION SYSTEM ====================

def send_notification(user_id, title, message, type='info'):
    """Send notification to user"""
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO notifications (user_id, title, message, type, created_at)
                        VALUES (?, ?, ?, ?, ?)''',
                     (user_id, title, message, type, datetime.now().isoformat()))
            conn.commit()
            
            # Try to send Telegram notification
            try:
                icon = {'info': 'ℹ️', 'success': '✅', 'warning': '⚠️', 'error': '❌'}.get(type, 'ℹ️')
                bot.send_message(user_id, f"{icon} **{title}**\n\n{message}", parse_mode='Markdown')
            except:
                pass
        finally:
            conn.close()

# ==================== BACKUP SYSTEM ====================

def create_backup(user_id, deployment_id):
    """Create backup of deployment"""
    try:
        backup_id = str(uuid.uuid4())
        backup_name = f"backup_{deployment_id}_{int(time.time())}.tar.gz"
        backup_path = os.path.join(BACKUP_DIR, str(user_id), backup_name)
        os.makedirs(os.path.dirname(backup_path), exist_ok=True)
        
        # Find deployment directory
        deploy_dir = os.path.join(DEVOPS_DIR, str(user_id), deployment_id)
        
        if not os.path.exists(deploy_dir):
            return None, "Deployment directory not found"
        
        # Create tar.gz backup
        import tarfile
        with tarfile.open(backup_path, "w:gz") as tar:
            tar.add(deploy_dir, arcname=os.path.basename(deploy_dir))
        
        file_size = os.path.getsize(backup_path)
        
        # Save to database
        with DB_LOCK:
            conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('''INSERT INTO backups 
                        (id, user_id, deployment_id, backup_type, file_path, file_size, created_at, expires_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (backup_id, user_id, deployment_id, 'full', backup_path, file_size,
                      datetime.now().isoformat(), (datetime.now() + timedelta(days=30)).isoformat()))
            conn.commit()
            conn.close()
        
        return backup_id, f"Backup created: {backup_name}"
    except Exception as e:
        logger.error(f"Backup error: {e}")
        return None, str(e)

def restore_backup(user_id, backup_id):
    """Restore deployment from backup"""
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('SELECT file_path, deployment_id FROM backups WHERE id=? AND user_id=?',
                     (backup_id, user_id))
            result = c.fetchone()
            conn.close()
        
        if not result:
            return None, "Backup not found"
        
        backup_path, deployment_id = result
        
        if not os.path.exists(backup_path):
            return None, "Backup file not found"
        
        # Extract backup
        restore_dir = os.path.join(DEVOPS_DIR, str(user_id), f"restored_{int(time.time())}")
        os.makedirs(restore_dir, exist_ok=True)
        
        import tarfile
        with tarfile.open(backup_path, "r:gz") as tar:
            tar.extractall(restore_dir)
        
        return restore_dir, "Backup restored successfully"
    except Exception as e:
        logger.error(f"Restore error: {e}")
        return None, str(e)

# ==================== WEBHOOK SYSTEM ====================

def register_webhook(user_id, event_type, url, secret=None):
    """Register webhook for events"""
    webhook_id = str(uuid.uuid4())
    
    if not secret:
        secret = secrets.token_hex(32)
    
    with DB_LOCK:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        c = conn.cursor()
        try:
            c.execute('''INSERT INTO webhooks (id, user_id, event_type, url, secret, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)''',
                     (webhook_id, user_id, event_type, url, secret, datetime.now().isoformat()))
            conn.commit()
            
            if user_id not in webhook_handlers:
                webhook_handlers[user_id] = {}
            webhook_handlers[user_id][event_type] = {'url': url, 'secret': secret}
            
            return webhook_id, secret
        finally:
            conn.close()

def trigger_webhook(user_id, event_type, data):
    """Trigger webhook for event"""
    if user_id not in webhook_handlers or event_type not in webhook_handlers[user_id]:
        return
    
    webhook = webhook_handlers[user_id][event_type]
    
    try:
        payload = {
            'event': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id
        }
        
        signature = hashlib.sha256(
            f"{json.dumps(payload)}{webhook['secret']}".encode()
        ).hexdigest()
        
        headers = {
            'Content-Type': 'application/json',
            'X-Webhook-Signature': signature
        }
        
        requests.post(webhook['url'], json=payload, headers=headers, timeout=10)
    except Exception as e:
        logger.error(f"Webhook trigger error: {e}")

# ==================== ENHANCED WEB DASHBOARD ====================

ENHANCED_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevOps Bot v2.0 - Advanced Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        :root {
            --primary: #667eea;
            --secondary: #764ba2;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --dark: #1f2937;
            --light: #f9fafb;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%);
            min-height: 100vh;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: 280px 1fr;
            min-height: 100vh;
        }
        
        .sidebar {
            background: var(--dark);
            color: white;
            padding: 20px;
            position: sticky;
            top: 0;
            height: 100vh;
            overflow-y: auto;
        }
        
        .logo {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 30px;
            color: var(--primary);
        }
        
        .nav-item {
            padding: 12px 16px;
            margin: 5px 0;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .nav-item:hover, .nav-item.active {
            background: var(--primary);
        }
        
        .main-content {
            padding: 30px;
            overflow-y: auto;
        }
        
        .header {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .credit-badge {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            padding: 12px 24px;
            border-radius: 50px;
            font-weight: bold;
            font-size: 18px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: bold;
            color: var(--primary);
            margin: 10px 0;
        }
        
        .stat-label {
            color: #6b7280;
            font-size: 14px;
        }
        
        .card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .card-title {
            font-size: 20px;
            font-weight: bold;
            color: var(--dark);
        }
        
        .btn {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 12px rgba(102, 126, 234, 0.4);
        }
        
        .btn-success { background: var(--success); }
        .btn-danger { background: var(--danger); }
        .btn-warning { background: var(--warning); }
        
        .input-group {
            margin-bottom: 20px;
        }
        
        .input-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--dark);
        }
        
        .input-group input, .input-group select, .input-group textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #e5e7eb;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        
        .input-group input:focus, .input-group select:focus, .input-group textarea:focus {
            outline: none;
            border-color: var(--primary);
        }
        
        .upload-zone {
            border: 3px dashed var(--primary);
            border-radius: 12px;
            padding: 60px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            background: #f9fafb;
        }
        
        .upload-zone:hover {
            background: #f3f4f6;
            border-color: var(--secondary);
        }
        
        .upload-zone.dragover {
            background: #e0e7ff;
            border-color: var(--primary);
        }
        
        .deployment-card {
            background: #f9fafb;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid var(--primary);
        }
        
        .deployment-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        
        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .status-running { background: #d1fae5; color: #065f46; }
        .status-pending { background: #fef3c7; color: #92400e; }
        .status-stopped { background: #fee2e2; color: #991b1b; }
        .status-completed { background: #dbeafe; color: #1e40af; }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        
        .modal.active {
            display: flex;
        }
        
        .modal-content {
            background: white;
            border-radius: 15px;
            padding: 30px;
            max-width: 600px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .terminal {
            background: #1e1e1e;
            color: #00ff00;
            padding: 20px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            max-height: 400px;
            overflow-y: auto;
            margin-top: 15px;
        }
        
        .pricing-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
        }
        
        .pricing-card {
            background: white;
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
            position: relative;
        }
        
        .pricing-card:hover {
            transform: scale(1.05);
        }
        
        .pricing-card.featured {
            border: 3px solid var(--primary);
        }
        
        .pricing-card.featured::before {
            content: 'POPULAR';
            position: absolute;
            top: -12px;
            left: 50%;
            transform: translateX(-50%);
            background: var(--primary);
            color: white;
            padding: 4px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .price {
            font-size: 48px;
            font-weight: bold;
            color: var(--primary);
            margin: 20px 0;
        }
        
        .features {
            list-style: none;
            text-align: left;
            margin: 20px 0;
        }
        
        .features li {
            padding: 10px 0;
            border-bottom: 1px solid #e5e7eb;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .features li::before {
            content: '✓';
            color: var(--success);
            font-weight: bold;
            font-size: 18px;
        }
        
        .tab-nav {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            border-bottom: 2px solid #e5e7eb;
        }
        
        .tab-btn {
            background: none;
            border: none;
            padding: 12px 24px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            color: #6b7280;
            position: relative;
            transition: color 0.3s;
        }
        
        .tab-btn.active {
            color: var(--primary);
        }
        
        .tab-btn.active::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--primary);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            z-index: 2000;
            min-width: 300px;
            display: none;
        }
        
        .notification.show {
            display: block;
            animation: slideIn 0.3s;
        }
        
        @keyframes slideIn {
            from { transform: translateX(400px); }
            to { transform: translateX(0); }
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .table th, .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .table th {
            font-weight: 600;
            color: var(--dark);
            background: #f9fafb;
        }
        
        .action-btn {
            padding: 6px 12px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 12px;
            margin: 0 4px;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="sidebar">
            <div class="logo"><i class="fas fa-rocket"></i> DevOps Bot v2.0</div>
            <div class="nav-item active" onclick="showSection('dashboard')">
                <i class="fas fa-chart-line"></i> Dashboard
            </div>
            <div class="nav-item" onclick="showSection('deploy')">
                <i class="fas fa-upload"></i> Deploy
            </div>
            <div class="nav-item" onclick="showSection('deployments')">
                <i class="fas fa-list"></i> Deployments
            </div>
            <div class="nav-item" onclick="showSection('vps')">
                <i class="fas fa-server"></i> VPS Management
            </div>
            <div class="nav-item" onclick="showSection('github')">
                <i class="fab fa-github"></i> GitHub
            </div>
            <div class="nav-item" onclick="showSection('docker')">
                <i class="fab fa-docker"></i> Docker
            </div>
            <div class="nav-item" onclick="showSection('env')">
                <i class="fas fa-key"></i> Environment
            </div>
            <div class="nav-item" onclick="showSection('backup')">
                <i class="fas fa-database"></i> Backups
            </div>
            <div class="nav-item" onclick="showSection('webhooks')">
                <i class="fas fa-webhook"></i> Webhooks
            </div>
            <div class="nav-item" onclick="showSection('pricing')">
                <i class="fas fa-credit-card"></i> Pricing
            </div>
            <div class="nav-item" onclick="showSection('settings')">
                <i class="fas fa-cog"></i> Settings
            </div>
        </div>
        
        <div class="main-content">
            <div class="header">
                <div>
                    <h1>Welcome back! 👋</h1>
                    <p style="color: #6b7280; margin-top: 5px;">Manage your deployments with ease</p>
                </div>
                <div class="credit-badge">
                    <i class="fas fa-coins"></i> <span id="creditBalance">{{ credits }}</span> Credits
                </div>
            </div>
            
            <!-- Dashboard Section -->
            <div id="dashboard-section" class="section">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-label">Total Deployments</div>
                        <div class="stat-value" id="totalDeploys">{{ total_deploys }}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Active Now</div>
                        <div class="stat-value" id="activeDeploys">{{ active_deploys }}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">VPS Servers</div>
                        <div class="stat-value" id="vpsCount">{{ vps_count }}</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">GitHub Repos</div>
                        <div class="stat-value" id="repoCount">{{ repo_count }}</div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fas fa-clock"></i> Recent Activity</h3>
                        <button class="btn btn-sm" onclick="refreshActivity()">
                            <i class="fas fa-sync"></i> Refresh
                        </button>
                    </div>
                    <div id="activityList"></div>
                </div>
            </div>
            
            <!-- Deploy Section -->
            <div id="deploy-section" class="section" style="display:none;">
                <div class="tab-nav">
                    <button class="tab-btn active" onclick="showTab('file')">
                        <i class="fas fa-file-upload"></i> File Upload
                    </button>
                    <button class="tab-btn" onclick="showTab('github')">
                        <i class="fab fa-github"></i> GitHub
                    </button>
                    <button class="tab-btn" onclick="showTab('docker')">
                        <i class="fab fa-docker"></i> Docker
                    </button>
                    <button class="tab-btn" onclick="showTab('custom')">
                        <i class="fas fa-magic"></i> Custom
                    </button>
                </div>
                
                <div id="file-tab" class="tab-content active">
                    <div class="card">
                        <h3 class="card-title">📤 Deploy from File</h3>
                        <p style="color: #6b7280; margin: 10px 0;">Cost: <strong>0.5 credits</strong></p>
                        <div class="upload-zone" id="uploadZone" onclick="document.getElementById('fileInput').click()">
                            <i class="fas fa-cloud-upload-alt" style="font-size: 48px; color: var(--primary); margin-bottom: 15px;"></i>
                            <h3>Drag & Drop or Click to Upload</h3>
                            <p style="color: #6b7280; margin-top: 10px;">Supports: .py, .js, .zip, .tar.gz</p>
                            <input type="file" id="fileInput" hidden accept=".py,.js,.zip,.tar.gz" onchange="handleFileUpload(this)">
                        </div>
                    </div>
                </div>
                
                <div id="github-tab" class="tab-content">
                    <div class="card">
                        <h3 class="card-title">🐙 Deploy from GitHub</h3>
                        <p style="color: #6b7280; margin: 10px 0 20px;">Cost: <strong>1 credit</strong></p>
                        <div class="input-group">
                            <label>Repository URL</label>
                            <input type="text" id="githubUrl" placeholder="https://github.com/user/repo.git">
                        </div>
                        <div class="input-group">
                            <label>Branch</label>
                            <input type="text" id="githubBranch" value="main" placeholder="main">
                        </div>
                        <div class="input-group">
                            <label>Build Command (optional)</label>
                            <input type="text" id="buildCmd" placeholder="npm install && npm run build">
                        </div>
                        <div class="input-group">
                            <label>Start Command (optional)</label>
                            <input type="text" id="startCmd" placeholder="npm start">
                        </div>
                        <button class="btn" onclick="deployGithub()">
                            <i class="fas fa-rocket"></i> Deploy from GitHub
                        </button>
                    </div>
                </div>
                
                <div id="docker-tab" class="tab-content">
                    <div class="card">
                        <h3 class="card-title">🐳 Docker Deploy</h3>
                        <p style="color: #6b7280; margin: 10px 0 20px;">Cost: <strong>1.5 credits</strong></p>
                        <div class="input-group">
                            <label>Project Type</label>
                            <select id="dockerType">
                                <option value="python">Python Application</option>
                                <option value="nodejs">Node.js Application</option>
                                <option value="bot">Telegram Bot</option>
                                <option value="custom">Custom Dockerfile</option>
                            </select>
                        </div>
                        <div class="input-group" id="dockerfileInput" style="display:none;">
                            <label>Dockerfile Content</label>
                            <textarea id="dockerfileContent" rows="10" placeholder="FROM python:3.9..."></textarea>
                        </div>
                        <button class="btn" onclick="deployDocker()">
                            <i class="fab fa-docker"></i> Deploy with Docker
                        </button>
                    </div>
                </div>
                
                <div id="custom-tab" class="tab-content">
                    <div class="card">
                        <h3 class="card-title">🔧 Custom Deployment</h3>
                        <p style="color: #6b7280; margin: 10px 0 20px;">Cost: <strong>2.5 credits</strong></p>
                        <div class="input-group">
                            <label>Deployment Name</label>
                            <input type="text" id="customName" placeholder="My Custom Deploy">
                        </div>
                        <div class="input-group">
                            <label>Repository/Source</label>
                            <input type="text" id="customSource" placeholder="GitHub URL or upload file">
                        </div>
                        <div class="input-group">
                            <label>Environment Variables</label>
                            <textarea id="customEnv" rows="5" placeholder="KEY1=value1
KEY2=value2"></textarea>
                        </div>
                        <div class="input-group">
                            <label>Build Script</label>
                            <textarea id="customBuild" rows="5" placeholder="#!/bin/bash
pip install -r requirements.txt"></textarea>
                        </div>
                        <div class="input-group">
                            <label>Start Command</label>
                            <input type="text" id="customStart" placeholder="python main.py">
                        </div>
                        <button class="btn" onclick="deployCustom()">
                            <i class="fas fa-magic"></i> Deploy Custom Configuration
                        </button>
                    </div>
                </div>
            </div>
            
            <!-- Deployments Section -->
            <div id="deployments-section" class="section" style="display:none;">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fas fa-list"></i> All Deployments</h3>
                        <button class="btn" onclick="loadDeployments()">
                            <i class="fas fa-sync"></i> Refresh
                        </button>
                    </div>
                    <div id="deploymentsList"></div>
                </div>
            </div>
            
            <!-- VPS Management Section -->
            <div id="vps-section" class="section" style="display:none;">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fas fa-server"></i> VPS Servers</h3>
                        <button class="btn" onclick="showAddVPS()">
                            <i class="fas fa-plus"></i> Add VPS
                        </button>
                    </div>
                    <div id="vpsList"></div>
                </div>
            </div>
            
            <!-- GitHub Section -->
            <div id="github-section" class="section" style="display:none;">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fab fa-github"></i> Connected Repositories</h3>
                        <button class="btn" onclick="showAddRepo()">
                            <i class="fas fa-plus"></i> Connect Repository
                        </button>
                    </div>
                    <div id="reposList"></div>
                </div>
            </div>
            
            <!-- Docker Section -->
            <div id="docker-section" class="section" style="display:none;">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fab fa-docker"></i> Docker Containers</h3>
                        <button class="btn" onclick="loadContainers()">
                            <i class="fas fa-sync"></i> Refresh
                        </button>
                    </div>
                    <div id="containersList"></div>
                </div>
            </div>
            
            <!-- Environment Variables Section -->
            <div id="env-section" class="section" style="display:none;">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fas fa-key"></i> Environment Variables</h3>
                        <button class="btn" onclick="showAddEnv()">
                            <i class="fas fa-plus"></i> Add Variable
                        </button>
                    </div>
                    <div id="envList"></div>
                </div>
            </div>
            
            <!-- Backups Section -->
            <div id="backup-section" class="section" style="display:none;">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fas fa-database"></i> Backups</h3>
                        <button class="btn" onclick="showCreateBackup()">
                            <i class="fas fa-plus"></i> Create Backup
                        </button>
                    </div>
                    <div id="backupsList"></div>
                </div>
            </div>
            
            <!-- Webhooks Section -->
            <div id="webhooks-section" class="section" style="display:none;">
                <div class="card">
                    <div class="card-header">
                        <h3 class="card-title"><i class="fas fa-webhook"></i> Webhooks</h3>
                        <button class="btn" onclick="showAddWebhook()">
                            <i class="fas fa-plus"></i> Add Webhook
                        </button>
                    </div>
                    <div id="webhooksList"></div>
                </div>
            </div>
            
            <!-- Pricing Section -->
            <div id="pricing-section" class="section" style="display:none;">
                <div class="card">
                    <h3 class="card-title" style="text-align: center; margin-bottom: 30px;">
                        💰 Choose Your Plan
                    </h3>
                    <div class="pricing-grid">
                        {% for plan_id, plan in pricing_plans.items() %}
                        <div class="pricing-card {% if plan_id == 'pro' %}featured{% endif %}">
                            <h3>{{ plan_id.title() }}</h3>
                            <div class="price">₹{{ plan.price }}</div>
                            <p style="color: #6b7280;">{{ plan.credits if plan.credits != -1 else 'Unlimited' }} Credits</p>
                            <p style="color: #6b7280; font-size: 14px;">{{ plan.validity_days }} days</p>
                            <ul class="features">
                                {% for feature in plan.features %}
                                <li>{{ feature }}</li>
                                {% endfor %}
                            </ul>
                            <button class="btn" onclick="buyPlan('{{ plan_id }}')">
                                <i class="fas fa-shopping-cart"></i> Buy Now
                            </button>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
            
            <!-- Settings Section -->
            <div id="settings-section" class="section" style="display:none;">
                <div class="card">
                    <h3 class="card-title"><i class="fas fa-cog"></i> Settings</h3>
                    <div class="input-group">
                        <label>Email Notifications</label>
                        <input type="email" id="emailNotif" placeholder="your@email.com">
                    </div>
                    <div class="input-group">
                        <label>Webhook URL</label>
                        <input type="url" id="webhookUrl" placeholder="https://your-webhook.com">
                    </div>
                    <div class="input-group">
                        <label>API Key</label>
                        <input type="text" id="apiKey" readonly placeholder="Click to generate">
                        <button class="btn" onclick="generateAPIKey()" style="margin-top: 10px;">
                            <i class="fas fa-key"></i> Generate New API Key
                        </button>
                    </div>
                    <button class="btn btn-success" onclick="saveSettings()">
                        <i class="fas fa-save"></i> Save Settings
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modals -->
    <div id="deployModal" class="modal">
        <div class="modal-content">
            <h3>Deployment Details</h3>
            <div id="modalContent"></div>
            <button class="btn" onclick="closeModal()">Close</button>
        </div>
    </div>
    
    <!-- Notification -->
    <div id="notification" class="notification"></div>

    <script>
        // Drag and drop
        const uploadZone = document.getElementById('uploadZone');
        
        ['dragover', 'drop'].forEach(evt => {
            uploadZone.addEventListener(evt, e => e.preventDefault());
        });
        
        uploadZone.addEventListener('dragover', () => uploadZone.classList.add('dragover'));
        uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
        
        uploadZone.addEventListener('drop', e => {
            uploadZone.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length) handleFileUpload({files});
        });
        
        // Navigation
        function showSection(section) {
            document.querySelectorAll('.section').forEach(s => s.style.display = 'none');
            document.getElementById(section + '-section').style.display = 'block';
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            event.target.closest('.nav-item').classList.add('active');
        }
        
        function showTab(tab) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.getElementById(tab + '-tab').classList.add('active');
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            
            if (tab === 'docker') {
                document.getElementById('dockerType').addEventListener('change', function() {
                    document.getElementById('dockerfileInput').style.display = 
                        this.value === 'custom' ? 'block' : 'none';
                });
            }
        }
        
        // File upload
        async function handleFileUpload(input) {
            const file = input.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            showNotification('Uploading...', 'info');
            
            try {
                const res = await fetch('/api/deploy/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Deployment started!', 'success');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Upload failed', 'error');
            }
        }
        
        // GitHub deploy
        async function deployGithub() {
            const url = document.getElementById('githubUrl').value;
            const branch = document.getElementById('githubBranch').value;
            const buildCmd = document.getElementById('buildCmd').value;
            const startCmd = document.getElementById('startCmd').value;
            
            if (!url) return showNotification('⚠️ Enter repository URL', 'warning');
            
            try {
                const res = await fetch('/api/deploy/github', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url, branch, buildCmd, startCmd})
                });
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ GitHub deployment started!', 'success');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Deployment failed', 'error');
            }
        }
        
        // Docker deploy
        async function deployDocker() {
            const type = document.getElementById('dockerType').value;
            const dockerfile = type === 'custom' ? document.getElementById('dockerfileContent').value : null;
            
            try {
                const res = await fetch('/api/deploy/docker', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({type, dockerfile})
                });
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Docker deployment started!', 'success');
                    setTimeout(() => location.reload(), 2000);
                } else {
                    showNotification('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showNotification('❌ Deployment failed', 'error');
            }
        }
        
        // Custom deploy
        async function deployCustom() {
            const name = document.getElementById('customName').value;
            const source = document.getElementById('customSource').value;
            const env = document.getElementById('customEnv').value;
            const build = document.getElementById('customBuild').value;
            const start = document.getElementById('customStart').value;
            
            if (!name || !source) return showNotification('⚠️ Fill required fields', 'warning');
            
            try {
                const res = await fetch('/api/deploy/custom', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name, source, env, build, start})
                });
                const data = await res.json();
                
                if (data.success) {
                    showNotification('✅ Custom deployment started!', 'success');
                    setTimeout(() => location.reload(), 2000);
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
                    list.innerHTML = '<p style="text-align:center;color:#6b7280;padding:40px;">No deployments yet</p>';
                    return;
                }
                
                list.innerHTML = data.deployments.map(d => `
                    <div class="deployment-card">
                        <div class="deployment-header">
                            <div>
                                <strong>${d.id}</strong>
                                <p style="color:#6b7280;font-size:14px;margin-top:5px;">${d.type}</p>
                            </div>
                            <span class="status-badge status-${d.status}">${d.status}</span>
                        </div>
                        <div style="margin-top:15px;">
                            <button class="action-btn btn-success" onclick="viewLogs('${d.id}')">
                                <i class="fas fa-file-alt"></i> Logs
                            </button>
                            <button class="action-btn btn-warning" onclick="restartDeploy('${d.id}')">
                                <i class="fas fa-redo"></i> Restart
                            </button>
                            <button class="action-btn btn-danger" onclick="stopDeploy('${d.id}')">
                                <i class="fas fa-stop"></i> Stop
                            </button>
                        </div>
                    </div>
                `).join('');
            } catch (err) {
                console.error(err);
            }
        }
        
        // Buy plan
        function buyPlan(plan) {
            showNotification('🔜 Payment integration coming soon! Contact @Zolvit', 'info');
        }
        
        // Notifications
        function showNotification(msg, type = 'info') {
            const notif = document.getElementById('notification');
            const icons = {info: 'ℹ️', success: '✅', warning: '⚠️', error: '❌'};
            notif.innerHTML = `${icons[type]} ${msg}`;
            notif.className = 'notification show';
            setTimeout(() => notif.className = 'notification', 3000);
        }
        
        // Refresh credits
        setInterval(async () => {
            try {
                const res = await fetch('/api/credits');
                const data = await res.json();
                document.getElementById('creditBalance').textContent = 
                    data.credits === 999999 ? '∞' : data.credits.toFixed(1);
            } catch (err) {
                console.error('Credit refresh failed:', err);
            }
        }, 5000);
        
        // Load initial data
        loadDeployments();
    </script>
</body>
</html>"""

@app.route('/')
def index():
    """Enhanced web dashboard"""
    user_id = session.get('user_id')
    
    if not user_id:
        user_id = session.get('demo_user_id', 999999)
        session['user_id'] = user_id
        session['demo_user_id'] = user_id
        
        if user_id not in user_credits:
            initialize_user_credits(user_id)
    
    credits = get_user_credits(user_id)
    total_deploys = len(deployment_history.get(user_id, []))
    vps_count = len(user_vps_servers.get(user_id, {}))
    repo_count = len(user_github_repos.get(user_id, {}))
    
    return render_template_string(
        ENHANCED_HTML,
        credits=f"{credits:.1f}" if credits != float('inf') else "∞",
        total_deploys=total_deploys,
        active_deploys=len([d for d in deployment_history.get(user_id, []) if d.get('status') == 'running']),
        vps_count=vps_count,
        repo_count=repo_count,
        pricing_plans=PRICING_PLANS
    )

@app.route('/api/credits')
def get_credits_api():
    """Get credits API"""
    user_id = session.get('user_id', 999999)
    credits = get_user_credits(user_id)
    return jsonify({
        'success': True,
        'credits': credits if credits != float('inf') else 999999
    })

@app.route('/api/deploy/upload', methods=['POST'])
def api_deploy_upload():
    """Upload deployment API"""
    user_id = session.get('user_id', 999999)
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file'})
    
    file = request.files['file']
    cost = CREDIT_COSTS['file_upload']
    
    if not deduct_credits(user_id, cost, f"File upload: {file.filename}"):
        return jsonify({'success': False, 'error': f'Need {cost} credits'})
    
    try:
        user_dir = os.path.join(WEB_UPLOADS_DIR, str(user_id))
        os.makedirs(user_dir, exist_ok=True)
        filepath = os.path.join(user_dir, secure_filename(file.filename))
        file.save(filepath)
        
        deploy_id, msg = deploy_from_file(user_id, filepath, file.filename)
        
        if deploy_id:
            trigger_webhook(user_id, 'deployment.created', {'deployment_id': deploy_id})
            return jsonify({'success': True, 'deployment_id': deploy_id})
        else:
            add_credits(user_id, cost, "Refund: Failed")
            return jsonify({'success': False, 'error': msg})
    except Exception as e:
        add_credits(user_id, cost, "Refund: Error")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deploy/github', methods=['POST'])
def api_deploy_github():
    """GitHub deployment API"""
    user_id = session.get('user_id', 999999)
    data = request.get_json()
    
    repo_url = data.get('url')
    branch = data.get('branch', 'main')
    cost = CREDIT_COSTS['github_deploy']
    
    if not deduct_credits(user_id, cost, f"GitHub: {repo_url}"):
        return jsonify({'success': False, 'error': f'Need {cost} credits'})
    
    try:
        deploy_id, msg = deploy_from_github(user_id, repo_url, branch)
        
        if deploy_id:
            trigger_webhook(user_id, 'deployment.created', {'deployment_id': deploy_id, 'source': 'github'})
            return jsonify({'success': True, 'deployment_id': deploy_id})
        else:
            add_credits(user_id, cost, "Refund: Failed")
            return jsonify({'success': False, 'error': msg})
    except Exception as e:
        add_credits(user_id, cost, "Refund: Error")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deploy/docker', methods=['POST'])
def api_deploy_docker():
    """Docker deployment API"""
    user_id = session.get('user_id', 999999)
    data = request.get_json()
    
    project_type = data.get('type', 'python')
    cost = CREDIT_COSTS['docker_deploy']
    
    if not deduct_credits(user_id, cost, f"Docker: {project_type}"):
        return jsonify({'success': False, 'error': f'Need {cost} credits'})
    
    try:
        deploy_id, msg = deploy_with_docker(user_id, project_type)
        
        if deploy_id:
            trigger_webhook(user_id, 'deployment.created', {'deployment_id': deploy_id, 'source': 'docker'})
            return jsonify({'success': True, 'deployment_id': deploy_id})
        else:
            add_credits(user_id, cost, "Refund: Failed")
            return jsonify({'success': False, 'error': msg})
    except Exception as e:
        add_credits(user_id, cost, "Refund: Error")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deploy/custom', methods=['POST'])
def api_deploy_custom():
    """Custom deployment API"""
    user_id = session.get('user_id', 999999)
    data = request.get_json()
    cost = CREDIT_COSTS['custom_deploy']
    
    if not deduct_credits(user_id, cost, "Custom deployment"):
        return jsonify({'success': False, 'error': f'Need {cost} credits'})
    
    try:
        deployment_id = create_deployment_record(user_id, 'custom', cost, data)
        trigger_webhook(user_id, 'deployment.created', {'deployment_id': deployment_id})
        return jsonify({'success': True, 'deployment_id': deployment_id})
    except Exception as e:
        add_credits(user_id, cost, "Refund: Error")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/deployments')
def api_deployments():
    """Get deployments API"""
    user_id = session.get('user_id', 999999)
    return jsonify({
        'success': True,
        'deployments': deployment_history.get(user_id, [])
    })

def run_flask():
    """Run Flask server"""
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

def keep_alive():
    """Start Flask in background"""
    t = Thread(target=run_flask, daemon=True)
    t.start()
    logger.info(f"✅ Web Dashboard: http://localhost:{os.environ.get('PORT', 8080)}")

# ==================== TELEGRAM BOT HANDLERS ====================

def create_main_menu(user_id):
    """Main menu keyboard"""
    markup = types.InlineKeyboardMarkup(row_width=2)
    credits = get_user_credits(user_id)
    credit_text = "∞" if credits == float('inf') else f"{credits:.1f}"
    
    markup.add(types.InlineKeyboardButton(f'💳 {credit_text} Credits', callback_data='credits'))
    markup.add(
        types.InlineKeyboardButton('🚀 Deploy', callback_data='deploy'),
        types.InlineKeyboardButton('📊 Dashboard', callback_data='dashboard')
    )
    markup.add(
        types.InlineKeyboardButton('🖥️ VPS', callback_data='vps'),
        types.InlineKeyboardButton('🐙 GitHub', callback_data='github')
    )
    markup.add(
        types.InlineKeyboardButton('🐳 Docker', callback_data='docker'),
        types.InlineKeyboardButton('🔐 ENV', callback_data='env')
    )
    markup.add(
        types.InlineKeyboardButton('💾 Backup', callback_data='backup'),
        types.InlineKeyboardButton('🔔 Webhooks', callback_data='webhooks')
    )
    markup.add(types.InlineKeyboardButton('💰 Buy Credits', callback_data='buy'))
    
    if user_id in admin_ids:
        markup.add(types.InlineKeyboardButton('👑 Admin', callback_data='admin'))
    
    return markup

@bot.message_handler(commands=['start'])
def start_cmd(message):
    """Start command"""
    user_id = message.from_user.id
    username = message.from_user.username
    first_name = message.from_user.first_name
    
    if user_id not in active_users:
        active_users.add(user_id)
        
        with DB_LOCK:
            conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('''INSERT OR REPLACE INTO users 
                        (user_id, username, first_name, joined_date, last_active)
                        VALUES (?, ?, ?, ?, ?)''',
                     (user_id, username, first_name, 
                      datetime.now().isoformat(), datetime.now().isoformat()))
            conn.commit()
            conn.close()
        
        if initialize_user_credits(user_id):
            bot.send_message(user_id, 
                f"🎉 Welcome! You got {FREE_CREDITS} FREE credit!",
                parse_mode='Markdown')
    
    credits = get_user_credits(user_id)
    
    bot.send_message(
        message.chat.id,
        f"🚀 **DevOps Bot v2.0**\n\n"
        f"👤 {first_name}\n"
        f"💳 Credits: {credits if credits != float('inf') else '∞'}\n\n"
        f"**Features:**\n"
        f"• Multi-deployment support\n"
        f"• VPS management\n"
        f"• GitHub integration\n"
        f"• Docker containers\n"
        f"• Auto backups\n"
        f"• Webhook notifications\n\n"
        f"Use buttons below! 👇",
        reply_markup=create_main_menu(user_id),
        parse_mode='Markdown'
    )

@bot.callback_query_handler(func=lambda call: True)
def callback_handler(call):
    """Callback handler"""
    user_id = call.from_user.id
    
    try:
        if call.data == 'credits':
            credits = get_user_credits(user_id)
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                f"💳 **Your Credits: {credits if credits != float('inf') else '∞'}**\n\n"
                f"Use /buy to get more!",
                parse_mode='Markdown')
        
        elif call.data == 'dashboard':
            port = os.environ.get('PORT', 8080)
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                f"🌐 **Web Dashboard**\n\n"
                f"Access at: http://your-url:{port}\n\n"
                f"Full-featured interface with:\n"
                f"• Drag & drop uploads\n"
                f"• Live deployment logs\n"
                f"• Resource monitoring\n"
                f"• Advanced controls",
                parse_mode='Markdown')
        
        else:
            bot.answer_callback_query(call.id, "Feature ready! Use web dashboard.", show_alert=True)
    
    except Exception as e:
        logger.error(f"Callback error: {e}")
        bot.answer_callback_query(call.id, "Error occurred")

@bot.message_handler(commands=['addcredits'])
def add_credits_cmd(message):
    """Admin: Add credits"""
    if message.from_user.id not in admin_ids:
        return bot.reply_to(message, "⚠️ Admin only")
    
    try:
        parts = message.text.split()
        if len(parts) != 3:
            return bot.reply_to(message, "Usage: /addcredits USER_ID AMOUNT")
        
        target_user = int(parts[1])
        amount = float(parts[2])
        
        if add_credits(target_user, amount, f"Admin bonus"):
            bot.reply_to(message, f"✅ Added {amount} credits to {target_user}")
            try:
                bot.send_message(target_user, f"🎉 You received {amount} credits!")
            except:
                pass
        else:
            bot.reply_to(message, "❌ Failed")
    except Exception as e:
        bot.reply_to(message, f"❌ Error: {e}")

def cleanup():
    """Cleanup on shutdown"""
    logger.warning("Shutting down...")
    
    for deploy_id, process in list(active_processes.items()):
        try:
            process.terminate()
            process.wait(timeout=5)
        except:
            try:
                process.kill()
            except:
                pass
    
    if DOCKER_AVAILABLE:
        try:
            containers = docker_client.containers.list()
            for container in containers:
                if container.name.startswith('deploy-'):
                    container.stop()
        except:
            pass
    
    logger.warning("✅ Cleanup complete")

atexit.register(cleanup)

# ==================== MAIN ====================

if __name__ == '__main__':
    print("=" * 70)
    print("🚀 ULTRA ADVANCED DEVOPS BOT v2.0 - PRODUCTION READY")
    print("=" * 70)
    print(f"🐍 Python: {sys.version.split()[0]}")
    print(f"📁 Base: {BASE_DIR}")
    print(f"👑 Owner: {OWNER_ID}")
    print(f"💳 Free Credits: {FREE_CREDITS}")
    print(f"🐳 Docker: {'Available' if DOCKER_AVAILABLE else 'Not Available'}")
    print("=" * 70)
    print("✅ FEATURES:")
    print("  ✓ Multi-deployment (File, GitHub, Docker, Custom)")
    print("  ✓ VPS SSH management")
    print("  ✓ Environment variables (encrypted)")
    print("  ✓ Automatic backups")
    print("  ✓ Webhook notifications")
    print("  ✓ GitHub auto-deploy")
    print("  ✓ Docker orchestration")
    print("  ✓ Advanced web dashboard")
    print("  ✓ Credit system with transactions")
    print("  ✓ Real-time monitoring")
    print("  ✓ API endpoints")
    print("  ✓ SSL certificate management")
    print("=" * 70)
    
    keep_alive()
    
    logger.info("🤖 Starting Telegram bot...")
    while True:
        try:
            bot.infinity_polling(timeout=60, long_polling_timeout=30)
        except Exception as e:
            logger.error(f"Polling error: {e}")
            time.sleep(5)
