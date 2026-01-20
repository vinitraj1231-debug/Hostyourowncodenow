# -*- coding: utf-8 -*-
"""
🚀 ULTRA ADVANCED DEVOPS BOT v10.0 - SUPREME PROFESSIONAL EDITION
Revolutionary AI-Powered Deployment Platform
Premium Design | Full Bot-Web Integration | Advanced Payment System
"""

import sys
import subprocess
import os

# ==================== SMART DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 NEXT-GEN DEPENDENCY INSTALLER v10.0")
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

# Enhanced credit system - PER USER
FREE_CREDITS = 2.0
CREDIT_PACKAGES = {
    '99': {'credits': 10, 'price': 99, 'name': 'Starter Pack', 'badge': '🥉'},
    '399': {'credits': 50, 'price': 399, 'name': 'Pro Pack', 'badge': '⭐'},
    '699': {'credits': 100, 'price': 699, 'name': 'Ultimate Pack', 'badge': '🔥'}
}

CREDIT_COSTS = {
    'file_upload': 0.5,
    'github_deploy': 1.0,
    'vps_command': 0.3,
    'backup': 0.5,
}

# Payment Gateway (UPI)
UPI_ID = "nitishkypaurai17@ibl"
PAYMENT_QR_IMAGE = "qr.jpg"  # Your QR code image

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

# Global state - PER USER ISOLATION
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
pending_payments = {}
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
    
    logger.info(f"{Fore.CYAN}🤖 AI DEPENDENCY ANALYZER v10.0 - STARTING...")
    install_log.append("🤖 AI DEPENDENCY ANALYZER v10.0")
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

# ==================== DATABASE V10 - PER USER ====================

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

def create_payment_record(user_id, amount, package_name):
    """Create payment record and return payment ID"""
    payment_id = str(uuid.uuid4())[:8].upper()
    
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
    
    return payment_id

def verify_payment(payment_id, transaction_id):
    """Verify and complete payment"""
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
        'pid':         .modal-content {
            background: rgba(30, 30, 46, 0.95);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 24px;
            padding: 28px;
            max-width: 600px;
            width: 100%;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            animation: slideUp 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
        }
        
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(50px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .modal-title {
            font-size: 20px;
            font-weight: 800;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .qr-container {
            text-align: center;
            padding: 20px 0;
        }
        
        .qr-code {
            max-width: 300px;
            border-radius: 16px;
            margin: 20px auto;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        
        .terminal {
            background: #1e1e2e;
            color: #00d4aa;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            padding: 16px;
            border-radius: 12px;
            max-height: 450px;
            overflow-y: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
            line-height: 1.6;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
        }
        
        .empty-icon {
            font-size: 64px;
            margin-bottom: 16px;
            opacity: 0.5;
        }
        
        .empty-title {
            font-size: 18px;
            font-weight: 800;
            margin-bottom: 8px;
        }
        
        .empty-desc {
            color: rgba(255, 255, 255, 0.7);
            font-size: 14px;
            font-weight: 600;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .pricing-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <div class="logo">
                <div class="logo-icon">
                    <i class="fas fa-rocket"></i>
                </div>
                <div class="logo-text">
                    <h1> narzohostbot</h1>
                    <p>made by @narzoxbot</p>
                </div>
            </div>
            <div class="credit-badge">
                <i class="fas fa-gem"></i>
                <span id="creditBalance">{{ credits }}</span>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon">🚀</div>
                <div class="stat-value" id="totalDeploys">0</div>
                <div class="stat-label">Total Deploys</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🟢</div>
                <div class="stat-value" id="activeDeploys">0</div>
                <div class="stat-label">Active Now</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">💻</div>
                <div class="stat-value" id="vpsCount">0</div>
                <div class="stat-label">VPS Servers</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon">🤖</div>
                <div class="stat-value">AI</div>
                <div class="stat-label">Powered</div>
            </div>
        </div>
        
        <div class="tab-nav">
            <button class="tab-btn active" onclick="showTab('deploy')">
                <i class="fas fa-rocket"></i> Deploy
            </button>
            <button class="tab-btn" onclick="showTab('apps')">
                <i class="fas fa-list"></i> My Apps
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
                    <h3 class="card-title">
                        <i class="fas fa-cloud-upload-alt"></i>
                        Smart File Deploy
                    </h3>
                </div>
                <p style="margin-bottom: 20px; color: rgba(255, 255, 255, 0.8); font-size: 13px; line-height: 1.6;">
                    <strong>🤖 AI-Powered Auto-Install:</strong> Upload your files and our advanced AI automatically detects and installs ALL dependencies!
                </p>
                <div class="upload-zone" onclick="document.getElementById('fileInput').click()">
                    <div class="upload-icon">
                        <i class="fas fa-cloud-upload-alt"></i>
                    </div>
                    <div class="upload-title">Tap to Upload File</div>
                    <div class="upload-desc">Supports: .py • .js • .zip archives</div>
                    <input type="file" id="fileInput" hidden accept=".py,.js,.zip" onchange="handleFileUpload(this)">
                </div>
            </div>
        </div>
        
        <div id="apps-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-server"></i>
                        My Deployments
                    </h3>
                    <button onclick="loadDeployments()" style="background: rgba(255,255,255,0.2); border: none; color: #fff; padding: 8px 12px; border-radius: 8px; cursor: pointer;">
                        <i class="fas fa-sync"></i>
                    </button>
                </div>
                <div id="deploymentsList"></div>
            </div>
        </div>
        
        <div id="github-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fab fa-github"></i>
                        GitHub Deploy
                    </h3>
                </div>
                <div class="input-group">
                    <label class="input-label">
                        <i class="fab fa-github"></i> Repository URL
                    </label>
                    <input type="url" class="input-field" id="repoUrl" placeholder="https://github.com/username/repo.git">
                </div>
                <div class="input-group">
                    <label class="input-label">
                        <i class="fas fa-code-branch"></i> Branch Name
                    </label>
                    <input type="text" class="input-field" id="repoBranch" value="main" placeholder="main">
                </div>
                <div class="input-group">
                    <label class="input-label">
                        <i class="fas fa-hammer"></i> Build Command (Optional)
                    </label>
                    <input type="text" class="input-field" id="buildCmd" placeholder="npm run build">
                </div>
                <div class="input-group">
                    <label class="input-label">
                        <i class="fas fa-play"></i> Start Command (Optional)
                    </label>
                    <input type="text" class="input-field" id="startCmd" placeholder="Auto-detected if empty">
                </div>
                <button class="btn" onclick="deployGithub()">
                    <i class="fab fa-github"></i> Deploy from GitHub
                </button>
            </div>
        </div>
        
        <div id="env-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-lock"></i>
                        Environment Variables
                    </h3>
                    <button onclick="showAddEnv()" style="background: rgba(255,255,255,0.2); border: none; color: #fff; padding: 8px 12px; border-radius: 8px; cursor: pointer;">
                        <i class="fas fa-plus"></i>
                    </button>
                </div>
                <div id="envList"></div>
            </div>
        </div>
        
        <div id="credits-tab" class="tab-content">
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-shopping-cart"></i>
                        Buy Premium Credits
                    </h3>
                </div>
                <div class="pricing-grid">
                    <div class="price-card">
                        <div class="price-badge">🥉</div>
                        <div class="price-name">Starter Pack</div>
                        <div class="price-amount">₹99</div>
                        <div class="price-credits">10 Credits</div>
                        <button class="btn" onclick="buyCredits(99)">
                            <i class="fas fa-shopping-cart"></i> Buy Now
                        </button>
                    </div>
                    <div class="price-card popular">
                        <div class="popular-badge">⭐ POPULAR</div>
                        <div class="price-badge">⭐</div>
                        <div class="price-name">Pro Pack</div>
                        <div class="price-amount">₹399</div>
                        <div class="price-credits">50 Credits</div>
                        <button class="btn" onclick="buyCredits(399)">
                            <i class="fas fa-shopping-cart"></i> Buy Now
                        </button>
                    </div>
                    <div class="price-card">
                        <div class="price-badge">🔥</div>
                        <div class="price-name">Ultimate Pack</div>
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
        <div class="nav-item" onclick="showTab('env')">
            <i class="fas fa-key"></i>
            <span>ENV</span>
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
            showToast('🤖 AI analyzing your code...', 'info');
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
                showToast('❌ Deployment failed', 'error');
            }
            input.value = '';
        }
        
        async function deployGithub() {
            const url = document.getElementById('repoUrl').value;
            const branch = document.getElementById('repoBranch').value;
            const buildCmd = document.getElementById('buildCmd').value;
            const startCmd = document.getElementById('startCmd').value;
            
            if (!url) return showToast('⚠️ Please enter repository URL', 'warning');
            showToast('🤖 AI cloning repository...', 'info');
            
            try {
                const res = await fetch('/api/deploy/github', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url, branch, build_cmd: buildCmd, start_cmd: startCmd})
                });
                const data = await res.json();
                if (data.success) {
                    showToast('✅ ' + data.message, 'success');
                    document.getElementById('repoUrl').value = '';
                    document.getElementById('buildCmd').value = '';
                    document.getElementById('startCmd').value = '';
                    setTimeout(() => {
                        updateCredits();
                        loadDeployments();
                        showTab('apps');
                    }, 1500);
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Deployment failed', 'error');
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
                            <div class="empty-title">No Deployments Yet</div>
                            <div class="empty-desc">Deploy your first app to get started!</div>
                        </div>
                    `;
                    document.getElementById('totalDeploys').textContent = '0';
                    document.getElementById('activeDeploys').textContent = '0';
                    return;
                }
                
                list.innerHTML = data.deployments.map(d => `
                    <div class="deploy-item">
                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                            <div style="flex: 1;">
                                <div class="deploy-name">${d.name}</div>
                                <div class="deploy-meta">
                                    <span><i class="fas fa-fingerprint"></i> ${d.id}</span>
                                    ${d.port ? `<span><i class="fas fa-network-wired"></i> Port ${d.port}</span>` : ''}
                                    ${d.type ? `<span><i class="fas fa-tag"></i> ${d.type}</span>` : ''}
                                </div>
                            </div>
                            <span class="status-badge status-${d.status}">${d.status}</span>
                        </div>
                        <div class="action-grid">
                            <button class="action-btn" style="background: linear-gradient(135deg, #48dbfb, #0abde3);" onclick="viewLogs('${d.id}')">
                                <i class="fas fa-terminal"></i> Logs
                            </button>
                            ${d.status === 'running' ? `
                                <button class="action-btn" style="background: linear-gradient(135deg, #ff6b6b, #ee5a6f);" onclick="stopDeploy('${d.id}')">
                                    <i class="fas fa-stop"></i> Stop
                                </button>
                            ` : ''}
                            <button class="action-btn" style="background: linear-gradient(135deg, #feca57, #ff9ff3);" onclick="deleteDeploy('${d.id}')">
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
        
        async function viewLogs(deployId) {
            try {
                const res = await fetch('/api/deployment/' + deployId + '/logs');
                const data = await res.json();
                showModal(`
                    <h3 class="modal-title">
                        <i class="fas fa-terminal"></i> Deployment Logs
                    </h3>
                    <div class="terminal">${data.logs || 'No logs available...'}</div>
                    <button class="btn" onclick="closeModal()" style="margin-top: 20px; background: linear-gradient(135deg, #ff6b6b, #ee5a6f);">
                        <i class="fas fa-times"></i> Close
                    </button>
                `);
            } catch (err) {
                showToast('❌ Failed to load logs', 'error');
            }
        }
        
        async function stopDeploy(deployId) {
            if (!confirm('Stop this deployment?')) return;
            showToast('⏳ Stopping deployment...', 'info');
            try {
                const res = await fetch('/api/deployment/' + deployId + '/stop', {method: 'POST'});
                const data = await res.json();
                if (data.success) {
                    showToast('✅ Deployment stopped', 'success');
                    loadDeployments();
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Stop failed', 'error');
            }
        }
        
        async function deleteDeploy(deployId) {
            if (!confirm('Delete this deployment permanently?')) return;
            showToast('⏳ Deleting...', 'info');
            try {
                const res = await fetch('/api/deployment/' + deployId, {method: 'DELETE'});
                const data = await res.json();
                if (data.success) {
                    showToast('✅ Deleted successfully', 'success');
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
                <h3 class="modal-title">
                    <i class="fas fa-plus"></i> Add Environment Variable
                </h3>
                <div class="input-group">
                    <label class="input-label">Variable Name</label>
                    <input type="text" class="input-field" id="envKey" placeholder="API_KEY">
                </div>
                <div class="input-group">
                    <label class="input-label">Variable Value</label>
                    <input type="text" class="input-field" id="envValue" placeholder="your_secret_value">
                </div>
                <button class="btn" onclick="addEnv()" style="background: linear-gradient(135deg, #00d4aa, #00a87e); margin-bottom: 10px;">
                    <i class="fas fa-save"></i> Add Variable
                </button>
                <button class="btn" onclick="closeModal()" style="background: linear-gradient(135deg, #ff6b6b, #ee5a6f);">
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
                    showToast('✅ Variable added', 'success');
                    closeModal();
                    loadEnv();
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Failed to add', 'error');
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
                            <div class="empty-title">No Variables Set</div>
                            <div class="empty-desc">Add environment variables for your deployments</div>
                        </div>
                    `;
                    return;
                }
                
                list.innerHTML = Object.entries(data.variables).map(([key, value]) => `
                    <div class="deploy-item">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <div style="flex: 1; min-width: 0;">
                                <div class="deploy-name">${key}</div>
                                <p style="color: rgba(255,255,255,0.6); font-size: 12px; margin-top: 6px; overflow: hidden; text-overflow: ellipsis; font-family: monospace;">
                                    ${value.substring(0, 40)}${value.length > 40 ? '...' : ''}
                                </p>
                            </div>
                            <button onclick="deleteEnv('${key}')" style="background: linear-gradient(135deg, #ff6b6b, #ee5a6f); border: none; color: #fff; padding: 10px 14px; border-radius: 10px; cursor: pointer;">
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
            showToast('⏳ Deleting...', 'info');
            try {
                const res = await fetch('/api/env/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({key})
                });
                const data = await res.json();
                if (data.success) {
                    showToast('✅ Variable deleted', 'success');
                    loadEnv();
                } else {
                    showToast('❌ ' + data.error, 'error');
                }
            } catch (err) {
                showToast('❌ Delete failed', 'error');
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
                            <h3 class="modal-title">
                                <i class="fas fa-qrcode"></i> Scan QR to Pay
                            </h3>
                            <p style="margin-bottom: 16px; color: rgba(255,255,255,0.8);">
                                Payment ID: <strong style="color: #feca57;">${data.payment_id}</strong>
                            </p>
                            <img src="${data.qr_url}" class="qr-code" alt="Payment QR Code">
                            <div style="background: rgba(255,255,255,0.1); padding: 20px; border-radius: 16px; margin: 24px 0; border: 1px solid rgba(255,255,255,0.2);">
                                <p style="font-weight: 800; font-size: 18px; margin-bottom: 8px;">Amount: ₹${amount}</p>
                                <p style="font-weight: 800; font-size: 20px; color: #00d4aa;">Credits: ${data.credits} 💎</p>
                            </div>
                            <p style="color: rgba(255,255,255,0.7); font-size: 13px; line-height: 1.6; margin-bottom: 20px;">
                                📱 Scan QR code or pay to UPI:<br>
                                <strong style="color: #fff;">${data.upi_id}</strong><br><br>
                                📸 After payment, send screenshot to<br>
                                <a href="${data.telegram_link}" target="_blank" style="color: #48dbfb; text-decoration: none; font-weight: 700;">${data.telegram_username}</a>
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
                info: '<i class="fas fa-info-circle toast-icon" style="color: #48dbfb;"></i>',
                success: '<i class="fas fa-check-circle toast-icon" style="color: #00d4aa;"></i>',
                warning: '<i class="fas fa-exclamation-triangle toast-icon" style="color: #feca57;"></i>',
                error: '<i class="fas fa-times-circle toast-icon" style="color: #ff6b6b;"></i>'
            };
            toast.innerHTML = (icons[type] || icons.info) + `<div class="toast-message">${msg}</div>`;
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 4000);
        }
        
        setInterval(updateCredits, 20000);
        setInterval(() => {
            if (document.getElementById('apps-tab').classList.contains('active')) {
                loadDeployments();
            }
        }, 15000);
        
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
        PREMIUM_DASHBOARD,
        credits=f"{credits:.1f}" if credits != float('inf') else "∞"
    )

@app.route('/api/credits')
def api_credits():
    user_id = session.get('user_id', 999999)
    return jsonify({'success': True, 'credits': get_credits(user_,
        'repo_url': kwargs.get('repo_url', ''),
        'branch': kwargs.get('branch', 'main')
    })
    
    return deploy_id, port

def update_deployment(deploy_id, status=@app.route('/api/credits')
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

@app.route('/api/payment/create', methods=['POST'])
def api_create_payment():
    user_id = session.get('user_id', 999999)
    data = request.get_json()
    amount = data.get('amount')
    
    if str(amount) not in CREDIT_PACKAGES:
        return jsonify({'success': False, 'error': 'Invalid package'})
    
    package = CREDIT_PACKAGES[str(amount)]
    payment_id = create_payment_record(user_id, amount, package['name'])
    
    return jsonify({
        'success': True,
        'payment_id': payment_id,
        'qr_url': f'/payment/qr',
        'upi_id': UPI_ID,
        'credits': package['credits'],
        'telegram_link': TELEGRAM_LINK,
        'telegram_username': YOUR_USERNAME
    })

@app.route('/payment/qr')
def payment_qr():
    """Serve the QR code image"""
    qr_path = os.path.join(BASE_DIR, PAYMENT_QR_IMAGE)
    if os.path.exists(qr_path):
        return send_file(qr_path, mimetype='image/jpeg')
    return "QR image not found. Please add qr.jpg to project directory", 404

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
            bot.send_message(user_id, 
                f"🎉 *Welcome Bonus!*\n\n"
                f"You received *{FREE_CREDITS} FREE credits*!\n\n"
                f"✨ _Your credits are private and separate from others_")
    
    credits = get_credits(user_id)
    
    bot.send_message(
        message.chat.id,
        f"🚀 *DevOps Bot v10.0 - SUPREME EDITION*\n\n"
        f"👤 *{first_name}*\n"
        f"💎 Credits: *{credits if credits != float('inf') else '∞'}*\n\n"
        f"*🌟 PREMIUM FEATURES:*\n\n"
        f"✅ *Per-User Credits* - Your balance is private!\n"
        f"✅ *Buy Credits* - ₹99/399/699 packages\n"
        f"✅ *Bot + Web Sync* - Fully integrated\n"
        f"✅ *AI Auto-Install* - Zero config needed\n"
        f"✅ *Direct Deploy* - Send files here!\n"
        f"✅ *GitHub Deploy* - Send GitHub URLs!\n"
        f"✅ *Premium UI* - Stylish web dashboard\n\n"
        f"📤 *Send .py, .js or .zip file to deploy instantly!*\n"
        f"🔗 *Or send GitHub URL for direct deploy!*\n"
        f"🌐 *Use web dashboard for advanced features*",
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
                f"🌐 *Premium Web Dashboard*\n\n"
                f"🔗 Access: `http://localhost:{port}`\n\n"
                f"*✨ PREMIUM FEATURES:*\n"
                f"• Stunning glass morphism design\n"
                f"• Smooth animations & transitions\n"
                f"• Upload & deploy files\n"
                f"• GitHub with build/start commands\n"
                f"• Manage deployments\n"
                f"• ENV variables\n"
                f"• Buy credits with UPI QR\n"
                f"• Real-time monitoring\n\n"
                f"*Experience premium quality!* 🎨")
        
        elif call.data == 'my_apps':
            deploys = active_deployments.get(user_id, [])
            if not deploys:
                bot.answer_callback_query(call.id)
                bot.send_message(call.message.chat.id, 
                    "📊 *No Deployments*\n\n"
                    "Send a file or GitHub URL to deploy!\n"
                    "Or use the web dashboard.")
            else:
                running = sum(1 for d in deploys if d['status'] == 'running')
                
                status_text = f"📊 *Your Deployments*\n\n"
                status_text += f"📦 Total: *{len(deploys)}*\n"
                status_text += f"🟢 Running: *{running}*\n\n"
                status_text += "*📋 Recent Apps:*\n\n"
                
                for d in deploys[-5:]:
                    emoji = {'running': '🟢', 'pending': '🟡', 'stopped': '🔴', 'failed': '❌'}
                    status_text += f"{emoji.get(d['status'], '⚪')} `{d['name'][:25]}...`\n"
                    status_text += f"   Port: `{d['port']}` | {d['status']}\n\n"
                
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
                f"💎 *Your Credit Balance*\n\n"
                f"💰 Current: *{credits if credits != float('inf') else '∞'}*\n"
                f"📈 Total Earned: *{earned:.1f}*\n"
                f"📉 Total Spent: *{spent:.1f}*\n\n"
                f"_Your credits are private and isolated!_")
        
        elif call.data == 'buy_credits':
            markup = types.InlineKeyboardMarkup()
            markup.add(
                types.InlineKeyboardButton('🥉 ₹99 → 10 Credits', callback_data='buy_99')
            )
            markup.add(
                types.InlineKeyboardButton('⭐ ₹399 → 50 Credits (Popular)', callback_data='buy_399')
            )
            markup.add(
                types.InlineKeyboardButton('🔥 ₹699 → 100 Credits', callback_data='buy_699')
            )
            markup.add(types.InlineKeyboardButton('◀️ Back', callback_data='back_menu'))
            
            bot.answer_callback_query(call.id)
            bot.edit_message_text(
                f"💰 *Buy Premium Credits*\n\n"
                f"*Choose your package:*\n\n"
                f"🥉 *Starter:* ₹99 = 10 credits\n"
                f"⭐ *Pro:* ₹399 = 50 credits (Most Popular)\n"
                f"🔥 *Ultimate:* ₹699 = 100 credits\n\n"
                f"_Payment via UPI - Instant activation after verification!_",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=markup
            )
        
        elif call.data.startswith('buy_'):
            amount = call.data.split('_')[1]
            package = CREDIT_PACKAGES[amount]
            payment_id = create_payment_record(user_id, int(amount), package['name'])
            
            bot.answer_callback_query(call.id)
            
            # Send QR image from file
            qr_path = os.path.join(BASE_DIR, PAYMENT_QR_IMAGE)
            if os.path.exists(qr_path):
                with open(qr_path, 'rb') as qr_file:
                    bot.send_photo(
                        call.message.chat.id,
                        qr_file,
                        caption=f"💳 *Payment Details*\n\n"
                                f"{package['badge']} Package: *{package['name']}*\n"
                                f"💰 Amount: *₹{amount}*\n"
                                f"💎 Credits: *{package['credits']}*\n\n"
                                f"🔑 Payment ID: `{payment_id}`\n\n"
                                f"*📱 Scan QR or pay to:*\n"
                                f"UPI: `{UPI_ID}`\n\n"
                                f"📸 *After payment:*\n"
                                f"Send screenshot to {YOUR_USERNAME}\n"
                                f"Include Payment ID: `{payment_id}`\n\n"
                                f"_Credits added within 5 minutes after verification!_"
                    )
            else:
                bot.send_message(
                    call.message.chat.id,
                    f"💳 *Payment Details*\n\n"
                    f"{package['badge']} Package: *{package['name']}*\n"
                    f"💰 Amount: *₹{amount}*\n"
                    f"💎 Credits: *{package['credits']}*\n\n"
                    f"🔑 Payment ID: `{payment_id}`\n\n"
                    f"*Pay to UPI:* `{UPI_ID}`\n\n"
                    f"📸 After payment, send screenshot to {YOUR_USERNAME}\n"
                    f"Include Payment ID: `{payment_id}`"
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
                text += f"\n_Use web dashboard to manage all variables_"
            else:
                text += "No variables set yet.\n\n_Use web dashboard to add ENV variables_"
            
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id, text)
        
        elif call.data == 'deploy_file':
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                "📤 *Deploy from File*\n\n"
                "Send me any of these:\n\n"
                "• Python file (.py)\n"
                "• JavaScript file (.js)\n"
                "• ZIP archive (.zip)\n\n"
                "🤖 *AI will auto-install ALL dependencies!*\n\n"
                "_Or send a GitHub repository URL for direct deploy_")
        
        elif call.data == 'back_menu':
            bot.answer_callback_query(call.id)
            bot.edit_message_text(
                "🚀 *Main Menu*\n\nChoose an option:",
                call.message.chat.id,
                call.message.message_id,
                reply_markup=create_main_menu(user_id)
            )
        
        elif call.data == 'admin':
            if user_id not in admin_ids:
                bot.answer_callback_query(call.id, "⚠️ Admin only", show_alert=True)
                return
            
            with DB_LOCK:
                conn = sqlite3.connect(DB_PATH, check_same_thread=False)
                c = conn.cursor()
                c.execute('SELECT COUNT(*) FROM users')
                total_users = c.fetchone()[0]
                c.execute('SELECT COUNT(*) FROM deployments WHERE status="running"')
                running = c.fetchone()[0]
                c.execute('SELECT COUNT(*) FROM payments WHERE status="completed"')
                payments = c.fetchone()[0]
                c.execute('SELECT SUM(amount) FROM payments WHERE status="completed"')
                revenue = c.fetchone()[0] or 0
                conn.close()
            
            bot.answer_callback_query(call.id)
            bot.send_message(call.message.chat.id,
                f"👑 *Admin Dashboard*\n\n"
                f"👥 Total Users: *{total_users}*\n"
                f"🟢 Running Deploys: *{running}*\n"
                f"💳 Completed Payments: *{payments}*\n"
                f"💵 Total Revenue: *₹{revenue:.0f}*\n\n"
                f"*Commands:*\n"
                f"`/stats` - Full statistics\n"
                f"`/addcredits USER_ID AMOUNT`\n"
                f"`/verify PAYMENT_ID TXN_ID`")
        
        else:
            bot.answer_callback_query(call.id, "Use dashboard for full features!")
    
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
        
        msg = bot.reply_to(message, "🤖 *AI Analyzing Your Code...*\n\nPlease wait...")
        deploy_id, result = deploy_from_file(user_id, filepath, filename)
        
        if deploy_id:
            bot.edit_message_text(
                f"✅ *Deployment Successful!*\n\n"
                f"🆔 ID: `{deploy_id}`\n"
                f"📦 AI auto-installed dependencies\n\n"
                f"{result}\n\n"
                f"💎 Remaining Credits: *{get_credits(user_id):.1f}*\n\n"
                f"_View in web dashboard for detailed logs!_",
                message.chat.id,
                msg.message_id
            )
        else:
            bot.edit_message_text(
                f"❌ *Deployment Failed*\n\n{result}",
                message.chat.id,
                msg.message_id
            )
    
    except Exception as e:
        logger.error(f"File handler error: {e}")
        bot.reply_to(message, f"❌ *Error:* {str(e)[:100]}")

@bot.message_handler(func=lambda message: message.text and message.text.startswith('https://github.com'))
def handle_github_link(message):
    """Deploy directly from GitHub URL"""
    user_id = message.from_user.id
    repo_url = message.text.strip()
    
    try:
        msg = bot.reply_to(message, "🤖 *GitHub Deploy Starting...*\n\nCloning repository...")
        deploy_id, result = deploy_from_github(user_id, repo_url)
        
        if deploy_id:
            bot.edit_message_text(
                f"✅ *GitHub Deployed Successfully!*\n\n"
                f"🆔 ID: `{deploy_id}`\n"
                f"📦 Repo: `{repo_url.split('/')[-1]}`\n"
                f"🤖 AI auto-installed dependencies\n\n"
                f"{result}\n\n"
                f"💎 Remaining Credits: *{get_credits(user_id):.1f}*",
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
        bot.reply_to(message, f"❌ *Error:* {str(e)[:100]}")

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
                    f"Admin added *{amount}* credits!\n\n"
                    f"💎 New Balance: *{get_credits(target_user):.1f}*")
            except:
                pass
        else:
            bot.reply_to(message, "❌ Failed to add credits")
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
        
        c.execute('SELECT COUNT(DISTINCT user_id) FROM deployments')
        active_deployers = c.fetchone()[0]
        
        conn.close()
    
    stats_text = f"📊 *System Statistics*\n\n"
    stats_text += f"*Users & Activity:*\n"
    stats_text += f"👥 Total Users: *{total_users}*\n"
    stats_text += f"🚀 Active Deployers: *{active_deployers}*\n\n"
    stats_text += f"*Deployments:*\n"
    stats_text += f"📦 Total: *{total_deploys}*\n"
    stats_text += f"🟢 Running: *{running_deploys}*\n"
    stats_text += f"⚡ Active Processes: *{len(active_processes)}*\n\n"
    stats_text += f"*Credits & Revenue:*\n"
    stats_text += f"💰 Credits Spent: *{total_spent:.1f}*\n"
    stats_text += f"💳 Payments: *{completed_payments}*\n"
    stats_text += f"💵 Revenue: *₹{total_revenue:.0f}*"
    
    bot.reply_to(message, stats_text)

@bot.message_handler(commands=['verify'])
def verify_payment_cmd(message):
    """Admin: Verify payment"""
    if message.from_user.id not in admin_ids:
        bot.reply_to(message, "⚠️ Admin only")
        return
    
    try:
        parts = message.text.split()
        if len(parts) != 3:
            bot.reply_to(message, "*Usage:* `/verify PAYMENT_ID TRANSACTION_ID`")
            return
        
        payment_id = parts[1].upper()
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
                    f"Thank you for your purchase! 🙏")
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
        bot.reply_to(message, "📊 *No Deployments*\n\nDeploy your first app by sending a file or GitHub URL!")
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
        f"_Your credits are private and isolated from other users!_")

@bot.message_handler(commands=['help'])
def help_cmd(message):
    """Show help"""
    bot.reply_to(message,
        f"📚 * @narzoxbot - Help*\n\n"
        f"*🚀 Deploy Methods:*\n"
        f"• Send .py, .js or .zip file\n"
        f"• Send GitHub repository URL\n"
        f"• Use /start menu buttons\n"
        f"• Use web dashboard\n\n"
        f"*💎 Credit Commands:*\n"
        f"/balance - Check credits\n"
        f"/myapps - View deployments\n\n"
        f"*🌐 Web Dashboard:*\n"
        f"Access full features at:\n"
        f"`http://localhost:{os.environ.get('PORT', 8080)}`\n\n"
        f"*💰 Buy Credits:*\n"
        f"Use /start → Buy Credits\n\n"
        f"Need help? Contact {YOUR_USERNAME}")

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
    print("\n" + "=" * 100)
    print(f"{Fore.CYAN}{'🚀 ULTRA ADVANCED DEVOPS BOT v10.0 - SUPREME EDITION':^100}")
    print("=" * 100)
    print(f"{Fore.GREEN}🐍 Python: {sys.version.split()[0]}")
    print(f"{Fore.GREEN}📁 Data Directory: {DATA_DIR}")
    print(f"{Fore.GREEN}👑 Owner ID: {OWNER_ID}")
    print(f"{Fore.GREEN}🔑 Admin ID: {ADMIN_ID}")
    print(f"{Fore.YELLOW}🎁 Free Credits Per User: {FREE_CREDITS}")
    print(f"{Fore.MAGENTA}💳 Payment UPI: {UPI_ID}")
    print(f"{Fore.MAGENTA}🖼️  QR Image: {PAYMENT_QR_IMAGE}")
    print("=" * 100)
    print(f"{Fore.MAGENTA}✨ SUPREME FEATURES v10.0:")
    print(f"{Fore.CYAN}  🎨 Premium Glass Morphism UI")
    print("     └ Stunning visual design")
    print("     └ Smooth animations")
    print("     └ Modern gradient effects")
    print("     └ Professional look & feel")
    print("")
    print(f"{Fore.CYAN}  💎 Per-User Credit System")
    print("     └ Each user gets 2 free credits")
    print("     └ Credits isolated per user")
    print("     └ Private balances")
    print("")
    print(f"{Fore.CYAN}  💰 Advanced Payment System")
    print("     └ ₹99 → 10 credits (Starter 🥉)")
    print("     └ ₹399 → 50 credits (Pro ⭐)")
    print("     └ ₹699 → 100 credits (Ultimate 🔥)")
    print("     └ UPI QR code from qr.jpg")
    print("     └ Manual verification system")
    print("")
    print(f"{Fore.CYAN}  🤖 AI Auto-Install")
    print("     └ Analyzes code imports")
    print("     └ Auto-installs packages")
    print("     └ Python, Node.js support")
    print("")
    print(f"{Fore.CYAN}  🔗 Full Bot-Web Integration")
    print("     └ Deploy from Telegram")
    print("     └ Deploy from Web")
    print("     └ Send files in chat")
    print("     └ Send GitHub URLs")
    print("     └ Real-time sync")
    print("")
    print(f"{Fore.CYAN}  🌐 GitHub Advanced Deploy")
    print("     └ Repository URL")
    print("     └ Branch selection")
    print("     └ Build command support")
    print("     └ Start command support")
    print("")
    print(f"{Fore.CYAN}  🔐 Environment Variables")
    print("     └ Per-user ENV vars")
    print("     └ Encrypted storage")
    print("     └ Manage from bot or web")
    print("=" * 100)
    
    keep_alive()
    
    port = os.environ.get('PORT', 8080)
    print(f"\n{Fore.GREEN}🌐 Premium Web Dashboard: http://localhost:{port}")
    print(f"{Fore.CYAN}📱 Telegram Bot: {TELEGRAM_LINK}")
    print(f"{Fore.MAGENTA}💳 Payment UPI ID: {UPI_ID}")
    print(f"{Fore.YELLOW}🖼️  QR Code Image: {PAYMENT_QR_IMAGE}")
    print(f"{Fore.YELLOW}🤖 Starting bot with supreme features...\n")
    print("=" * 100)
    print(f"{Fore.GREEN}{'🎉 SYSTEM READY - SUPREME EDITION ACTIVE':^100}")
    print("=" * 100 + "\n")
    
    print(f"{Fore.CYAN}📋 QUICK REFERENCE:")
    print(f"{Fore.YELLOW}  👤 User Commands:")
    print("    /start - Main menu")
    print("    /myapps - View deployments")
    print("    /balance - Check credits")
    print("    /help - Show help")
    print(f"{Fore.YELLOW}  👑 Admin Commands:")
    print("    /stats - System statistics")
    print("    /addcredits USER_ID AMOUNT - Add credits")
    print("    /verify PAYMENT_ID TXN_ID - Verify payment")
    print(f"{Fore.YELLOW}  🚀 Deploy Methods:")
    print("    1. Send .py/.js/.zip file in Telegram")
    print("    2. Send GitHub URL in Telegram")
    print("    3. Upload file in web dashboard")
    print("    4. Deploy from GitHub in web dashboard")
    print(f"{Fore.YELLOW}  💰 Payment Setup:")
    print(f"    1. Place your QR image as: {PAYMENT_QR_IMAGE}")
    print(f"    2. Users scan QR and pay to: {UPI_ID}")
    print("    3. User sends screenshot to admin")
    print("    4. Admin uses /verify to confirm")
    print("=" * 100 + "\n")
    
    # Check if QR image exists
    if not os.path.exists(os.path.join(BASE_DIR, PAYMENT_QR_IMAGE)):
        print(f"{Fore.RED}⚠️  WARNING: QR image '{PAYMENT_QR_IMAGE}' not found!")
        print(f"{Fore.YELLOW}   Please add your QR code image as '{PAYMENT_QR_IMAGE}' in the project directory")
        print(f"{Fore.YELLOW}   Payment feature will not work without it!\n")
    else:
        print(f"{Fore.GREEN}✅ QR image found: {PAYMENT_QR_IMAGE}\n")
    
    while True:
        try:
            logger.info(f"{Fore.GREEN}🤖 Bot polling - Supreme Edition Ready!")
            bot.infinity_polling(timeout=60, long_polling_timeout=30)
        except Exception as e:
            logger.error(f"{Fore.RED}Polling error: {e}")
            time.sleep(5), logs=None, pid=None, deps=None, install_log=None):
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

# ==================== 🎨 PREMIUM STYLISH WEB DASHBOARD ====================

PREMIUM_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevOps Pro v10.0 - Premium</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
        
        :root {
            --primary: #667eea;
            --primary-dark: #5568d3;
            --secondary: #764ba2;
            --accent: #f093fb;
            --success: #00d4aa;
            --danger: #ff6b6b;
            --warning: #feca57;
            --info: #48dbfb;
            --dark: #1e1e2e;
            --light: #f8f9fa;
            --glass: rgba(255, 255, 255, 0.1);
        }
        
        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 50%, #f093fb 100%);
            background-attachment: fixed;
            min-height: 100vh;
            color: #fff;
            padding-bottom: 80px;
            overflow-x: hidden;
        }
        
        /* Animated Background */
        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 50%, rgba(102, 126, 234, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(240, 147, 251, 0.3) 0%, transparent 50%),
                radial-gradient(circle at 40% 20%, rgba(118, 75, 162, 0.3) 0%, transparent 50%);
            animation: backgroundShift 15s ease infinite;
            z-index: -1;
        }
        
        @keyframes backgroundShift {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-20px); }
        }
        
        /* Glass Morphism Header */
        .header {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px) saturate(180%);
            -webkit-backdrop-filter: blur(20px) saturate(180%);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            padding: 16px 20px;
            position: sticky;
            top: 0;
            z-index: 1000;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
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
            width: 45px;
            height: 45px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 22px;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
            animation: logoPulse 2s ease-in-out infinite;
        }
        
        @keyframes logoPulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }
        
        .logo-text h1 {
            font-size: 20px;
            font-weight: 800;
            background: linear-gradient(135deg, #fff, #f093fb);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            letter-spacing: -0.5px;
        }
        
        .logo-text p {
            font-size: 10px;
            font-weight: 600;
            color: rgba(255, 255, 255, 0.7);
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .credit-badge {
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.2), rgba(255, 255, 255, 0.1));
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.3);
            padding: 8px 16px;
            border-radius: 25px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 700;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }
        
        .credit-badge i {
            font-size: 16px;
            color: #feca57;
            animation: shimmer 2s ease-in-out infinite;
        }
        
        @keyframes shimmer {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.2); opacity: 0.8; }
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        /* Premium Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 20px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.1), transparent);
            opacity: 0;
            transition: opacity 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            border-color: rgba(255, 255, 255, 0.4);
        }
        
        .stat-card:hover::before {
            opacity: 1;
        }
        
        .stat-icon {
            font-size: 32px;
            margin-bottom: 10px;
            filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.2));
        }
        
        .stat-value {
            font-size: 28px;
            font-weight: 900;
            line-height: 1;
            margin-bottom: 6px;
        }
        
        .stat-label {
            color: rgba(255, 255, 255, 0.8);
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        /* Premium Tab Navigation */
        .tab-nav {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 20px;
            padding: 6px;
            margin-bottom: 20px;
            display: flex;
            gap: 6px;
            overflow-x: auto;
            scrollbar-width: none;
        }
        
        .tab-nav::-webkit-scrollbar { display: none; }
        
        .tab-btn {
            flex: 1;
            min-width: 90px;
            padding: 12px 16px;
            border: none;
            background: transparent;
            border-radius: 14px;
            font-size: 13px;
            font-weight: 700;
            color: rgba(255, 255, 255, 0.7);
            cursor: pointer;
            transition: all 0.3s;
            white-space: nowrap;
        }
        
        .tab-btn i {
            margin-right: 6px;
        }
        
        .tab-btn.active {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: #fff;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
            transform: scale(1.02);
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        /* Premium Card Design */
        .card {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 24px;
            padding: 24px;
            margin-bottom: 16px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            transition: all 0.3s;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.15);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .card-title {
            font-size: 18px;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .card-title i {
            font-size: 20px;
            background: linear-gradient(135deg, #667eea, #f093fb);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        /* Premium Upload Zone */
        .upload-zone {
            border: 2px dashed rgba(255, 255, 255, 0.4);
            border-radius: 20px;
            padding: 40px 20px;
            text-align: center;
            background: rgba(255, 255, 255, 0.05);
            cursor: pointer;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .upload-zone::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.1);
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }
        
        .upload-zone:hover {
            border-color: rgba(255, 255, 255, 0.6);
            background: rgba(255, 255, 255, 0.1);
            transform: scale(1.02);
        }
        
        .upload-zone:hover::before {
            width: 300px;
            height: 300px;
        }
        
        .upload-icon {
            font-size: 48px;
            margin-bottom: 16px;
            background: linear-gradient(135deg, #667eea, #f093fb);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: float 3s ease-in-out infinite;
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
        }
        
        .upload-title {
            font-size: 18px;
            font-weight: 800;
            margin-bottom: 6px;
        }
        
        .upload-desc {
            color: rgba(255, 255, 255, 0.8);
            font-size: 13px;
            font-weight: 600;
        }
        
        /* Premium Buttons */
        .btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 14px 24px;
            border-radius: 14px;
            font-size: 14px;
            font-weight: 700;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            cursor: pointer;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }
        
        .btn::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.2);
            transform: translate(-50%, -50%);
            transition: width 0.6s, height 0.6s;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
        }
        
        .btn:hover::before {
            width: 300px;
            height: 300px;
        }
        
        .btn:active {
            transform: translateY(0);
        }
        
        /* Input Fields */
        .input-group {
            margin-bottom: 16px;
        }
        
        .input-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 700;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: rgba(255, 255, 255, 0.9);
        }
        
        .input-field {
            width: 100%;
            padding: 14px 16px;
            border: 1px solid rgba(255, 255, 255, 0.3);
            border-radius: 12px;
            font-size: 14px;
            font-family: inherit;
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
            transition: all 0.3s;
        }
        
        .input-field::placeholder {
            color: rgba(255, 255, 255, 0.5);
        }
        
        .input-field:focus {
            outline: none;
            border-color: #667eea;
            background: rgba(255, 255, 255, 0.15);
            box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.2);
        }
        
        /* Deployment Items */
        .deploy-item {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 16px;
            padding: 18px;
            margin-bottom: 12px;
            transition: all 0.3s;
        }
        
        .deploy-item:hover {
            transform: translateX(4px);
            border-color: rgba(255, 255, 255, 0.4);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
        }
        
        .deploy-name {
            font-size: 15px;
            font-weight: 800;
            margin-bottom: 6px;
        }
        
        .deploy-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            font-size: 11px;
            font-weight: 600;
            color: rgba(255, 255, 255, 0.7);
            margin-bottom: 12px;
        }
        
        .status-badge {
            padding: 6px 12px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .status-running { background: linear-gradient(135deg, #00d4aa, #00a87e); color: #fff; }
        .status-pending { background: linear-gradient(135deg, #feca57, #ff9ff3); color: #fff; }
        .status-stopped { background: linear-gradient(135deg, #ff6b6b, #ee5a6f); color: #fff; }
        .status-failed { background: linear-gradient(135deg, #fc5c65, #fd79a8); color: #fff; }
        
        .action-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(90px, 1fr));
            gap: 8px;
        }
        
        .action-btn {
            padding: 10px;
            border: none;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 700;
            color: white;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
        }
        
        .action-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        
        /* Premium Pricing Cards */
        .pricing-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .price-card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 2px solid rgba(255, 255, 255, 0.2);
            border-radius: 24px;
            padding: 32px 24px;
            text-align: center;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }
        
        .price-card::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(45deg, transparent, rgba(255, 255, 255, 0.1), transparent);
            transform: rotate(45deg);
            transition: all 0.6s;
        }
        
        .price-card:hover {
            transform: translateY(-10px) scale(1.02);
            border-color: rgba(255, 255, 255, 0.5);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }
        
        .price-card:hover::before {
            left: 100%;
        }
        
        .price-card.popular {
            border-color: #feca57;
            box-shadow: 0 8px 32px rgba(254, 202, 87, 0.3);
        }
        
        .popular-badge {
            position: absolute;
            top: 20px;
            right: 20px;
            background: linear-gradient(135deg, #feca57, #ff9ff3);
            color: #fff;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 800;
            box-shadow: 0 4px 12px rgba(254, 202, 87, 0.4);
        }
        
        .price-badge {
            font-size: 40px;
            margin-bottom: 12px;
        }
        
        .price-name {
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 12px;
            color: rgba(255, 255, 255, 0.9);
        }
        
        .price-amount {
            font-size: 48px;
            font-weight: 900;
            margin-bottom: 8px;
            line-height: 1;
        }
        
        .price-credits {
            font-size: 20px;
            font-weight: 700;
            color: rgba(255, 255, 255, 0.8);
            margin-bottom: 24px;
        }
        
        /* Bottom Navigation */
        .bottom-nav {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(20px);
            border-top: 1px solid rgba(255, 255, 255, 0.2);
            display: flex;
            justify-content: space-around;
            padding: 10px 0;
            box-shadow: 0 -4px 30px rgba(0, 0, 0, 0.1);
            z-index: 999;
        }
        
        .nav-item {
            flex: 1;
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 4px;
            color: rgba(255, 255, 255, 0.6);
            font-size: 11px;
            font-weight: 700;
            cursor: pointer;
            padding: 8px;
            transition: all 0.3s;
        }
        
        .nav-item i {
            font-size: 20px;
            transition: all 0.3s;
        }
        
        .nav-item.active {
            color: #fff;
        }
        
        .nav-item.active i {
            transform: scale(1.2);
        }
        
        /* Toast Notification */
        .toast {
            position: fixed;
            top: 90px;
            left: 50%;
            transform: translateX(-50%) translateY(-150px);
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            color: #1e1e2e;
            padding: 16px 24px;
            border-radius: 14px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
            display: flex;
            align-items: center;
            gap: 12px;
            z-index: 9999;
            max-width: 90%;
            transition: all 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
        }
        
        .toast.show {
            transform: translateX(-50%) translateY(0);
        }
        
        .toast-icon {
            font-size: 20px;
        }
        
        .toast-message {
            font-size: 14px;
            font-weight: 600;
        }
        
        /* Modal */
        .modal {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            backdrop-filter: blur(8px);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 10000;
            padding: 20px;
            animation: fadeIn 0.3s;
        }
        
        .modal.show {
            display: flex;
        }
        
        .modal-content {
            background: rgba(30, 30, 46, 0.95);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 24px;
            padding: 28px;
            max-width: 600px;
            width: 100%;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            animation: slideUp
