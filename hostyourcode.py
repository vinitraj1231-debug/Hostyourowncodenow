# -*- coding: utf-8 -*-
"""
🚀 ULTRA ADVANCED DEVOPS BOT v10.0 - ENTERPRISE EDITION
Revolutionary AI-Powered Deployment Platform with Advanced Authentication
Device Lock | Email Auth | User Ban System | Admin Controls
"""

import sys
import subprocess
import os

# ==================== SMART DEPENDENCY INSTALLER ====================
print("=" * 90)
print("🔧 ENTERPRISE DEPENDENCY INSTALLER v10.0")
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
import bcrypt

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

# Default credits for new users
FREE_CREDITS = 2.0

# Credit costs
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
USERS_JSON = os.path.join(DATA_DIR, 'users.json')

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

# ==================== USER DATA MANAGEMENT ====================

def load_users_json():
    """Load users from JSON file"""
    if os.path.exists(USERS_JSON):
        try:
            with open(USERS_JSON, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_users_json(users_data):
    """Save users to JSON file"""
    try:
        with open(USERS_JSON, 'w') as f:
            json.dump(users_data, f, indent=2)
        return True
    except Exception as e:
        logger.error(f"Failed to save users.json: {e}")
        return False

# ==================== DEVICE FINGERPRINTING ====================

def get_device_fingerprint(request):
    """Generate unique device fingerprint"""
    user_agent = request.headers.get('User-Agent', '')
    accept_language = request.headers.get('Accept-Language', '')
    accept_encoding = request.headers.get('Accept-Encoding', '')
    
    # Create fingerprint from multiple factors
    fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}"
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    return fingerprint

def is_device_locked(email, device_fingerprint):
    """Check if user is trying to access from a different device"""
    users_data = load_users_json()
    
    if email in users_data:
        user = users_data[email]
        if 'device_fingerprint' in user and user['device_fingerprint']:
            if user['device_fingerprint'] != device_fingerprint:
                return True, user['device_fingerprint']
    
    return False, None

def lock_device(email, device_fingerprint):
    """Lock user to current device"""
    users_data = load_users_json()
    
    if email in users_data:
        users_data[email]['device_fingerprint'] = device_fingerprint
        users_data[email]['device_locked_at'] = datetime.now().isoformat()
        save_users_json(users_data)
        return True
    
    return False

# ==================== DATABASE INITIALIZATION ====================

def init_db():
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        # Users table with email authentication
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            email TEXT UNIQUE,
            password_hash TEXT,
            username TEXT,
            first_name TEXT,
            joined_date TEXT,
            last_active TEXT,
            total_deployments INTEGER DEFAULT 0,
            successful_deployments INTEGER DEFAULT 0,
            total_api_calls INTEGER DEFAULT 0,
            pro_member INTEGER DEFAULT 0,
            is_banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            device_fingerprint TEXT,
            ip_address TEXT,
            telegram_id INTEGER
        )''')
        
        # Credits table
        c.execute('''CREATE TABLE IF NOT EXISTS credits (
            user_id INTEGER PRIMARY KEY,
            balance REAL DEFAULT 0,
            total_spent REAL DEFAULT 0,
            total_earned REAL DEFAULT 0,
            last_purchase TEXT
        )''')
        
        # Deployments table
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
        
        # Environment variables table
        c.execute('''CREATE TABLE IF NOT EXISTS env_vars (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            deployment_id TEXT,
            key TEXT,
            value_encrypted TEXT,
            created_at TEXT
        )''')
        
        # Activity log table
        c.execute('''CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            email TEXT,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            device_fingerprint TEXT,
            timestamp TEXT
        )''')
        
        # Domains table
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
        
        # Backups table
        c.execute('''CREATE TABLE IF NOT EXISTS backups (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            deployment_id TEXT,
            backup_path TEXT,
            size_mb REAL,
            created_at TEXT
        )''')
        
        # Payment requests table
        c.execute('''CREATE TABLE IF NOT EXISTS payment_requests (
            id TEXT PRIMARY KEY,
            user_id INTEGER,
            email TEXT,
            amount REAL,
            screenshot_path TEXT,
            status TEXT,
            created_at TEXT,
            processed_at TEXT,
            processed_by INTEGER
        )''')
        
        # Login attempts tracking
        c.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            ip_address TEXT,
            device_fingerprint TEXT,
            success INTEGER,
            timestamp TEXT
        )''')
        
        conn.commit()
        conn.close()

def load_data():
    """Load existing data from database"""
    with DB_LOCK:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        c = conn.cursor()
        
        # Load users
        c.execute('SELECT user_id, email FROM users WHERE is_banned = 0')
        for user_id, email in c.fetchall():
            active_users.add(user_id)
        
        # Load credits
        c.execute('SELECT user_id, balance FROM credits')
        for user_id, balance in c.fetchall():
            user_credits[user_id] = balance
        
        # Load deployments
        c.execute('''SELECT id, user_id, name, type, status, port, pid, repo_url, branch, 
                    cpu_usage, memory_usage, custom_domain 
                    FROM deployments WHERE status != "deleted"''')
        for row in c.fetchall():
            dep_id, user_id, name, dep_type, status, port, pid, repo_url, branch, cpu, mem, domain = row
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
        
        # Load environment variables
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

# ==================== AUTHENTICATION FUNCTIONS ====================

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    """Verify password against hash"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except:
        return False

def create_user(email, password, first_name, device_fingerprint, ip_address):
    """Create new user account"""
    try:
        # Check if email already exists
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            
            c.execute('SELECT user_id FROM users WHERE email = ?', (email,))
            if c.fetchone():
                conn.close()
                return None, "Email already registered"
            
            # Generate user ID
            user_id = int(time.time() * 1000) % 1000000000
            
            # Hash password
            password_hash = hash_password(password)
            
            # Insert user
            c.execute('''INSERT INTO users 
                        (user_id, email, password_hash, first_name, joined_date, last_active, 
                         device_fingerprint, ip_address, is_banned)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)''',
                     (user_id, email, password_hash, first_name, 
                      datetime.now().isoformat(), datetime.now().isoformat(),
                      device_fingerprint, ip_address))
            
            # Give initial credits
            c.execute('''INSERT INTO credits (user_id, balance, total_earned) 
                        VALUES (?, ?, ?)''', (user_id, FREE_CREDITS, FREE_CREDITS))
            
            # Log activity
            c.execute('''INSERT INTO activity_log 
                        (user_id, email, action, details, ip_address, device_fingerprint, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (user_id, email, 'REGISTER', f'New account created', 
                      ip_address, device_fingerprint, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            # Update JSON
            users_data = load_users_json()
            users_data[email] = {
                'user_id': user_id,
                'email': email,
                'first_name': first_name,
                'joined_date': datetime.now().isoformat(),
                'device_fingerprint': device_fingerprint,
                'credits': FREE_CREDITS,
                'is_banned': False
            }
            save_users_json(users_data)
            
            # Update global state
            active_users.add(user_id)
            user_credits[user_id] = FREE_CREDITS
            
            return user_id, "Account created successfully"
    
    except Exception as e:
        logger.error(f"Create user error: {e}")
        return None, str(e)

def authenticate_user(email, password, device_fingerprint, ip_address):
    """Authenticate user login"""
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            
            # Get user
            c.execute('''SELECT user_id, password_hash, is_banned, ban_reason, device_fingerprint 
                        FROM users WHERE email = ?''', (email,))
            result = c.fetchone()
            
            if not result:
                # Log failed attempt
                c.execute('''INSERT INTO login_attempts 
                            (email, ip_address, device_fingerprint, success, timestamp)
                            VALUES (?, ?, ?, 0, ?)''',
                         (email, ip_address, device_fingerprint, datetime.now().isoformat()))
                conn.commit()
                conn.close()
                return None, "Invalid email or password"
            
            user_id, password_hash, is_banned, ban_reason, stored_fingerprint = result
            
            # Check if banned
            if is_banned:
                conn.close()
                return None, f"Account banned: {ban_reason or 'Contact admin'}"
            
            # Verify password
            if not verify_password(password, password_hash):
                # Log failed attempt
                c.execute('''INSERT INTO login_attempts 
                            (email, ip_address, device_fingerprint, success, timestamp)
                            VALUES (?, ?, ?, 0, ?)''',
                         (email, ip_address, device_fingerprint, datetime.now().isoformat()))
                conn.commit()
                conn.close()
                return None, "Invalid email or password"
            
            # Check device lock
            if stored_fingerprint and stored_fingerprint != device_fingerprint:
                conn.close()
                return None, "Account locked to another device. Contact admin to unlock."
            
            # Update device fingerprint if first login
            if not stored_fingerprint:
                c.execute('UPDATE users SET device_fingerprint = ? WHERE user_id = ?',
                         (device_fingerprint, user_id))
            
            # Update last active
            c.execute('UPDATE users SET last_active = ?, ip_address = ? WHERE user_id = ?',
                     (datetime.now().isoformat(), ip_address, user_id))
            
            # Log successful login
            c.execute('''INSERT INTO login_attempts 
                        (email, ip_address, device_fingerprint, success, timestamp)
                        VALUES (?, ?, ?, 1, ?)''',
                     (email, ip_address, device_fingerprint, datetime.now().isoformat()))
            
            c.execute('''INSERT INTO activity_log 
                        (user_id, email, action, details, ip_address, device_fingerprint, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (user_id, email, 'LOGIN', 'User logged in', 
                      ip_address, device_fingerprint, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            return user_id, "Login successful"
    
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return None, str(e)

def is_user_banned(user_id):
    """Check if user is banned"""
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            c.execute('SELECT is_banned, ban_reason FROM users WHERE user_id = ?', (user_id,))
            result = c.fetchone()
            conn.close()
            
            if result and result[0]:
                return True, result[1]
            return False, None
    except:
        return False, None

def ban_user(user_id, reason, banned_by):
    """Ban a user"""
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            
            c.execute('UPDATE users SET is_banned = 1, ban_reason = ? WHERE user_id = ?',
                     (reason, user_id))
            
            c.execute('''INSERT INTO activity_log 
                        (user_id, action, details, timestamp)
                        VALUES (?, ?, ?, ?)''',
                     (banned_by, 'BAN_USER', f'Banned user {user_id}: {reason}', 
                      datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            # Update JSON
            users_data = load_users_json()
            for email, data in users_data.items():
                if data.get('user_id') == user_id:
                    data['is_banned'] = True
                    data['ban_reason'] = reason
                    break
            save_users_json(users_data)
            
            # Remove from active users
            if user_id in active_users:
                active_users.remove(user_id)
            
            # Notify via bot
            try:
                bot.send_message(user_id, 
                    f"🚫 *Account Banned*\n\n"
                    f"Reason: {reason}\n\n"
                    f"Contact {YOUR_USERNAME} to appeal.")
            except:
                pass
            
            return True, "User banned successfully"
    except Exception as e:
        logger.error(f"Ban user error: {e}")
        return False, str(e)

def unban_user(user_id, unbanned_by):
    """Unban a user"""
    try:
        with DB_LOCK:
            conn = sqlite3.connect(DB_PATH, check_same_thread=False)
            c = conn.cursor()
            
            c.execute('UPDATE users SET is_banned = 0, ban_reason = NULL WHERE user_id = ?',
                     (user_id,))
            
            c.execute('''INSERT INTO activity_log 
                        (user_id, action, details, timestamp)
                        VALUES (?, ?, ?, ?)''',
                     (unbanned_by, 'UNBAN_USER', f'Unbanned user {user_id}', 
                      datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            # Update JSON
            users_data = load_users_json()
            for email, data in users_data.items():
                if data.get('user_id') == user_id:
                    data['is_banned'] = False
                    data['ban_reason'] = None
                    break
            save_users_json(users_data)
            
            # Add back to active users
            active_users.add(user_id)
            
            # Notify via bot
            try:
                bot.send_message(user_id, 
                    f"✅ *Account Unbanned*\n\n"
                    f"Your account has been restored.\n"
                    f"You can now access all features!")
            except:
                pass
            
            return True, "User unbanned successfully"
    except Exception as e:
        logger.error(f"Unban user error: {e}")
        return False, str(e)

# ==================== CREDIT SYSTEM ====================

def get_credits(user_id):
    """Get user credits - admins have unlimited"""
    if user_id in admin_ids:
        return float('inf')
    return user_credits.get(user_id, 0.0)

def add_credits(user_id, amount, description="Credit added"):
    """Add credits to user"""
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
        
        c.execute('''INSERT INTO activity_log (user_id, action, details, timestamp) 
                    VALUES (?, ?, ?, ?)''',
                 (user_id, 'CREDIT_ADD', f"{amount} - {description}", datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        user_credits[user_id] = new_balance
        
        # Update JSON
        users_data = load_users_json()
        for email, data in users_data.items():
            if data.get('user_id') == user_id:
                data['credits'] = new_balance
                break
        save_users_json(users_data)
        
        return True

def deduct_credits(user_id, amount, description="Credit used"):
    """Deduct credits from user"""
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
        
        c.execute('''INSERT INTO activity_log (user_id, action, details, timestamp) 
                    VALUES (?, ?, ?, ?)''',
                 (user_id, 'CREDIT_USE', f"{amount} - {description}", datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        user_credits[user_id] = new_balance
        
        # Update JSON
        users_data = load_users_json()
        for email, data in users_data.items():
            if data.get('user_id') == user_id:
                data['credits'] = new_balance
                break
        save_users_json(users_data)
        
        return True

# ==================== AI DEPENDENCY DETECTOR (Keep existing) ====================

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
    
    logger.info(f"{Fore.CYAN}🤖 AI DEPENDENCY ANALYZER v10.0 - STARTING...")
    install_log.append("🤖 AI DEPENDENCY ANALYZER v10.0 - ENTERPRISE")
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

# ==================== DEPLOYMENT FUNCTIONS (Keep existing but add user check) ====================

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port

def create_deployment(user_id, name, deploy_type, **kwargs):
    # Check if user is banned
    is_banned, ban_reason = is_user_banned(user_id)
    if is_banned:
        return None, f"Account banned: {ban_reason}"
    
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
        
        c.execute('''INSERT INTO activity_log (user_id, action, details, timestamp) 
                    VALUES (?, ?, ?, ?)''',
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
    # Check if user is banned
    is_banned, ban_reason = is_user_banned(user_id)
    if is_banned:
        return None, f"Account banned: {ban_reason}"
    
    try:
        cost = CREDIT_COSTS['file_upload']
        if not deduct_credits(user_id, cost, f"File deploy: {filename}"):
            return None, f"❌ Need {cost} credits"
        
        deploy_id, port = create_deployment(user_id, filename, 'file_upload')
        if not deploy_id:
            add_credits(user_id, cost, "Refund: Failed")
            return None, port
        
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
    # Check if user is banned
    is_banned, ban_reason = is_user_banned(user_id)
    if is_banned:
        return None, f"Account banned: {ban_reason}"
    
    try:
        cost = CREDIT_COSTS['github_deploy']
        if not deduct_credits(user_id, cost, f"GitHub: {repo_url}"):
            return None, f"❌ Need {cost} credits"
        
        repo_name = repo_url.split('/')[-1].replace('.git', '')
        deploy_id, port = create_deployment(user_id, repo_name, 'github',
                                           repo_url=repo_url, branch=branch,
                                           build_cmd=build_cmd, start_cmd=start_cmd)
        
        if not deploy_id:
            add_credits(user_id, cost, "Refund: Failed")
            return None, port
        
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

# ==================== MOBILE APP HTML WITH LOGIN ====================

MOBILE_APP_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#1e293b">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <title>EliteHost v10.0 - Enterprise</title>
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
        }
        
        /* Auth Screen */
        .auth-screen {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, var(--dark) 0%, var(--dark-lighter) 100%);
            z-index: 10000;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .auth-screen.hide {
            display: none;
        }
        
        .auth-box {
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
        
        .auth-logo {
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
        
        .auth-title {
            text-align: center;
            font-size: 28px;
            font-weight: 900;
            margin-bottom: 8px;
            background: linear-gradient(135deg, #fff, var(--primary-light));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .auth-subtitle {
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
        
        .btn-auth {
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
        
        .btn-auth:active {
            transform: scale(0.98);
        }
        
        .auth-switch {
            text-align: center;
            margin-top: 20px;
            color: var(--gray);
            font-size: 14px;
        }
        
        .auth-switch button {
            background: none;
            border: none;
            color: var(--primary-light);
            font-weight: 700;
            cursor: pointer;
            text-decoration: underline;
        }
        
        /* App Container */
        .app-container {
            display: none;
            padding-bottom: 80px;
        }
        
        .app-container.show {
            display: block;
        }
        
        /* Top Bar with Navigation */
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
        
        .top-nav {
            display: flex;
            gap: 8px;
        }
        
        .nav-btn {
            padding: 8px 16px;
            background: rgba(59, 130, 246, 0.15);
            border: 1px solid rgba(59, 130, 246, 0.3);
            border-radius: 10px;
            color: var(--primary-light);
            font-size: 12px;
            font-weight: 700;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 6px;
            transition: all 0.2s;
        }
        
        .nav-btn:active {
            transform: scale(0.95);
        }
        
        .nav-btn.admin {
            background: rgba(139, 92, 246, 0.15);
            border-color: rgba(139, 92, 246, 0.3);
            color: var(--secondary);
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
        
        /* Bottom Navigation */
        .bottom-nav {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: rgba(30, 41, 59, 0.98);
            backdrop-filter: blur(20px);
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            display: grid;
            grid-template-columns: repeat(4, 1fr);
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
        
        /* Admin Panel */
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
        
        /* Toast */
        .toast {
            position: fixed;
            bottom: 100px;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: rgba(30, 41, 59, 0.95);
            backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 12px;
            padding: 14px 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            z-index: 10001;
            transition: transform 0.3s ease;
            max-width: 90%;
        }
        
        .toast.show {
            transform: translateX(-50%) translateY(0);
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
    </style>
</head>
<body>
    <!-- Auth Screen -->
    <div class="auth-screen" id="authScreen">
        <div class="auth-box">
            <div class="auth-logo">
                <i class="fas fa-rocket"></i>
            </div>
            <h1 class="auth-title">EliteHost v10.0</h1>
            <p class="auth-subtitle">Enterprise DevOps Platform</p>
            
            <!-- Login Form -->
            <form id="loginForm" style="display: block;" onsubmit="handleLogin(event)">
                <div class="form-group">
                    <label class="form-label">Email Address</label>
                    <input type="email" class="form-input" id="loginEmail" placeholder="your@email.com" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" class="form-input" id="loginPassword" placeholder="Enter password" required>
                </div>
                
                <button type="submit" class="btn-auth">
                    <i class="fas fa-sign-in-alt"></i> Login
                </button>
                
                <div class="auth-switch">
                    Don't have an account? <button type="button" onclick="showRegister()">Register</button>
                </div>
            </form>
            
            <!-- Register Form -->
            <form id="registerForm" style="display: none;" onsubmit="handleRegister(event)">
                <div class="form-group">
                    <label class="form-label">Full Name</label>
                    <input type="text" class="form-input" id="registerName" placeholder="John Doe" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Email Address</label>
                    <input type="email" class="form-input" id="registerEmail" placeholder="your@email.com" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Password</label>
                    <input type="password" class="form-input" id="registerPassword" placeholder="Min 8 characters" required minlength="8">
                </div>
                
                <button type="submit" class="btn-auth">
                    <i class="fas fa-user-plus"></i> Create Account
                </button>
                
                <div class="auth-switch">
                    Already have an account? <button type="button" onclick="showLogin()">Login</button>
                </div>
            </form>
        </div>
    </div>

    <!-- App Container -->
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
                <div style="display: flex; align-items: center; gap: 8px;">
                    <div class="credit-badge">
                        <i class="fas fa-gem"></i>
                        <span id="creditBalance">0</span>
                    </div>
                    <button class="nav-btn admin" id="adminNavBtn" style="display: none;" onclick="switchPage('adminPage')">
                        <i class="fas fa-crown"></i>
                        Admin
                    </button>
                    <button class="nav-btn" onclick="logout()">
                        <i class="fas fa-sign-out-alt"></i>
                    </button>
                </div>
            </div>
        </div>

        <!-- Home Page -->
        <div class="page active" id="homePage">
            <div class="page-content">
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-icon">🚀</div>
                        <div class="stat-value" id="totalDeploys">0</div>
                        <div class="stat-label">Total</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">🟢</div>
                        <div class="stat-value" id="activeDeploys">0</div>
                        <div class="stat-label">Active</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">💎</div>
                        <div class="stat-value" id="creditsDisplay">0</div>
                        <div class="stat-label">Credits</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon">🤖</div>
                        <div class="stat-value">AI</div>
                        <div class="stat-label">Powered</div>
                    </div>
                </div>

                <div class="section-header">
                    <h2 class="section-title">Recent Deployments</h2>
                </div>

                <div id="recentDeployments"></div>
            </div>
        </div>

        <!-- Deployments Page -->
        <div class="page" id="deploymentsPage">
            <div class="page-content">
                <div class="section-header">
                    <h2 class="section-title">All Deployments</h2>
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

                <button class="btn" onclick="deployGithub()">
                    <i class="fab fa-github"></i>
                    Deploy from GitHub
                </button>
            </div>
        </div>

        <!-- Admin Page -->
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
                        <div class="admin-stat-value" id="adminBanned">0</div>
                        <div class="admin-stat-label">Banned</div>
                    </div>
                </div>

                <div class="admin-actions">
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--success), #059669);" onclick="showAddCreditsModal()">
                        <i class="fas fa-coins"></i> Add Credits to User
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--danger), #dc2626);" onclick="showBanUserModal()">
                        <i class="fas fa-ban"></i> Ban User
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--success), #059669);" onclick="showUnbanUserModal()">
                        <i class="fas fa-check-circle"></i> Unban User
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--secondary), #7c3aed);" onclick="viewAllUsers()">
                        <i class="fas fa-users"></i> All Users
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--primary), var(--primary-dark));" onclick="viewAllDeployments()">
                        <i class="fas fa-server"></i> All Deployments
                    </button>
                    <button class="admin-btn" style="background: linear-gradient(135deg, var(--info), #0e7490);" onclick="viewActivityLog()">
                        <i class="fas fa-history"></i> Activity Log
                    </button>
                </div>
            </div>
        </div>

        <!-- Bottom Navigation -->
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
            <button class="nav-item" onclick="switchPage('profilePage', this)">
                <div class="nav-icon"><i class="fas fa-user"></i></div>
                <div class="nav-label">Profile</div>
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
        let currentUser = null;
        let isAdmin = false;

        // Check session on load
        window.addEventListener('load', async () => {
            const session = await fetch('/api/auth/session').then(r => r.json());
            if (session.authenticated) {
                currentUser = session.user;
                isAdmin = session.is_admin;
                showApp();
            } else {
                document.getElementById('authScreen').style.display = 'flex';
            }
        });

        // Auth Functions
        function showLogin() {
            document.getElementById('loginForm').style.display = 'block';
            document.getElementById('registerForm').style.display = 'none';
        }

        function showRegister() {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('registerForm').style.display = 'block';
        }

        async function handleLogin(e) {
            e.preventDefault();
            
            const email = document.getElementById('loginEmail').value;
            const password = document.getElementById('loginPassword').value;
            
            showToast('info', '🔐 Authenticating...');
            
            try {
                const res = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email, password})
                });
                
                const data = await res.json();
                
                if (data.success) {
                    currentUser = data.user;
                    isAdmin = data.is_admin;
                    showToast('success', '✅ Login successful!');
                    showApp();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Login failed');
            }
        }

        async function handleRegister(e) {
            e.preventDefault();
            
            const name = document.getElementById('registerName').value;
            const email = document.getElementById('registerEmail').value;
            const password = document.getElementById('registerPassword').value;
            
            showToast('info', '📝 Creating account...');
            
            try {
                const res = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name, email, password})
                });
                
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Account created! Logging in...');
                    setTimeout(() => {
                        document.getElementById('loginEmail').value = email;
                        document.getElementById('loginPassword').value = password;
                        showLogin();
                    }, 1500);
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Registration failed');
            }
        }

        async function logout() {
            if (!confirm('Logout from your account?')) return;
            
            await fetch('/api/auth/logout', {method: 'POST'});
            
            currentUser = null;
            isAdmin = false;
            
            document.getElementById('appContainer').classList.remove('show');
            document.getElementById('authScreen').style.display = 'flex';
            
            showToast('info', '👋 Logged out successfully');
        }

        function showApp() {
            document.getElementById('authScreen').style.display = 'none';
            document.getElementById('appContainer').classList.add('show');
            
            if (isAdmin) {
                document.getElementById('adminNavBtn').style.display = 'flex';
            }
            
            loadData();
        }

        // Page Switching
        function switchPage(pageId, navBtn) {
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            document.getElementById(pageId).classList.add('active');
            
            if (navBtn) {
                document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                navBtn.classList.add('active');
            }
            
            window.scrollTo(0, 0);
            
            if (pageId === 'adminPage' && isAdmin) {
                loadAdminStats();
            }
        }

        // Load Data
        async function loadData() {
            await updateCredits();
            await loadDeployments();
        }

        async function updateCredits() {
            try {
                const res = await fetch('/api/credits');
                const data = await res.json();
                const credits = data.credits === Infinity ? '∞' : data.credits.toFixed(1);
                document.getElementById('creditBalance').textContent = credits;
                document.getElementById('creditsDisplay').textContent = credits;
            } catch (err) {
                console.error(err);
            }
        }

        async function loadDeployments() {
            try {
                const res = await fetch('/api/deployments');
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

        // File Upload
        async function handleFileUpload(input) {
            const file = input.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            showToast('info', '📤 Uploading...');
            
            try {
                const res = await fetch('/api/deploy/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ ' + data.message);
                    loadDeployments();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Upload failed');
            }
            
            input.value = '';
        }

        // GitHub Deploy
        async function deployGithub() {
            const url = document.getElementById('repoUrl').value;
            const branch = document.getElementById('repoBranch').value || 'main';
            
            if (!url) {
                showToast('warning', '⚠️ Enter repository URL');
                return;
            }
            
            showToast('info', '🚀 Deploying from GitHub...');
            
            try {
                const res = await fetch('/api/deploy/github', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url, branch})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ ' + data.message);
                    loadDeployments();
                    document.getElementById('repoUrl').value = '';
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Deploy failed');
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
            if (!confirm('Create backup?')) return;
            
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
            if (!confirm('Delete permanently?')) return;
            
            try {
                const res = await fetch(`/api/deployment/${deployId}`, {method: 'DELETE'});
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ Deleted');
                    loadDeployments();
                } else {
                    showToast('error', '❌ Failed');
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
                    document.getElementById('adminBanned').textContent = data.stats.banned_users;
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
                <button class="btn" onclick="adminAddCredits()" style="background: var(--success);">
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
                    showToast('success', '✅ Credits added');
                    closeModal();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        function showBanUserModal() {
            showModal('Ban User', `
                <div class="input-group">
                    <label class="input-label">User ID</label>
                    <input type="number" class="input-field" id="banUserId" placeholder="123456789">
                </div>
                <div class="input-group">
                    <label class="input-label">Ban Reason</label>
                    <input type="text" class="input-field" id="banReason" placeholder="Violation of terms">
                </div>
                <button class="btn" onclick="adminBanUser()" style="background: var(--danger);">
                    <i class="fas fa-ban"></i> Ban User
                </button>
            `);
        }

        async function adminBanUser() {
            const userId = document.getElementById('banUserId').value;
            const reason = document.getElementById('banReason').value;
            
            if (!userId || !reason) {
                showToast('warning', '⚠️ Fill all fields');
                return;
            }
            
            if (!confirm(`Ban user ${userId}?`)) return;
            
            try {
                const res = await fetch('/api/admin/ban-user', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({user_id: parseInt(userId), reason})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ User banned');
                    closeModal();
                    loadAdminStats();
                } else {
                    showToast('error', '❌ ' + data.error);
                }
            } catch (err) {
                showToast('error', '❌ Failed');
            }
        }

        function showUnbanUserModal() {
            showModal('Unban User', `
                <div class="input-group">
                    <label class="input-label">User ID</label>
                    <input type="number" class="input-field" id="unbanUserId" placeholder="123456789">
                </div>
                <button class="btn" onclick="adminUnbanUser()" style="background: var(--success);">
                    <i class="fas fa-check-circle"></i> Unban User
                </button>
            `);
        }

        async function adminUnbanUser() {
            const userId = document.getElementById('unbanUserId').value;
            
            if (!userId) {
                showToast('warning', '⚠️ Enter user ID');
                return;
            }
            
            try {
                const res = await fetch('/api/admin/unban-user', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({user_id: parseInt(userId)})
                });
                const data = await res.json();
                
                if (data.success) {
                    showToast('success', '✅ User unbanned');
                    closeModal();
                    loadAdminStats();
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
                            <div style="font-weight: 800; font-size: 14px; margin-bottom: 6px;">${u.first_name} ${u.is_banned ? '<span style="color: var(--danger);">[BANNED]</span>' : ''}</div>
                            <div style="font-size: 11px; color: var(--gray); line-height: 1.6;">
                                <div>ID: ${u.user_id}</div>
                                <div>Email: ${u.email}</div>
                                <div>Deploys: ${u.total_deployments}</div>
                                <div>Joined: ${new Date(u.joined_date).toLocaleDateString()}</div>
                                ${u.is_banned ? `<div style="color: var(--danger);">Reason: ${u.ban_reason}</div>` : ''}
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
                                <div>User: ${a.user_id} (${a.email || 'N/A'})</div>
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

        // Utility Functions
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

        // Auto-refresh
        setInterval(() => {
            if (currentUser) {
                updateCredits();
                loadDeployments();
                if (document.getElementById('adminPage').classList.contains('active') && isAdmin) {
                    loadAdminStats();
                }
            }
        }, 10000);
    </script>
</body>
</html>
"""

# ==================== FLASK ROUTES (Continue in next message due to length) ====================
