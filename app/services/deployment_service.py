import os
import uuid
import json
import shutil
import zipfile
import subprocess
import sys
import re
import psutil
from datetime import datetime
from threading import Lock
from collections import defaultdict
from app.db import get_db
from app.config import (
    DEPLOYS_DIR, BACKUPS_DIR, MAX_DEPLOYMENTS_PER_USER,
    OWNER_ID, CREDIT_COSTS, MAX_DEPLOY_RESTARTS
)
from app.services.credit_service import deduct_credits, add_credits
from app.utils import log_error

active_processes = {}  # deploy_id → subprocess.Popen
process_restart_ct = defaultdict(int)
PROCESS_LOCK = Lock()

PACKAGE_MAP = {
    'cv2': 'opencv-python', 'PIL': 'pillow', 'sklearn': 'scikit-learn',
    'yaml': 'pyyaml', 'dotenv': 'python-dotenv', 'telebot': 'pyTelegramBotAPI',
    'bs4': 'beautifulsoup4', 'Crypto': 'pycryptodome', 'jwt': 'PyJWT',
    'aiohttp': 'aiohttp', 'fastapi': 'fastapi', 'uvicorn': 'uvicorn',
    'motor': 'motor', 'pymongo': 'pymongo', 'redis': 'redis',
    'celery': 'celery', 'pydantic': 'pydantic', 'sqlalchemy': 'SQLAlchemy',
}

STDLIB_MODULES = {
    'os', 'sys', 'time', 'json', 're', 'math', 'random', 'datetime',
    'collections', 'itertools', 'functools', 'pathlib', 'threading',
    'multiprocessing', 'subprocess', 'shutil', 'tempfile', 'io', 'abc',
    'typing', 'dataclasses', 'enum', 'copy', 'pickle', 'struct', 'hashlib',
    'hmac', 'secrets', 'base64', 'binascii', 'csv', 'configparser',
    'argparse', 'logging', 'unittest', 'socket', 'ssl', 'http', 'urllib',
    'email', 'html', 'xml', 'sqlite3', 'queue', 'asyncio', 'contextlib',
    'inspect', 'traceback', 'warnings', 'weakref', 'gc', 'platform',
    'signal', 'atexit', 'uuid', 'calendar', 'textwrap', 'string', 'builtins',
}

def find_free_port():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        return s.getsockname()[1]

def create_deployment(user_id, name, deploy_type, **kwargs):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                SELECT COUNT(*) as cnt FROM deployments
                WHERE user_id=? AND status IN ('running','pending')
            ''', (user_id,))
            if c.fetchone()['cnt'] >= MAX_DEPLOYMENTS_PER_USER and str(user_id) != str(OWNER_ID):
                return None, None

        deploy_id = str(uuid.uuid4())[:8]
        port = find_free_port()

        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO deployments (id, user_id, name, type, status, port,
                    created_at, updated_at, logs, dependencies,
                    repo_url, branch, build_command, start_command, env_vars, restart_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (deploy_id, user_id, name, deploy_type, 'pending', port,
                  datetime.now().isoformat(), datetime.now().isoformat(),
                  '', json.dumps([]),
                  kwargs.get('repo_url', ''), kwargs.get('branch', 'main'),
                  kwargs.get('build_command', ''), kwargs.get('start_command', ''),
                  json.dumps({}), 0))

        return deploy_id, port
    except Exception as e:
        log_error(str(e), "create_deployment")
        return None, None

def update_deployment(deploy_id, **kwargs):
    try:
        kwargs['updated_at'] = datetime.now().isoformat()
        for key in ['dependencies', 'env_vars']:
            if key in kwargs and isinstance(kwargs[key], (list, dict)):
                kwargs[key] = json.dumps(kwargs[key])
        set_clause = ', '.join([f"{k} = ?" for k in kwargs.keys()])
        values = list(kwargs.values()) + [deploy_id]
        with get_db() as conn:
            c = conn.cursor()
            c.execute(f'UPDATE deployments SET {set_clause} WHERE id = ?', values)
    except Exception as e:
        log_error(str(e), f"update_deployment {deploy_id}")

def get_deployment(deploy_id):
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM deployments WHERE id = ?', (deploy_id,))
            row = c.fetchone()
            if row:
                d = dict(row)
                d['dependencies'] = json.loads(d.get('dependencies') or '[]')
                d['env_vars'] = json.loads(d.get('env_vars') or '{}')
                return d
        return None
    except Exception:
        return None

def _launch_process(cmd, cwd, port, env=None):
    proc_env = os.environ.copy()
    proc_env['PORT'] = str(port)
    if env:
        proc_env.update(env)
    return subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=cwd, env=proc_env
    )

def extract_imports_from_code(code_content):
    imports = set()
    for line in code_content.split('\n'):
        for pattern in [r'^\s*import\s+([a-zA-Z0-9_\.]+)', r'^\s*from\s+([a-zA-Z0-9_\.]+)\s+import']:
            m = re.match(pattern, line)
            if m:
                imports.add(m.group(1).split('.')[0])
    return imports

def detect_and_install_deps(project_path):
    installed, log_lines = [], ["🤖 AI DEPENDENCY ANALYZER", "=" * 60]
    try:
        req_file = os.path.join(project_path, 'requirements.txt')
        if os.path.exists(req_file):
            log_lines.append("\n📦 REQUIREMENTS.TXT")
            with open(req_file, 'r') as f:
                packages = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            for pkg in packages:
                try:
                    subprocess.run([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                                   check=True, capture_output=True, timeout=300)
                    log_lines.append(f"  ✅ {pkg}")
                    installed.append(pkg)
                except Exception:
                    log_lines.append(f"  ⚠️  {pkg} (skipped)")

        py_files = []
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv'}]
            py_files.extend(os.path.join(root, f) for f in files if f.endswith('.py'))

        if py_files:
            all_imports = set()
            for pf in py_files[:30]:
                try:
                    with open(pf, 'r', encoding='utf-8', errors='ignore') as f:
                        all_imports.update(extract_imports_from_code(f.read()))
                except Exception:
                    continue

            third_party = all_imports - STDLIB_MODULES
            log_lines.append("\n🔍 AUTO-DETECTED DEPENDENCIES")
            for imp in third_party:
                pkg = PACKAGE_MAP.get(imp, imp)
                try:
                    __import__(imp)
                    log_lines.append(f"  ✓ {pkg} (installed)")
                except ImportError:
                    try:
                        subprocess.run([sys.executable, '-m', 'pip', 'install', pkg, '--quiet'],
                                       check=True, capture_output=True, timeout=300)
                        log_lines.append(f"  ✅ {pkg} (auto-installed)")
                        installed.append(pkg)
                    except Exception:
                        log_lines.append(f"  ⚠️  {pkg} (failed)")

        log_lines += ["", "=" * 60, f"📦 Total Installed: {len(set(installed))}", "=" * 60]
        return list(set(installed)), "\n".join(log_lines)
    except Exception as e:
        log_error(str(e), "detect_and_install_deps")
        return installed, "\n".join(log_lines) + f"\n\n❌ Error: {str(e)}"

def deploy_from_file(user_id, file_path, filename):
    cost = CREDIT_COSTS['file_upload']
    if not deduct_credits(user_id, cost, f"File deploy: {filename}"):
        return None, f"❌ Need {cost} credits"

    deploy_id, port = create_deployment(user_id, filename, 'file_upload')
    if not deploy_id:
        add_credits(user_id, cost, "Refund"); return None, "Failed to create deployment"

    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    os.makedirs(deploy_dir, exist_ok=True)

    try:
        if filename.endswith('.zip'):
            update_deployment(deploy_id, status='extracting', logs='📦 Extracting ZIP...')
            with zipfile.ZipFile(file_path, 'r') as z:
                z.extractall(deploy_dir)
            main_file = None
            for root, _, files in os.walk(deploy_dir):
                for f in files:
                    if f in ('main.py', 'app.py', 'bot.py', 'index.js', 'server.js'):
                        main_file = os.path.join(root, f); break
                if main_file:
                    break
            if not main_file:
                update_deployment(deploy_id, status='failed', logs='❌ No entry point found')
                add_credits(user_id, cost, "Refund"); return None, "❌ No main file found"
            file_path = main_file
        else:
            dest = os.path.join(deploy_dir, filename)
            shutil.copy(file_path, dest)
            file_path = dest

        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        update_deployment(deploy_id, dependencies=installed_deps)

        deployment = get_deployment(deploy_id)
        env_vars = deployment.get('env_vars', {})

        cmd = [sys.executable, file_path] if file_path.endswith('.py') else ['node', file_path]
        update_deployment(deploy_id, status='starting',
                          logs=f'🚀 Launching on port {port}...\n{install_log}')

        process = _launch_process(cmd, os.path.dirname(file_path), port, env_vars)
        with PROCESS_LOCK:
            active_processes[deploy_id] = process
            process_restart_ct[deploy_id] = 0
        update_deployment(deploy_id, status='running', pid=process.pid,
                          logs=f'✅ Live on port {port}!\n\n{install_log}')
        return deploy_id, f"🎉 Deployed! Port {port}"

    except Exception as e:
        log_error(str(e), "deploy_from_file")
        update_deployment(deploy_id, status='failed', logs=str(e))
        add_credits(user_id, cost, "Refund")
        return None, str(e)

def deploy_from_github(user_id, repo_url, branch='main', build_cmd='', start_cmd=''):
    cost = CREDIT_COSTS['github_deploy']
    if not deduct_credits(user_id, cost, f"GitHub: {repo_url}"):
        return None, f"❌ Need {cost} credits"

    repo_name = repo_url.split('/')[-1].replace('.git', '')
    deploy_id, port = create_deployment(user_id, repo_name, 'github',
                                        repo_url=repo_url, branch=branch,
                                        build_command=build_cmd, start_command=start_cmd)
    if not deploy_id:
        add_credits(user_id, cost, "Refund"); return None, "Failed to create deployment"

    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    os.makedirs(deploy_dir, exist_ok=True)

    try:
        update_deployment(deploy_id, status='cloning', logs=f'🔄 Cloning {repo_url}...')
        result = subprocess.run(
            ['git', 'clone', '-b', branch, '--depth', '1', repo_url, deploy_dir],
            capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            update_deployment(deploy_id, status='failed', logs=f'❌ Clone failed:\n{result.stderr}')
            add_credits(user_id, cost, "Refund"); return None, "❌ Clone failed"

        if build_cmd:
            update_deployment(deploy_id, status='building', logs=f'🔨 Running: {build_cmd}')
            br = subprocess.run(build_cmd, shell=True, cwd=deploy_dir,
                                capture_output=True, text=True, timeout=600)
            if br.returncode != 0:
                update_deployment(deploy_id, status='failed', logs=f'❌ Build failed:\n{br.stderr}')
                add_credits(user_id, cost, "Refund"); return None, "❌ Build failed"

        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        update_deployment(deploy_id, dependencies=installed_deps)

        if not start_cmd:
            MAIN_FILES = {
                'main.py': f'{sys.executable} main.py', 'app.py': f'{sys.executable} app.py',
                'bot.py': f'{sys.executable} bot.py', 'index.js': 'node index.js',
                'server.js': 'node server.js',
            }
            for fname, cmd in MAIN_FILES.items():
                if os.path.exists(os.path.join(deploy_dir, fname)):
                    start_cmd = cmd; break

        if not start_cmd:
            update_deployment(deploy_id, status='failed', logs='❌ No start command')
            add_credits(user_id, cost, "Refund"); return None, "❌ No start command found"

        deployment = get_deployment(deploy_id)
        env_vars = deployment.get('env_vars', {})
        update_deployment(deploy_id, status='starting',
                          logs=f'🚀 Starting: {start_cmd}', start_command=start_cmd)

        process = _launch_process(start_cmd.split(), deploy_dir, port, env_vars)
        with PROCESS_LOCK:
            active_processes[deploy_id] = process
            process_restart_ct[deploy_id] = 0
        update_deployment(deploy_id, status='running', pid=process.pid,
                          logs=f'✅ Running on port {port}!\n\n{install_log}')
        return deploy_id, f"🎉 Deployed! Port {port}"

    except Exception as e:
        log_error(str(e), "deploy_from_github")
        update_deployment(deploy_id, status='failed', logs=str(e))
        add_credits(user_id, cost, "Refund"); return None, str(e)

def create_backup(deploy_id):
    try:
        deployment = get_deployment(deploy_id)
        if not deployment:
            return None, "Deployment not found"
        user_id = deployment['user_id']
        cost = CREDIT_COSTS['backup']
        if not deduct_credits(user_id, cost, f"Backup: {deployment['name']}"):
            return None, f"❌ Need {cost} credits"

        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if not os.path.exists(deploy_dir):
            add_credits(user_id, cost, "Refund")
            return None, "Deployment directory not found"

        backup_name = f"{deployment['name']}_{deploy_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
        backup_path = os.path.join(BACKUPS_DIR, backup_name)
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(deploy_dir):
                for file in files:
                    fp = os.path.join(root, file)
                    zf.write(fp, os.path.relpath(fp, deploy_dir))
        return backup_path, backup_name
    except Exception as e:
        log_error(str(e), f"create_backup {deploy_id}")
        return None, str(e)

def get_deployment_files(deploy_id):
    try:
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if not os.path.exists(deploy_dir):
            return []
        files = []
        for root, _, filenames in os.walk(deploy_dir):
            for fn in filenames:
                fp = os.path.join(root, fn)
                files.append({
                    'name': fn,
                    'path': os.path.relpath(fp, deploy_dir),
                    'size': os.path.getsize(fp),
                    'modified': datetime.fromtimestamp(os.path.getmtime(fp)).isoformat()
                })
        return files
    except Exception:
        return []

def stop_deployment(deploy_id):
    try:
        with PROCESS_LOCK:
            if deploy_id in active_processes:
                p = active_processes[deploy_id]
                p.terminate()
                try:
                    p.wait(timeout=5)
                except Exception:
                    p.kill()
                del active_processes[deploy_id]
        update_deployment(deploy_id, status='stopped', logs='🛑 Stopped by user')
        return True, "Stopped"
    except Exception as e:
        log_error(str(e), f"stop_deployment {deploy_id}")
        return False, str(e)

def delete_deployment(deploy_id):
    try:
        stop_deployment(deploy_id)
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        if os.path.exists(deploy_dir):
            shutil.rmtree(deploy_dir, ignore_errors=True)
        with get_db() as conn:
            c = conn.cursor()
            c.execute('DELETE FROM deployments WHERE id = ?', (deploy_id,))
        return True, "Deleted successfully"
    except Exception as e:
        log_error(str(e), f"delete_deployment {deploy_id}")
        return False, str(e)

def get_system_metrics():
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        net = psutil.net_io_counters()
        return {
            'cpu': round(cpu, 1),
            'memory_percent': round(mem.percent, 1),
            'memory_used': round(mem.used / (1024**3), 2),
            'memory_total': round(mem.total / (1024**3), 2),
            'disk_percent': round(disk.percent, 1),
            'disk_used': round(disk.used / (1024**3), 2),
            'disk_total': round(disk.total / (1024**3), 2),
            'net_sent_mb': round(net.bytes_sent / (1024**2), 1),
            'net_recv_mb': round(net.bytes_recv / (1024**2), 1),
            'active_processes': len(active_processes),
        }
    except Exception:
        return {k: 0 for k in ['cpu','memory_percent','memory_used','memory_total',
                                 'disk_percent','disk_used','disk_total','net_sent_mb',
                                 'net_recv_mb','active_processes']}
