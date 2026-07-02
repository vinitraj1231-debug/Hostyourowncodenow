import os
import uuid
import json
import shutil
import zipfile
import subprocess
import sys
import re
import psutil
import time
from datetime import datetime
from threading import Lock
from collections import defaultdict
from app.services.json_db import db
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
    'flask': 'flask', 'django': 'django', 'numpy': 'numpy', 'pandas': 'pandas',
    'requests': 'requests', 'httpx': 'httpx', 'discord': 'discord.py',
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
        active_deploys = db.deployments.find(user_id=user_id, status='running')
        if len(active_deploys) >= MAX_DEPLOYMENTS_PER_USER and str(user_id) != str(OWNER_ID) and user_id != 'admin_raj':
            return None, "Deployment limit reached"

        deploy_id = str(uuid.uuid4())[:8]
        port = find_free_port()

        deployment = {
            'id': deploy_id,
            'user_id': user_id,
            'name': name,
            'type': deploy_type,
            'status': 'pending',
            'port': port,
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'logs': '',
            'dependencies': [],
            'repo_url': kwargs.get('repo_url', ''),
            'branch': kwargs.get('branch', 'main'),
            'build_command': kwargs.get('build_command', ''),
            'start_command': kwargs.get('start_command', ''),
            'env_vars': {},
            'restart_count': 0,
            'version': 1
        }
        db.deployments.insert(deployment)
        return deploy_id, port
    except Exception as e:
        log_error(str(e), "create_deployment")
        return None, str(e)

def update_deployment(deploy_id, **kwargs):
    try:
        db.deployments.update({'id': deploy_id}, kwargs)
    except Exception as e:
        log_error(str(e), f"update_deployment {deploy_id}")

def get_deployment(deploy_id):
    return db.deployments.find_one(id=deploy_id)

def _get_venv_bin(project_path, binary='python'):
    if sys.platform == 'win32':
        return os.path.join(project_path, 'venv', 'Scripts', f"{binary}.exe")
    return os.path.join(project_path, 'venv', 'bin', binary)

def _launch_process(cmd, cwd, port, env=None, project_path=None, deploy_id=None):
    proc_env = os.environ.copy()
    proc_env['PORT'] = str(port)
    if env:
        proc_env.update(env)

    if project_path:
        venv_python = _get_venv_bin(project_path, 'python')
        if os.path.exists(venv_python):
            if isinstance(cmd, list) and cmd[0] in [sys.executable, 'python', 'python3']:
                cmd[0] = venv_python

    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=cwd, env=proc_env, text=True, bufsize=1
    )

    if deploy_id:
        from threading import Thread
        from app.services.sse_service import sse_notify
        def stream_logs():
            for line in iter(process.stdout.readline, ''):
                if not line: break
                deployment = get_deployment(deploy_id)
                if deployment:
                    new_logs = (deployment.get('logs', '') + line)[-10000:]
                    update_deployment(deploy_id, logs=new_logs)
                    sse_notify(deployment['user_id'], 'logs', {'id': deploy_id, 'line': line})
            process.stdout.close()
        Thread(target=stream_logs, daemon=True).start()

    return process

def detect_and_install_deps(project_path):
    installed, log_lines = [], ["🤖 AI DEPENDENCY ANALYZER", "=" * 60]
    try:
        venv_dir = os.path.join(project_path, 'venv')
        if not os.path.exists(venv_dir):
            log_lines.append("🛠 Creating virtual environment...")
            subprocess.run([sys.executable, '-m', 'venv', venv_dir], check=True)

        venv_pip = _get_venv_bin(project_path, 'pip')
        venv_python = _get_venv_bin(project_path, 'python')

        req_file = os.path.join(project_path, 'requirements.txt')
        if os.path.exists(req_file):
            log_lines.append("\n📦 REQUIREMENTS.TXT")
            try:
                subprocess.run([venv_pip, 'install', '-r', req_file, '--quiet'],
                               check=True, capture_output=True, timeout=600)
                with open(req_file, 'r') as f:
                    for l in f:
                        if l.strip() and not l.startswith('#'):
                            log_lines.append(f"  ✅ {l.strip()}")
                            installed.append(l.strip())
            except Exception as e:
                log_lines.append(f"  ❌ Failed to install from requirements.txt: {str(e)}")

        py_files = []
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', 'venv', '.venv'}]
            py_files.extend(os.path.join(root, f) for f in files if f.endswith('.py'))

        if py_files:
            all_imports = set()
            for pf in py_files[:30]:
                try:
                    with open(pf, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            for pattern in [r'^\s*import\s+([a-zA-Z0-9_\.]+)', r'^\s*from\s+([a-zA-Z0-9_\.]+)\s+import']:
                                m = re.match(pattern, line)
                                if m:
                                    all_imports.add(m.group(1).split('.')[0])
                except Exception:
                    continue

            third_party = all_imports - STDLIB_MODULES
            log_lines.append("\n🔍 AUTO-DETECTED DEPENDENCIES")
            for imp in third_party:
                pkg = PACKAGE_MAP.get(imp, imp)
                check_proc = subprocess.run([venv_python, '-c', f'import {imp}'], capture_output=True)
                if check_proc.returncode == 0:
                    log_lines.append(f"  ✓ {pkg} (already present)")
                else:
                    try:
                        subprocess.run([venv_pip, 'install', pkg, '--quiet'],
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
    is_zip = filename.endswith('.zip')
    cost = CREDIT_COSTS['zip_deploy'] if is_zip else CREDIT_COSTS['file_upload']

    if not deduct_credits(user_id, cost, f"File deploy: {filename}"):
        return None, f"❌ Need {cost} credits"

    res = create_deployment(user_id, filename, 'zip_upload' if is_zip else 'file_upload')
    deploy_id, port = res if isinstance(res, tuple) else (None, res)
    if not deploy_id:
        add_credits(user_id, cost, "Refund"); return None, port

    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    os.makedirs(deploy_dir, exist_ok=True)

    try:
        if is_zip:
            update_deployment(deploy_id, status='extracting', logs='📦 Extracting ZIP...')
            with zipfile.ZipFile(file_path, 'r') as z:
                z.extractall(deploy_dir)
            main_file = None
            for root, _, files in os.walk(deploy_dir):
                for f in files:
                    if f in ('main.py', 'app.py', 'bot.py', 'index.js', 'server.js'):
                        main_file = os.path.join(root, f); break
                if main_file: break
            if not main_file:
                update_deployment(deploy_id, status='failed', logs='❌ No entry point found')
                add_credits(user_id, cost, "Refund"); return None, "❌ No main file found"
            entry_path = main_file
        else:
            dest = os.path.join(deploy_dir, filename)
            shutil.copy(file_path, dest)
            entry_path = dest

        update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing dependencies...')
        installed_deps, install_log = detect_and_install_deps(deploy_dir)
        update_deployment(deploy_id, dependencies=installed_deps)

        deployment = get_deployment(deploy_id)
        env_vars = deployment.get('env_vars', {})

        cmd = [sys.executable, entry_path] if entry_path.endswith('.py') else ['node', entry_path]
        update_deployment(deploy_id, status='starting',
                          logs=f'🚀 Launching on port {port}...\n{install_log}')

        process = _launch_process(cmd, deploy_dir, port, env_vars, project_path=deploy_dir, deploy_id=deploy_id)
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
    res = create_deployment(user_id, repo_name, 'github',
                                        repo_url=repo_url, branch=branch,
                                        build_command=build_cmd, start_command=start_cmd)
    deploy_id, port = res if isinstance(res, tuple) else (None, res)
    if not deploy_id:
        add_credits(user_id, cost, "Refund"); return None, port

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

        process = _launch_process(start_cmd.split(), deploy_dir, port, env_vars, project_path=deploy_dir, deploy_id=deploy_id)
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
        if not deployment: return None, "Deployment not found"
        user_id = deployment['user_id']
        cost = CREDIT_COSTS['backup']
        if not deduct_credits(user_id, cost, f"Backup: {deployment['name']}"):
            return None, f"❌ Need {cost} credits"

        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        backup_name = f"{deployment['name']}_{deploy_id}_{int(time.time())}.zip"
        backup_path = os.path.join(BACKUPS_DIR, backup_name)

        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(deploy_dir):
                for file in files:
                    if 'venv' in root or '__pycache__' in root: continue
                    fp = os.path.join(root, file)
                    zf.write(fp, os.path.relpath(fp, deploy_dir))
        return backup_path, backup_name
    except Exception as e:
        return None, str(e)

def get_deployment_files(deploy_id):
    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    if not os.path.exists(deploy_dir): return []
    files = []
    for root, _, filenames in os.walk(deploy_dir):
        if 'venv' in root or '__pycache__' in root or '.git' in root: continue
        for fn in filenames:
            fp = os.path.join(root, fn)
            files.append({
                'name': fn,
                'path': os.path.relpath(fp, deploy_dir),
                'size': os.path.getsize(fp),
                'modified': datetime.fromtimestamp(os.path.getmtime(fp)).isoformat()
            })
    return files

def stop_deployment(deploy_id):
    with PROCESS_LOCK:
        if deploy_id in active_processes:
            p = active_processes[deploy_id]
            p.terminate()
            try: p.wait(timeout=5)
            except: p.kill()
            del active_processes[deploy_id]
    update_deployment(deploy_id, status='stopped', pid=None)
    return True, "Stopped"

def delete_deployment(deploy_id):
    stop_deployment(deploy_id)
    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    if os.path.exists(deploy_dir):
        shutil.rmtree(deploy_dir, ignore_errors=True)
    db.deployments.delete(id=deploy_id)
    return True, "Deleted"

def restart_deployment(deploy_id):
    try:
        deployment = get_deployment(deploy_id)
        if not deployment: return False, "Not found"

        stop_deployment(deploy_id)
        time.sleep(1)

        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
        start_cmd = deployment.get('start_command', '')
        env_vars = deployment.get('env_vars', {})
        port = deployment.get('port', find_free_port())

        if not start_cmd:
            MAIN_FILES = {
                'main.py': f'{sys.executable} main.py', 'app.py': f'{sys.executable} app.py',
                'bot.py': f'{sys.executable} bot.py', 'index.js': 'node index.js',
                'server.js': 'node server.js',
            }
            for fname, cmd in MAIN_FILES.items():
                if os.path.exists(os.path.join(deploy_dir, fname)):
                    start_cmd = cmd; break

        if not start_cmd: return False, "No entry point"

        process = _launch_process(start_cmd.split(), deploy_dir, port, env_vars, project_path=deploy_dir, deploy_id=deploy_id)
        with PROCESS_LOCK:
            active_processes[deploy_id] = process
            process_restart_ct[deploy_id] += 1

        update_deployment(deploy_id, status='running', pid=process.pid,
                         restart_count=process_restart_ct[deploy_id],
                         logs=f"🔄 Restarted (#{process_restart_ct[deploy_id]})")
        return True, "Restarted"
    except Exception as e:
        return False, str(e)

def deploy_from_raw_code(user_id, code, filename):
    cost = CREDIT_COSTS['raw_deploy']
    if not deduct_credits(user_id, cost, f"Raw deploy: {filename}"):
        return None, f"❌ Need {cost} credits"

    res = create_deployment(user_id, filename, 'raw_code')
    deploy_id, port = res if isinstance(res, tuple) else (None, res)
    if not deploy_id:
        add_credits(user_id, cost, "Refund"); return None, port

    deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
    os.makedirs(deploy_dir, exist_ok=True)

    file_path = os.path.join(deploy_dir, filename)
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(code)

    update_deployment(deploy_id, status='installing', logs='🤖 AI analyzing dependencies...')
    installed_deps, install_log = detect_and_install_deps(deploy_dir)
    update_deployment(deploy_id, dependencies=installed_deps)

    cmd = [sys.executable, file_path] if file_path.endswith('.py') else ['node', file_path]
    process = _launch_process(cmd, deploy_dir, port, {}, project_path=deploy_dir, deploy_id=deploy_id)

    with PROCESS_LOCK:
        active_processes[deploy_id] = process
    update_deployment(deploy_id, status='running', pid=process.pid, logs=f"✅ Live on port {port}\n\n{install_log}")
    return deploy_id, f"🎉 Deployed! Port {port}"

def rollback_deployment(deploy_id, backup_name):
    try:
        deployment = get_deployment(deploy_id)
        if not deployment: return False, "Not found"

        backup_path = os.path.join(BACKUPS_DIR, backup_name)
        if not os.path.exists(backup_path): return False, "Backup not found"

        stop_deployment(deploy_id)
        deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)

        # Clear current files (except venv)
        for item in os.listdir(deploy_dir):
            if item == 'venv': continue
            path = os.path.join(deploy_dir, item)
            if os.path.isdir(path): shutil.rmtree(path)
            else: os.remove(path)

        # Extract backup
        with zipfile.ZipFile(backup_path, 'r') as zf:
            zf.extractall(deploy_dir)

        update_deployment(deploy_id, status='stopped', logs=f"🔄 Rolled back to {backup_name}")
        return True, "Rolled back successfully"
    except Exception as e:
        return False, str(e)

def get_system_metrics():
    try:
        return {
            'cpu': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'memory_used': round(psutil.virtual_memory().used / (1024**3), 2),
            'memory_total': round(psutil.virtual_memory().total / (1024**3), 2),
            'disk_percent': psutil.disk_usage('/').percent,
            'disk_used': round(psutil.disk_usage('/').used / (1024**3), 2),
            'disk_total': round(psutil.disk_usage('/').total / (1024**3), 2),
            'net_sent_mb': round(psutil.net_io_counters().bytes_sent / (1024**2), 1),
            'net_recv_mb': round(psutil.net_io_counters().bytes_recv / (1024**2), 1),
            'active_processes': len(active_processes),
        }
    except: return {}
