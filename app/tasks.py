import os
import time
import logging
from datetime import datetime
from app.db import get_db
from app.config import LOGS_DIR, DEPLOYS_DIR, MAX_DEPLOY_RESTARTS
from app.services.deployment_service import (
    active_processes, process_restart_ct, PROCESS_LOCK,
    get_deployment, _launch_process, update_deployment, find_free_port
)
from app.services.sse_service import sse_notify
from app.utils import log_error

logger = logging.getLogger(__name__)

def cleanup_expired_sessions():
    while True:
        try:
            time.sleep(3600)
            with get_db() as conn:
                c = conn.cursor()
                c.execute("DELETE FROM sessions WHERE expires_at < ?", (datetime.now().isoformat(),))
        except Exception as e:
            log_error(str(e), "cleanup_sessions")

def monitor_and_autorestart():
    while True:
        try:
            time.sleep(15)
            with PROCESS_LOCK:
                for deploy_id, process in list(active_processes.items()):
                    if process.poll() is not None:
                        return_code = process.returncode
                        del active_processes[deploy_id]

                        deployment = get_deployment(deploy_id)
                        if not deployment:
                            continue

                        restarts = process_restart_ct.get(deploy_id, 0)

                        if restarts < MAX_DEPLOY_RESTARTS:
                            process_restart_ct[deploy_id] = restarts + 1
                            deploy_dir = os.path.join(DEPLOYS_DIR, deploy_id)
                            start_cmd = deployment.get('start_command', '')
                            env_vars = deployment.get('env_vars', {})
                            port = deployment.get('port', find_free_port())

                            if start_cmd and os.path.exists(deploy_dir):
                                try:
                                    new_proc = _launch_process(start_cmd.split(), deploy_dir, port, env_vars, project_path=deploy_dir, deploy_id=deploy_id)
                                    active_processes[deploy_id] = new_proc
                                    update_deployment(deploy_id, status='running', pid=new_proc.pid,
                                                     restart_count=restarts+1,
                                                     logs=f'🔄 Auto-restarted #{restarts+1}')
                                    sse_notify(deployment['user_id'], 'deployment_updated',
                                              {'id': deploy_id, 'status': 'running', 'restarted': True})
                                    continue
                                except Exception as e:
                                    log_error(str(e), f"auto_restart {deploy_id}")

                        update_deployment(deploy_id, status='crashed',
                                         logs=f'💥 Crashed (exit {return_code}) after {restarts} restarts')
                        sse_notify(deployment['user_id'], 'deployment_updated',
                                  {'id': deploy_id, 'status': 'crashed'})

        except Exception as e:
            log_error(str(e), "monitor_and_autorestart")

def cleanup_old_logs():
    while True:
        try:
            time.sleep(86400)
            log_file = os.path.join(LOGS_DIR, 'elitehost.log')
            if os.path.exists(log_file) and os.path.getsize(log_file) > 50 * 1024 * 1024:
                os.rename(log_file, log_file + f".{datetime.now().strftime('%Y%m%d')}")
        except Exception:
            pass
