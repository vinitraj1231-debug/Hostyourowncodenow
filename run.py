import os
import signal
import sys
import time
import atexit
from threading import Thread
from app import create_app
from app.tasks import cleanup_expired_sessions, monitor_and_autorestart, cleanup_old_logs
from app.bot import run_bot
from app.services.deployment_service import active_processes, PROCESS_LOCK

app = create_app()

def cleanup_on_exit():
    print("🛑 Shutting down EliteHost...")
    with PROCESS_LOCK:
        for deploy_id, process in list(active_processes.items()):
            try:
                process.terminate()
                process.wait(timeout=3)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
    print("✅ Cleanup complete")

atexit.register(cleanup_on_exit)

def signal_handler(sig, frame):
    cleanup_on_exit()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == '__main__':
    # Start background tasks
    Thread(target=cleanup_expired_sessions, daemon=True).start()
    Thread(target=monitor_and_autorestart, daemon=True).start()
    Thread(target=cleanup_old_logs, daemon=True).start()

    # Start bot in a separate thread
    Thread(target=run_bot, daemon=True).start()

    # Run Flask app
    port = int(os.environ.get("PORT", 8080))
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False, threaded=True)
