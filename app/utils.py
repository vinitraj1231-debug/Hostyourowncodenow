import os
import hashlib
import logging
import traceback
from datetime import datetime
from app.config import LOGS_DIR

logger = logging.getLogger(__name__)

def log_error(error_msg, context=""):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = f"[{ts}] ERROR in {context}: {error_msg}\n{traceback.format_exc()}\n"
    error_file = os.path.join(LOGS_DIR, 'errors.log')
    with open(error_file, 'a') as f:
        f.write(entry)
    logger.error(entry)

def get_device_fingerprint(req):
    """
    Generate a device fingerprint based on User-Agent and Accept-Language.
    IP is excluded to allow for mobile network roaming, but sessions are
    still tracked by IP separately in the database for auditing.
    """
    components = [
        req.headers.get('User-Agent', ''),
        req.headers.get('Accept-Language', ''),
    ]
    return hashlib.sha256('|'.join(components).encode()).hexdigest()

def format_bytes(b):
    if not b: return '0 B'
    k = 1024
    sizes = ['B', 'KB', 'MB', 'GB']
    import math
    i = math.floor(math.log(b)/math.log(k))
    return f"{(b/math.pow(k,i)):.1f} {sizes[i]}"
