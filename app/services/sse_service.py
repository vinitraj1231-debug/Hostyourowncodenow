import json
import queue
import logging
from threading import Lock
from collections import defaultdict

logger = logging.getLogger(__name__)

SSE_CLIENTS = defaultdict(set)   # user_id → {queue objects}
SSE_LOCK = Lock()

def sse_notify(user_id, event_type, data):
    """Push a real-time event to all connected SSE clients for a user."""
    with SSE_LOCK:
        clients = SSE_CLIENTS.get(str(user_id), set())
        dead = set()
        for q in clients:
            try:
                q.put_nowait({'type': event_type, 'data': data})
            except Exception:
                dead.add(q)
        SSE_CLIENTS[str(user_id)] -= dead

def get_sse_clients():
    return SSE_CLIENTS

def get_sse_lock():
    return SSE_LOCK
