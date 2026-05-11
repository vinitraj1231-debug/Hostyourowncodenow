import logging
from datetime import datetime
from app.db import get_db

logger = logging.getLogger(__name__)

def audit_log(event_type, severity, description, user_id=None, ip_address=None, user_agent=None):
    """
    Record a security event in the audit log.
    severity: INFO, WARNING, CRITICAL
    """
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO audit_logs (user_id, event_type, severity, description, ip_address, user_agent, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, event_type, severity, description, ip_address, user_agent, datetime.now().isoformat()))
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")

def log_security_event(request, event_type, severity, description, user_id=None):
    audit_log(
        event_type=event_type,
        severity=severity,
        description=description,
        user_id=user_id,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
