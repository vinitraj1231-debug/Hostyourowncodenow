import os
import json
import fcntl
import logging
from datetime import datetime
from threading import Lock
from app.config import DATA_DIR

logger = logging.getLogger(__name__)

JSON_DB_DIR = os.path.join(DATA_DIR, 'json_db')
os.makedirs(JSON_DB_DIR, exist_ok=True)

class JSONTable:
    def __init__(self, table_name):
        self.filepath = os.path.join(JSON_DB_DIR, f"{table_name}.json")
        self.lock = Lock()
        self._ensure_file()

    def _ensure_file(self):
        if not os.path.exists(self.filepath):
            os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
            with open(self.filepath, 'w') as f:
                json.dump([], f)

    def _read(self):
        self._ensure_file()
        with open(self.filepath, 'r') as f:
            # For simplicity in this environment, using fcntl for process-level locking if needed,
            # but threading.Lock is usually enough for a single process Flask app.
            # However, enterprise-grade implies robustness.
            try:
                fcntl.flock(f, fcntl.LOCK_SH)
                data = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
                return data
            except (json.JSONDecodeError, IOError):
                return []

    def _write(self, data):
        with open(self.filepath, 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            json.dump(data, f, indent=4)
            fcntl.flock(f, fcntl.LOCK_UN)

    def all(self):
        with self.lock:
            return self._read()

    def find(self, **kwargs):
        with self.lock:
            data = self._read()
            return [item for item in data if all(item.get(k) == v for k, v in kwargs.items())]

    def find_one(self, **kwargs):
        res = self.find(**kwargs)
        return res[0] if res else None

    def insert(self, item):
        with self.lock:
            data = self._read()
            if 'created_at' not in item:
                item['created_at'] = datetime.now().isoformat()
            if 'updated_at' not in item:
                item['updated_at'] = datetime.now().isoformat()
            data.append(item)
            self._write(data)
            return item

    def update(self, query, updates):
        with self.lock:
            data = self._read()
            updated_count = 0
            for item in data:
                if all(item.get(k) == v for k, v in query.items()):
                    item.update(updates)
                    item['updated_at'] = datetime.now().isoformat()
                    updated_count += 1
            if updated_count > 0:
                self._write(data)
            return updated_count

    def delete(self, **kwargs):
        with self.lock:
            data = self._read()
            original_len = len(data)
            data = [item for item in data if not all(item.get(k) == v for k, v in kwargs.items())]
            if len(data) < original_len:
                self._write(data)
            return original_len - len(data)

class JSONDatabase:
    def __init__(self):
        self.users = JSONTable('users')
        self.sessions = JSONTable('sessions')
        self.projects = JSONTable('projects')
        self.deployments = JSONTable('deployments')
        self.files = JSONTable('files')
        self.logs = JSONTable('logs')
        self.credits_ledger = JSONTable('credits_ledger')
        self.wallets = JSONTable('wallets')
        self.referrals = JSONTable('referrals')
        self.commissions = JSONTable('commissions')
        self.withdrawals = JSONTable('withdrawals')
        self.tickets = JSONTable('tickets')
        self.messages = JSONTable('messages')
        self.plans = JSONTable('plans')
        self.trials = JSONTable('trials')
        self.audit_logs = JSONTable('audit_logs')
        self.settings = JSONTable('settings')

        # Initialize default settings if not present
        if not self.settings.find_one(key='platform_config'):
            self.settings.insert({
                'key': 'platform_config',
                'trial_duration_hours': 3,
                'referral_commission_percent': 30,
                'github_deploy_cost': 2,
                'zip_deploy_cost': 2,
                'raw_deploy_cost': 1,
                'single_file_deploy_cost': 1
            })

db = JSONDatabase()
