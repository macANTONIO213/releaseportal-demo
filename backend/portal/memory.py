"""Per-process capability store. Secrets are never serialized or logged.
Worker/browser restart requires fresh credentials; this is deliberately not a
durable queue. Shared hosting uses one trusted API process for this MVP.
"""
import secrets
import threading
import time
from dataclasses import dataclass, field

@dataclass(repr=False)
class SecretEntry:
    value: object = field(repr=False)
    expires: float
    binding: object

class MemoryStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.entries = {}
    def put(self, value, binding, ttl=3600):
        with self.lock:
            self._prune()
            if len(self.entries) >= 200:
                raise RuntimeError('Credential capacity reached.')
            key = secrets.token_urlsafe(32)
            self.entries[key] = SecretEntry(value, time.monotonic()+ttl, binding)
            return key
    def _prune(self):
        now = time.monotonic()
        self.entries = {k: v for k,v in self.entries.items() if v.expires > now}
    def get(self, key, binding, consume=False):
        with self.lock:
            self._prune()
            entry = self.entries.get(key)
            if not entry or entry.binding != binding:
                return None
            if consume:
                self.entries.pop(key)
            return entry.value
    def remove(self, key):
        with self.lock:
            self.entries.pop(key, None)

github_tokens = MemoryStore()
