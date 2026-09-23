# monitoring/storage.py
"""Хранилище мониторов — in-memory с персистентностью через JSON-файл."""
from __future__ import annotations

import json
import logging
import os
from typing import Dict, List, Optional

from monitoring.models import MonitorEntry

log = logging.getLogger(__name__)

STORAGE_FILE = "data/monitors.json"
MAX_MONITORS_PER_USER = 5


class MonitorStorage:
    """Thread-safe in-memory хранилище записей мониторинга."""

    def __init__(self, filepath: str = STORAGE_FILE) -> None:
        self._filepath = filepath
        self._entries: Dict[str, MonitorEntry] = {}  # key → entry
        self._load()

    # ── persistence ──────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not os.path.exists(self._filepath):
            return
        try:
            with open(self._filepath, "r", encoding="utf-8") as f:
                raw: list = json.load(f)
            for d in raw:
                entry = MonitorEntry.from_dict(d)
                self._entries[entry.key] = entry
            log.info(f"[Monitor] Loaded {len(self._entries)} monitors from {self._filepath}")
        except Exception as e:
            log.warning(f"[Monitor] Failed to load storage: {e}")

    def save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self._filepath), exist_ok=True)
            with open(self._filepath, "w", encoding="utf-8") as f:
                json.dump([e.to_dict() for e in self._entries.values()], f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.warning(f"[Monitor] Failed to save storage: {e}")

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def add(self, entry: MonitorEntry) -> bool:
        """Добавляет монитор. Возвращает False если лимит превышен или уже существует."""
        if entry.key in self._entries:
            return False  # уже мониторится
        user_monitors = self.list_for_user(entry.user_id)
        if len(user_monitors) >= MAX_MONITORS_PER_USER:
            return False  # лимит
        self._entries[entry.key] = entry
        self.save()
        return True

    def remove(self, user_id: int, scan_type: str, target: str) -> bool:
        key = f"{user_id}:{scan_type}:{target}"
        if key not in self._entries:
            return False
        del self._entries[key]
        self.save()
        return True

    def list_for_user(self, user_id: int) -> List[MonitorEntry]:
        return [e for e in self._entries.values() if e.user_id == user_id]

    def all_due(self) -> List[MonitorEntry]:
        """Возвращает все мониторы, которые нужно проверить сейчас."""
        return [e for e in self._entries.values() if e.is_due()]

    def update_result(self, key: str, risk_level: str, score: int) -> None:
        import time
        if key in self._entries:
            entry = self._entries[key]
            entry.last_checked_at = time.time()
            entry.last_risk_level = risk_level
            entry.last_score = score
            self.save()

    def get(self, user_id: int, scan_type: str, target: str) -> Optional[MonitorEntry]:
        key = f"{user_id}:{scan_type}:{target}"
        return self._entries.get(key)
