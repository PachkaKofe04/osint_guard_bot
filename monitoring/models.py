# monitoring/models.py
"""Модели данных для системы мониторинга."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MonitorEntry:
    """Одна запись мониторинга (один пользователь следит за одним объектом)."""
    user_id: int
    target: str           # домен, IP, email — то, что мониторим
    scan_type: str        # "domain" | "ip" | "email"
    created_at: float = field(default_factory=time.time)
    last_checked_at: Optional[float] = None
    last_risk_level: Optional[str] = None  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    last_score: Optional[int] = None
    check_interval_hours: int = 24         # как часто проверять

    @property
    def key(self) -> str:
        return f"{self.user_id}:{self.scan_type}:{self.target}"

    def is_due(self) -> bool:
        """Нужно ли проверять прямо сейчас."""
        if self.last_checked_at is None:
            return True
        return (time.time() - self.last_checked_at) >= self.check_interval_hours * 3600

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "target": self.target,
            "scan_type": self.scan_type,
            "created_at": self.created_at,
            "last_checked_at": self.last_checked_at,
            "last_risk_level": self.last_risk_level,
            "last_score": self.last_score,
            "check_interval_hours": self.check_interval_hours,
        }

    @classmethod
    def from_dict(cls, d: dict) -> MonitorEntry:
        return cls(
            user_id=d["user_id"],
            target=d["target"],
            scan_type=d["scan_type"],
            created_at=d.get("created_at", time.time()),
            last_checked_at=d.get("last_checked_at"),
            last_risk_level=d.get("last_risk_level"),
            last_score=d.get("last_score"),
            check_interval_hours=d.get("check_interval_hours", 24),
        )
