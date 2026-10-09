from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class AuthEvent:
    time: datetime
    ip: str
    user: str
    success: bool
    method: str


@dataclass
class WebEvent:
    time: datetime
    ip: str
    method: str
    path: str
    status: int
    user_agent: str


@dataclass
class Finding:
    rule: str
    severity: str  # low | medium | high | critical
    ip: str
    count: int
    first_seen: datetime
    last_seen: datetime
    mitre: str
    description: str
    evidence: list

    def to_dict(self) -> dict:
        d = asdict(self)
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
