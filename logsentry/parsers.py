"""Parsers for Linux auth.log (sshd) and Apache/Nginx combined access logs."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable, Iterator

from .models import AuthEvent, WebEvent

SSH_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+[\d:]{8})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<result>Failed|Accepted)\s+(?P<method>\S+)\s+for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>[\d.]+)"
)

ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)


def parse_auth_log(lines: Iterable[str], year: int | None = None) -> Iterator[AuthEvent]:
    year = year or datetime.now().year
    for line in lines:
        m = SSH_RE.match(line)
        if not m:
            continue
        ts = " ".join(m["ts"].split())
        when = datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
        yield AuthEvent(when, m["ip"], m["user"], m["result"] == "Accepted", m["method"])


def parse_access_log(lines: Iterable[str]) -> Iterator[WebEvent]:
    for line in lines:
        m = ACCESS_RE.match(line)
        if not m:
            continue
        when = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(tzinfo=None)
        yield WebEvent(when, m["ip"], m["method"], m["path"], int(m["status"]), m["ua"])
