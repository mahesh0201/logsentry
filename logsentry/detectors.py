"""Detection rules. Each rule returns a list of Finding objects."""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from urllib.parse import unquote

from .models import AuthEvent, Finding, WebEvent

# --- Web attack signatures (matched against the URL-decoded request path) ----
WEB_PATTERNS = {
    "SQL injection": re.compile(
        r"(union\s+(all\s+)?select|\bor\b\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1|"
        r"sleep\s*\(\d+\)|information_schema|;\s*drop\s+table|benchmark\s*\()",
        re.I,
    ),
    "Cross-site scripting": re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=)", re.I),
    "Path traversal": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/proc/self)", re.I),
    "Command injection": re.compile(r"(;|\|\||&&)\s*(cat|ls|id|whoami|wget|curl)\b", re.I),
}

SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan|nuclei|acunetix|zgrab)", re.I
)


def ssh_bruteforce(events: list[AuthEvent], threshold: int = 5,
                   window: timedelta = timedelta(minutes=10)) -> list[Finding]:
    """T1110 Brute Force. Escalates to critical if a login succeeds after the burst."""
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for e in sorted(events, key=lambda x: x.time):
        by_ip[e.ip].append(e)

    findings = []
    for ip, evs in by_ip.items():
        fails = [e for e in evs if not e.success]
        burst = None
        start = 0
        for end in range(len(fails)):
            while fails[end].time - fails[start].time > window:
                start += 1
            if end - start + 1 >= threshold:
                burst = (start, end)  # keep extending to the largest window
        if not burst:
            continue
        group = fails[burst[0]: burst[1] + 1]
        last_fail = group[-1].time
        compromised = [e for e in evs if e.success and e.time >= last_fail
                       and e.time - last_fail <= window]
        users = sorted({e.user for e in group})
        sev, mitre = "high", "T1110 Brute Force"
        desc = f"{len(group)} failed SSH logins within {int(window.total_seconds() // 60)} min " \
               f"targeting {len(users)} account(s)"
        if compromised:
            sev, mitre = "critical", "T1110 Brute Force -> T1078 Valid Accounts"
            desc += f"; SUCCESSFUL login as '{compromised[0].user}' followed the burst"
        findings.append(Finding("ssh_bruteforce", sev, ip, len(group), group[0].time, group[-1].time,
                                mitre, desc, [f"{e.time} user={e.user}" for e in group[:5]]))
    return findings


def web_attacks(events: list[WebEvent]) -> list[Finding]:
    """T1190 Exploit Public-Facing Application - signature matches in request paths."""
    grouped: dict[tuple, list[WebEvent]] = defaultdict(list)
    for e in events:
        decoded = unquote(unquote(e.path))  # double-decode to catch simple evasion
        for name, rx in WEB_PATTERNS.items():
            if rx.search(decoded):
                grouped[(e.ip, name)].append(e)
    findings = []
    for (ip, name), evs in grouped.items():
        findings.append(Finding(
            "web_attack", "high", ip, len(evs), evs[0].time, evs[-1].time,
            "T1190 Exploit Public-Facing Application",
            f"{name} attempt(s) detected in request URLs",
            [f"{e.method} {unquote(e.path)[:120]} -> {e.status}" for e in evs[:3]],
        ))
    return findings


def scanner_activity(events: list[WebEvent], not_found_threshold: int = 20,
                     window: timedelta = timedelta(minutes=5)) -> list[Finding]:
    """T1595 Active Scanning - known scanner user agents and 404 floods."""
    findings = []
    ua_hits: dict[tuple, list[WebEvent]] = defaultdict(list)
    for e in events:
        m = SCANNER_UA.search(e.user_agent)
        if m:
            ua_hits[(e.ip, m.group(1).lower())].append(e)
    for (ip, tool), evs in ua_hits.items():
        findings.append(Finding(
            "scanner_user_agent", "medium", ip, len(evs), evs[0].time, evs[-1].time,
            "T1595.002 Vulnerability Scanning", f"Requests from known scanner '{tool}'",
            [f"{e.method} {e.path[:100]} -> {e.status}" for e in evs[:3]]))

    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for e in sorted(events, key=lambda x: x.time):
        if e.status == 404:
            by_ip[e.ip].append(e)
    for ip, evs in by_ip.items():
        start, best = 0, None
        for end in range(len(evs)):
            while evs[end].time - evs[start].time > window:
                start += 1
            if end - start + 1 >= not_found_threshold:
                best = (start, end)
        if best:
            grp = evs[best[0]: best[1] + 1]
            findings.append(Finding(
                "directory_enumeration", "medium", ip, len(grp), grp[0].time, grp[-1].time,
                "T1595.003 Wordlist Scanning",
                f"{len(grp)} HTTP 404 responses within {int(window.total_seconds() // 60)} min",
                [f"{e.path[:100]}" for e in grp[:5]]))
    return findings
