from __future__ import annotations

import json
from collections import Counter

from .models import Finding, SEVERITY_ORDER


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.first_seen))


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.to_dict() for f in sort_findings(findings)], indent=2)


def to_markdown(findings: list[Finding]) -> str:
    findings = sort_findings(findings)
    counts = Counter(f.severity for f in findings)
    out = ["# LogSentry Report", "",
           f"**Total findings:** {len(findings)}  |  " +
           "  ".join(f"{s}: {counts.get(s, 0)}" for s in ("critical", "high", "medium", "low")), ""]
    if not findings:
        out.append("No suspicious activity detected.")
    for i, f in enumerate(findings, 1):
        out += [f"## {i}. [{f.severity.upper()}] {f.rule} - {f.ip}", "",
                f"- **MITRE ATT&CK:** {f.mitre}",
                f"- **Events:** {f.count} ({f.first_seen} -> {f.last_seen})",
                f"- **Details:** {f.description}", "- **Evidence:**"]
        out += [f"  - `{e}`" for e in f.evidence]
        out.append("")
    return "\n".join(out)
