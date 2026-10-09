"""Generates synthetic sample logs (no real data). Run: python samples/generate_samples.py"""
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote

out = Path(__file__).parent
base = datetime(2026, 10, 3, 2, 14, 0)

auth = []
def a(t, msg): auth.append(f"{t.strftime('%b %e %H:%M:%S')} web01 sshd[{4000 + len(auth)}]: {msg}")

for i in range(12):  # brute force burst from 203.0.113.45
    t = base + timedelta(seconds=i * 7)
    user = ["root", "admin", "ubuntu", "test"][i % 4]
    a(t, f"Failed password for {'invalid user ' if user != 'root' else ''}{user} from 203.0.113.45 port {50000 + i} ssh2")
a(base + timedelta(seconds=100), "Accepted password for ubuntu from 203.0.113.45 port 50100 ssh2")
for i in range(2):  # benign typos
    a(base + timedelta(hours=3, minutes=i), f"Failed password for mahesh from 198.51.100.7 port 4100{i} ssh2")
a(base + timedelta(hours=3, minutes=5), "Accepted publickey for mahesh from 198.51.100.7 port 41010 ssh2")
(out / "auth.log").write_text("\n".join(auth) + "\n")

web = []
def w(t, ip, path, status, ua="Mozilla/5.0", m="GET"):
    web.append(f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{m} {path} HTTP/1.1" {status} 512 "-" "{ua}"')

t0 = datetime(2026, 10, 3, 9, 0, 0)
for i, p in enumerate(["/", "/about", "/products?id=3", "/login"]):
    w(t0 + timedelta(seconds=i * 30), "198.51.100.7", p, 200)
for i, payload in enumerate(["1' OR '1'='1", "1 UNION SELECT username,password FROM users--",
                             "1; DROP TABLE users"]):
    w(t0 + timedelta(minutes=1, seconds=i), "192.0.2.99", "/products?id=" + quote(payload), 500,
      "sqlmap/1.7.2#stable (https://sqlmap.org)")
w(t0 + timedelta(minutes=2), "192.0.2.50", "/search?q=" + quote("<script>alert(1)</script>"), 200)
w(t0 + timedelta(minutes=2, seconds=5), "192.0.2.50", "/download?file=" + quote("../../etc/passwd"), 403)
for i in range(30):
    w(t0 + timedelta(minutes=3, seconds=i), "192.0.2.77", f"/admin{i}.php", 404, "gobuster/3.6")
(out / "access.log").write_text("\n".join(web) + "\n")
print("Wrote auth.log and access.log")
