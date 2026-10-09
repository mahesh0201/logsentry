from datetime import datetime, timedelta
from pathlib import Path

from logsentry import detectors
from logsentry.cli import main
from logsentry.models import AuthEvent, WebEvent
from logsentry.parsers import parse_access_log, parse_auth_log

SAMPLES = Path(__file__).parent.parent / "samples"
T0 = datetime(2026, 10, 3, 2, 0, 0)


def auth(ip, secs, ok=False, user="root"):
    return AuthEvent(T0 + timedelta(seconds=secs), ip, user, ok, "password")


def web(ip, path, status=200, ua="Mozilla/5.0", secs=0):
    return WebEvent(T0 + timedelta(seconds=secs), ip, "GET", path, status, ua)


def test_parse_auth_line_with_double_space_day():
    line = "Oct  3 02:14:00 web01 sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 22 ssh2"
    ev = list(parse_auth_log([line], year=2026))[0]
    assert (ev.ip, ev.user, ev.success) == ("1.2.3.4", "admin", False)


def test_parse_access_line():
    line = '1.2.3.4 - - [03/Oct/2026:09:00:00 +0000] "GET /x?id=1 HTTP/1.1" 404 10 "-" "curl/8"'
    ev = list(parse_access_log([line]))[0]
    assert ev.status == 404 and ev.path == "/x?id=1" and ev.user_agent == "curl/8"


def test_bruteforce_detected():
    f = detectors.ssh_bruteforce([auth("9.9.9.9", i * 5) for i in range(6)])
    assert len(f) == 1 and f[0].severity == "high"


def test_bruteforce_below_threshold_ignored():
    assert detectors.ssh_bruteforce([auth("9.9.9.9", i * 5) for i in range(4)]) == []


def test_slow_attempts_outside_window_ignored():
    evs = [auth("9.9.9.9", i * 600) for i in range(6)]  # one every 10 min
    assert detectors.ssh_bruteforce(evs, window=timedelta(minutes=5)) == []


def test_success_after_burst_is_critical():
    evs = [auth("9.9.9.9", i * 5) for i in range(6)] + [auth("9.9.9.9", 60, ok=True, user="ubuntu")]
    f = detectors.ssh_bruteforce(evs)
    assert f[0].severity == "critical" and "T1078" in f[0].mitre


def test_sqli_url_encoded_detected():
    f = detectors.web_attacks([web("8.8.8.8", "/p?id=1%20UNION%20SELECT%20pass%20FROM%20u")])
    assert f and f[0].description.startswith("SQL injection")


def test_double_encoded_traversal_detected():
    f = detectors.web_attacks([web("8.8.8.8", "/f?x=%252e%252e%252fetc/passwd")])
    assert f and "Path traversal" in f[0].description


def test_clean_traffic_has_no_findings():
    evs = [web("8.8.8.8", p) for p in ("/", "/about", "/products?id=3")]
    assert detectors.web_attacks(evs) == [] and detectors.scanner_activity(evs) == []


def test_scanner_user_agent():
    f = detectors.scanner_activity([web("7.7.7.7", "/", ua="Nikto/2.5")])
    assert f[0].rule == "scanner_user_agent"


def test_404_flood():
    evs = [web("7.7.7.7", f"/a{i}", 404, secs=i) for i in range(25)]
    assert any(f.rule == "directory_enumeration" for f in detectors.scanner_activity(evs))


def test_cli_on_samples_returns_exit_2(capsys):
    code = main(["--auth", str(SAMPLES / "auth.log"), "--access", str(SAMPLES / "access.log"),
                 "--year", "2026"])
    out = capsys.readouterr().out
    assert code == 2 and "203.0.113.45" in out and "198.51.100.7" not in out
