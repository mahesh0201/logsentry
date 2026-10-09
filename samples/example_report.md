# LogSentry Report

**Total findings:** 7  |  critical: 1  high: 3  medium: 3  low: 0

## 1. [CRITICAL] ssh_bruteforce - 203.0.113.45

- **MITRE ATT&CK:** T1110 Brute Force -> T1078 Valid Accounts
- **Events:** 12 (2026-10-03 02:14:00 -> 2026-10-03 02:15:17)
- **Details:** 12 failed SSH logins within 10 min targeting 4 account(s); SUCCESSFUL login as 'ubuntu' followed the burst
- **Evidence:**
  - `2026-10-03 02:14:00 user=root`
  - `2026-10-03 02:14:07 user=admin`
  - `2026-10-03 02:14:14 user=ubuntu`
  - `2026-10-03 02:14:21 user=test`
  - `2026-10-03 02:14:28 user=root`

## 2. [HIGH] web_attack - 192.0.2.99

- **MITRE ATT&CK:** T1190 Exploit Public-Facing Application
- **Events:** 3 (2026-10-03 09:01:00 -> 2026-10-03 09:01:02)
- **Details:** SQL injection attempt(s) detected in request URLs
- **Evidence:**
  - `GET /products?id=1' OR '1'='1 -> 500`
  - `GET /products?id=1 UNION SELECT username,password FROM users-- -> 500`
  - `GET /products?id=1; DROP TABLE users -> 500`

## 3. [HIGH] web_attack - 192.0.2.50

- **MITRE ATT&CK:** T1190 Exploit Public-Facing Application
- **Events:** 1 (2026-10-03 09:02:00 -> 2026-10-03 09:02:00)
- **Details:** Cross-site scripting attempt(s) detected in request URLs
- **Evidence:**
  - `GET /search?q=<script>alert(1)</script> -> 200`

## 4. [HIGH] web_attack - 192.0.2.50

- **MITRE ATT&CK:** T1190 Exploit Public-Facing Application
- **Events:** 1 (2026-10-03 09:02:05 -> 2026-10-03 09:02:05)
- **Details:** Path traversal attempt(s) detected in request URLs
- **Evidence:**
  - `GET /download?file=../../etc/passwd -> 403`

## 5. [MEDIUM] scanner_user_agent - 192.0.2.99

- **MITRE ATT&CK:** T1595.002 Vulnerability Scanning
- **Events:** 3 (2026-10-03 09:01:00 -> 2026-10-03 09:01:02)
- **Details:** Requests from known scanner 'sqlmap'
- **Evidence:**
  - `GET /products?id=1%27%20OR%20%271%27%3D%271 -> 500`
  - `GET /products?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users-- -> 500`
  - `GET /products?id=1%3B%20DROP%20TABLE%20users -> 500`

## 6. [MEDIUM] scanner_user_agent - 192.0.2.77

- **MITRE ATT&CK:** T1595.002 Vulnerability Scanning
- **Events:** 30 (2026-10-03 09:03:00 -> 2026-10-03 09:03:29)
- **Details:** Requests from known scanner 'gobuster'
- **Evidence:**
  - `GET /admin0.php -> 404`
  - `GET /admin1.php -> 404`
  - `GET /admin2.php -> 404`

## 7. [MEDIUM] directory_enumeration - 192.0.2.77

- **MITRE ATT&CK:** T1595.003 Wordlist Scanning
- **Events:** 30 (2026-10-03 09:03:00 -> 2026-10-03 09:03:29)
- **Details:** 30 HTTP 404 responses within 5 min
- **Evidence:**
  - `/admin0.php`
  - `/admin1.php`
  - `/admin2.php`
  - `/admin3.php`
  - `/admin4.php`

