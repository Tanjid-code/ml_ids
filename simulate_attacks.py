"""
Attack Simulator - Tests Rule-Based + ML Detection
Sends real HTTP requests to the IDS system
"""
import requests
import time
import random
import json
from datetime import datetime

BASE_URL = "http://localhost:5000"

# ── Colors for terminal ────────────────────────────────────
class C:
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    CYAN   = '\033[96m'
    WHITE  = '\033[97m'
    BOLD   = '\033[1m'
    END    = '\033[0m'

def pr(color, msg):
    print(f"{color}{msg}{C.END}")

def separator(title=""):
    print()
    pr(C.CYAN, "=" * 60)
    if title:
        pr(C.BOLD, f"  {title}")
        pr(C.CYAN, "=" * 60)

# ══════════════════════════════════════════════════════════
# SYSTEM CHECK
# ══════════════════════════════════════════════════════════
def check_system():
    separator("SYSTEM CHECK")
    
    checks = {
        "Dashboard":       "/",
        "Alerts API":      "/api/alerts",
        "ML Predictions":  "/api/ml/predictions",
        "ML Summary":      "/api/ml/summary",
        "ML Model Info":   "/api/ml/model-info",
        "Comparison Log":  "/api/comparison/log",
        "Comparison Sum":  "/api/comparison/summary",
        "Traffic":         "/api/traffic/summary",
    }
    
    all_ok = True
    for name, path in checks.items():
        try:
            r = requests.get(
                f"{BASE_URL}{path}", timeout=5
            )
            if r.status_code == 200:
                pr(C.GREEN, f"  ✅ {name:<20} OK ({r.status_code})")
            else:
                pr(C.RED, 
                   f"  ❌ {name:<20} FAIL ({r.status_code})")
                all_ok = False
        except requests.exceptions.ConnectionError:
            pr(C.RED,
               f"  ❌ {name:<20} CONNECTION REFUSED")
            pr(C.YELLOW,
               "\n  ⚠️  Is the app running? "
               "Start it with: python app.py")
            return False
        except Exception as e:
            pr(C.RED, f"  ❌ {name:<20} ERROR: {e}")
            all_ok = False
    
    return all_ok


# ══════════════════════════════════════════════════════════
# CHECK ML STATUS
# ══════════════════════════════════════════════════════════
def check_ml_status():
    separator("ML MODEL STATUS")
    try:
        r    = requests.get(f"{BASE_URL}/api/ml/model-info")
        info = r.json()
        
        if info.get("loaded"):
            pr(C.GREEN,  f"  ✅ Model loaded!")
            pr(C.WHITE,  f"     Class     : {info.get('model_class')}")
            pr(C.WHITE,  f"     Features  : {info.get('n_features')}")
            pr(C.WHITE,  f"     Estimators: {info.get('n_estimators')}")
            pr(C.WHITE,  f"     Objective : {info.get('objective')}")
            return True
        else:
            pr(C.RED,    "  ❌ Model NOT loaded!")
            pr(C.YELLOW, "     Check model path in app.py")
            return False
    except Exception as e:
        pr(C.RED, f"  ❌ ML check failed: {e}")
        return False


# ══════════════════════════════════════════════════════════
# SEND REQUEST + SHOW RESULT
# ══════════════════════════════════════════════════════════
def send_request(method, path, 
                 headers=None, 
                 data=None, 
                 params=None,
                 label=""):
    """Send request and return response."""
    try:
        url = f"{BASE_URL}{path}"
        h   = headers or {}
        
        if method == "GET":
            r = requests.get(
                url, headers=h, 
                params=params, timeout=10
            )
        elif method == "POST":
            r = requests.post(
                url, headers=h,
                data=data, timeout=10
            )
        else:
            r = requests.request(
                method, url,
                headers=h, timeout=10
            )
        
        return r
    except Exception as e:
        pr(C.RED, f"  ❌ Request failed: {e}")
        return None


def show_result(label, r, delay=0.5):
    """Show request result."""
    if r:
        status_color = C.GREEN if r.status_code < 400 else C.RED
        pr(status_color,
           f"  → HTTP {r.status_code} | "
           f"{len(r.content)} bytes")
    time.sleep(delay)


# ══════════════════════════════════════════════════════════
# ATTACK SIMULATIONS
# ══════════════════════════════════════════════════════════

def simulate_normal_traffic():
    separator("NORMAL TRAFFIC (10 requests)")
    
    normal_paths = [
        ("GET",  "/",              {}),
        ("GET",  "/alerts",        {}),
        ("GET",  "/traffic",       {}),
        ("GET",  "/reports",       {}),
        ("GET",  "/settings",      {}),
        ("GET",  "/help",          {}),
        ("GET",  "/api/alerts",    {}),
        ("GET",  "/api/ml/summary",{}),
        ("GET",  "/api/traffic/summary", {}),
        ("GET",  "/api/system/info",     {}),
    ]
    
    for i, (method, path, headers) in enumerate(normal_paths):
        pr(C.WHITE, f"\n  [{i+1}/10] Normal: {method} {path}")
        r = send_request(method, path, headers)
        show_result("normal", r, delay=0.3)
    
    pr(C.GREEN, "\n  ✅ Normal traffic simulation complete")


def simulate_sql_injection():
    separator("SQL INJECTION ATTACKS")
    
    payloads = [
        "?id=1' OR '1'='1",
        "?user=admin'--",
        "?id=1; DROP TABLE users--",
        "?search=1' UNION SELECT * FROM passwords--",
        "?login=1' OR 1=1#",
        "?q=' OR 'x'='x",
        "?id=1' AND SLEEP(5)--",
        "?user=admin' AND 1=1--",
    ]
    
    for i, payload in enumerate(payloads):
        path = f"/api/alerts{payload}"
        pr(C.RED, f"\n  [{i+1}] SQL Injection: {payload[:50]}")
        r = send_request("GET", path)
        show_result("sql", r, delay=0.4)
    
    pr(C.YELLOW, "\n  ⚠️  SQL Injection simulation complete")


def simulate_xss_attacks():
    separator("XSS ATTACKS")
    
    payloads = [
        "?q=<script>alert('XSS')</script>",
        "?name=<img src=x onerror=alert(1)>",
        "?input=javascript:alert('xss')",
        "?search=<svg onload=alert(1)>",
        "?data=<iframe src=javascript:alert(1)>",
        "?msg=';alert('XSS')//",
    ]
    
    for i, payload in enumerate(payloads):
        path = f"/api/alerts{payload}"
        pr(C.YELLOW, f"\n  [{i+1}] XSS: {payload[:50]}")
        r = send_request("GET", path)
        show_result("xss", r, delay=0.4)
    
    pr(C.YELLOW, "\n  ⚠️  XSS simulation complete")


def simulate_path_traversal():
    separator("PATH TRAVERSAL ATTACKS")
    
    payloads = [
        "/api/alerts?file=../../../etc/passwd",
        "/api/alerts?path=..%2F..%2F..%2Fetc%2Fshadow",
        "/api/alerts?file=....//....//etc/passwd",
        "/api/alerts?dir=../../windows/system32",
        "/api/alerts?file=..\\..\\..\\windows\\win.ini",
    ]
    
    for i, payload in enumerate(payloads):
        pr(C.PURPLE, f"\n  [{i+1}] Path Traversal: {payload[:55]}")
        r = send_request("GET", payload)
        show_result("traversal", r, delay=0.4)
    
    pr(C.YELLOW, "\n  ⚠️  Path traversal simulation complete")


def simulate_command_injection():
    separator("COMMAND INJECTION ATTACKS")
    
    payloads = [
        "?cmd=ls -la",
        "?exec=cat /etc/passwd",
        "?run=;id;",
        "?q=|whoami",
        "?input=`id`",
        "?data=$(cat /etc/shadow)",
        "?cmd=ping -c 4 127.0.0.1",
    ]
    
    for i, payload in enumerate(payloads):
        path = f"/api/alerts{payload}"
        pr(C.RED, f"\n  [{i+1}] Cmd Injection: {payload[:50]}")
        r = send_request("GET", path)
        show_result("cmd", r, delay=0.4)
    
    pr(C.YELLOW, "\n  ⚠️  Command injection simulation complete")


def simulate_scanner_detection():
    separator("SCANNER / BOT DETECTION")
    
    scanner_agents = [
        "sqlmap/1.7.8",
        "Nikto/2.1.6",
        "Nmap Scripting Engine",
        "masscan/1.3",
        "python-requests/2.28.0 (scanner)",
        "zgrab/0.x",
        "Mozilla/5.0 (compatible; Nessus;)",
        "Acunetix Web Vulnerability Scanner",
    ]
    
    for i, agent in enumerate(scanner_agents):
        pr(C.PURPLE,
           f"\n  [{i+1}] Scanner UA: {agent[:45]}")
        r = send_request(
            "GET", "/api/alerts",
            headers={"User-Agent": agent}
        )
        show_result("scanner", r, delay=0.4)
    
    pr(C.YELLOW, "\n  ⚠️  Scanner detection simulation complete")


def simulate_brute_force():
    separator("BRUTE FORCE ATTACKS (10 attempts)")
    
    credentials = [
        ("admin",     "password"),
        ("admin",     "123456"),
        ("root",      "root"),
        ("admin",     "admin"),
        ("user",      "pass"),
        ("admin",     "letmein"),
        ("test",      "test"),
        ("admin",     "qwerty"),
        ("superuser", "super"),
        ("admin",     "password123"),
    ]
    
    for i, (user, pwd) in enumerate(credentials):
        pr(C.RED,
           f"\n  [{i+1}] Brute Force: "
           f"user={user} pass={pwd}")
        r = send_request(
            "POST", "/api/monitor/start",
            data={"username": user, "password": pwd}
        )
        show_result("brute", r, delay=0.3)
    
    pr(C.YELLOW, "\n  ⚠️  Brute force simulation complete")


def simulate_ddos():
    separator("DDoS SIMULATION (50 rapid requests)")
    
    pr(C.RED, "  Sending 50 rapid requests...")
    
    success = 0
    for i in range(50):
        try:
            r = requests.get(
                f"{BASE_URL}/api/alerts",
                timeout=5
            )
            success += 1
            if i % 10 == 0:
                pr(C.YELLOW,
                   f"  ... {i+1}/50 sent")
        except Exception:
            pass
        time.sleep(0.05)  # 50ms between requests
    
    pr(C.YELLOW,
       f"\n  ⚠️  DDoS simulation complete "
       f"({success}/50 sent)")


def simulate_sensitive_data():
    separator("SENSITIVE DATA EXPOSURE ATTEMPTS")
    
    payloads = [
        "/api/alerts?q=password=secret123",
        "/api/alerts?data=api_key=sk-1234567890",
        "/api/alerts?token=Bearer eyJhbGciOiJIUzI1NiJ9",
        "/api/alerts?q=credit_card=4111111111111111",
        "/api/alerts?ssn=123-45-6789",
        "/api/alerts?private_key=-----BEGIN RSA PRIVATE KEY-----",
    ]
    
    for i, path in enumerate(payloads):
        pr(C.PURPLE, f"\n  [{i+1}] Sensitive Data: {path[:55]}")
        r = send_request("GET", path)
        show_result("sensitive", r, delay=0.4)
    
    pr(C.YELLOW, "\n  ⚠️  Sensitive data simulation complete")


# ══════════════════════════════════════════════════════════
# CHECK RESULTS
# ══════════════════════════════════════════════════════════
def check_results():
    separator("CHECKING DETECTION RESULTS")
    
    # ── Rule-Based Results ──
    pr(C.BLUE, "\n  📏 RULE-BASED DETECTION:")
    try:
        r     = requests.get(f"{BASE_URL}/api/alerts/stats")
        stats = r.json()
        
        total = stats.get("total", 0)
        sev   = stats.get("by_severity", {})
        types = stats.get("by_type", {})
        
        pr(C.WHITE, f"     Total Alerts : {total}")
        pr(C.RED,   f"     Critical     : {sev.get('critical',0)}")
        pr(C.RED,   f"     High         : {sev.get('high', 0)}")
        pr(C.YELLOW,f"     Medium       : {sev.get('medium', 0)}")
        pr(C.GREEN, f"     Low          : {sev.get('low',  0)}")
        
        if types:
            pr(C.WHITE, "\n     By Type:")
            for t, count in sorted(
                types.items(),
                key=lambda x: x[1],
                reverse=True
            )[:8]:
                pr(C.WHITE, f"       {t:<30} {count}")
        
        if total == 0:
            pr(C.RED,
               "\n     ❌ No rule-based alerts detected!")
            pr(C.YELLOW,
               "        Check threat_detector.py patterns")
        else:
            pr(C.GREEN,
               f"\n     ✅ Rule-based detected {total} alerts!")
            
    except Exception as e:
        pr(C.RED, f"     ❌ Failed: {e}")
    
    # ── ML Results ──
    pr(C.PURPLE, "\n  🤖 ML MODEL DETECTION:")
    try:
        r   = requests.get(f"{BASE_URL}/api/ml/summary")
        s   = r.json()
        
        total   = s.get("total_predictions",  0)
        attacks = s.get("attack_predictions", 0)
        normal  = s.get("normal_predictions", 0)
        rate    = s.get("attack_rate",        0)
        conf    = s.get("avg_confidence",     0)
        quality = s.get("avg_data_quality",   0)
        sev     = s.get("severity_breakdown", {})
        
        pr(C.WHITE,  f"     Total Predictions: {total}")
        pr(C.RED,    f"     Attacks Detected : {attacks}")
        pr(C.GREEN,  f"     Normal Traffic   : {normal}")
        pr(C.WHITE,  f"     Attack Rate      : {rate}%")
        pr(C.WHITE,  f"     Avg Confidence   : {conf}%")
        pr(C.WHITE,  f"     Data Quality     : {quality}%")
        pr(C.RED,    f"     Critical         : {sev.get('critical',0)}")
        pr(C.RED,    f"     High             : {sev.get('high',    0)}")
        pr(C.YELLOW, f"     Medium           : {sev.get('medium',  0)}")
        pr(C.GREEN,  f"     Low              : {sev.get('low',     0)}")
        
        if total == 0:
            pr(C.RED,
               "\n     ❌ No ML predictions recorded!")
            pr(C.YELLOW,
               "        Check after_request in app.py")
            pr(C.YELLOW,
               "        Check ml_detector.is_loaded")
        else:
            pr(C.GREEN,
               f"\n     ✅ ML made {total} predictions!")
            if attacks > 0:
                pr(C.GREEN,
                   f"     ✅ ML detected {attacks} attacks!")
            else:
                pr(C.YELLOW,
                   "     ⚠️  ML detected 0 attacks "
                   "(model may need tuning)")
                   
    except Exception as e:
        pr(C.RED, f"     ❌ Failed: {e}")
    
    # ── Comparison Results ──
    pr(C.CYAN, "\n  ⚖️  COMPARISON:")
    try:
        r   = requests.get(f"{BASE_URL}/api/comparison/summary")
        s   = r.json()
        
        total        = s.get("total",            0)
        both         = s.get("both_detected",    0)
        rule_only    = s.get("only_rule",        0)
        ml_only      = s.get("only_ml",          0)
        both_normal  = s.get("both_normal",      0)
        agree        = s.get("agreement_rate",   0)
        rule_rate    = s.get("rule_detection_rate", 0)
        ml_rate      = s.get("ml_detection_rate",   0)
        
        pr(C.WHITE,  f"     Total Requests   : {total}")
        pr(C.RED,    f"     Both Detected    : {both}")
        pr(C.BLUE,   f"     Rule Only        : {rule_only}")
        pr(C.PURPLE, f"     ML Only          : {ml_only}")
        pr(C.GREEN,  f"     Both Normal      : {both_normal}")
        pr(C.WHITE,  f"     Agreement Rate   : {agree}%")
        pr(C.BLUE,   f"     Rule Det. Rate   : {rule_rate}%")
        pr(C.PURPLE, f"     ML Det. Rate     : {ml_rate}%")
        
        if total == 0:
            pr(C.RED,
               "\n     ❌ No comparison data!")
        else:
            pr(C.GREEN,
               f"\n     ✅ Comparison data: {total} entries")
            
    except Exception as e:
        pr(C.RED, f"     ❌ Failed: {e}")


# ══════════════════════════════════════════════════════════
# RECENT PREDICTIONS SAMPLE
# ══════════════════════════════════════════════════════════
def show_recent_predictions():
    separator("RECENT ML PREDICTIONS (Last 5)")
    try:
        r     = requests.get(
            f"{BASE_URL}/api/ml/predictions?limit=5"
        )
        preds = r.json()
        
        if not preds:
            pr(C.RED, "  ❌ No predictions found!")
            return
        
        for i, p in enumerate(preds):
            is_atk  = p.get("is_attack", False)
            color   = C.RED if is_atk else C.GREEN
            label   = p.get("label",            "?")
            prob    = p.get("attack_probability", 0)
            conf    = p.get("confidence",         0)
            path    = p.get("path",              "/")
            ip      = p.get("source_ip",     "?")
            quality = p.get("data_quality",      {})
            qpct    = quality.get("quality_percent", 0)
            
            pr(color, f"\n  [{i+1}] {label}")
            pr(C.WHITE, f"       IP      : {ip}")
            pr(C.WHITE, f"       Path    : {path}")
            pr(C.WHITE, f"       Attack% : {prob}%")
            pr(C.WHITE, f"       Conf    : {conf}%")
            pr(C.WHITE, f"       Quality : {qpct}%")
            
    except Exception as e:
        pr(C.RED, f"  ❌ Failed: {e}")


# ══════════════════════════════════════════════════════════
# RECENT COMPARISON SAMPLE
# ══════════════════════════════════════════════════════════
def show_recent_comparison():
    separator("RECENT COMPARISON (Last 5)")
    try:
        r    = requests.get(
            f"{BASE_URL}/api/comparison/log?limit=5"
        )
        logs = r.json()
        
        if not logs:
            pr(C.RED, "  ❌ No comparison data!")
            return
        
        for i, l in enumerate(logs):
            rule_det = l.get("rule_detected", False)
            ml_det   = l.get("ml_detected",   False)
            agree    = l.get("agreement",      False)
            conf     = l.get("ml_confidence",  0)
            path     = l.get("path",           "/")
            ip       = l.get("source_ip",      "?")
            
            # Determine situation
            if l.get("both_detected"):
                situation = "🤝 BOTH DETECTED"
                color     = C.RED
            elif l.get("only_rule"):
                situation = "📏 RULE ONLY"
                color     = C.BLUE
            elif l.get("only_ml"):
                situation = "🤖 ML ONLY"
                color     = C.PURPLE
            else:
                situation = "✅ BOTH NORMAL"
                color     = C.GREEN
            
            pr(color, f"\n  [{i+1}] {situation}")
            pr(C.WHITE, f"       IP      : {ip}")
            pr(C.WHITE, f"       Path    : {path}")
            pr(C.WHITE, 
               f"       Rule    : "
               f"{'THREAT' if rule_det else 'normal'}")
            pr(C.WHITE,
               f"       ML      : "
               f"{'ATTACK' if ml_det else 'normal'} "
               f"({conf}%)")
            pr(C.WHITE,
               f"       Agree   : "
               f"{'✅ Yes' if agree else '❌ No'}")
            
    except Exception as e:
        pr(C.RED, f"  ❌ Failed: {e}")


# ══════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════
def main():
    pr(C.BOLD + C.CYAN, """
╔══════════════════════════════════════════════════╗
║      IDS Attack Simulator & System Tester       ║
║      Rule-Based + ML Detection Verifier         ║
╚══════════════════════════════════════════════════╝
    """)
    
    # ── Check system is running ────────────────────────────
    if not check_system():
        pr(C.RED, "\n❌ System not running. Start app.py first!")
        pr(C.YELLOW, "   Run: python app.py")
        return
    
    # ── Check ML model ─────────────────────────────────────
    ml_ok = check_ml_status()
    if not ml_ok:
        pr(C.YELLOW,
           "\n⚠️  ML model not loaded. "
           "Continuing with rule-based only...")
    
    # ── Ask user what to run ───────────────────────────────
    pr(C.BOLD, "\n\nWhat do you want to simulate?")
    pr(C.WHITE, """
  [1] Run ALL attacks (recommended)
  [2] Normal traffic only
  [3] SQL Injection only
  [4] XSS only
  [5] Path Traversal only
  [6] Command Injection only
  [7] Scanner Detection only
  [8] Brute Force only
  [9] DDoS only
  [10] Check results only (no attacks)
    """)
    
    choice = input("  Enter choice (1-10): ").strip()
    
    pr(C.CYAN, f"\n  Starting simulation...\n")
    time.sleep(1)
    
    if choice == "1":
        simulate_normal_traffic()
        time.sleep(1)
        simulate_sql_injection()
        time.sleep(1)
        simulate_xss_attacks()
        time.sleep(1)
        simulate_path_traversal()
        time.sleep(1)
        simulate_command_injection()
        time.sleep(1)
        simulate_scanner_detection()
        time.sleep(1)
        simulate_brute_force()
        time.sleep(1)
        simulate_ddos()
        time.sleep(1)
        simulate_sensitive_data()
        
    elif choice == "2":
        simulate_normal_traffic()
    elif choice == "3":
        simulate_sql_injection()
    elif choice == "4":
        simulate_xss_attacks()
    elif choice == "5":
        simulate_path_traversal()
    elif choice == "6":
        simulate_command_injection()
    elif choice == "7":
        simulate_scanner_detection()
    elif choice == "8":
        simulate_brute_force()
    elif choice == "9":
        simulate_ddos()
    elif choice == "10":
        pass  # just check results
    else:
        pr(C.YELLOW, "  Invalid choice, running all...")
        simulate_normal_traffic()
        simulate_sql_injection()
    
    # ── Wait for after_request to process ─────────────────
    pr(C.CYAN, "\n\n  ⏳ Waiting 3 seconds for processing...")
    time.sleep(3)
    
    # ── Show results ───────────────────────────────────────
    check_results()
    show_recent_predictions()
    show_recent_comparison()
    
    # ── Final summary ──────────────────────────────────────
    separator("FINAL SUMMARY")
    pr(C.WHITE, """
  📊 Check these pages in your browser:
  
  Rule-Based Alerts:
    http://localhost:5000/alerts
    
  ML Predictions:
    http://localhost:5000/ml-predictions
    
  Comparison:
    http://localhost:5000/comparison
    
  Traffic Monitor:
    http://localhost:5000/traffic
    """)
    
    pr(C.GREEN + C.BOLD, "  ✅ Simulation complete!")


if __name__ == "__main__":
    main()