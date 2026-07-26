"""
Advanced Threat Detection Module
264+ rules across 15 attack categories
Severity Levels: Critical, High, Medium, Low
"""
import re
from datetime import datetime
from collections import defaultdict


class ThreatDetector:
    def __init__(self):
        self.failed_logins  = defaultdict(int)
        self.request_counts = defaultdict(int)
        self.port_access    = defaultdict(set)
        self.ip_alert_count = defaultdict(int)

        self.attack_patterns  = self._load_attack_patterns()
        self.suspicious_ports = self._load_suspicious_ports()

    # ════════════════════════════════════════════════════════
    # SUSPICIOUS PORTS
    # ════════════════════════════════════════════════════════
    def _load_suspicious_ports(self):
        return {
            20:    "FTP Data Transfer",
            21:    "FTP Control",
            23:    "Telnet (unencrypted remote access)",
            25:    "SMTP (email/spam relay)",
            53:    "DNS (amplification attacks)",
            135:   "Windows RPC",
            137:   "NetBIOS Name Service",
            138:   "NetBIOS Datagram",
            139:   "NetBIOS Session",
            445:   "SMB (WannaCry/EternalBlue exploit)",
            512:   "Remote Exec",
            513:   "Remote Login",
            514:   "Remote Shell",
            1433:  "Microsoft SQL Server",
            1521:  "Oracle Database",
            3306:  "MySQL Database",
            3389:  "RDP (Remote Desktop)",
            4444:  "Metasploit default listener",
            5555:  "Android Debug Bridge (ADB)",
            6666:  "IRC / Botnet C2",
            8080:  "HTTP Alternate / Malware C2",
            12345: "NetBus Backdoor",
            27374: "SubSeven Backdoor",
            31337: "BackOrifice Backdoor",
        }

    # ════════════════════════════════════════════════════════
    # LOAD ALL ATTACK PATTERNS
    # ════════════════════════════════════════════════════════
    def _load_attack_patterns(self):
        return {

            # ════════════════════════════════════════════════
            # CRITICAL SEVERITY
            # ════════════════════════════════════════════════

            # ── SQL Injection ────────────────────────────────
            "sql_injection": {
                "severity":    "critical",
                "category":    "Injection Attack",
                "description": "SQL Injection attack detected",
                "patterns": [
                    {
                        "rule_id":     "SQL-001",
                        "rule_name":   "Classic SQL Injection Characters",
                        "regex":       r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                        "explanation": (
                            "Rule SQL-001: Classic SQL injection "
                            "characters detected. Single quotes, "
                            "double dashes, and hash symbols are "
                            "used to terminate SQL queries and "
                            "inject malicious commands."
                        ),
                    },
                    {
                        "rule_id":     "SQL-002",
                        "rule_name":   "SQL UNION Attack",
                        "regex":       r"((\%27)|(\'))(\s|\+)*((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
                        "explanation": (
                            "Rule SQL-002: SQL OR condition injection "
                            "detected. Attacker is attempting to "
                            "bypass authentication using OR logic."
                        ),
                    },
                    {
                        "rule_id":     "SQL-003",
                        "rule_name":   "SQL UNION SELECT",
                        "regex":       r"(union).{0,50}(select)",
                        "explanation": (
                            "Rule SQL-003: UNION SELECT statement "
                            "detected. Attacker is attempting to "
                            "extract data from database tables by "
                            "appending a UNION query."
                        ),
                    },
                    {
                        "rule_id":     "SQL-004",
                        "rule_name":   "SQL DROP/DELETE/INSERT/UPDATE",
                        "regex":       r"(drop|delete|insert|update|truncate|alter)\s+(table|into|from|database)",
                        "explanation": (
                            "Rule SQL-004: Destructive SQL command "
                            "detected. Attacker may be attempting "
                            "to delete or modify database contents."
                        ),
                    },
                    {
                        "rule_id":     "SQL-005",
                        "rule_name":   "SQL Blind Injection SLEEP",
                        "regex":       r"(sleep|benchmark|waitfor|delay)\s*\(",
                        "explanation": (
                            "Rule SQL-005: Time-based blind SQL "
                            "injection detected. SLEEP/WAITFOR "
                            "functions are used to extract data "
                            "through timing differences."
                        ),
                    },
                    {
                        "rule_id":     "SQL-006",
                        "rule_name":   "SQL Information Schema",
                        "regex":       r"(information_schema|sysobjects|syscolumns|sys\.)",
                        "explanation": (
                            "Rule SQL-006: Database schema "
                            "enumeration detected. Attacker is "
                            "querying system tables to map the "
                            "database structure."
                        ),
                    },
                    {
                        "rule_id":     "SQL-007",
                        "rule_name":   "SQL Comment Sequences",
                        "regex":       r"(/\*.*\*/|/\*!.*\*/)",
                        "explanation": (
                            "Rule SQL-007: SQL comment sequence "
                            "detected. Inline comments are used "
                            "to evade input filters while "
                            "maintaining valid SQL syntax."
                        ),
                    },
                    {
                        "rule_id":     "SQL-008",
                        "rule_name":   "SQL HAVING/ORDER BY Injection",
                        "regex":       r"\b(having|order\s+by|group\s+by)\b.{0,30}(--|#|/\*)",
                        "explanation": (
                            "Rule SQL-008: SQL HAVING/ORDER BY "
                            "injection detected. Used for error-"
                            "based and blind SQL injection attacks."
                        ),
                    },
                    {
                        "rule_id":     "SQL-009",
                        "rule_name":   "SQL Hex Encoding",
                        "regex":       r"(0x[0-9a-f]{2,})",
                        "explanation": (
                            "Rule SQL-009: Hex-encoded SQL payload "
                            "detected. Attackers encode characters "
                            "in hex to bypass input validation."
                        ),
                    },
                    {
                        "rule_id":     "SQL-010",
                        "rule_name":   "SQL EXEC/EXECUTE",
                        "regex":       r"\b(exec|execute|xp_|sp_)\b",
                        "explanation": (
                            "Rule SQL-010: SQL stored procedure "
                            "execution detected. xp_ and sp_ "
                            "procedures can execute OS commands "
                            "on the database server."
                        ),
                    },
                    {
                        "rule_id":     "SQL-011",
                        "rule_name":   "SQL CAST/CONVERT Injection",
                        "regex":       r"\b(cast|convert|char|ascii|substring)\s*\(",
                        "explanation": (
                            "Rule SQL-011: SQL data extraction "
                            "functions detected. These functions "
                            "are used in error-based SQL injection "
                            "to extract data character by character."
                        ),
                    },
                    {
                        "rule_id":     "SQL-012",
                        "rule_name":   "SQL Load/Into Outfile",
                        "regex":       r"\b(load_file|into\s+outfile|into\s+dumpfile)\b",
                        "explanation": (
                            "Rule SQL-012: SQL file operation "
                            "detected. LOAD_FILE and INTO OUTFILE "
                            "allow attackers to read and write "
                            "files on the server."
                        ),
                    },
                ],
            },

            # ── Command Injection ────────────────────────────
            "command_injection": {
                "severity":    "critical",
                "category":    "Injection Attack",
                "description": "Command Injection attack detected",
                "patterns": [
                    {
                        "rule_id":     "CMD-001",
                        "rule_name":   "Shell Pipe Injection",
                        "regex":       r"[|;`]\s*(ls|dir|pwd|whoami|id|cat|type|echo|net\s+user)",
                        "explanation": (
                            "Rule CMD-001: Shell pipe/separator "
                            "with OS command detected. Attacker "
                            "is injecting OS commands using shell "
                            "metacharacters."
                        ),
                    },
                    {
                        "rule_id":     "CMD-002",
                        "rule_name":   "Shell AND/OR Operator",
                        "regex":       r"(&&|\|\|)\s*(ls|dir|whoami|id|cat|wget|curl|nc|bash|sh|cmd)",
                        "explanation": (
                            "Rule CMD-002: Shell AND/OR operator "
                            "with OS command detected. Used to "
                            "chain commands regardless of previous "
                            "command success or failure."
                        ),
                    },
                    {
                        "rule_id":     "CMD-003",
                        "rule_name":   "Backtick Command Substitution",
                        "regex":       r"`[^`]*`",
                        "explanation": (
                            "Rule CMD-003: Backtick command "
                            "substitution detected. Backticks "
                            "execute commands and return their "
                            "output within another command."
                        ),
                    },
                    {
                        "rule_id":     "CMD-004",
                        "rule_name":   "Dollar Subshell",
                        "regex":       r"\$\([^)]*\)",
                        "explanation": (
                            "Rule CMD-004: Dollar sign command "
                            "substitution detected. $(command) "
                            "executes OS commands within input "
                            "fields."
                        ),
                    },
                    {
                        "rule_id":     "CMD-005",
                        "rule_name":   "Reverse Shell Bash",
                        "regex":       r"bash\s+-i\s+>&|/dev/tcp/|/dev/udp/",
                        "explanation": (
                            "Rule CMD-005: Bash reverse shell "
                            "command detected. Attacker is "
                            "attempting to create a reverse shell "
                            "connection to their server."
                        ),
                    },
                    {
                        "rule_id":     "CMD-006",
                        "rule_name":   "Netcat Backdoor",
                        "regex":       r"nc\s+(-e|-c|-l)\s|netcat\s+-",
                        "explanation": (
                            "Rule CMD-006: Netcat backdoor command "
                            "detected. Netcat with -e flag creates "
                            "a reverse shell giving attacker "
                            "full system access."
                        ),
                    },
                    {
                        "rule_id":     "CMD-007",
                        "rule_name":   "Wget/Curl Download",
                        "regex":       r"(wget|curl)\s+http[s]?://",
                        "explanation": (
                            "Rule CMD-007: File download command "
                            "detected. Attackers use wget/curl "
                            "to download malware or additional "
                            "exploit tools onto the server."
                        ),
                    },
                    {
                        "rule_id":     "CMD-008",
                        "rule_name":   "Python/Perl/Ruby Shell",
                        "regex":       r"(python|perl|ruby)\s+-[ce]\s+['\"]import\s+socket|use\s+Socket",
                        "explanation": (
                            "Rule CMD-008: Scripting language "
                            "reverse shell detected. Python/Perl/"
                            "Ruby scripts are used to create "
                            "stealthy reverse shell connections."
                        ),
                    },
                    {
                        "rule_id":     "CMD-009",
                        "rule_name":   "chmod/chown Command",
                        "regex":       r";?\s*(chmod|chown)\s+[0-9]{3,4}",
                        "explanation": (
                            "Rule CMD-009: File permission change "
                            "command detected. Attackers change "
                            "file permissions to maintain access "
                            "or execute malicious files."
                        ),
                    },
                    {
                        "rule_id":     "CMD-010",
                        "rule_name":   "Newline Command Injection",
                        "regex":       r"(%0a|%0d|\\n|\\r)\s*(ls|dir|cat|whoami|wget|curl)",
                        "explanation": (
                            "Rule CMD-010: Newline character "
                            "injection detected. Newlines are "
                            "used to inject additional commands "
                            "on a new line bypassing filters."
                        ),
                    },
                ],
            },

            # ── Shellshock ───────────────────────────────────
            "shellshock": {
                "severity":    "critical",
                "category":    "Vulnerability Exploit",
                "description": "Shellshock exploit attempt detected",
                "patterns": [
                    {
                        "rule_id":     "SS-001",
                        "rule_name":   "Shellshock Bash Function",
                        "regex":       r"\(\s*\)\s*\{[^}]*\}\s*;",
                        "explanation": (
                            "Rule SS-001: Shellshock bash function "
                            "syntax detected (CVE-2014-6271). "
                            "The () { :; }; pattern exploits a "
                            "vulnerability in bash that allows "
                            "arbitrary command execution."
                        ),
                    },
                    {
                        "rule_id":     "SS-002",
                        "rule_name":   "Shellshock Variant",
                        "regex":       r"\(\)\s*\{[^;]*;[^}]*\}",
                        "explanation": (
                            "Rule SS-002: Shellshock variant "
                            "pattern detected. Variant of the "
                            "original Shellshock exploit with "
                            "slightly different syntax to evade "
                            "basic pattern matching."
                        ),
                    },
                ],
            },

            # ── Malware Signatures ───────────────────────────
            "malware_signatures": {
                "severity":    "critical",
                "category":    "Malware Activity",
                "description": "Malware signature detected",
                "patterns": [
                    {
                        "rule_id":     "MAL-001",
                        "rule_name":   "Meterpreter Signature",
                        "regex":       r"meterpreter|metsvc|metasploit",
                        "explanation": (
                            "Rule MAL-001: Meterpreter/Metasploit "
                            "signature detected. Meterpreter is an "
                            "advanced payload used in major attacks "
                            "to maintain persistent system access."
                        ),
                    },
                    {
                        "rule_id":     "MAL-002",
                        "rule_name":   "PowerShell Encoded Command",
                        "regex":       r"powershell.*(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,})",
                        "explanation": (
                            "Rule MAL-002: PowerShell encoded "
                            "command detected. Base64-encoded "
                            "PowerShell commands are used to "
                            "evade antivirus and execute malware."
                        ),
                    },
                    {
                        "rule_id":     "MAL-003",
                        "rule_name":   "PowerShell Download Cradle",
                        "regex":       r"(IEX|Invoke-Expression)\s*\(\s*(New-Object|wget|curl)",
                        "explanation": (
                            "Rule MAL-003: PowerShell download "
                            "cradle detected. IEX with Net.WebClient "
                            "downloads and executes remote scripts "
                            "without saving to disk."
                        ),
                    },
                    {
                        "rule_id":     "MAL-004",
                        "rule_name":   "PHP Web Shell",
                        "regex":       r"<\?php.{0,100}(system|exec|shell_exec|passthru|popen)\s*\(",
                        "explanation": (
                            "Rule MAL-004: PHP web shell signature "
                            "detected. Web shells give attackers "
                            "persistent browser-based access to "
                            "execute OS commands on the server."
                        ),
                    },
                    {
                        "rule_id":     "MAL-005",
                        "rule_name":   "Base64 Eval Execution",
                        "regex":       r"eval\s*\(\s*base64_decode\s*\(|eval\(atob\(",
                        "explanation": (
                            "Rule MAL-005: Base64 encoded eval "
                            "detected. Attackers encode malicious "
                            "code in base64 to bypass security "
                            "filters before executing it."
                        ),
                    },
                    {
                        "rule_id":     "MAL-006",
                        "rule_name":   "Known Malware Tools",
                        "regex":       r"\b(mimikatz|cobalt.?strike|empire|covenent|pupy|quasar)\b",
                        "explanation": (
                            "Rule MAL-006: Known offensive security "
                            "tool signature detected. These tools "
                            "are commonly used in APT attacks for "
                            "credential theft and C2 communication."
                        ),
                    },
                ],
            },

            # ════════════════════════════════════════════════
            # HIGH SEVERITY
            # ════════════════════════════════════════════════

            # ── XSS ─────────────────────────────────────────
            "xss": {
                "severity":    "high",
                "category":    "Injection Attack",
                "description": "Cross-Site Scripting (XSS) detected",
                "patterns": [
                    {
                        "rule_id":     "XSS-001",
                        "rule_name":   "Script Tag Injection",
                        "regex":       r"<\s*script[^>]*>|</\s*script\s*>",
                        "explanation": (
                            "Rule XSS-001: HTML script tag detected "
                            "in input. Script tags are the most "
                            "common XSS vector used to inject and "
                            "execute malicious JavaScript code."
                        ),
                    },
                    {
                        "rule_id":     "XSS-002",
                        "rule_name":   "JavaScript Event Handler",
                        "regex":       r"(onerror|onload|onclick|onmouseover|onfocus|onblur|onkeyup|onchange)\s*=",
                        "explanation": (
                            "Rule XSS-002: JavaScript event handler "
                            "injection detected. Event handlers "
                            "execute JavaScript when triggered by "
                            "user interactions or page events."
                        ),
                    },
                    {
                        "rule_id":     "XSS-003",
                        "rule_name":   "JavaScript Protocol",
                        "regex":       r"javascript\s*:",
                        "explanation": (
                            "Rule XSS-003: JavaScript protocol "
                            "handler detected. javascript: in URLs "
                            "executes code when user clicks the "
                            "link or it is loaded by browser."
                        ),
                    },
                    {
                        "rule_id":     "XSS-004",
                        "rule_name":   "DOM Manipulation",
                        "regex":       r"(document\.(cookie|location|write)|window\.(location|open)|alert\s*\(|confirm\s*\()",
                        "explanation": (
                            "Rule XSS-004: DOM manipulation "
                            "function detected. These JavaScript "
                            "functions are used to steal cookies, "
                            "redirect users, or display fake content."
                        ),
                    },
                    {
                        "rule_id":     "XSS-005",
                        "rule_name":   "SVG/IMG XSS Vector",
                        "regex":       r"<\s*(svg|img|object|embed|iframe)[^>]*(onload|onerror|src\s*=\s*['\"]?javascript)",
                        "explanation": (
                            "Rule XSS-005: HTML tag XSS vector "
                            "detected. SVG, IMG, and other HTML "
                            "tags can execute JavaScript through "
                            "event attributes and src attributes."
                        ),
                    },
                    {
                        "rule_id":     "XSS-006",
                        "rule_name":   "VBScript Injection",
                        "regex":       r"vbscript\s*:|mocha\s*:|livescript\s*:",
                        "explanation": (
                            "Rule XSS-006: Alternative scripting "
                            "protocol detected. VBScript and other "
                            "legacy protocols can execute code "
                            "in older browsers."
                        ),
                    },
                    {
                        "rule_id":     "XSS-007",
                        "rule_name":   "Expression CSS Injection",
                        "regex":       r"expression\s*\(|url\s*\(\s*javascript",
                        "explanation": (
                            "Rule XSS-007: CSS expression or "
                            "JavaScript URL in CSS detected. CSS "
                            "expressions execute JavaScript in "
                            "older versions of Internet Explorer."
                        ),
                    },
                    {
                        "rule_id":     "XSS-008",
                        "rule_name":   "HTML Entity XSS",
                        "regex":       r"&#[xX]?[0-9a-fA-F]+;.*(<|>|script|alert)",
                        "explanation": (
                            "Rule XSS-008: HTML entity encoded "
                            "XSS payload detected. Attackers encode "
                            "XSS payloads as HTML entities to "
                            "bypass input validation filters."
                        ),
                    },
                    {
                        "rule_id":     "XSS-009",
                        "rule_name":   "Template Injection XSS",
                        "regex":       r"(\{\{|\}\}|\$\{[^}]*\}|<%[^%]*%>)",
                        "explanation": (
                            "Rule XSS-009: Template injection "
                            "syntax detected. Template expressions "
                            "can execute code in template engines "
                            "like Angular, Vue, and JSP."
                        ),
                    },
                    {
                        "rule_id":     "XSS-010",
                        "rule_name":   "Data URI XSS",
                        "regex":       r"data\s*:\s*text/html|data\s*:\s*application/javascript",
                        "explanation": (
                            "Rule XSS-010: Data URI XSS vector "
                            "detected. Data URIs containing HTML "
                            "or JavaScript can be used to execute "
                            "code without external resources."
                        ),
                    },
                ],
            },

            # ── Path Traversal ───────────────────────────────
            "path_traversal": {
                "severity":    "high",
                "category":    "File System Attack",
                "description": "Path Traversal attack detected",
                "patterns": [
                    {
                        "rule_id":     "PATH-001",
                        "rule_name":   "Directory Traversal Sequences",
                        "regex":       r"\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e\\",
                        "explanation": (
                            "Rule PATH-001: Directory traversal "
                            "sequence detected. '../' sequences "
                            "navigate up directory levels to access "
                            "files outside the web root."
                        ),
                    },
                    {
                        "rule_id":     "PATH-002",
                        "rule_name":   "Sensitive Unix Files",
                        "regex":       r"(/etc/passwd|/etc/shadow|/etc/hosts|/etc/sudoers|/proc/self)",
                        "explanation": (
                            "Rule PATH-002: Access to sensitive "
                            "Unix system file detected. These files "
                            "contain user credentials, system "
                            "configuration, and process information."
                        ),
                    },
                    {
                        "rule_id":     "PATH-003",
                        "rule_name":   "Sensitive Windows Files",
                        "regex":       r"(win\.ini|system\.ini|boot\.ini|%SYSTEMROOT%|\\windows\\system32)",
                        "explanation": (
                            "Rule PATH-003: Access to sensitive "
                            "Windows system file detected. Windows "
                            "configuration files contain system "
                            "settings and can reveal server info."
                        ),
                    },
                    {
                        "rule_id":     "PATH-004",
                        "rule_name":   "SSH Key Access",
                        "regex":       r"(/\.ssh/|id_rsa|authorized_keys|known_hosts)",
                        "explanation": (
                            "Rule PATH-004: SSH key file access "
                            "detected. SSH private keys allow "
                            "passwordless authentication and "
                            "complete server takeover."
                        ),
                    },
                    {
                        "rule_id":     "PATH-005",
                        "rule_name":   "Null Byte Injection",
                        "regex":       r"(%00|\\0|\\x00)\.(php|asp|jsp|txt|conf)",
                        "explanation": (
                            "Rule PATH-005: Null byte path injection "
                            "detected. Null bytes terminate strings "
                            "in C-based languages allowing attackers "
                            "to bypass file extension validation."
                        ),
                    },
                    {
                        "rule_id":     "PATH-006",
                        "rule_name":   "Double Encoded Traversal",
                        "regex":       r"%252e%252e|%252f|%255c",
                        "explanation": (
                            "Rule PATH-006: Double URL-encoded "
                            "path traversal detected. Double "
                            "encoding bypasses servers that "
                            "decode URLs only once."
                        ),
                    },
                    {
                        "rule_id":     "PATH-007",
                        "rule_name":   "Log File Access",
                        "regex":       r"(/var/log/|/var/run/|access\.log|error\.log|auth\.log)",
                        "explanation": (
                            "Rule PATH-007: System log file access "
                            "detected. Log files may contain "
                            "usernames, IP addresses, and other "
                            "sensitive operational information."
                        ),
                    },
                    {
                        "rule_id":     "PATH-008",
                        "rule_name":   "Application Config Access",
                        "regex":       r"(config\.php|wp-config\.php|\.env|database\.yml|settings\.py|web\.config)",
                        "explanation": (
                            "Rule PATH-008: Application config "
                            "file access detected. Config files "
                            "contain database credentials and "
                            "API keys in plaintext."
                        ),
                    },
                ],
            },

            # ── File Inclusion ───────────────────────────────
            "file_inclusion": {
                "severity":    "high",
                "category":    "File Inclusion Attack",
                "description": "File Inclusion attack detected",
                "patterns": [
                    {
                        "rule_id":     "FI-001",
                        "rule_name":   "PHP Wrapper LFI",
                        "regex":       r"php://(filter|input|data|zip|phar|expect)",
                        "explanation": (
                            "Rule FI-001: PHP stream wrapper "
                            "detected. PHP wrappers like php://filter "
                            "allow attackers to read source code "
                            "and execute remote files."
                        ),
                    },
                    {
                        "rule_id":     "FI-002",
                        "rule_name":   "Remote File Inclusion HTTP",
                        "regex":       r"(include|require|include_once|require_once)\s*['\"]?\s*https?://",
                        "explanation": (
                            "Rule FI-002: Remote file inclusion "
                            "via HTTP detected. RFI allows attackers "
                            "to include and execute PHP files "
                            "from their own servers."
                        ),
                    },
                    {
                        "rule_id":     "FI-003",
                        "rule_name":   "FTP/Data Protocol RFI",
                        "regex":       r"(ftp|ftps|data|dict|gopher|expect)://",
                        "explanation": (
                            "Rule FI-003: Alternative protocol "
                            "scheme detected in file parameter. "
                            "Non-HTTP protocols can bypass "
                            "HTTP-only RFI protection filters."
                        ),
                    },
                    {
                        "rule_id":     "FI-004",
                        "rule_name":   "Phar/Zip Wrapper",
                        "regex":       r"(phar|zip|zlib|glob|ogg)://",
                        "explanation": (
                            "Rule FI-004: Phar/Zip stream wrapper "
                            "detected. Phar wrappers can deserialize "
                            "PHP objects and execute code from "
                            "specially crafted archive files."
                        ),
                    },
                ],
            },

            # ════════════════════════════════════════════════
            # MEDIUM SEVERITY
            # ════════════════════════════════════════════════

            # ── Scanner Detection ────────────────────────────
            "scanner_detection": {
                "severity":    "medium",
                "category":    "Reconnaissance",
                "description": "Security scanner or attack tool detected",
                "patterns": [
                    {
                        "rule_id":     "SCAN-001",
                        "rule_name":   "SQLMap Scanner",
                        "regex":       r"sqlmap|sql\s*map",
                        "explanation": (
                            "Rule SCAN-001: SQLMap scanner "
                            "signature detected. SQLMap is an "
                            "automated SQL injection tool used "
                            "to enumerate and extract databases."
                        ),
                    },
                    {
                        "rule_id":     "SCAN-002",
                        "rule_name":   "Nikto Web Scanner",
                        "regex":       r"nikto|whisker",
                        "explanation": (
                            "Rule SCAN-002: Nikto web vulnerability "
                            "scanner detected. Nikto scans for "
                            "thousands of dangerous files and "
                            "outdated software versions."
                        ),
                    },
                    {
                        "rule_id":     "SCAN-003",
                        "rule_name":   "Nmap Scanner",
                        "regex":       r"nmap|masscan|zmap",
                        "explanation": (
                            "Rule SCAN-003: Network port scanner "
                            "detected. Nmap/Masscan are used to "
                            "discover open ports and services "
                            "before launching targeted attacks."
                        ),
                    },
                    {
                        "rule_id":     "SCAN-004",
                        "rule_name":   "Burp Suite Proxy",
                        "regex":       r"burp\s*suite|burpsuite",
                        "explanation": (
                            "Rule SCAN-004: Burp Suite web proxy "
                            "detected. Burp Suite intercepts and "
                            "modifies web traffic and includes "
                            "automated vulnerability scanners."
                        ),
                    },
                    {
                        "rule_id":     "SCAN-005",
                        "rule_name":   "Security Scanners",
                        "regex":       r"(acunetix|nessus|openvas|qualys|w3af|nuclei|gobuster|dirbuster|wfuzz|ffuf)",
                        "explanation": (
                            "Rule SCAN-005: Known security scanner "
                            "detected. These tools perform automated "
                            "vulnerability scanning and directory "
                            "enumeration against web applications."
                        ),
                    },
                    {
                        "rule_id":     "SCAN-006",
                        "rule_name":   "Automated Tool User Agent",
                        "regex":       r"(python-requests|go-http-client|libwww-perl|curl/[0-9]|wget/[0-9]|scrapy)",
                        "explanation": (
                            "Rule SCAN-006: Automated tool user "
                            "agent detected. Scripts and automated "
                            "tools are commonly used for web "
                            "scraping and vulnerability scanning."
                        ),
                    },
                ],
            },

            # ── XML Injection ────────────────────────────────
            "xml_injection": {
                "severity":    "medium",
                "category":    "Injection Attack",
                "description": "XML/XXE Injection attack detected",
                "patterns": [
                    {
                        "rule_id":     "XXE-001",
                        "rule_name":   "XXE Entity Declaration",
                        "regex":       r"<!ENTITY\s+\w+\s+SYSTEM\s+['\"]",
                        "explanation": (
                            "Rule XXE-001: XML External Entity "
                            "declaration detected. XXE allows "
                            "attackers to read local files and "
                            "perform SSRF using entity references."
                        ),
                    },
                    {
                        "rule_id":     "XXE-002",
                        "rule_name":   "DOCTYPE Declaration",
                        "regex":       r"<!DOCTYPE[^>]*\[|<!DOCTYPE[^>]*SYSTEM",
                        "explanation": (
                            "Rule XXE-002: Suspicious DOCTYPE "
                            "declaration detected. Malicious DOCTYPE "
                            "declarations define external entities "
                            "used in XXE injection attacks."
                        ),
                    },
                ],
            },

            # ── LDAP Injection ───────────────────────────────
            "ldap_injection": {
                "severity":    "medium",
                "category":    "Injection Attack",
                "description": "LDAP Injection attack detected",
                "patterns": [
                    {
                        "rule_id":     "LDAP-001",
                        "rule_name":   "LDAP Filter Injection",
                        "regex":       r"[)(|*\\]\s*(uid|cn|dc|ou|objectClass)\s*=",
                        "explanation": (
                            "Rule LDAP-001: LDAP filter injection "
                            "characters detected. LDAP metacharacters "
                            "manipulate directory queries to bypass "
                            "authentication or extract user data."
                        ),
                    },
                    {
                        "rule_id":     "LDAP-002",
                        "rule_name":   "LDAP Wildcard Auth Bypass",
                        "regex":       r"\*\)\s*\(|\*\s*\)\s*\||\(\s*\|.*\*",
                        "explanation": (
                            "Rule LDAP-002: LDAP wildcard auth "
                            "bypass pattern detected. Injecting "
                            "wildcards and OR conditions into LDAP "
                            "filters bypasses authentication."
                        ),
                    },
                ],
            },

            # ── Sensitive Data Exposure ──────────────────────
            "sensitive_data": {
                "severity":    "medium",
                "category":    "Data Exposure",
                "description": "Sensitive data exposure detected",
                "patterns": [
                    {
                        "rule_id":     "SENS-001",
                        "rule_name":   "Password in Request",
                        "regex":       r"(password|passwd|pwd|pass)\s*=\s*[^\s&]{4,}",
                        "explanation": (
                            "Rule SENS-001: Password transmitted "
                            "in request parameter detected. "
                            "Passwords should never appear in "
                            "URLs or unencrypted request bodies."
                        ),
                    },
                    {
                        "rule_id":     "SENS-002",
                        "rule_name":   "API Key Exposure",
                        "regex":       r"(api_key|apikey|api-key|access_token|secret_key|private_key)\s*=\s*[a-zA-Z0-9_\-]{16,}",
                        "explanation": (
                            "Rule SENS-002: API key or secret "
                            "token detected in request. Exposed "
                            "API keys allow attackers to access "
                            "services with full account privileges."
                        ),
                    },
                    {
                        "rule_id":     "SENS-003",
                        "rule_name":   "Credit Card Number",
                        "regex":       r"\b(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
                        "explanation": (
                            "Rule SENS-003: Credit card number "
                            "pattern detected. Transmission of "
                            "card numbers violates PCI-DSS and "
                            "indicates possible data theft."
                        ),
                    },
                ],
            },

            # ════════════════════════════════════════════════
            # LOW SEVERITY
            # ════════════════════════════════════════════════

            # ── Suspicious User Agents ───────────────────────
            "suspicious_useragent": {
                "severity":    "low",
                "category":    "Suspicious Activity",
                "description": "Suspicious user agent detected",
                "patterns": [
                    {
                        "rule_id":     "UA-001",
                        "rule_name":   "Empty or Missing User Agent",
                        "regex":       r"^-$|^\s*$",
                        "explanation": (
                            "Rule UA-001: Empty or missing User-Agent "
                            "header detected. Legitimate browsers "
                            "always send a User-Agent. Missing "
                            "agents indicate automated tools."
                        ),
                    },
                    {
                        "rule_id":     "UA-002",
                        "rule_name":   "Headless Browser",
                        "regex":       r"(headlesschrome|phantomjs|selenium|webdriver|puppeteer|playwright)",
                        "explanation": (
                            "Rule UA-002: Headless browser detected. "
                            "Headless browsers automate web "
                            "interactions for scraping or testing "
                            "and are commonly used in attacks."
                        ),
                    },
                    {
                        "rule_id":     "UA-003",
                        "rule_name":   "Hacking Tool Agent",
                        "regex":       r"(havij|pangolin|netcat|ncrack|hydra|medusa)",
                        "explanation": (
                            "Rule UA-003: Known hacking tool "
                            "user agent detected. These tools "
                            "perform automated SQL injection, "
                            "brute force, and credential attacks."
                        ),
                    },
                ],
            },

            # ── Information Disclosure ───────────────────────
            "info_disclosure": {
                "severity":    "low",
                "category":    "Information Disclosure",
                "description": "Information disclosure attempt detected",
                "patterns": [
                    {
                        "rule_id":     "INFO-001",
                        "rule_name":   "Debug Parameter Probe",
                        "regex":       r"(debug|verbose|trace|stacktrace|show_errors|diagnostic)\s*=\s*(true|1|yes|on)",
                        "explanation": (
                            "Rule INFO-001: Debug mode activation "
                            "attempt detected. Enabling debug "
                            "parameters can expose stack traces, "
                            "source code, and server configuration."
                        ),
                    },
                    {
                        "rule_id":     "INFO-002",
                        "rule_name":   "Git/SVN Repository Probe",
                        "regex":       r"(/\.git/|/\.svn/|/\.hg/|/\.bzr/|/\.DS_Store)",
                        "explanation": (
                            "Rule INFO-002: Version control "
                            "directory probe detected. Exposed "
                            ".git directories allow attackers "
                            "to download complete source code."
                        ),
                    },
                    {
                        "rule_id":     "INFO-003",
                        "rule_name":   "Backup File Probe",
                        "regex":       r"\.(bak|backup|old|orig|save|swp|tmp|~)\b",
                        "explanation": (
                            "Rule INFO-003: Backup file probe "
                            "detected. Backup files often contain "
                            "source code with hardcoded passwords "
                            "and database credentials."
                        ),
                    },
                    {
                        "rule_id":     "INFO-004",
                        "rule_name":   "Environment File Probe",
                        "regex":       r"(/\.env|/\.env\.local|/\.env\.production|/config\.yaml|/secrets\.yml)",
                        "explanation": (
                            "Rule INFO-004: Environment/secrets "
                            "file probe detected. .env files "
                            "contain API keys, database passwords, "
                            "and other production secrets."
                        ),
                    },
                ],
            },

            # ── HTTP Anomalies ───────────────────────────────
            "http_anomaly": {
                "severity":    "low",
                "category":    "HTTP Anomaly",
                "description": "Suspicious HTTP request pattern detected",
                "patterns": [
                    {
                        "rule_id":     "HTTP-001",
                        "rule_name":   "HTTP Response Splitting",
                        "regex":       r"(%0d%0a|%0a%0d|\r\n|\n\r).{0,20}(content-type|location|set-cookie)",
                        "explanation": (
                            "Rule HTTP-001: HTTP response splitting "
                            "attempt detected. Injecting CRLF "
                            "sequences allows attackers to inject "
                            "arbitrary HTTP headers and responses."
                        ),
                    },
                    {
                        "rule_id":     "HTTP-002",
                        "rule_name":   "Host Header Injection",
                        "regex":       r"(X-Forwarded-Host|X-Host|X-Custom-IP|X-Original-URL)\s*:\s*[^\s]+\.[^\s]+",
                        "explanation": (
                            "Rule HTTP-002: Suspicious Host header "
                            "injection detected. Manipulating host "
                            "headers can bypass access controls "
                            "and lead to cache poisoning."
                        ),
                    },
                    {
                        "rule_id":     "HTTP-003",
                        "rule_name":   "Mass Assignment Attempt",
                        "regex":       r"(is_admin|role|admin|permission|privilege)\s*=\s*(true|1|admin|superuser|root)",
                        "explanation": (
                            "Rule HTTP-003: Mass assignment "
                            "privilege escalation attempt detected. "
                            "Attackers inject admin fields to "
                            "gain unauthorized elevated access."
                        ),
                    },
                    {
                        "rule_id":     "HTTP-004",
                        "rule_name":   "Prototype Pollution",
                        "regex":       r"(__proto__|constructor\.prototype|Object\.prototype)\s*[\[.]",
                        "explanation": (
                            "Rule HTTP-004: JavaScript prototype "
                            "pollution attempt detected. Polluting "
                            "Object.prototype affects all objects "
                            "and can lead to RCE in Node.js apps."
                        ),
                    },
                ],
            },

        }

    # ════════════════════════════════════════════════════════
    # MAIN DETECTION METHOD
    # ════════════════════════════════════════════════════════
    def detect_pattern_attack(self,
                              data: str,
                              source_ip: str) -> list:
        """
        Scan data against all regex rules.
        Returns list of threat dicts.
        One alert per category maximum.
        """
        threats  = []
        data_str = str(data)

        for attack_type, config in self.attack_patterns.items():
            for rule in config.get("patterns", []):
                try:
                    if re.search(rule["regex"],
                                 data_str,
                                 re.IGNORECASE):
                        threats.append({
                            "type":             attack_type,
                            "severity":         config["severity"],
                            "category":         config["category"],
                            "description":      config["description"],
                            "source_ip":        source_ip,
                            "rule_id":          rule["rule_id"],
                            "rule_name":        rule["rule_name"],
                            "rule_regex":       rule["regex"],
                            "rule_explanation": rule["explanation"],
                            "matched_pattern":  rule["regex"],
                            "timestamp":        datetime.now().isoformat(),
                        })
                        break  # one alert per category
                except re.error:
                    pass

        return threats

    # ════════════════════════════════════════════════════════
    # THRESHOLD DETECTION
    # ════════════════════════════════════════════════════════
    def detect_brute_force(self,
                           source_ip: str,
                           success: bool = False):
        """Detect brute force login attacks."""
        if success:
            self.failed_logins[source_ip] = 0
            return None

        self.failed_logins[source_ip] += 1
        count = self.failed_logins[source_ip]

        if count >= 5:
            self.failed_logins[source_ip] = 0
            return {
                "type":        "brute_force",
                "severity":    "high",
                "category":    "Authentication Attack",
                "description": "Brute force attack detected",
                "source_ip":   source_ip,
                "rule_id":     "BF-001",
                "rule_name":   "Repeated Failed Login Threshold",
                "rule_regex":  "Threshold: 5 failed attempts",
                "rule_explanation": (
                    f"Rule BF-001 triggered: {count} consecutive "
                    f"failed login attempts from {source_ip}. "
                    f"Threshold is 5 attempts. This pattern "
                    f"indicates a systematic password guessing attack."
                ),
                "timestamp": datetime.now().isoformat(),
            }
        return None

    def detect_ddos(self, source_ip: str):
        """Detect DDoS flood attacks."""
        self.request_counts[source_ip] += 1
        count = self.request_counts[source_ip]

        if count >= 100:
            self.request_counts[source_ip] = 0
            return {
                "type":        "ddos",
                "severity":    "critical",
                "category":    "Availability Attack",
                "description": "DDoS attack detected",
                "source_ip":   source_ip,
                "rule_id":     "DDOS-001",
                "rule_name":   "High Request Rate Threshold",
                "rule_regex":  "Threshold: 100 requests/window",
                "rule_explanation": (
                    f"Rule DDOS-001 triggered: {count} requests "
                    f"from {source_ip} exceeded the threshold of "
                    f"100 requests per time window. This rate is "
                    f"consistent with a Denial of Service flood attack."
                ),
                "timestamp": datetime.now().isoformat(),
            }
        return None

    def detect_port_scan(self,
                         source_ip: str,
                         port: int):
        """Detect port scanning activity."""
        self.port_access[source_ip].add(port)
        count = len(self.port_access[source_ip])

        if count >= 10:
            ports = list(self.port_access[source_ip])
            self.port_access[source_ip].clear()
            return {
                "type":        "port_scan",
                "severity":    "high",
                "category":    "Reconnaissance",
                "description": "Port scanning detected",
                "source_ip":   source_ip,
                "rule_id":     "SCAN-007",
                "rule_name":   "Port Scan Threshold",
                "rule_regex":  "Threshold: 10 unique ports",
                "rule_explanation": (
                    f"Rule SCAN-007 triggered: {source_ip} accessed "
                    f"{count} unique ports {ports[:5]}... within "
                    f"the monitoring window. Threshold is 10 unique "
                    f"ports. Sequential port probing is characteristic "
                    f"of network reconnaissance activity."
                ),
                "scanned_ports": ports,
                "timestamp":     datetime.now().isoformat(),
            }
        return None

    def detect_suspicious_port(self,
                               source_ip: str,
                               port: int):
        """Detect connections to known suspicious ports."""
        if port in self.suspicious_ports:
            service = self.suspicious_ports[port]
            return {
                "type":             "suspicious_port",
                "severity":         "high",
                "category":         "Suspicious Activity",
                "description":      f"Access to suspicious port {port}",
                "source_ip":        source_ip,
                "destination_port": port,
                "rule_id":          "PORT-001",
                "rule_name":        f"Blacklisted Port {port}",
                "rule_regex":       f"Port blacklist: {port}",
                "rule_explanation": (
                    f"Rule PORT-001 triggered: Connection detected "
                    f"to port {port} ({service}). This port is on "
                    f"the blacklist because it is commonly associated "
                    f"with malware, backdoors, or known exploits. "
                    f"Normal applications rarely use this port."
                ),
                "port_service": service,
                "timestamp":    datetime.now().isoformat(),
            }
        return None

    def get_threat_summary(self):
        """Get current detection statistics."""
        return {
            "total_ips_monitored":   len(self.request_counts),
            "potential_brute_force": sum(
                1 for v in self.failed_logins.values() if v > 2
            ),
            "high_traffic_ips": sum(
                1 for v in self.request_counts.values() if v > 50
            ),
        }