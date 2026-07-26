"""
AI Explainer Module
Pre-written explanations for all 15 attack categories
Severity comes from rule-based detection only
"""
from datetime import datetime


class AIExplainer:
    def __init__(self):
        self.explanations = self._load_explanations()

    def _load_explanations(self):
        return {
            "sql_injection": {
                "what_is_it": (
                    "SQL Injection is an attack where malicious "
                    "SQL code is inserted into input fields to "
                    "manipulate the database. The attacker tricks "
                    "the application into executing unintended SQL "
                    "commands."
                ),
                "how_it_works": (
                    "1. Attacker finds an input field that passes "
                    "data to a SQL query\n"
                    "2. Injects SQL syntax like ' OR 1=1 -- \n"
                    "3. The database executes the malicious query\n"
                    "4. Attacker gains unauthorized data access"
                ),
                "why_dangerous": (
                    "Can expose entire databases, bypass login "
                    "authentication, delete or modify data, and "
                    "in some cases execute OS commands."
                ),
                "real_example": (
                    "In 2019, a major retailer lost 77 million "
                    "customer records due to SQL injection in their "
                    "login form. Attackers used a simple ' OR '1'='1 "
                    "payload to bypass authentication."
                ),
                "potential_impact": [
                    "Complete database exposure",
                    "Authentication bypass",
                    "Data theft and modification",
                    "Complete system compromise",
                    "Regulatory fines (GDPR/HIPAA)",
                ],
                "user_can_do": [
                    "Review and block the source IP",
                    "Acknowledge and document the alert",
                    "Mark as false positive if legitimate",
                    "Generate a report for compliance",
                    "Add note with investigation findings",
                ],
                "user_cannot_do": [
                    "Patch the vulnerable application automatically",
                    "Recover already exfiltrated data",
                    "Trace attacker beyond their IP address",
                ],
                "prevention_tips": [
                    "Use parameterized queries / prepared statements",
                    "Implement input validation and sanitization",
                    "Apply principle of least privilege to DB users",
                    "Use a Web Application Firewall (WAF)",
                    "Regular security code reviews",
                ],
            },
            "xss": {
                "what_is_it": (
                    "Cross-Site Scripting (XSS) injects malicious "
                    "scripts into web pages viewed by other users. "
                    "The scripts execute in victims browsers."
                ),
                "how_it_works": (
                    "1. Attacker finds an input that reflects "
                    "content back to users\n"
                    "2. Injects <script>malicious code</script>\n"
                    "3. Victim visits the page with injected script\n"
                    "4. Script executes stealing cookies or data"
                ),
                "why_dangerous": (
                    "Allows session hijacking, credential theft, "
                    "malware distribution, and defacement of websites."
                ),
                "real_example": (
                    "The 2018 British Airways breach involved XSS "
                    "to inject a payment skimmer, stealing 500,000 "
                    "customer credit card details."
                ),
                "potential_impact": [
                    "Session cookie theft",
                    "Account takeover",
                    "Malware distribution to visitors",
                    "Website defacement",
                    "Phishing attacks via trusted domain",
                ],
                "user_can_do": [
                    "Block the attacking IP address",
                    "Acknowledge the alert",
                    "Document the attack vector",
                    "Report to development team",
                ],
                "user_cannot_do": [
                    "Fix the XSS vulnerability automatically",
                    "Protect users already affected",
                    "Remove injected content from CDN caches",
                ],
                "prevention_tips": [
                    "Encode output data properly",
                    "Implement Content Security Policy (CSP)",
                    "Use HTTPOnly and Secure cookie flags",
                    "Validate and sanitize all inputs",
                    "Regular penetration testing",
                ],
            },
            "path_traversal": {
                "what_is_it": (
                    "Path traversal attacks use ../ sequences to "
                    "navigate outside the web root directory and "
                    "access sensitive system files."
                ),
                "how_it_works": (
                    "1. Attacker manipulates file path parameters\n"
                    "2. Uses sequences like ../../etc/passwd\n"
                    "3. Server resolves path outside web root\n"
                    "4. Sensitive files are read or executed"
                ),
                "why_dangerous": (
                    "Can expose system configuration files, "
                    "passwords, private keys, and application "
                    "source code."
                ),
                "real_example": (
                    "In 2021, a vulnerability in Pulse Secure VPN "
                    "allowed path traversal to read private keys "
                    "and credentials from thousands of organizations."
                ),
                "potential_impact": [
                    "Exposure of /etc/passwd and system files",
                    "Private key and certificate theft",
                    "Application source code disclosure",
                    "Configuration file exposure",
                ],
                "user_can_do": [
                    "Block the source IP immediately",
                    "Review what files may have been accessed",
                    "Acknowledge and escalate the alert",
                ],
                "user_cannot_do": [
                    "Determine if files were successfully read",
                    "Automatically patch the directory traversal",
                ],
                "prevention_tips": [
                    "Validate and sanitize file path inputs",
                    "Use chroot jails or containers",
                    "Implement strict access controls",
                    "Never expose raw file paths to users",
                ],
            },
            "command_injection": {
                "what_is_it": (
                    "Command injection allows attackers to execute "
                    "arbitrary operating system commands on the "
                    "server through vulnerable input fields."
                ),
                "how_it_works": (
                    "1. Application passes user input to OS command\n"
                    "2. Attacker injects ; id; or | whoami\n"
                    "3. Server executes both legitimate and "
                    "malicious commands\n"
                    "4. Attacker gains OS-level access"
                ),
                "why_dangerous": (
                    "Provides direct OS access, allowing data theft, "
                    "backdoor installation, and complete system "
                    "compromise."
                ),
                "real_example": (
                    "The 2014 Shellshock vulnerability allowed "
                    "command injection via Bash environment variables, "
                    "affecting millions of web servers worldwide."
                ),
                "potential_impact": [
                    "Complete server compromise",
                    "Backdoor installation",
                    "Data exfiltration",
                    "Lateral movement within network",
                    "Ransomware deployment",
                ],
                "user_can_do": [
                    "Block attacker IP immediately",
                    "Check server logs for executed commands",
                    "Escalate to incident response team",
                ],
                "user_cannot_do": [
                    "Undo already executed commands",
                    "Automatically patch the vulnerability",
                ],
                "prevention_tips": [
                    "Never pass user input directly to OS commands",
                    "Use language APIs instead of shell commands",
                    "Implement strict input validation",
                    "Run applications with minimal OS privileges",
                ],
            },
            "brute_force": {
                "what_is_it": (
                    "Brute force attacks systematically try all "
                    "possible password combinations until the "
                    "correct one is found."
                ),
                "how_it_works": (
                    "1. Attacker identifies login endpoint\n"
                    "2. Automates login attempts with wordlists\n"
                    "3. Tries thousands of username/password combos\n"
                    "4. Gains access on successful match"
                ),
                "why_dangerous": (
                    "Weak or reused passwords are quickly cracked, "
                    "leading to account takeover and unauthorized "
                    "access."
                ),
                "real_example": (
                    "In 2020, the SolarWinds attack began with "
                    "brute force against exposed admin panels using "
                    "the password SolarWinds123."
                ),
                "potential_impact": [
                    "Unauthorized account access",
                    "Data theft from compromised accounts",
                    "Administrative takeover",
                    "Pivoting to internal systems",
                ],
                "user_can_do": [
                    "Block the attacking IP",
                    "Enable account lockout policies",
                    "Force password reset for targeted accounts",
                    "Enable multi-factor authentication",
                ],
                "user_cannot_do": [
                    "Determine if any login succeeded",
                    "Identify all attack sources if using proxies",
                ],
                "prevention_tips": [
                    "Implement account lockout after failed attempts",
                    "Enable multi-factor authentication (MFA)",
                    "Use CAPTCHA on login forms",
                    "Monitor and alert on login failures",
                    "Enforce strong password policies",
                ],
            },
            "ddos": {
                "what_is_it": (
                    "Distributed Denial of Service floods servers "
                    "with massive traffic to exhaust resources and "
                    "make services unavailable to legitimate users."
                ),
                "how_it_works": (
                    "1. Attacker controls botnet of compromised "
                    "machines\n"
                    "2. Commands all bots to flood the target\n"
                    "3. Server resources are exhausted\n"
                    "4. Legitimate users cannot access service"
                ),
                "why_dangerous": (
                    "Causes service downtime, revenue loss, "
                    "reputational damage, and can be used as "
                    "a distraction for other attacks."
                ),
                "real_example": (
                    "The 2016 Mirai botnet DDoS attack took down "
                    "major internet services including Twitter, "
                    "Netflix, and Reddit using IoT devices."
                ),
                "potential_impact": [
                    "Complete service outage",
                    "Revenue loss during downtime",
                    "Reputational damage",
                    "Infrastructure costs from traffic",
                ],
                "user_can_do": [
                    "Block high-traffic source IPs",
                    "Enable rate limiting",
                    "Contact ISP for upstream filtering",
                    "Document attack patterns",
                ],
                "user_cannot_do": [
                    "Stop distributed attack from all sources",
                    "Identify all attacker-controlled IPs",
                ],
                "prevention_tips": [
                    "Implement rate limiting and throttling",
                    "Use CDN with DDoS protection",
                    "Configure traffic filtering rules",
                    "Have an incident response plan ready",
                    "Use cloud-based DDoS mitigation services",
                ],
            },
            "port_scan": {
                "what_is_it": (
                    "Port scanning probes a network host to "
                    "discover open ports and running services "
                    "as reconnaissance for future attacks."
                ),
                "how_it_works": (
                    "1. Attacker sends probes to multiple ports\n"
                    "2. Analyzes responses to map open services\n"
                    "3. Identifies potentially vulnerable services\n"
                    "4. Uses findings to plan targeted attacks"
                ),
                "why_dangerous": (
                    "Provides attackers with a map of attack "
                    "surface, enabling targeted exploitation of "
                    "discovered services."
                ),
                "real_example": (
                    "Most major breaches begin with port scanning. "
                    "The 2017 Equifax breach started with "
                    "reconnaissance scans identifying an unpatched "
                    "Apache Struts server."
                ),
                "potential_impact": [
                    "Network topology exposure",
                    "Service and version fingerprinting",
                    "Attack surface mapping",
                    "Targeted follow-up exploitation",
                ],
                "user_can_do": [
                    "Block the scanning IP",
                    "Review which ports are exposed",
                    "Audit firewall rules",
                ],
                "user_cannot_do": [
                    "Determine what the attacker plans to do",
                    "Hide already discovered open ports",
                ],
                "prevention_tips": [
                    "Close unnecessary open ports",
                    "Implement port knocking",
                    "Use firewall to restrict port access",
                    "Monitor for scanning patterns",
                ],
            },
            "suspicious_port": {
                "what_is_it": (
                    "Connection to a port associated with malware, "
                    "backdoors, remote access tools, or known "
                    "exploit frameworks."
                ),
                "how_it_works": (
                    "1. Malware or attacker tool opens connection\n"
                    "2. Uses well-known backdoor port numbers\n"
                    "3. Establishes command and control channel\n"
                    "4. Attacker sends commands to compromised host"
                ),
                "why_dangerous": (
                    "May indicate active malware infection, "
                    "established backdoor, or command and control "
                    "communication."
                ),
                "real_example": (
                    "Port 4444 is the default Metasploit listener. "
                    "Port 31337 (BackOrifice) was used in numerous "
                    "corporate espionage cases in the 2000s."
                ),
                "potential_impact": [
                    "Active malware infection",
                    "Established attacker backdoor",
                    "Data exfiltration channel",
                    "Lateral movement within network",
                ],
                "user_can_do": [
                    "Block the IP and port immediately",
                    "Isolate the affected host",
                    "Run malware scan on affected systems",
                ],
                "user_cannot_do": [
                    "Automatically remove malware",
                    "Determine scope of compromise from IDS alone",
                ],
                "prevention_tips": [
                    "Block known malware ports at firewall",
                    "Monitor outbound connections",
                    "Deploy endpoint detection and response (EDR)",
                    "Regular malware scanning",
                ],
            },
            "scanner_detection": {
                "what_is_it": (
                    "Automated security scanning tools like Nikto, "
                    "SQLmap, or Nessus probing for vulnerabilities "
                    "in web applications and services."
                ),
                "how_it_works": (
                    "1. Attacker runs automated scanner tool\n"
                    "2. Tool sends thousands of test requests\n"
                    "3. Identifies vulnerable endpoints\n"
                    "4. Attacker uses findings for targeted attack"
                ),
                "why_dangerous": (
                    "Automated scanners quickly identify "
                    "vulnerabilities that can then be exploited "
                    "with targeted attacks."
                ),
                "real_example": (
                    "Many bug bounty hunters and attackers use "
                    "Nikto and Burp Suite to scan targets. Detected "
                    "User-Agent strings reveal the tool being used."
                ),
                "potential_impact": [
                    "Vulnerability discovery by attackers",
                    "Application fingerprinting",
                    "Automated exploit attempts",
                    "Increased server load from scan traffic",
                ],
                "user_can_do": [
                    "Block the scanner IP",
                    "Review what endpoints were scanned",
                    "Check if any vulnerabilities were exposed",
                ],
                "user_cannot_do": [
                    "Determine what the scanner found",
                    "Prevent scanning from distributed sources",
                ],
                "prevention_tips": [
                    "Block known scanner User-Agents",
                    "Implement rate limiting",
                    "Use WAF with bot detection",
                    "Run your own scans first to find issues",
                ],
            },
            "file_inclusion": {
                "what_is_it": (
                    "File inclusion attacks trick the server into "
                    "including and executing unintended files, "
                    "either local (LFI) or remote (RFI)."
                ),
                "how_it_works": (
                    "1. Application includes files based on user "
                    "input\n"
                    "2. Attacker manipulates the file parameter\n"
                    "3. LFI reads local system files\n"
                    "4. RFI executes attacker-hosted malicious code"
                ),
                "why_dangerous": (
                    "Can lead to remote code execution, "
                    "sensitive file disclosure, and complete "
                    "server compromise."
                ),
                "real_example": (
                    "In 2020, numerous WordPress plugins with LFI "
                    "vulnerabilities were exploited to read wp-config"
                    ".php containing database credentials."
                ),
                "potential_impact": [
                    "Remote code execution (RFI)",
                    "Sensitive file disclosure (LFI)",
                    "Database credential exposure",
                    "Full server compromise",
                ],
                "user_can_do": [
                    "Block the attacking IP",
                    "Identify what files were targeted",
                    "Escalate to development team",
                ],
                "user_cannot_do": [
                    "Automatically fix the vulnerability",
                    "Determine if attack was successful",
                ],
                "prevention_tips": [
                    "Never use user input in file paths",
                    "Whitelist allowed file names",
                    "Disable remote file inclusion in PHP config",
                    "Use chroot/containerization",
                ],
            },
            "shellshock": {
                "what_is_it": (
                    "Shellshock is a critical Bash vulnerability "
                    "(CVE-2014-6271) allowing attackers to execute "
                    "arbitrary commands via environment variables."
                ),
                "how_it_works": (
                    "1. Attacker crafts malicious HTTP headers\n"
                    "2. Header contains () { :; }; malicious_cmd\n"
                    "3. Vulnerable Bash executes the command\n"
                    "4. Attacker gains OS command execution"
                ),
                "why_dangerous": (
                    "Affects any service that uses Bash to process "
                    "requests, including CGI scripts, DHCP clients, "
                    "and SSH. Allows immediate RCE."
                ),
                "real_example": (
                    "Within 24 hours of Shellshock disclosure in "
                    "2014, millions of servers were scanned and "
                    "thousands compromised including servers at "
                    "major cloud providers."
                ),
                "potential_impact": [
                    "Immediate remote code execution",
                    "Backdoor installation",
                    "Botnet recruitment",
                    "Complete server compromise",
                ],
                "user_can_do": [
                    "Block the attacking IP immediately",
                    "Patch Bash to latest version urgently",
                    "Check for signs of compromise",
                ],
                "user_cannot_do": [
                    "Automatically patch the vulnerability",
                    "Undo any commands already executed",
                ],
                "prevention_tips": [
                    "Update Bash immediately (patch available)",
                    "Disable CGI scripts if not needed",
                    "Use WAF rules to block Shellshock patterns",
                    "Monitor for unusual process spawning",
                ],
            },
            "malware_signatures": {
                "what_is_it": (
                    "Traffic matching known malware signatures, "
                    "C2 communication patterns, or exploit kit "
                    "fingerprints in request data."
                ),
                "how_it_works": (
                    "1. Malware on client connects to C2 server\n"
                    "2. Sends beacons with characteristic patterns\n"
                    "3. IDS rule matches known malware signature\n"
                    "4. Alert generated for investigation"
                ),
                "why_dangerous": (
                    "Indicates active malware infection that may be "
                    "communicating with attacker infrastructure or "
                    "exfiltrating data."
                ),
                "real_example": (
                    "Emotet malware uses distinctive HTTP patterns "
                    "for C2 communication. Many organizations "
                    "discovered infections through IDS signature "
                    "matching."
                ),
                "potential_impact": [
                    "Active infection confirmed",
                    "Data exfiltration in progress",
                    "Ransomware deployment imminent",
                    "Lateral movement within network",
                ],
                "user_can_do": [
                    "Block C2 IP addresses immediately",
                    "Isolate potentially infected hosts",
                    "Run emergency malware scans",
                    "Preserve logs for forensic analysis",
                ],
                "user_cannot_do": [
                    "Remove malware automatically",
                    "Recover exfiltrated data",
                ],
                "prevention_tips": [
                    "Deploy endpoint detection and response",
                    "Block known malware C2 domains/IPs",
                    "User security awareness training",
                    "Email filtering for malware attachments",
                ],
            },
            "xml_injection": {
                "what_is_it": (
                    "XML/XXE injection attacks exploit XML parsers "
                    "to read local files, make server-side requests, "
                    "or cause denial of service."
                ),
                "how_it_works": (
                    "1. Application accepts XML input\n"
                    "2. Attacker injects malicious DOCTYPE\n"
                    "3. Parser processes external entity reference\n"
                    "4. Server reads local files or makes requests"
                ),
                "why_dangerous": (
                    "Can expose internal files, perform SSRF attacks, "
                    "enable port scanning, and cause DoS via "
                    "billion laughs attack."
                ),
                "real_example": (
                    "In 2019, a XXE vulnerability in a major "
                    "financial institution API allowed reading of "
                    "internal configuration files including AWS "
                    "credentials."
                ),
                "potential_impact": [
                    "Internal file system access",
                    "SSRF to internal services",
                    "Cloud credential theft (AWS/Azure metadata)",
                    "Denial of service via recursive entities",
                ],
                "user_can_do": [
                    "Block the attacking IP",
                    "Disable XML if not required",
                    "Alert development team",
                ],
                "user_cannot_do": [
                    "Fix XML parser configuration automatically",
                ],
                "prevention_tips": [
                    "Disable external entity processing in XML",
                    "Use JSON instead of XML where possible",
                    "Validate and sanitize XML input",
                    "Use updated XML libraries",
                ],
            },
            "ldap_injection": {
                "what_is_it": (
                    "LDAP injection manipulates LDAP queries to "
                    "bypass authentication, access unauthorized "
                    "directory data, or extract sensitive information."
                ),
                "how_it_works": (
                    "1. Application constructs LDAP query from "
                    "user input\n"
                    "2. Attacker injects LDAP special characters\n"
                    "3. Query logic is modified\n"
                    "4. Authentication bypassed or data extracted"
                ),
                "why_dangerous": (
                    "LDAP directories often contain all user "
                    "credentials, group memberships, and "
                    "organizational data."
                ),
                "real_example": (
                    "Multiple Active Directory integrations have "
                    "been compromised via LDAP injection allowing "
                    "complete directory enumeration."
                ),
                "potential_impact": [
                    "Authentication bypass",
                    "Complete directory data extraction",
                    "User credential exposure",
                    "Privilege escalation",
                ],
                "user_can_do": [
                    "Block the attacking IP",
                    "Review LDAP query logs",
                    "Force password resets if compromise suspected",
                ],
                "user_cannot_do": [
                    "Automatically fix LDAP query construction",
                ],
                "prevention_tips": [
                    "Use parameterized LDAP queries",
                    "Escape special LDAP characters in input",
                    "Implement least-privilege LDAP accounts",
                    "Monitor LDAP query patterns",
                ],
            },
            "sensitive_data": {
                "what_is_it": (
                    "Detection of sensitive data patterns such as "
                    "API keys, passwords, credit card numbers, or "
                    "private keys in request data."
                ),
                "how_it_works": (
                    "1. Sensitive data appears in request parameters\n"
                    "2. May indicate data exfiltration attempt\n"
                    "3. Or misconfigured client sending credentials\n"
                    "4. IDS pattern matches sensitive data format"
                ),
                "why_dangerous": (
                    "Exposed credentials enable account takeover, "
                    "financial fraud, and can trigger regulatory "
                    "compliance violations."
                ),
                "real_example": (
                    "In 2021, Twitch suffered a breach where API "
                    "keys and internal credentials were exposed in "
                    "git repositories and request logs."
                ),
                "potential_impact": [
                    "Credential theft and account takeover",
                    "Financial fraud via card data",
                    "Regulatory violations (PCI-DSS, GDPR)",
                    "API abuse with stolen keys",
                ],
                "user_can_do": [
                    "Immediately revoke exposed credentials",
                    "Block the source IP",
                    "Audit what data was exposed",
                    "File compliance incident report",
                ],
                "user_cannot_do": [
                    "Recall already transmitted sensitive data",
                    "Automatically rotate all credentials",
                ],
                "prevention_tips": [
                    "Never send credentials in URL parameters",
                    "Use environment variables for secrets",
                    "Implement data loss prevention (DLP)",
                    "Encrypt sensitive data in transit and at rest",
                    "Regular credential rotation",
                ],
            },
        }

    def get_explanation(self, alert: dict):
        alert_type = alert.get("type", "unknown")
        exp        = self.explanations.get(
            alert_type,
            self._get_default_explanation(alert_type)
        )

        rule_details = {
            "rule_id":          alert.get("rule_id", "N/A"),
            "rule_name":        alert.get("rule_name", "N/A"),
            "rule_pattern":     alert.get("rule_regex", "N/A"),
            "detection_method": (
                "Signature-based pattern matching"
                if alert.get("rule_id")
                else "Threshold-based detection"
            ),
            "why_this_is_attack": alert.get(
                "rule_explanation", "N/A"
            ),
            "payload_sample":   (
                alert.get("details", {}).get(
                    "payload_sample", "N/A"
                )
            ),
        }

        sev = alert.get("severity", "medium")
        if sev == "critical":
            risk_level = "CRITICAL"
        elif sev == "high":
            risk_level = "HIGH"
        elif sev == "medium":
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "alert_id":       alert.get("id"),
            "alert_type":     alert_type,
            "summary":        (
                f"A {alert_type.replace('_', ' ').title()} "
                f"attack was detected from "
                f"{alert.get('source_ip', 'unknown')} "
                f"with {sev.upper()} severity based on "
                f"rule {rule_details['rule_id']}."
            ),
            "risk_level":        risk_level,
            "rule_details":      rule_details,
            "what_is_it":        exp.get("what_is_it", ""),
            "how_it_works":      exp.get("how_it_works", ""),
            "why_dangerous":     exp.get("why_dangerous", ""),
            "real_example":      exp.get("real_example", ""),
            "potential_impact":  exp.get(
                "potential_impact", []
            ),
            "user_can_do":       exp.get("user_can_do", []),
            "user_cannot_do":    exp.get(
                "user_cannot_do", []
            ),
            "prevention_tips":   exp.get(
                "prevention_tips", []
            ),
            "technical_details": {
                "source_ip":        alert.get("source_ip"),
                "destination_ip":   alert.get(
                    "destination_ip"
                ),
                "destination_port": alert.get(
                    "destination_port"
                ),
                "severity":         sev,
                "status":           alert.get("status"),
                "timestamp":        alert.get("timestamp"),
                "detection_source": alert.get(
                    "detection_source", "rule"
                ),
                "ml_detected":      alert.get(
                    "ml_detected", False
                ),
                "ml_confidence":    alert.get(
                    "ml_confidence", 0
                ),
            },
        }

    def _get_default_explanation(self, alert_type):
        return {
            "what_is_it": (
                f"A {alert_type.replace('_', ' ')} "
                f"threat was detected in network traffic."
            ),
            "how_it_works": (
                "The IDS detected a pattern matching "
                "known attack signatures."
            ),
            "why_dangerous": (
                "This type of activity may indicate "
                "malicious intent or active attack."
            ),
            "real_example": (
                "Various attacks of this type have been "
                "documented in security research."
            ),
            "potential_impact": [
                "Unauthorized access",
                "Data exposure",
                "Service disruption",
            ],
            "user_can_do": [
                "Block the source IP",
                "Acknowledge the alert",
                "Investigate the source",
                "Add notes to document findings",
            ],
            "user_cannot_do": [
                "Automatically remediate the vulnerability",
                "Guarantee the attack was unsuccessful",
            ],
            "prevention_tips": [
                "Keep software updated and patched",
                "Implement defense in depth",
                "Regular security assessments",
                "Monitor logs continuously",
            ],
        }

    def get_quick_summary(self, alert: dict):
        exp = self.get_explanation(alert)
        return {
            "alert_id":   alert.get("id"),
            "summary":    exp["summary"],
            "risk_level": exp["risk_level"],
            "top_action": (
                exp["user_can_do"][0]
                if exp["user_can_do"] else
                "Investigate and block if malicious"
            ),
            "top_tip":    (
                exp["prevention_tips"][0]
                if exp["prevention_tips"] else
                "Apply security best practices"
            ),
        }