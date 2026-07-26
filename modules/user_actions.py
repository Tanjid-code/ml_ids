"""User Actions - What users CAN and CANNOT do"""


class UserActions:
    def get_all_actions(self):
        return {
            "can_do":    self.get_can_do(),
            "cannot_do": self.get_cannot_do(),
        }

    def get_can_do(self):
        return {
            "monitoring": [
                {
                    "action":      "Start/Stop Monitoring",
                    "description": (
                        "Control real-time network monitoring"
                    ),
                    "how_to": (
                        "Click Start/Stop buttons in dashboard"
                    ),
                },
                {
                    "action":      "View Real-time Alerts",
                    "description": "See alerts as they happen",
                    "how_to": (
                        "Watch the alerts table - auto updates"
                    ),
                },
                {
                    "action":      "View ML Predictions",
                    "description": (
                        "See XGBoost model attack predictions"
                    ),
                    "how_to": (
                        "Go to ML Predictions page"
                    ),
                },
                {
                    "action":      "Compare Detections",
                    "description": (
                        "See rule vs ML detection comparison"
                    ),
                    "how_to": "Go to Comparison page",
                },
            ],
            "alert_management": [
                {
                    "action":      "View Alert Details",
                    "description": (
                        "See full alert info including "
                        "rule details"
                    ),
                    "how_to": "Click any alert row",
                },
                {
                    "action":      "Acknowledge Alerts",
                    "description": "Mark alerts as reviewed",
                    "how_to": "Click Acknowledge on alert",
                },
                {
                    "action":      "Mark False Positive",
                    "description": (
                        "Indicate alert is not real threat"
                    ),
                    "how_to": (
                        "Click False Positive and add reason"
                    ),
                },
                {
                    "action":      "Add Notes to Alerts",
                    "description": "Document your analysis",
                    "how_to": (
                        "Use Add Note in alert details"
                    ),
                },
                {
                    "action":      "Bulk Actions",
                    "description": (
                        "Acknowledge or delete multiple alerts"
                    ),
                    "how_to": (
                        "Select checkboxes and use bulk "
                        "action buttons"
                    ),
                },
                {
                    "action":      "Delete Single Alert",
                    "description": "Remove one alert",
                    "how_to": (
                        "Click delete button on alert row"
                    ),
                },
            ],
            "ip_management": [
                {
                    "action":      "Block IP Manually",
                    "description": "Block any IP address",
                    "how_to": (
                        "Click Block IP or go to Settings"
                    ),
                },
                {
                    "action":      "Unblock IP",
                    "description": (
                        "Remove IP from blocked list"
                    ),
                    "how_to": (
                        "Settings > Blocked IPs > Unblock"
                    ),
                },
                {
                    "action":      "Delete All Alerts from IP",
                    "description": (
                        "Remove all alerts for specific IP"
                    ),
                    "how_to": (
                        "IP Details modal > Delete All Alerts"
                    ),
                },
                {
                    "action":      "Whitelist Trusted IPs",
                    "description": "Mark IP as trusted",
                    "how_to": (
                        "Settings > Whitelist > Add IP"
                    ),
                },
                {
                    "action":      "Enable Auto-Blocking",
                    "description": (
                        "Auto-block on critical alerts"
                    ),
                    "how_to": (
                        "Settings > Auto-Block Settings"
                    ),
                },
                {
                    "action":      "View IP Details",
                    "description": (
                        "See all info about any IP address"
                    ),
                    "how_to": "Click any IP in alerts table",
                },
            ],
            "reporting": [
                {
                    "action":      "Generate JSON Report",
                    "description": "Export alerts as JSON",
                    "how_to": (
                        "Reports > Generate > Select JSON"
                    ),
                },
                {
                    "action":      "Generate CSV Report",
                    "description": "Export alerts as CSV",
                    "how_to": (
                        "Reports > Generate > Select CSV"
                    ),
                },
                {
                    "action":      "Generate PDF Report",
                    "description": (
                        "Export formatted PDF report"
                    ),
                    "how_to": (
                        "Reports > Generate > Select PDF"
                    ),
                },
                {
                    "action":      "AI Threat Explanation",
                    "description": (
                        "Get plain-language explanation"
                    ),
                    "how_to": "Click Explain on any alert",
                },
            ],
        }

    def get_cannot_do(self):
        return {
            "technical_limitations": [
                {
                    "limitation": (
                        "Read Encrypted Traffic Content"
                    ),
                    "reason": (
                        "HTTPS/TLS encryption prevents "
                        "reading packet payloads"
                    ),
                    "workaround": (
                        "Monitor metadata (IPs, ports, "
                        "timing) instead"
                    ),
                },
                {
                    "limitation": "Stop All Attacks",
                    "reason": (
                        "New attack methods constantly emerge"
                    ),
                    "workaround": (
                        "Regular rule updates and multiple "
                        "security layers"
                    ),
                },
                {
                    "limitation": (
                        "Guarantee 100% ML Accuracy"
                    ),
                    "reason": (
                        "ML model uses approximated features "
                        "from HTTP data. Some features like TTL "
                        "and jitter cannot be measured at "
                        "application layer."
                    ),
                    "workaround": (
                        "Use ML as a supplementary detector. "
                        "Rule-based detection provides the "
                        "authoritative severity classification."
                    ),
                },
                {
                    "limitation": (
                        "Identify True Attacker Identity"
                    ),
                    "reason": (
                        "Attackers use VPNs, proxies, "
                        "and IP spoofing"
                    ),
                    "workaround": (
                        "Report to authorities for "
                        "investigation"
                    ),
                },
            ],
            "scope_limitations": [
                {
                    "limitation": (
                        "Block at Network/Firewall Level"
                    ),
                    "reason": (
                        "System monitors only — does not "
                        "control firewall"
                    ),
                    "workaround": (
                        "Use blocked IP list with external "
                        "firewall rules"
                    ),
                },
                {
                    "limitation": "Prevent Insider Threats",
                    "reason": (
                        "Internal traffic may be trusted "
                        "by default"
                    ),
                    "workaround": (
                        "Implement zero-trust and monitor "
                        "all traffic"
                    ),
                },
                {
                    "limitation": "Recover Stolen Data",
                    "reason": (
                        "Once exfiltrated data is out of "
                        "control"
                    ),
                    "workaround": (
                        "Focus on prevention and early "
                        "detection"
                    ),
                },
            ],
        }