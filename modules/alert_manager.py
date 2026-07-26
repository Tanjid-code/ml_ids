"""
Alert Management Module
Handles storage, retrieval, management, and IP blocking
"""
import json
import os
from datetime import datetime
from threading import Lock
from config import Config


class AlertManager:
    def __init__(self, data_dir="data"):
        self.data_dir        = data_dir
        self.lock            = Lock()
        self.alerts_file     = os.path.join(data_dir, "alerts.json")
        self.feedback_file   = os.path.join(data_dir, "feedback.json")
        self.blocked_file    = os.path.join(data_dir, "blocked_ips.json")
        self.whitelist_file  = os.path.join(data_dir, "whitelist.json")
        self.auto_block_file = os.path.join(
            data_dir, "auto_block_settings.json"
        )
        self._next_id = 1
        self._initialize_files()

    # ── File init ─────────────────────────────────────────
    def _initialize_files(self):
        os.makedirs(self.data_dir, exist_ok=True)
        defaults = {
            self.alerts_file:    {"alerts": []},
            self.feedback_file:  {"feedback": []},
            self.blocked_file:   {"blocked_ips": []},
            self.whitelist_file: {"whitelist": []},
            self.auto_block_file: {
                "enabled":               False,
                "block_on_critical":     True,
                "block_on_high":         False,
                "alert_count_threshold": 3,
                "blocked_count":         0,
            },
        }
        for path, default in defaults.items():
            if not os.path.exists(path):
                self._save_json(path, default)

        # Set next_id from existing alerts
        data   = self._load_json(self.alerts_file)
        alerts = data.get("alerts", [])
        if alerts:
            self._next_id = max(
                a.get("id", 0) for a in alerts
            ) + 1

    # ── JSON helpers (thread-safe) ────────────────────────
    def _load_json(self, path):
        with self.lock:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}

    def _save_json(self, path, data):
        with self.lock:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                print(f"⚠️ Save error: {e}")

    def _get_next_id(self):
        """Thread-safe incrementing ID."""
        current = self._next_id
        self._next_id += 1
        return current

    # ── Auto-block settings ───────────────────────────────
    def get_auto_block_settings(self):
        return self._load_json(self.auto_block_file)

    def update_auto_block_settings(self, settings: dict):
        current = self._load_json(self.auto_block_file)
        current.update(settings)
        self._save_json(self.auto_block_file, current)
        return current

    # ── IP management ─────────────────────────────────────
    def get_whitelist(self):
        return self._load_json(
            self.whitelist_file
        ).get("whitelist", [])

    def add_to_whitelist(self, ip: str):
        data = self._load_json(self.whitelist_file)
        wl   = data.get("whitelist", [])
        if ip not in wl:
            wl.append(ip)
            data["whitelist"] = wl
            self._save_json(self.whitelist_file, data)
        return True

    def remove_from_whitelist(self, ip: str):
        data = self._load_json(self.whitelist_file)
        data["whitelist"] = [
            i for i in data.get("whitelist", []) if i != ip
        ]
        self._save_json(self.whitelist_file, data)
        return True

    def get_blocked_ips(self):
        return self._load_json(
            self.blocked_file
        ).get("blocked_ips", [])

    def get_blocked_ip_list(self):
        return [e["ip"] for e in self.get_blocked_ips()]

    def block_ip(self, ip: str, reason: str = "",
                 auto_blocked: bool = False):
        data    = self._load_json(self.blocked_file)
        blocked = data.get("blocked_ips", [])
        existing = [e for e in blocked if e["ip"] == ip]
        if existing:
            return existing[0]

        entry = {
            "ip":           ip,
            "blocked_at":   datetime.now().isoformat(),
            "reason":       reason,
            "auto_blocked": auto_blocked,
        }
        blocked.append(entry)
        data["blocked_ips"] = blocked
        self._save_json(self.blocked_file, data)
        return entry

    def unblock_ip(self, ip: str):
        data = self._load_json(self.blocked_file)
        data["blocked_ips"] = [
            e for e in data.get("blocked_ips", [])
            if e["ip"] != ip
        ]
        self._save_json(self.blocked_file, data)
        return True

    # ── Auto-block check ──────────────────────────────────
    def check_auto_block(self, alert: dict):
        settings = self.get_auto_block_settings()
        if not settings.get("enabled", False):
            return False

        ip       = alert.get("source_ip", "")
        severity = alert.get("severity", "")

        if not ip:
            return False
        if ip in self.get_whitelist():
            return False
        if ip in self.get_blocked_ip_list():
            return False

        should_block = False
        if (settings.get("block_on_critical") and
                severity == "critical"):
            should_block = True
        if (settings.get("block_on_high") and
                severity == "high"):
            should_block = True

        if should_block:
            self.block_ip(
                ip,
                reason=(
                    f"Auto-blocked: {alert.get('type')} "
                    f"({severity})"
                ),
                auto_blocked=True,
            )
            ab = self._load_json(self.auto_block_file)
            ab["blocked_count"] = ab.get("blocked_count", 0) + 1
            self._save_json(self.auto_block_file, ab)
            return True

        return False

    # ── Alert CRUD ────────────────────────────────────────
    def create_alert(self, alert_data: dict):
        whitelist = self.get_whitelist()
        src_ip    = alert_data.get("source_ip", "")
        if src_ip in whitelist:
            return None

        alert = {
            "id":               self._get_next_id(),
            "timestamp":        datetime.now().isoformat(),
            "type":             alert_data.get("type", "unknown"),
            "severity":         alert_data.get("severity", "medium"),
            "category":         alert_data.get("category", ""),
            "source_ip":        src_ip,
            "destination_ip":   alert_data.get(
                "destination_ip", ""
            ),
            "destination_port": alert_data.get(
                "destination_port", 0
            ),
            "description":      alert_data.get(
                "description", ""
            ),
            "status":           "new",
            "acknowledged":     False,
            "false_positive":   False,
            "notes":            "",
            "details":          alert_data.get("details", {}),
            "rule_id":          alert_data.get("rule_id", ""),
            "rule_name":        alert_data.get("rule_name", ""),
            "rule_regex":       alert_data.get("rule_regex", ""),
            "rule_explanation": alert_data.get(
                "rule_explanation", ""
            ),
            # ML fields
            "ml_detected":      alert_data.get(
                "ml_detected", False
            ),
            "ml_confidence":    alert_data.get(
                "ml_confidence", 0
            ),
            "detection_source": alert_data.get(
                "detection_source", "rule"
            ),
        }

        data   = self._load_json(self.alerts_file)
        alerts = data.get("alerts", [])
        alerts.append(alert)

        if len(alerts) > 5000:
            alerts = alerts[-5000:]

        data["alerts"] = alerts
        self._save_json(self.alerts_file, data)
        self.check_auto_block(alert)
        return alert

    def get_alerts(self, limit=100, severity=None,
                   status=None, alert_type=None,
                   source_ip=None, page=1):
        data   = self._load_json(self.alerts_file)
        alerts = data.get("alerts", [])

        if severity:
            alerts = [
                a for a in alerts
                if a.get("severity") == severity
            ]
        if status:
            alerts = [
                a for a in alerts
                if a.get("status") == status
            ]
        if alert_type:
            alerts = [
                a for a in alerts
                if a.get("type") == alert_type
            ]
        if source_ip:
            alerts = [
                a for a in alerts
                if a.get("source_ip") == source_ip
            ]

        # Newest first
        alerts = alerts[::-1]

        # Pagination
        total       = len(alerts)
        total_pages = max(1, (total + limit - 1) // limit)
        page        = max(1, min(page, total_pages))
        start       = (page - 1) * limit
        end         = start + limit

        return {
            "alerts":      alerts[start:end],
            "total":       total,
            "page":        page,
            "total_pages": total_pages,
            "per_page":    limit,
        }

    def get_alert_by_id(self, alert_id: int):
        data = self._load_json(self.alerts_file)
        for a in data.get("alerts", []):
            if a["id"] == alert_id:
                return a
        return None

    def update_alert(self, alert_id: int, updates: dict):
        data = self._load_json(self.alerts_file)
        for i, a in enumerate(data.get("alerts", [])):
            if a["id"] == alert_id:
                data["alerts"][i].update(updates)
                data["alerts"][i]["updated_at"] = (
                    datetime.now().isoformat()
                )
                self._save_json(self.alerts_file, data)
                return data["alerts"][i]
        return None

    def acknowledge_alert(self, alert_id: int):
        return self.update_alert(alert_id, {
            "acknowledged": True,
            "status":       "acknowledged",
        })

    def mark_false_positive(self, alert_id: int,
                            reason: str = ""):
        return self.update_alert(alert_id, {
            "false_positive":        True,
            "status":                "false_positive",
            "false_positive_reason": reason,
        })

    def add_note(self, alert_id: int, note: str):
        alert = self.get_alert_by_id(alert_id)
        if alert:
            existing = alert.get("notes", "")
            ts       = datetime.now().strftime('%Y-%m-%d %H:%M')
            new_note = f"{ts} - {note}"
            combined = f"{existing}\n{new_note}".strip()
            return self.update_alert(
                alert_id, {"notes": combined}
            )
        return None

    def delete_alert(self, alert_id: int):
        data = self._load_json(self.alerts_file)
        data["alerts"] = [
            a for a in data.get("alerts", [])
            if a["id"] != alert_id
        ]
        self._save_json(self.alerts_file, data)
        return True

    def delete_alerts_by_ip(self, ip: str):
        """Delete all alerts from a specific IP."""
        data = self._load_json(self.alerts_file)
        before = len(data.get("alerts", []))
        data["alerts"] = [
            a for a in data.get("alerts", [])
            if a.get("source_ip") != ip
        ]
        after = len(data["alerts"])
        self._save_json(self.alerts_file, data)
        return {"deleted": before - after}

    def clear_alerts(self):
        self._save_json(self.alerts_file, {"alerts": []})
        self._next_id = 1
        return True

    # ── Statistics ────────────────────────────────────────
    def get_statistics(self):
        data   = self._load_json(self.alerts_file)
        alerts = data.get("alerts", [])

        stats = {
            "total": len(alerts),
            "by_severity": {
                "critical": 0, "high": 0,
                "medium": 0,   "low": 0, "info": 0,
            },
            "by_status": {
                "new": 0, "acknowledged": 0,
                "resolved": 0, "false_positive": 0,
            },
            "by_type":    {},
            "by_source":  {},
            "recent_24h": 0,
            "unique_ips": 0,
            "top_ips":    {},
        }

        now     = datetime.now()
        ip_set  = set()

        for a in alerts:
            sev = a.get("severity", "medium")
            if sev in stats["by_severity"]:
                stats["by_severity"][sev] += 1

            st = a.get("status", "new")
            if st in stats["by_status"]:
                stats["by_status"][st] += 1

            at = a.get("type", "unknown")
            stats["by_type"][at] = (
                stats["by_type"].get(at, 0) + 1
            )

            src = a.get("detection_source", "rule")
            stats["by_source"][src] = (
                stats["by_source"].get(src, 0) + 1
            )

            try:
                t = datetime.fromisoformat(a["timestamp"])
                if (now - t).total_seconds() < 86400:
                    stats["recent_24h"] += 1
            except Exception:
                pass

            ip = a.get("source_ip", "")
            ip_set.add(ip)
            stats["top_ips"][ip] = (
                stats["top_ips"].get(ip, 0) + 1
            )

        stats["unique_ips"] = len(ip_set)
        stats["top_ips"] = dict(
            sorted(
                stats["top_ips"].items(),
                key=lambda x: x[1],
                reverse=True,
            )[:10]
        )
        return stats

    # ── IP details ────────────────────────────────────────
    def get_ip_details(self, ip: str):
        data   = self._load_json(self.alerts_file)
        alerts = [
            a for a in data.get("alerts", [])
            if a.get("source_ip") == ip
        ]

        blocked     = ip in self.get_blocked_ip_list()
        whitelisted = ip in self.get_whitelist()

        attack_types = {}
        severities   = {}
        ports        = set()
        dest_ips     = set()
        sources      = {}

        for a in alerts:
            t = a.get("type", "unknown")
            attack_types[t] = attack_types.get(t, 0) + 1
            s = a.get("severity", "medium")
            severities[s] = severities.get(s, 0) + 1
            if a.get("destination_port"):
                ports.add(a["destination_port"])
            if a.get("destination_ip"):
                dest_ips.add(a["destination_ip"])
            src = a.get("detection_source", "rule")
            sources[src] = sources.get(src, 0) + 1

        # First/last seen (alerts in file order = oldest first)
        first_seen = alerts[0]["timestamp"] if alerts else None
        last_seen  = alerts[-1]["timestamp"] if alerts else None

        return {
            "ip":                 ip,
            "total_alerts":       len(alerts),
            "is_blocked":         blocked,
            "is_whitelisted":     whitelisted,
            "attack_types":       attack_types,
            "severity_breakdown": severities,
            "targeted_ports":     list(ports),
            "destination_ips":    list(dest_ips),
            "detection_sources":  sources,
            "first_seen":         first_seen,
            "last_seen":          last_seen,
            "recent_alerts":      alerts[-10:][::-1],
            "risk_score":         self._calculate_risk(alerts),
        }

    def _calculate_risk(self, alerts: list) -> str:
        if not alerts:
            return "None"
        critical = sum(
            1 for a in alerts
            if a.get("severity") == "critical"
        )
        high = sum(
            1 for a in alerts
            if a.get("severity") == "high"
        )
        if critical >= 2:
            return "Critical"
        if critical == 1 or high > 3:
            return "High"
        if len(alerts) > 10:
            return "Medium"
        return "Low"

    # ── Feedback ──────────────────────────────────────────
    def add_feedback(self, alert_id, feedback_type,
                     message, user="anonymous"):
        fb = {
            "id":        self._get_next_id(),
            "alert_id":  alert_id,
            "type":      feedback_type,
            "message":   message,
            "user":      user,
            "timestamp": datetime.now().isoformat(),
        }
        data = self._load_json(self.feedback_file)
        fbs  = data.get("feedback", [])
        fbs.append(fb)
        data["feedback"] = fbs
        self._save_json(self.feedback_file, data)
        return fb

    def get_feedback(self, alert_id=None):
        data = self._load_json(self.feedback_file)
        fb   = data.get("feedback", [])
        if alert_id:
            fb = [f for f in fb if f["alert_id"] == alert_id]
        return fb