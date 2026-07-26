"""
Notification Service Module
"""
import json
import os
from datetime import datetime
from threading import Lock


class NotificationService:
    def __init__(self, data_dir="data"):
        self.data_dir  = data_dir
        self.lock      = Lock()
        self.notif_file = os.path.join(
            data_dir, "notifications.json"
        )
        self._next_id  = 1
        self._initialize()

    def _initialize(self):
        os.makedirs(self.data_dir, exist_ok=True)
        if not os.path.exists(self.notif_file):
            self._save({"notifications": []})
        else:
            data  = self._load()
            notifs = data.get("notifications", [])
            if notifs:
                self._next_id = max(
                    n.get("id", 0) for n in notifs
                ) + 1

    def _load(self):
        with self.lock:
            try:
                with open(
                    self.notif_file, 'r',
                    encoding='utf-8'
                ) as f:
                    return json.load(f)
            except Exception:
                return {"notifications": []}

    def _save(self, data):
        with self.lock:
            try:
                with open(
                    self.notif_file, 'w',
                    encoding='utf-8'
                ) as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                print(f"⚠️ Notification save error: {e}")

    def _get_next_id(self):
        current       = self._next_id
        self._next_id += 1
        return current

    def create_notification(self, alert: dict):
        sev   = alert.get("severity", "medium")
        atype = alert.get("type", "unknown")
        src   = alert.get("source_ip", "unknown")

        icons = {
            "critical": "🔴",
            "high":     "🟠",
            "medium":   "🟡",
            "low":      "🟢",
        }
        icon = icons.get(sev, "🔵")

        notif = {
            "id":        self._get_next_id(),
            "alert_id":  alert.get("id"),
            "title":     (
                f"{icon} {sev.upper()} Alert: "
                f"{atype.replace('_', ' ').title()}"
            ),
            "message":   (
                f"Threat from {src} — "
                f"{alert.get('description', '')[:80]}"
            ),
            "severity":  sev,
            "type":      atype,
            "source_ip": src,
            "timestamp": datetime.now().isoformat(),
            "read":      False,
        }

        data   = self._load()
        notifs = data.get("notifications", [])
        notifs.append(notif)

        # Keep last 200
        if len(notifs) > 200:
            notifs = notifs[-200:]

        data["notifications"] = notifs
        self._save(data)
        return notif

    def get_notifications(self, unread_only=False,
                          limit=50):
        data   = self._load()
        notifs = data.get("notifications", [])[::-1]
        if unread_only:
            notifs = [
                n for n in notifs if not n.get("read")
            ]
        return notifs[:limit]

    def get_unread_count(self):
        data   = self._load()
        notifs = data.get("notifications", [])
        return sum(
            1 for n in notifs if not n.get("read")
        )

    def mark_as_read(self, notif_id: int):
        data   = self._load()
        notifs = data.get("notifications", [])
        for n in notifs:
            if n.get("id") == notif_id:
                n["read"] = True
                break
        data["notifications"] = notifs
        self._save(data)

    def mark_all_as_read(self):
        data   = self._load()
        notifs = data.get("notifications", [])
        for n in notifs:
            n["read"] = True
        data["notifications"] = notifs
        self._save(data)

    def clear_all(self):
        self._save({"notifications": []})
        self._next_id = 1