"""
Traffic Monitor Module
Tracks ALL traffic - normal and suspicious
"""
import json
import os
import time
from datetime import datetime
from threading import Lock
from collections import defaultdict


class TrafficMonitor:
    def __init__(self, data_dir="data"):
        self.data_dir      = data_dir
        self.lock          = Lock()
        self.traffic_file  = os.path.join(
            data_dir, "traffic_log.json"
        )
        self.ip_stats_file = os.path.join(
            data_dir, "ip_statistics.json"
        )

        self.ip_stats    = defaultdict(lambda: {
            "ip":               "",
            "total_requests":   0,
            "total_bytes_in":   0,
            "total_bytes_out":  0,
            "packets_in":       0,
            "packets_out":      0,
            "first_seen":       None,
            "last_seen":        None,
            "paths_visited":    [],
            "methods_used":     [],
            "user_agents":      [],
            "ports_accessed":   [],
            "alert_count":      0,
            "is_threat":        False,
            "classification":   "normal",
            "requests_per_min": 0,
            "request_times":    [],
            "status_codes":     {},
        })

        self.traffic_log = []
        self.MAX_LOG     = 1000
        self.MAX_PATHS   = 30
        self.MAX_AGENTS  = 5

        self._initialize_files()
        self._load_from_disk()

    def _initialize_files(self):
        os.makedirs(self.data_dir, exist_ok=True)
        if not os.path.exists(self.traffic_file):
            self._save_file(self.traffic_file,
                            {"traffic": []})
        if not os.path.exists(self.ip_stats_file):
            self._save_file(self.ip_stats_file,
                            {"ip_stats": {}})

    def _save_file(self, path, data):
        try:
            with open(path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"⚠️ Save error: {e}")

    def _load_from_disk(self):
        try:
            if os.path.exists(self.ip_stats_file):
                with open(self.ip_stats_file, 'r') as f:
                    data = json.load(f)
                for ip, stats in data.get(
                    "ip_stats", {}
                ).items():
                    self.ip_stats[ip].update(stats)
        except Exception as e:
            print(f"⚠️ Load IP stats error: {e}")

        try:
            if os.path.exists(self.traffic_file):
                with open(self.traffic_file, 'r') as f:
                    data = json.load(f)
                self.traffic_log = data.get("traffic", [])
        except Exception as e:
            print(f"⚠️ Load traffic error: {e}")

    def record_request(self, ip, path, method,
                       user_agent, status_code,
                       bytes_in=0, bytes_out=0,
                       port=80, is_threat=False,
                       threat_type=None):
        with self.lock:
            now   = datetime.now().isoformat()
            stats = self.ip_stats[ip]

            stats["ip"]              = ip
            stats["total_requests"] += 1
            stats["total_bytes_in"] += bytes_in
            stats["total_bytes_out"]+= bytes_out
            stats["packets_in"]    += 1
            stats["last_seen"]      = now

            if not stats["first_seen"]:
                stats["first_seen"] = now

            if path not in stats["paths_visited"]:
                stats["paths_visited"].append(path)
                if len(stats["paths_visited"]) > self.MAX_PATHS:
                    stats["paths_visited"] = \
                        stats["paths_visited"][-self.MAX_PATHS:]

            if method not in stats["methods_used"]:
                stats["methods_used"].append(method)

            if (user_agent and
                    user_agent not in stats["user_agents"]):
                stats["user_agents"].append(
                    user_agent[:100]
                )
                if len(stats["user_agents"]) > self.MAX_AGENTS:
                    stats["user_agents"] = \
                        stats["user_agents"][-self.MAX_AGENTS:]

            if port and port not in stats["ports_accessed"]:
                stats["ports_accessed"].append(port)

            code = str(status_code)
            stats["status_codes"][code] = \
                stats["status_codes"].get(code, 0) + 1

            current_time = time.time()
            stats["request_times"].append(current_time)
            stats["request_times"] = [
                t for t in stats["request_times"]
                if current_time - t <= 60
            ]
            stats["requests_per_min"] = len(
                stats["request_times"]
            )

            if is_threat:
                stats["alert_count"] += 1
                stats["is_threat"]    = True

            stats["classification"] = \
                self._classify_ip(stats)

            log_entry = {
                "id":             int(time.time() * 1000),
                "timestamp":      now,
                "ip":             ip,
                "path":           path,
                "method":         method,
                "status_code":    status_code,
                "bytes_in":       bytes_in,
                "bytes_out":      bytes_out,
                "port":           port,
                "user_agent":     (user_agent or "")[:100],
                "is_threat":      is_threat,
                "threat_type":    threat_type or "",
                "classification": stats["classification"],
            }

            self.traffic_log.append(log_entry)
            if len(self.traffic_log) > self.MAX_LOG:
                self.traffic_log = \
                    self.traffic_log[-self.MAX_LOG:]

            if stats["total_requests"] % 50 == 0:
                self._persist_unsafe()

        return log_entry

    def _classify_ip(self, stats):
        ac  = stats.get("alert_count", 0)
        rpm = stats.get("requests_per_min", 0)
        tr  = stats.get("total_requests", 0)

        if ac >= 5:    return "attacker"
        elif ac >= 2:  return "suspicious"
        elif rpm > 50: return "bot"
        elif ac == 1:  return "low_risk"
        elif tr > 100: return "high_volume"
        else:          return "normal"

    def _persist_unsafe(self):
        """Save to disk. Must be called inside lock."""
        try:
            serializable = {}
            for ip, stats in self.ip_stats.items():
                s = dict(stats)
                s.pop("request_times", None)
                serializable[ip] = s
            self._save_file(
                self.ip_stats_file,
                {"ip_stats": serializable}
            )
            self._save_file(
                self.traffic_file,
                {"traffic": self.traffic_log[-self.MAX_LOG:]}
            )
        except Exception as e:
            print(f"⚠️ Persist error: {e}")

    def get_recent_traffic(self, limit=100,
                           include_threats=True,
                           normal_only=False,
                           threats_only=False,
                           ip_filter=None):
        with self.lock:
            logs = list(self.traffic_log)

        if normal_only:
            logs = [l for l in logs if not l["is_threat"]]
        elif threats_only:
            logs = [l for l in logs if l["is_threat"]]

        if ip_filter:
            logs = [l for l in logs if l["ip"] == ip_filter]

        return logs[-limit:][::-1]

    def get_ip_full_details(self, ip):
        with self.lock:
            if ip not in self.ip_stats:
                return None
            stats = dict(self.ip_stats[ip])

        total_bytes = (
            stats.get("total_bytes_in", 0) +
            stats.get("total_bytes_out", 0)
        )
        total_pkts = (
            stats.get("packets_in", 0) +
            stats.get("packets_out", 0)
        )
        avg_pkt = (
            total_bytes // total_pkts
            if total_pkts > 0 else 0
        )

        duration_str = "N/A"
        if stats.get("first_seen") and stats.get("last_seen"):
            try:
                f = datetime.fromisoformat(stats["first_seen"])
                l = datetime.fromisoformat(stats["last_seen"])
                d = int((l - f).total_seconds())
                if d < 60:
                    duration_str = f"{d}s"
                elif d < 3600:
                    duration_str = f"{d // 60}m {d % 60}s"
                else:
                    duration_str = (
                        f"{d // 3600}h "
                        f"{(d % 3600) // 60}m"
                    )
            except Exception:
                pass

        recent = self.get_recent_traffic(
            limit=20, ip_filter=ip
        )

        return {
            "ip":               ip,
            "classification":   stats.get(
                "classification", "normal"
            ),
            "first_seen":       stats.get("first_seen"),
            "last_seen":        stats.get("last_seen"),
            "session_duration": duration_str,
            "packets_in":       stats.get("packets_in", 0),
            "packets_out":      stats.get("packets_out", 0),
            "total_packets":    total_pkts,
            "bytes_in":         stats.get(
                "total_bytes_in", 0
            ),
            "bytes_out":        stats.get(
                "total_bytes_out", 0
            ),
            "total_bytes":      total_bytes,
            "avg_packet_size":  avg_pkt,
            "total_requests":   stats.get(
                "total_requests", 0
            ),
            "requests_per_min": stats.get(
                "requests_per_min", 0
            ),
            "paths_visited":    stats.get(
                "paths_visited", []
            ),
            "methods_used":     stats.get(
                "methods_used", []
            ),
            "user_agents":      stats.get(
                "user_agents", []
            ),
            "ports_accessed":   stats.get(
                "ports_accessed", []
            ),
            "status_codes":     stats.get(
                "status_codes", {}
            ),
            "alert_count":      stats.get(
                "alert_count", 0
            ),
            "is_threat":        stats.get(
                "is_threat", False
            ),
            "recent_traffic":   recent,
        }

    def get_all_ip_stats(self, limit=50):
        with self.lock:
            all_stats = []
            for ip, stats in self.ip_stats.items():
                all_stats.append({
                    "ip":              ip,
                    "total_requests":  stats.get(
                        "total_requests", 0
                    ),
                    "packets_in":      stats.get(
                        "packets_in", 0
                    ),
                    "packets_out":     stats.get(
                        "packets_out", 0
                    ),
                    "bytes_in":        stats.get(
                        "total_bytes_in", 0
                    ),
                    "bytes_out":       stats.get(
                        "total_bytes_out", 0
                    ),
                    "alert_count":     stats.get(
                        "alert_count", 0
                    ),
                    "classification":  stats.get(
                        "classification", "normal"
                    ),
                    "first_seen":      stats.get(
                        "first_seen"
                    ),
                    "last_seen":       stats.get(
                        "last_seen"
                    ),
                    "requests_per_min": stats.get(
                        "requests_per_min", 0
                    ),
                })

        all_stats.sort(
            key=lambda x: x["total_requests"],
            reverse=True,
        )
        return all_stats[:limit]

    def get_traffic_summary(self):
        with self.lock:
            total_ips  = len(self.ip_stats)
            total_reqs = sum(
                s.get("total_requests", 0)
                for s in self.ip_stats.values()
            )
            total_in = sum(
                s.get("total_bytes_in", 0)
                for s in self.ip_stats.values()
            )
            total_out = sum(
                s.get("total_bytes_out", 0)
                for s in self.ip_stats.values()
            )
            threat_ips = sum(
                1 for s in self.ip_stats.values()
                if s.get("is_threat")
            )

        return {
            "total_unique_ips": total_ips,
            "total_requests":   total_reqs,
            "total_bytes_in":   total_in,
            "total_bytes_out":  total_out,
            "total_bytes":      total_in + total_out,
            "threat_ips":       threat_ips,
            "normal_ips":       total_ips - threat_ips,
            "recent_log_count": len(self.traffic_log),
        }

    def get_top_talkers(self, limit=10):
        with self.lock:
            talkers = [
                {
                    "ip":             ip,
                    "total_requests": s.get(
                        "total_requests", 0
                    ),
                    "packets_in":     s.get(
                        "packets_in", 0
                    ),
                    "packets_out":    s.get(
                        "packets_out", 0
                    ),
                    "bytes_in":       s.get(
                        "total_bytes_in", 0
                    ),
                    "bytes_out":      s.get(
                        "total_bytes_out", 0
                    ),
                    "threats":        s.get(
                        "alert_count", 0
                    ),
                    "class":          s.get(
                        "classification", "normal"
                    ),
                }
                for ip, s in self.ip_stats.items()
            ]

        talkers.sort(
            key=lambda x: x["total_requests"],
            reverse=True,
        )
        return talkers[:limit]

    def clear_traffic(self):
        with self.lock:
            self.traffic_log = []
            self.ip_stats.clear()
        self._save_file(
            self.traffic_file, {"traffic": []}
        )
        self._save_file(
            self.ip_stats_file, {"ip_stats": {}}
        )
        return True

    def save(self):
        with self.lock:
            self._persist_unsafe()