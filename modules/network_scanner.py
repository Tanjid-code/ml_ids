"""
Real-Time Network Scanner Module
"""
import socket
import time
import psutil
from datetime import datetime
from threading import Thread, Lock
from collections import defaultdict


class NetworkScanner:
    def __init__(self):
        self.is_running      = False
        self.port_access     = defaultdict(set)
        self.reported_scans  = set()
        self.lock            = Lock()
        self.callbacks       = []
        self.monitor_thread  = None
        self.stats           = {
            "packets_captured": 0,
            "alerts_generated": 0,
            "bytes_processed":  0,
            "start_time":       None,
        }

    def add_callback(self, cb):
        self.callbacks.append(cb)

    def notify_callbacks(self, event_type, data):
        for cb in self.callbacks:
            try:
                cb(event_type, data)
            except Exception as e:
                print(f"⚠️ Callback error: {e}")

    def get_network_interfaces(self):
        interfaces = []
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        interfaces.append({
                            "name":    iface,
                            "ip":      addr.address,
                            "netmask": addr.netmask or "N/A",
                        })
        except Exception:
            pass
        return interfaces

    def get_active_connections(self):
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if (conn.status == 'ESTABLISHED' and
                        conn.raddr):
                    # Skip loopback
                    if conn.raddr.ip == '127.0.0.1':
                        continue
                    connections.append({
                        "local_ip":    (
                            conn.laddr.ip
                            if conn.laddr else "N/A"
                        ),
                        "local_port":  (
                            conn.laddr.port
                            if conn.laddr else 0
                        ),
                        "remote_ip":   conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "status":      conn.status,
                        "pid":         conn.pid,
                    })
        except Exception:
            pass
        return connections

    def get_network_stats(self):
        try:
            s = psutil.net_io_counters()
            return {
                "bytes_sent":   s.bytes_sent,
                "bytes_recv":   s.bytes_recv,
                "packets_sent": s.packets_sent,
                "packets_recv": s.packets_recv,
                "errors_in":    s.errin,
                "errors_out":   s.errout,
            }
        except Exception:
            return {
                "bytes_sent": 0, "bytes_recv": 0,
                "packets_sent": 0, "packets_recv": 0,
                "errors_in": 0, "errors_out": 0,
            }

    def analyze_connection(self, connection):
        alerts      = []
        remote_ip   = connection.get("remote_ip", "")
        remote_port = connection.get("remote_port", 0)

        suspicious_ports = {
            20: "FTP Data", 21: "FTP", 23: "Telnet",
            25: "SMTP", 53: "DNS", 135: "Windows RPC",
            137: "NetBIOS", 138: "NetBIOS",
            139: "NetBIOS",
            445: "SMB/WannaCry", 512: "rexec",
            513: "rlogin", 514: "rsh",
            1433: "MSSQL", 1521: "Oracle",
            3306: "MySQL", 3389: "RDP",
            4444: "Metasploit", 5555: "Android ADB",
            6666: "IRC/Botnet", 8080: "HTTP-Alt",
            12345: "NetBus", 27374: "SubSeven",
            31337: "BackOrifice",
        }

        if remote_port in suspicious_ports:
            svc = suspicious_ports[remote_port]
            alerts.append({
                "type":        "suspicious_port",
                "severity":    "high",
                "category":    "Suspicious Activity",
                "description": (
                    f"Connection to port {remote_port} "
                    f"({svc})"
                ),
                "source_ip":        remote_ip,
                "destination_port": remote_port,
                "rule_id":          "PORT-001",
                "rule_name":        (
                    f"Blacklisted Port {remote_port}"
                ),
                "rule_regex":       (
                    f"Port blacklist: {remote_port}"
                ),
                "rule_explanation": (
                    f"Port {remote_port} ({svc}) is "
                    f"associated with malware or exploits."
                ),
                "timestamp": datetime.now().isoformat(),
            })

        with self.lock:
            self.port_access[remote_ip].add(remote_port)
            port_count = len(self.port_access[remote_ip])
            if (port_count > 10 and
                    remote_ip not in self.reported_scans):
                ports = list(
                    self.port_access[remote_ip]
                )
                alerts.append({
                    "type":        "port_scan",
                    "severity":    "high",
                    "category":    "Reconnaissance",
                    "description": (
                        f"Port scan from {remote_ip}"
                    ),
                    "source_ip":   remote_ip,
                    "rule_id":     "SCAN-007",
                    "rule_name":   "Port Scan Detection",
                    "rule_regex":  "Threshold: 10 ports",
                    "rule_explanation": (
                        f"{remote_ip} scanned "
                        f"{len(ports)} ports"
                    ),
                    "scanned_ports": ports[:20],
                    "timestamp":
                        datetime.now().isoformat(),
                })
                self.reported_scans.add(remote_ip)

        return alerts

    def monitor_loop(self):
        self.stats["start_time"] = (
            datetime.now().isoformat()
        )
        previous = set()
        print("🔍 Monitor loop started...")

        while self.is_running:
            try:
                conns    = self.get_active_connections()
                cur_set  = {
                    (c["remote_ip"], c["remote_port"])
                    for c in conns
                }
                new_set  = cur_set - previous
                ns       = self.get_network_stats()

                for conn in conns:
                    key = (
                        conn["remote_ip"],
                        conn["remote_port"],
                    )
                    if key in new_set:
                        alerts = self.analyze_connection(
                            conn
                        )
                        for alert in alerts:
                            with self.lock:
                                self.stats[
                                    "alerts_generated"
                                ] += 1
                            self.notify_callbacks(
                                "alert", alert
                            )
                        self.notify_callbacks(
                            "connection", conn
                        )

                with self.lock:
                    self.stats["bytes_processed"] = (
                        ns["bytes_recv"]
                    )
                    self.stats["packets_captured"] = (
                        ns["packets_recv"]
                    )

                previous = cur_set
                self.notify_callbacks(
                    "stats", self.get_stats()
                )
                time.sleep(1)

            except Exception as e:
                print(f"⚠️ Monitor loop error: {e}")
                time.sleep(1)

    def start(self):
        if not self.is_running:
            self.is_running     = True
            self.monitor_thread = Thread(
                target=self.monitor_loop, daemon=True
            )
            self.monitor_thread.start()
            print("✅ Network monitoring started!")
            return {
                "status":  "started",
                "message": "Network monitoring started",
            }
        return {
            "status":  "already_running",
            "message": "Already active",
        }

    def stop(self):
        self.is_running = False
        print("⛔ Network monitoring stopped!")
        return {
            "status":  "stopped",
            "message": "Network monitoring stopped",
        }

    def get_stats(self):
        with self.lock:
            s = dict(self.stats)
        s["is_running"]         = self.is_running
        s["active_connections"] = len(
            self.get_active_connections()
        )
        s["thread_alive"] = (
            self.monitor_thread.is_alive()
            if self.monitor_thread else False
        )
        return s