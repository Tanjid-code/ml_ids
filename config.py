"""
IDS System Configuration
"""
import os


class Config:
    APP_NAME   = "Advanced IDS System"
    VERSION    = "3.0.0"
    DEBUG      = True
    SECRET_KEY = os.environ.get(
        "SECRET_KEY", "ids-secret-key-2024-v3"
    )

    HOST = "0.0.0.0"
    PORT = 5000

    BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR    = os.path.join(BASE_DIR, "data")
    REPORTS_DIR = os.path.join(DATA_DIR, "reports")
    LOGS_DIR    = os.path.join(DATA_DIR, "logs")

    # Detection thresholds
    PORT_SCAN_THRESHOLD   = 10
    DDOS_THRESHOLD        = 100
    BRUTE_FORCE_THRESHOLD = 5

    # Auto-block settings
    AUTO_BLOCK_ENABLED          = False
    AUTO_BLOCK_ON_CRITICAL      = True
    AUTO_BLOCK_ON_HIGH          = False
    AUTO_BLOCK_THRESHOLD_COUNT  = 3

    # Pagination
    DEFAULT_PAGE_SIZE = 50
    MAX_PAGE_SIZE     = 500

    SUSPICIOUS_PORTS = [
        20, 21, 23, 25, 53, 135, 137, 138,
        139, 445, 512, 513, 514, 1433, 1521,
        3306, 3389, 4444, 5555, 6666, 8080,
        12345, 27374, 31337
    ]

    SEVERITY_LEVELS = {
        "critical": {"color": "#dc2626", "priority": 1},
        "high":     {"color": "#ef4444", "priority": 2},
        "medium":   {"color": "#f59e0b", "priority": 3},
        "low":      {"color": "#10b981", "priority": 4},
        "info":     {"color": "#3b82f6", "priority": 5},
    }


os.makedirs(Config.DATA_DIR,    exist_ok=True)
os.makedirs(Config.REPORTS_DIR, exist_ok=True)
os.makedirs(Config.LOGS_DIR,    exist_ok=True)