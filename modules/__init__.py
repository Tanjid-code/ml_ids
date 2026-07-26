"""IDS Modules Package"""
from .network_scanner      import NetworkScanner
from .threat_detector      import ThreatDetector
from .alert_manager        import AlertManager
from .ai_explainer         import AIExplainer
from .report_generator     import ReportGenerator
from .user_actions         import UserActions
from .notification_service import NotificationService
from .traffic_monitor      import TrafficMonitor
from .ml_detector          import MLDetector

__version__ = "3.0.0"
__all__ = [
    "NetworkScanner",
    "ThreatDetector",
    "AlertManager",
    "AIExplainer",
    "ReportGenerator",
    "UserActions",
    "NotificationService",
    "TrafficMonitor",
    "MLDetector",
]