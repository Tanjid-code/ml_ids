"""
Advanced Intrusion Detection System v3.0
Rule-Based + ML Detection
Main Application
"""
from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
from flask_socketio import SocketIO
import os
import time
from datetime import datetime

from modules.network_scanner      import NetworkScanner
from modules.threat_detector      import ThreatDetector
from modules.alert_manager        import AlertManager
from modules.ai_explainer         import AIExplainer
from modules.report_generator     import ReportGenerator
from modules.user_actions         import UserActions
from modules.notification_service import NotificationService
from modules.traffic_monitor      import TrafficMonitor
from modules.ml_detector          import MLDetector
from config import Config

# ══════════════════════════════════════════════════════════
# APP INIT
# ══════════════════════════════════════════════════════════
app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
CORS(app)
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='eventlet',
    ping_timeout=60,
    ping_interval=25,
    logger=False,
    engineio_logger=False,
)

# ══════════════════════════════════════════════════════════
# MODULE INIT
# ══════════════════════════════════════════════════════════
scanner              = NetworkScanner()
detector             = ThreatDetector()
alert_manager        = AlertManager()
explainer            = AIExplainer()
report_generator     = ReportGenerator()
user_actions         = UserActions()
notification_service = NotificationService()
traffic_monitor      = TrafficMonitor()
ml_detector          = MLDetector(
    model_path=os.path.join(
        Config.BASE_DIR,
        "unsw_nb15_xgb_model.pkl"
    )
)

# ── In-memory comparison log ──────────────────────────────
comparison_log = []
MAX_COMP_LOG   = 500

# ── Paths to skip for detection ───────────────────────────
SKIP_PATHS = (
    '/static',
    '/socket.io',
    '/favicon',
    '/api/ml',
    '/api/comparison',
)


# ══════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════
def get_source_ip():
    return (
        request.headers.get(
            'X-Forwarded-For', ''
        ).split(',')[0].strip()
        or request.headers.get('X-Real-IP', '')
        or request.remote_addr
        or '127.0.0.1'
    )


def get_server_ip():
    try:
        return request.host.split(':')[0]
    except Exception:
        return '127.0.0.1'


def get_server_port():
    try:
        return (
            int(request.host.split(':')[1])
            if ':' in request.host else Config.PORT
        )
    except Exception:
        return Config.PORT


def get_content_length():
    try:
        return int(request.content_length or 0)
    except Exception:
        return 0


def should_skip(path):
    return any(path.startswith(p) for p in SKIP_PATHS)


def create_and_emit(threat, source_ip, path,
                    method, payload,
                    ml_detected=False,
                    ml_confidence=0,
                    detection_source="rule"):
    """Create alert and broadcast via WebSocket."""
    try:
        alert_data = {
            "type":             threat.get("type", "unknown"),
            "severity":         threat.get("severity", "medium"),
            "category":         threat.get("category", ""),
            "source_ip":        source_ip,
            "destination_ip":   get_server_ip(),
            "destination_port": get_server_port(),
            "description":      threat.get(
                "description", "Threat detected"
            ),
            "rule_id":          threat.get("rule_id", ""),
            "rule_name":        threat.get("rule_name", ""),
            "rule_regex":       threat.get("rule_regex", ""),
            "rule_explanation": threat.get(
                "rule_explanation", ""
            ),
            "ml_detected":      ml_detected,
            "ml_confidence":    ml_confidence,
            "detection_source": detection_source,
            "details": {
                "matched_pattern": threat.get(
                    "matched_pattern", ""
                ),
                "request_path":    path,
                "request_method":  method,
                "payload_sample":  payload[:300],
            },
        }

        alert = alert_manager.create_alert(alert_data)

        if alert:
            notif = notification_service.create_notification(
                alert
            )
            try:
                socketio.emit('new_alert', alert)
                socketio.emit('notification', notif)
            except Exception:
                pass

            print(
                f"🚨 {threat['type']} | "
                f"{threat['severity']} | "
                f"{source_ip} | "
                f"Rule: {threat.get('rule_id', '?')} | "
                f"Source: {detection_source}"
            )

        return alert

    except Exception as e:
        print(f"❌ create_and_emit error: {e}")
        return None


# ══════════════════════════════════════════════════════════
# MIDDLEWARE
# ══════════════════════════════════════════════════════════
@app.before_request
def inspect_request():
    """Rule-based detection on every request."""
    request.start_time = time.time()
    request.rule_result = {
        "is_threat":   False,
        "threat_type": None,
        "threats":     [],
    }

    if should_skip(request.path):
        return None

    req = request

    # Build inspection payload
    parts = [req.path]

    for k, v in req.args.items():
        parts.append(f"{k}={v}")

    if req.query_string:
        parts.append(
            req.query_string.decode('utf-8', errors='ignore')
        )

    try:
        for k, v in req.form.items():
            parts.append(f"{k}={v}")
    except Exception:
        pass

    try:
        jd = req.get_json(silent=True, force=True)
        if jd:
            if isinstance(jd, dict):
                for k, v in jd.items():
                    parts.append(f"{k}={str(v)}")
            else:
                parts.append(str(jd))
    except Exception:
        pass

    for h in ('User-Agent', 'Referer',
              'X-Forwarded-For', 'Cookie',
              'X-Attack-Type'):
        val = req.headers.get(h, '')
        if val:
            parts.append(val)

    full_data = ' '.join(parts)
    source_ip = get_source_ip()

    if not full_data.strip():
        return None

    # ── Rule-based detection ──
    threats = detector.detect_pattern_attack(
        full_data, source_ip
    )

    ddos = detector.detect_ddos(source_ip)
    if ddos:
        threats.append(ddos)

    try:
        port = int(req.environ.get('SERVER_PORT', 5000))
    except Exception:
        port = 5000

    scan = detector.detect_port_scan(source_ip, port)
    if scan:
        threats.append(scan)

    if any(kw in req.path.lower() for kw in
           ('login', 'auth', 'signin',
            'password', 'passwd')):
        bf = detector.detect_brute_force(source_ip)
        if bf:
            threats.append(bf)

    susp = detector.detect_suspicious_port(source_ip, port)
    if susp:
        threats.append(susp)

    # Create rule-based alerts
    is_rule_threat   = len(threats) > 0
    rule_threat_type = (
        threats[0].get('type') if is_rule_threat else None
    )

    for threat in threats:
        create_and_emit(
            threat, source_ip,
            req.path, req.method, full_data,
            detection_source="rule",
        )

    # Store rule result for after_request
    request.rule_result = {
        "is_threat":   is_rule_threat,
        "threat_type": rule_threat_type,
        "threats":     threats,
    }

    # Record traffic
    user_agent = req.headers.get('User-Agent', '')
    bytes_in   = get_content_length()

    traffic_monitor.record_request(
        ip          = source_ip,
        path        = req.path,
        method      = req.method,
        user_agent  = user_agent,
        status_code = 200,
        bytes_in    = bytes_in,
        bytes_out   = 0,
        port        = port,
        is_threat   = is_rule_threat,
        threat_type = rule_threat_type,
    )

    return None


@app.after_request
def after_request(response):
    """Run ML prediction and build comparison."""
    try:
        if should_skip(request.path):
            return response

        source_ip     = get_source_ip()
        dst_ip        = get_server_ip()
        dst_port      = get_server_port()
        method        = request.method
        path          = request.path
        user_agent    = request.headers.get('User-Agent', '')
        content_len   = get_content_length()
        response_size = int(
            response.headers.get('Content-Length', 0) or 0
        )
        start_time = getattr(
            request, 'start_time', time.time()
        )
        rule_result = getattr(request, 'rule_result', {
            "is_threat":   False,
            "threat_type": None,
            "threats":     [],
        })

        if not ml_detector.is_loaded:
            return response

        # ── ML Prediction ──────────────────────────────────
        ml_result = ml_detector.predict(
            src_ip             = source_ip,
            dst_ip             = dst_ip,
            dst_port           = dst_port,
            method             = method,
            path               = path,
            user_agent         = user_agent,
            content_length     = content_len,
            request_start_time = start_time,
            status_code        = response.status_code,
            response_size      = response_size,
        )

        # Skip internal IPs
        if ml_result.get("skipped"):
            return response

        if not ml_result.get("success"):
            return response

        is_rule_threat = rule_result.get("is_threat", False)
        is_ml_attack   = ml_result.get("is_attack", False)

        # ── KEY DESIGN: ML detects, Rules classify ────────
        # If ML detects attack but rules didn't:
        #   - Create alert with ML info
        #   - Use "medium" severity (unknown attack type)
        #   - Let user investigate
        if is_ml_attack and not is_rule_threat:
            ml_alert_data = {
                "type":        "ml_anomaly",
                "severity":    "medium",
                "category":    "ML Detection",
                "description": (
                    f"ML model detected anomaly from "
                    f"{source_ip} "
                    f"({ml_result['attack_probability']}% "
                    f"confidence) on {path}"
                ),
                "rule_id":     "ML-001",
                "rule_name":   "XGBoost Anomaly Detection",
                "rule_regex":  "ML model prediction",
                "rule_explanation": (
                    f"The XGBoost model trained on UNSW-NB15 "
                    f"dataset classified this request as "
                    f"an attack with "
                    f"{ml_result['attack_probability']}% "
                    f"probability. Data quality: "
                    f"{ml_result.get('data_quality', {}).get('quality_percent', 0)}%. "
                    f"This detection was not matched by any "
                    f"rule-based signature."
                ),
            }
            create_and_emit(
                ml_alert_data, source_ip,
                path, method,
                f"ML anomaly: {ml_result['attack_probability']}%",
                ml_detected=True,
                ml_confidence=ml_result['confidence'],
                detection_source="ml",
            )

        # If both detected: update existing alert with ML info
        # (already created by rule in before_request)

        # ── Build comparison entry ─────────────────────────
        comp_entry = {
            "timestamp":    datetime.now().isoformat(),
            "source_ip":    source_ip,
            "path":         path,
            "method":       method,

            # Rule result
            "rule_detected":     is_rule_threat,
            "rule_threat_type":  rule_result.get(
                "threat_type"
            ),
            "rule_threat_count": len(
                rule_result.get("threats", [])
            ),
            "rule_severity":     (
                rule_result["threats"][0].get("severity", "")
                if rule_result.get("threats") else ""
            ),

            # ML result
            "ml_detected":    is_ml_attack,
            "ml_label":       ml_result.get("label", "NORMAL"),
            "ml_confidence":  ml_result.get("confidence", 0),
            "ml_attack_prob": ml_result.get(
                "attack_probability", 0
            ),

            # Agreement flags
            "agreement":      is_rule_threat == is_ml_attack,
            "both_detected":  (
                is_rule_threat and is_ml_attack
            ),
            "only_rule":      (
                is_rule_threat and not is_ml_attack
            ),
            "only_ml":        (
                not is_rule_threat and is_ml_attack
            ),
            "both_normal":    (
                not is_rule_threat and not is_ml_attack
            ),

            # Combined severity (from rules only)
            "final_severity": (
                rule_result["threats"][0].get("severity", "medium")
                if rule_result.get("threats")
                else ("medium" if is_ml_attack else "none")
            ),

            # Quality
            "feature_quality": ml_result.get(
                "data_quality", {}
            ).get("quality_percent", 0),
        }

        comparison_log.append(comp_entry)
        if len(comparison_log) > MAX_COMP_LOG:
            comparison_log.pop(0)

        # Emit ML alert via WebSocket
        if is_ml_attack:
            try:
                socketio.emit('ml_alert', ml_result)
            except Exception:
                pass

            if not is_rule_threat:
                print(
                    f"🤖 ML ONLY: ATTACK | "
                    f"{ml_result['attack_probability']}% | "
                    f"{source_ip} | {path}"
                )

    except Exception as e:
        print(f"❌ after_request error: {e}")
        import traceback
        traceback.print_exc()

    return response


# ── Scanner callback ──────────────────────────────────────
def handle_scanner_event(event_type, data):
    try:
        if event_type == "alert":
            alert = alert_manager.create_alert(data)
            if alert:
                notif = notification_service.create_notification(
                    alert
                )
                socketio.emit('new_alert',    alert)
                socketio.emit('notification', notif)
        elif event_type == "stats":
            socketio.emit('stats_update', data)
        elif event_type == "connection":
            socketio.emit('new_connection', data)
    except Exception as e:
        print(f"❌ Scanner event error: {e}")

scanner.add_callback(handle_scanner_event)


# ══════════════════════════════════════════════════════════
# PAGE ROUTES
# ══════════════════════════════════════════════════════════
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alerts')
def alerts_page():
    return render_template('alerts.html')

@app.route('/reports')
def reports_page():
    return render_template('reports.html')

@app.route('/settings')
def settings_page():
    return render_template('settings.html')

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/traffic')
def traffic_page():
    return render_template('traffic.html')

@app.route('/ml-predictions')
def ml_predictions_page():
    return render_template('ml_predictions.html')

@app.route('/comparison')
def comparison_page():
    return render_template('comparison.html')


# ══════════════════════════════════════════════════════════
# API - MONITORING
# ══════════════════════════════════════════════════════════
@app.route('/api/monitor/start', methods=['POST'])
def start_monitoring():
    return jsonify(scanner.start())

@app.route('/api/monitor/stop', methods=['POST'])
def stop_monitoring():
    return jsonify(scanner.stop())

@app.route('/api/monitor/status')
def monitor_status():
    return jsonify(scanner.get_stats())

@app.route('/api/network/interfaces')
def get_interfaces():
    return jsonify(scanner.get_network_interfaces())

@app.route('/api/network/connections')
def get_connections():
    return jsonify(scanner.get_active_connections())

@app.route('/api/network/stats')
def get_network_stats():
    return jsonify(scanner.get_network_stats())


# ══════════════════════════════════════════════════════════
# API - ML PREDICTIONS
# ══════════════════════════════════════════════════════════
@app.route('/api/ml/predictions')
def get_ml_predictions():
    try:
        limit        = request.args.get(
            'limit', 100, type=int
        )
        only_attacks = request.args.get(
            'only_attacks', 'false'
        ).lower() == 'true'
        page         = request.args.get(
            'page', 1, type=int
        )

        preds = ml_detector.get_predictions(
            limit=500,
            only_attacks=only_attacks,
        )

        # Pagination
        total       = len(preds)
        total_pages = max(1, (total + limit - 1) // limit)
        page        = max(1, min(page, total_pages))
        start       = (page - 1) * limit
        end         = start + limit

        return jsonify({
            "predictions": preds[start:end],
            "total":       total,
            "page":        page,
            "total_pages": total_pages,
            "per_page":    limit,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/ml/summary')
def get_ml_summary():
    try:
        return jsonify(ml_detector.get_summary())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/ml/model-info')
def get_model_info():
    try:
        return jsonify(ml_detector.get_model_info())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/ml/clear', methods=['POST'])
def clear_ml_predictions():
    ml_detector.clear_history()
    return jsonify({"message": "ML predictions cleared"})


# ══════════════════════════════════════════════════════════
# API - COMPARISON
# ══════════════════════════════════════════════════════════
@app.route('/api/comparison/log')
def get_comparison_log():
    try:
        limit  = request.args.get('limit', 100, type=int)
        page   = request.args.get('page', 1, type=int)
        logs   = list(comparison_log)[::-1]

        total       = len(logs)
        total_pages = max(1, (total + limit - 1) // limit)
        page        = max(1, min(page, total_pages))
        start       = (page - 1) * limit
        end         = start + limit

        return jsonify({
            "logs":        logs[start:end],
            "total":       total,
            "page":        page,
            "total_pages": total_pages,
            "per_page":    limit,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/comparison/summary')
def get_comparison_summary():
    try:
        logs  = list(comparison_log)
        total = len(logs)

        if total == 0:
            return jsonify({
                "total":                 0,
                "both_detected":         0,
                "only_rule":             0,
                "only_ml":               0,
                "both_normal":           0,
                "agreement":             0,
                "agreement_rate":        0,
                "rule_detection_rate":   0,
                "ml_detection_rate":     0,
                "rule_total_detections": 0,
                "ml_total_detections":   0,
            })

        both_detected = sum(
            1 for l in logs if l.get('both_detected')
        )
        only_rule = sum(
            1 for l in logs if l.get('only_rule')
        )
        only_ml = sum(
            1 for l in logs if l.get('only_ml')
        )
        both_normal = sum(
            1 for l in logs if l.get('both_normal')
        )
        agreement = sum(
            1 for l in logs if l.get('agreement')
        )

        rule_det = both_detected + only_rule
        ml_det   = both_detected + only_ml

        return jsonify({
            "total":           total,
            "both_detected":   both_detected,
            "only_rule":       only_rule,
            "only_ml":         only_ml,
            "both_normal":     both_normal,
            "agreement":       agreement,
            "agreement_rate":  round(
                agreement / total * 100, 1
            ),
            "rule_detection_rate": round(
                rule_det / total * 100, 1
            ),
            "ml_detection_rate": round(
                ml_det / total * 100, 1
            ),
            "rule_total_detections": rule_det,
            "ml_total_detections":   ml_det,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/comparison/clear', methods=['POST'])
def clear_comparison():
    global comparison_log
    comparison_log = []
    return jsonify({"message": "Comparison log cleared"})


# ══════════════════════════════════════════════════════════
# API - TRAFFIC
# ══════════════════════════════════════════════════════════
@app.route('/api/traffic')
def get_traffic():
    try:
        limit       = request.args.get(
            'limit', 100, type=int
        )
        normal_only = request.args.get(
            'normal_only', 'false'
        ).lower() == 'true'
        threats_only = request.args.get(
            'threats_only', 'false'
        ).lower() == 'true'
        ip_filter   = request.args.get('ip')
        page        = request.args.get('page', 1, type=int)

        traffic = traffic_monitor.get_recent_traffic(
            limit        = 1000,
            normal_only  = normal_only,
            threats_only = threats_only,
            ip_filter    = ip_filter,
        )

        total       = len(traffic)
        total_pages = max(1, (total + limit - 1) // limit)
        page        = max(1, min(page, total_pages))
        start       = (page - 1) * limit
        end         = start + limit

        return jsonify({
            "traffic":     traffic[start:end],
            "total":       total,
            "page":        page,
            "total_pages": total_pages,
            "per_page":    limit,
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/traffic/summary')
def get_traffic_summary():
    return jsonify(traffic_monitor.get_traffic_summary())


@app.route('/api/traffic/top-talkers')
def get_top_talkers():
    limit = request.args.get('limit', 10, type=int)
    return jsonify(traffic_monitor.get_top_talkers(limit))


@app.route('/api/traffic/clear', methods=['POST'])
def clear_traffic():
    traffic_monitor.clear_traffic()
    return jsonify({"message": "Traffic log cleared"})


# ══════════════════════════════════════════════════════════
# API - IP DETAILS
# ══════════════════════════════════════════════════════════
@app.route('/api/ip/details/<ip>')
def ip_details(ip):
    try:
        alert_details   = alert_manager.get_ip_details(ip)
        traffic_details = traffic_monitor.get_ip_full_details(ip)

        if alert_details and traffic_details:
            merged = {**alert_details}
            merged["traffic"] = traffic_details
            return jsonify(merged)
        elif alert_details:
            return jsonify(alert_details)
        elif traffic_details:
            return jsonify(traffic_details)
        else:
            return jsonify({"error": "IP not found"}), 404

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/ip/all-stats')
def get_all_ip_stats():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(traffic_monitor.get_all_ip_stats(limit))


# ══════════════════════════════════════════════════════════
# API - ALERTS
# ══════════════════════════════════════════════════════════
@app.route('/api/alerts')
def get_alerts():
    try:
        limit      = request.args.get('limit', 50, type=int)
        severity   = request.args.get('severity')
        status     = request.args.get('status')
        alert_type = request.args.get('type')
        source_ip  = request.args.get('source_ip')
        page       = request.args.get('page', 1, type=int)

        result = alert_manager.get_alerts(
            limit      = limit,
            severity   = severity,
            status     = status,
            alert_type = alert_type,
            source_ip  = source_ip,
            page       = page,
        )
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/alerts/<int:alert_id>')
def get_alert(alert_id):
    a = alert_manager.get_alert_by_id(alert_id)
    return jsonify(a) if a else (
        jsonify({"error": "Not found"}), 404
    )


@app.route('/api/alerts/<int:alert_id>/acknowledge',
           methods=['POST'])
def acknowledge_alert(alert_id):
    r = alert_manager.acknowledge_alert(alert_id)
    return jsonify(r) if r else (
        jsonify({"error": "Not found"}), 404
    )


@app.route('/api/alerts/<int:alert_id>/false-positive',
           methods=['POST'])
def mark_false_positive(alert_id):
    d      = request.get_json() or {}
    reason = d.get('reason', '')
    r = alert_manager.mark_false_positive(alert_id, reason)
    return jsonify(r) if r else (
        jsonify({"error": "Not found"}), 404
    )


@app.route('/api/alerts/<int:alert_id>/note',
           methods=['POST'])
def add_note(alert_id):
    d    = request.get_json() or {}
    note = d.get('note', '')
    r    = alert_manager.add_note(alert_id, note)
    return jsonify(r) if r else (
        jsonify({"error": "Not found"}), 404
    )


@app.route('/api/alerts/<int:alert_id>', methods=['DELETE'])
def delete_alert(alert_id):
    alert_manager.delete_alert(alert_id)
    return jsonify({"message": "Alert deleted"})


@app.route('/api/alerts/ip/<ip>', methods=['DELETE'])
def delete_alerts_by_ip(ip):
    """Delete all alerts from a specific IP."""
    result = alert_manager.delete_alerts_by_ip(ip)
    return jsonify(result)


@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    alert_manager.clear_alerts()
    return jsonify({"message": "All alerts cleared"})


@app.route('/api/alerts/stats')
def get_alert_stats():
    return jsonify(alert_manager.get_statistics())


# ══════════════════════════════════════════════════════════
# API - AI EXPLANATION
# ══════════════════════════════════════════════════════════
@app.route('/api/explain/<int:alert_id>')
def explain_alert(alert_id):
    a = alert_manager.get_alert_by_id(alert_id)
    if a:
        return jsonify(explainer.get_explanation(a))
    return jsonify({"error": "Not found"}), 404


@app.route('/api/explain/<int:alert_id>/quick')
def quick_explain(alert_id):
    a = alert_manager.get_alert_by_id(alert_id)
    if a:
        return jsonify(explainer.get_quick_summary(a))
    return jsonify({"error": "Not found"}), 404


# ══════════════════════════════════════════════════════════
# API - IP MANAGEMENT
# ══════════════════════════════════════════════════════════
@app.route('/api/ip/block', methods=['POST'])
def block_ip():
    d      = request.get_json() or {}
    ip     = d.get('ip')
    reason = d.get('reason', '')
    if not ip:
        return jsonify({"error": "IP required"}), 400
    return jsonify(
        alert_manager.block_ip(
            ip, reason, auto_blocked=False
        )
    )


@app.route('/api/ip/unblock', methods=['POST'])
def unblock_ip():
    d  = request.get_json() or {}
    ip = d.get('ip')
    if not ip:
        return jsonify({"error": "IP required"}), 400
    alert_manager.unblock_ip(ip)
    return jsonify({"message": f"IP {ip} unblocked"})


@app.route('/api/ip/blocked')
def get_blocked_ips():
    return jsonify(alert_manager.get_blocked_ips())


@app.route('/api/ip/whitelist',
           methods=['GET', 'POST', 'DELETE'])
def manage_whitelist():
    if request.method == 'GET':
        return jsonify(alert_manager.get_whitelist())
    d  = request.get_json() or {}
    ip = d.get('ip')
    if not ip:
        return jsonify({"error": "IP required"}), 400
    if request.method == 'POST':
        alert_manager.add_to_whitelist(ip)
        return jsonify({"message": f"{ip} whitelisted"})
    alert_manager.remove_from_whitelist(ip)
    return jsonify({"message": f"{ip} removed"})


@app.route('/api/ip/auto-block', methods=['GET', 'POST'])
def auto_block_settings():
    if request.method == 'GET':
        return jsonify(
            alert_manager.get_auto_block_settings()
        )
    d = request.get_json() or {}
    return jsonify(
        alert_manager.update_auto_block_settings(d)
    )


# ══════════════════════════════════════════════════════════
# API - FEEDBACK
# ══════════════════════════════════════════════════════════
@app.route('/api/feedback', methods=['POST'])
def add_feedback():
    d = request.get_json() or {}
    return jsonify(alert_manager.add_feedback(
        d.get('alert_id'),
        d.get('type'),
        d.get('message'),
    ))


@app.route('/api/feedback/<int:alert_id>')
def get_feedback(alert_id):
    return jsonify(alert_manager.get_feedback(alert_id))


# ══════════════════════════════════════════════════════════
# API - REPORTS
# ══════════════════════════════════════════════════════════
@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    d     = request.get_json() or {}
    rtype = d.get('type', 'json')

    if rtype == 'csv':
        result = report_generator.generate_csv_report(
            d.get('start_date'),
            d.get('end_date'),
            d.get('severity'),
        )
    elif rtype == 'pdf':
        result = report_generator.generate_pdf_report(
            d.get('start_date'),
            d.get('end_date'),
            d.get('severity'),
        )
    else:
        result = report_generator.generate_json_report(
            d.get('start_date'),
            d.get('end_date'),
            d.get('severity'),
        )

    return jsonify(result)


@app.route('/api/reports/summary')
def get_summary_report():
    return jsonify(
        report_generator.generate_summary_report()
    )


@app.route('/api/reports/list')
def list_reports():
    return jsonify(report_generator.get_saved_reports())


@app.route('/api/reports/download/<filename>')
def download_report(filename):
    filename = os.path.basename(filename)
    fpath    = os.path.join(Config.REPORTS_DIR, filename)
    if os.path.exists(fpath):
        return send_file(fpath, as_attachment=True)
    return jsonify({"error": "Not found"}), 404


@app.route('/api/reports/<filename>', methods=['DELETE'])
def delete_report(filename):
    """Delete a saved report."""
    result = report_generator.delete_report(filename)
    if result:
        return jsonify({"message": "Report deleted"})
    return jsonify({"error": "Not found"}), 404


# ══════════════════════════════════════════════════════════
# API - USER ACTIONS
# ══════════════════════════════════════════════════════════
@app.route('/api/user-actions')
def get_user_actions():
    return jsonify(user_actions.get_all_actions())

@app.route('/api/user-actions/can-do')
def get_can_do():
    return jsonify(user_actions.get_can_do())

@app.route('/api/user-actions/cannot-do')
def get_cannot_do():
    return jsonify(user_actions.get_cannot_do())


# ══════════════════════════════════════════════════════════
# API - NOTIFICATIONS
# ══════════════════════════════════════════════════════════
@app.route('/api/notifications')
def get_notifications():
    unread = request.args.get(
        'unread', 'false'
    ).lower() == 'true'
    return jsonify(
        notification_service.get_notifications(
            unread_only=unread
        )
    )


@app.route('/api/notifications/count')
def get_notification_count():
    return jsonify({
        "count": notification_service.get_unread_count()
    })


@app.route('/api/notifications/<int:nid>/read',
           methods=['POST'])
def mark_read(nid):
    notification_service.mark_as_read(nid)
    return jsonify({"message": "Marked as read"})


@app.route('/api/notifications/read-all', methods=['POST'])
def mark_all_read():
    notification_service.mark_all_as_read()
    return jsonify({"message": "All marked as read"})


# ══════════════════════════════════════════════════════════
# API - SYSTEM INFO
# ══════════════════════════════════════════════════════════
@app.route('/api/system/info')
def system_info():
    import psutil
    try:
        disk = (
            psutil.disk_usage('C:\\').percent
            if os.name == 'nt'
            else psutil.disk_usage('/').percent
        )
    except Exception:
        disk = 0
    try:
        cpu = psutil.cpu_percent(interval=0.1)
    except Exception:
        cpu = 0
    try:
        mem = psutil.virtual_memory().percent
    except Exception:
        mem = 0

    return jsonify({
        "app_name":          Config.APP_NAME,
        "version":           Config.VERSION,
        "cpu_percent":       cpu,
        "memory_percent":    mem,
        "disk_percent":      disk,
        "monitoring_active": scanner.is_running,
        "ml_model_loaded":   ml_detector.is_loaded,
        "timestamp":         datetime.now().isoformat(),
    })


# ══════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════
if __name__ == '__main__':
    print("=" * 60)
    print(f"🛡️  {Config.APP_NAME} v{Config.VERSION}")
    print("=" * 60)
    print(f"📊 Dashboard     : http://localhost:{Config.PORT}")
    print(f"🚨 Alerts        : http://localhost:{Config.PORT}/alerts")
    print(f"🌐 Traffic       : http://localhost:{Config.PORT}/traffic")
    print(f"🤖 ML Predictions: http://localhost:{Config.PORT}/ml-predictions")
    print(f"⚖️  Comparison    : http://localhost:{Config.PORT}/comparison")
    print(f"📄 Reports       : http://localhost:{Config.PORT}/reports")
    print(f"⚙️  Settings      : http://localhost:{Config.PORT}/settings")
    print(f"📁 Data Dir      : {Config.DATA_DIR}")
    print(f"🧠 ML Model      : "
          f"{'✅ Loaded' if ml_detector.is_loaded else '❌ Not Found'}")
    print("=" * 60)
    socketio.run(
        app,
        debug=Config.DEBUG,
        host=Config.HOST,
        port=Config.PORT,
    )