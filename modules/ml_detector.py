"""
ML Detector Module - XGBoost UNSW-NB15 Integration
Option B: Real network data via psutil + HTTP request data

Key Design:
- ML predicts ATTACK vs NORMAL only
- Severity comes from RULE-BASED detection
- Internal IPs are skipped
- Confidence score shows prediction certainty
"""
import pickle
import numpy as np
import psutil
import time
from datetime import datetime
from threading import Lock
from collections import defaultdict


class MLDetector:
    def __init__(self, model_path="unsw_nb15_xgb_model.pkl"):
        self.model      = None
        self.model_path = model_path
        self.lock       = Lock()
        self.is_loaded  = False

        # Connection history for ct_* features
        self.conn_history = defaultdict(list)
        self.MAX_HISTORY  = 1000

        # Prediction history for stats
        self.prediction_history = []
        self.MAX_PRED_HISTORY   = 500

        # Feature names (must match training order)
        self.feature_names = [
            'srcip', 'sport', 'dstip', 'dsport',
            'proto', 'dur', 'sbytes', 'dbytes',
            'sttl', 'dttl', 'sloss', 'dloss',
            'service', 'Sload', 'Dload', 'Spkts',
            'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
            'smeansz', 'dmeansz', 'Sjit', 'Djit',
            'Stime', 'Ltime', 'Sintpkt', 'Dintpkt',
            'tcprtt', 'synack', 'ackdat',
            'ct_state_ttl', 'ct_ftp_cmd',
            'ct_srv_src', 'ct_srv_dst',
            'ct_dst_ltm', 'ct_src_ltm',
            'ct_dst_src_ltm'
        ]

        # Protocol mapping
        self.proto_map = {
            'tcp': 6, 'udp': 17, 'icmp': 1,
            'http': 6, 'https': 6, 'ftp': 6,
            'smtp': 6, 'dns': 17,
        }

        # Service mapping
        self.service_map = {
            80: 1, 443: 2, 21: 3, 22: 4,
            25: 5, 53: 6, 3306: 7, 3389: 8, 8080: 9,
        }

        # IPs to skip
        self.skip_ips = {
            '127.0.0.1', 'localhost', '::1', '0.0.0.0',
        }

        self._load_model()

    # ── Model Loading ──────────────────────────────────────
    def _load_model(self):
        try:
            with open(self.model_path, 'rb') as f:
                self.model = pickle.load(f)
            self.is_loaded = True
            print(f"✅ ML Model loaded: "
                  f"{self.model.__class__.__name__}")
            print(f"   Features : {self.model.n_features_in_}")
            print(f"   Classes  : {list(self.model.classes_)}")
        except FileNotFoundError:
            print(f"❌ Model not found: {self.model_path}")
            self.is_loaded = False
        except Exception as e:
            print(f"❌ Model load error: {e}")
            self.is_loaded = False

    # ── Type conversion ────────────────────────────────────
    def _to_python(self, obj):
        """Convert numpy types to Python native."""
        if isinstance(obj, dict):
            return {k: self._to_python(v)
                    for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._to_python(i) for i in obj]
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.bool_):
            return bool(obj)
        return obj

    # ── IP Helpers ─────────────────────────────────────────
    def _ip_to_int(self, ip_str):
        try:
            parts = ip_str.strip().split('.')
            if len(parts) == 4:
                return (int(parts[0]) << 24 |
                        int(parts[1]) << 16 |
                        int(parts[2]) << 8 |
                        int(parts[3]))
        except Exception:
            pass
        return 0

    def _is_internal_ip(self, ip):
        if ip in self.skip_ips:
            return True
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                first  = int(parts[0])
                second = int(parts[1])
                if first == 10:
                    return True
                if first == 172 and 16 <= second <= 31:
                    return True
                if first == 192 and second == 168:
                    return True
        except Exception:
            pass
        return False

    # ── psutil helpers ─────────────────────────────────────
    def _get_psutil_connection(self, src_ip):
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.raddr.ip == src_ip:
                    return conn
        except Exception:
            pass
        return None

    # ── ct_* features ──────────────────────────────────────
    def _calculate_ct_features(self, src_ip, dst_ip,
                                dst_port, service):
        now    = time.time()
        window = 100

        self.conn_history['all'] = [
            c for c in self.conn_history['all']
            if now - c['time'] <= window
        ]
        recent = self.conn_history['all']

        ct_srv_src = sum(
            1 for c in recent
            if c['src_ip'] == src_ip and
               c['service'] == service
        )
        ct_srv_dst = sum(
            1 for c in recent
            if c['dst_ip'] == dst_ip and
               c['service'] == service
        )
        ct_dst_ltm = sum(
            1 for c in recent
            if c['dst_ip'] == dst_ip
        )
        ct_src_ltm = sum(
            1 for c in recent
            if c['src_ip'] == src_ip
        )
        ct_dst_src_ltm = sum(
            1 for c in recent
            if c['src_ip'] == src_ip and
               c['dst_ip'] == dst_ip
        )

        self.conn_history['all'].append({
            'time': now, 'src_ip': src_ip,
            'dst_ip': dst_ip, 'service': service,
            'port': dst_port,
        })

        if len(self.conn_history['all']) > self.MAX_HISTORY:
            self.conn_history['all'] = \
                self.conn_history['all'][-self.MAX_HISTORY:]

        return {
            'ct_srv_src': ct_srv_src,
            'ct_srv_dst': ct_srv_dst,
            'ct_dst_ltm': ct_dst_ltm,
            'ct_src_ltm': ct_src_ltm,
            'ct_dst_src_ltm': ct_dst_src_ltm,
        }

    # ══════════════════════════════════════════════════════
    # FEATURE EXTRACTION
    # ══════════════════════════════════════════════════════
    def extract_features(self, src_ip, dst_ip, dst_port,
                         method, path, user_agent,
                         content_length, request_start_time,
                         status_code=200, response_size=0):

        psutil_conn = self._get_psutil_connection(src_ip)

        now   = time.time()
        dur   = max(now - request_start_time, 0.001)
        stime = request_start_time
        ltime = now

        # Port
        if psutil_conn and psutil_conn.raddr:
            sport         = int(psutil_conn.raddr.port)
            quality_sport = "real"
        else:
            sport         = 0
            quality_sport = "estimated"

        proto   = 6
        service = self.service_map.get(dst_port, 0)
        sbytes  = max(int(content_length or 0), 0)
        dbytes  = max(int(response_size or 0), 0)

        mtu     = 1500
        spkts   = max(1, sbytes // mtu + 1)
        dpkts   = max(1, dbytes // mtu + 1)
        smeansz = sbytes / spkts if spkts > 0 else 0.0
        dmeansz = dbytes / dpkts if dpkts > 0 else 0.0
        sload   = (sbytes * 8) / dur if dur > 0 else 0.0
        dload   = (dbytes * 8) / dur if dur > 0 else 0.0

        sttl, dttl     = 64, 64
        sloss, dloss   = 0, 0
        swin, dwin     = 255, 255
        stcpb, dtcpb   = 0, 0
        sjit, djit     = 0.0, 0.0
        sintpkt = dur / spkts if spkts > 1 else dur
        dintpkt = dur / dpkts if dpkts > 1 else dur
        tcprtt  = dur * 0.1
        synack  = dur * 0.05
        ackdat  = dur * 0.05
        ct_ftp_cmd   = 1 if dst_port == 21 else 0

        if 60 <= sttl <= 64:
            ct_state_ttl = 2
        elif 124 <= sttl <= 128:
            ct_state_ttl = 3
        elif sttl == 255:
            ct_state_ttl = 4
        else:
            ct_state_ttl = 1

        ct = self._calculate_ct_features(
            src_ip, dst_ip, dst_port, service
        )

        feature_dict = {
            'srcip':          float(self._ip_to_int(src_ip)),
            'sport':          float(sport),
            'dstip':          float(self._ip_to_int(dst_ip)),
            'dsport':         float(dst_port),
            'proto':          float(proto),
            'dur':            round(float(dur), 6),
            'sbytes':         float(sbytes),
            'dbytes':         float(dbytes),
            'sttl':           float(sttl),
            'dttl':           float(dttl),
            'sloss':          float(sloss),
            'dloss':          float(dloss),
            'service':        float(service),
            'Sload':          round(float(sload), 4),
            'Dload':          round(float(dload), 4),
            'Spkts':          float(spkts),
            'Dpkts':          float(dpkts),
            'swin':           float(swin),
            'dwin':           float(dwin),
            'stcpb':          float(stcpb),
            'dtcpb':          float(dtcpb),
            'smeansz':        round(float(smeansz), 2),
            'dmeansz':        round(float(dmeansz), 2),
            'Sjit':           float(sjit),
            'Djit':           float(djit),
            'Stime':          round(float(stime), 6),
            'Ltime':          round(float(ltime), 6),
            'Sintpkt':        round(float(sintpkt), 6),
            'Dintpkt':        round(float(dintpkt), 6),
            'tcprtt':         round(float(tcprtt), 6),
            'synack':         round(float(synack), 6),
            'ackdat':         round(float(ackdat), 6),
            'ct_state_ttl':   float(ct_state_ttl),
            'ct_ftp_cmd':     float(ct_ftp_cmd),
            'ct_srv_src':     float(ct['ct_srv_src']),
            'ct_srv_dst':     float(ct['ct_srv_dst']),
            'ct_dst_ltm':     float(ct['ct_dst_ltm']),
            'ct_src_ltm':     float(ct['ct_src_ltm']),
            'ct_dst_src_ltm': float(ct['ct_dst_src_ltm']),
        }

        feature_array = np.array([
            feature_dict[n] for n in self.feature_names
        ], dtype=np.float64).reshape(1, -1)

        # Quality info
        real_features = [
            'srcip', 'dstip', 'dsport', 'proto',
            'dur', 'sbytes', 'Sload', 'Spkts',
            'smeansz', 'Stime', 'Ltime',
            'ct_srv_src', 'ct_srv_dst',
            'ct_dst_ltm', 'ct_src_ltm',
            'ct_dst_src_ltm', 'ct_ftp_cmd', 'service',
        ]
        if quality_sport == "real":
            real_features.append('sport')

        quality_info = {
            "total_features":     39,
            "real_features":      0,
            "estimated_features": 0,
            "real_list":          [],
            "estimated_list":     [],
        }
        for f in self.feature_names:
            if f in real_features:
                quality_info["real_features"] += 1
                quality_info["real_list"].append(f)
            else:
                quality_info["estimated_features"] += 1
                quality_info["estimated_list"].append(f)

        return feature_array, feature_dict, quality_info

    # ══════════════════════════════════════════════════════
    # PREDICTION (attack/normal only, NO severity)
    # ══════════════════════════════════════════════════════
    def predict(self, src_ip, dst_ip, dst_port,
                method, path, user_agent,
                content_length, request_start_time,
                status_code=200, response_size=0):
        """
        Predict ATTACK or NORMAL only.
        Severity is NOT determined here —
        it comes from rule-based detection.
        """
        if not self.is_loaded:
            return {
                "success": False,
                "error": "Model not loaded",
                "prediction": None,
            }

        # Skip internal IPs
        if self._is_internal_ip(src_ip):
            return {
                "success":            True,
                "skipped":            True,
                "reason":             "Internal IP",
                "source_ip":          src_ip,
                "is_attack":          False,
                "prediction":         0,
                "label":              "NORMAL",
                "attack_probability": 0.0,
                "normal_probability": 100.0,
                "confidence":         100.0,
                "timestamp":          datetime.now().isoformat(),
                "path":               path,
                "method":             method,
                "features":           {},
                "data_quality": {
                    "real_features": 0,
                    "estimated_features": 39,
                    "total_features": 39,
                    "quality_percent": 0,
                    "real_list": [],
                    "estimated_list": self.feature_names,
                },
            }

        try:
            features, feat_dict, quality = \
                self.extract_features(
                    src_ip, dst_ip, dst_port,
                    method, path, user_agent,
                    content_length, request_start_time,
                    status_code, response_size
                )

            with self.lock:
                pred  = self.model.predict(features)[0]
                proba = self.model.predict_proba(features)[0]

            pred    = int(pred)
            proba_0 = float(proba[0])
            proba_1 = float(proba[1])

            is_attack   = pred == 1
            attack_prob = round(proba_1 * 100, 2)
            normal_prob = round(proba_0 * 100, 2)
            confidence  = round(
                max(proba_0, proba_1) * 100, 2
            )

            feat_dict_clean = self._to_python(feat_dict)

            quality_pct = round(
                quality["real_features"] /
                quality["total_features"] * 100, 1
            )

            result = self._to_python({
                "success":            True,
                "skipped":            False,
                "timestamp":          datetime.now().isoformat(),
                "source_ip":          src_ip,
                "destination_ip":     dst_ip,
                "destination_port":   dst_port,
                "method":             method,
                "path":               path,
                "prediction":         pred,
                "is_attack":          is_attack,
                "attack_probability": attack_prob,
                "normal_probability": normal_prob,
                "confidence":         confidence,
                "label":              (
                    "ATTACK" if is_attack else "NORMAL"
                ),
                # NO severity here — comes from rules
                "features":           feat_dict_clean,
                "data_quality": {
                    "real_features":     quality[
                        "real_features"
                    ],
                    "estimated_features": quality[
                        "estimated_features"
                    ],
                    "total_features":    quality[
                        "total_features"
                    ],
                    "quality_percent":   quality_pct,
                    "real_list":         quality["real_list"],
                    "estimated_list":    quality[
                        "estimated_list"
                    ],
                },
            })

            # Store in history
            self.prediction_history.append(result)
            if len(self.prediction_history) > \
                    self.MAX_PRED_HISTORY:
                self.prediction_history.pop(0)

            return result

        except Exception as e:
            print(f"❌ ML prediction error: {e}")
            import traceback
            traceback.print_exc()
            return {
                "success":    False,
                "error":      str(e),
                "prediction": None,
            }

    # ══════════════════════════════════════════════════════
    # STATS & INFO
    # ══════════════════════════════════════════════════════
    def get_model_info(self):
        if not self.is_loaded:
            return {"loaded": False}
        return {
            "loaded":        True,
            "model_class":   str(
                self.model.__class__.__name__
            ),
            "n_features":    int(self.model.n_features_in_),
            "n_estimators":  int(self.model.n_estimators),
            "max_depth":     int(self.model.max_depth),
            "learning_rate": float(self.model.learning_rate),
            "objective":     str(self.model.objective),
            "classes":       [
                int(c) for c in self.model.classes_
            ],
            "feature_names": self.feature_names,
            "note": (
                "ML predicts ATTACK/NORMAL only. "
                "Severity comes from rule-based detection."
            ),
        }

    def get_predictions(self, limit=100,
                        only_attacks=False):
        preds = list(self.prediction_history)
        if only_attacks:
            preds = [
                p for p in preds if p.get('is_attack')
            ]
        return preds[-limit:][::-1]

    def get_summary(self):
        preds   = list(self.prediction_history)
        total   = len(preds)
        attacks = sum(
            1 for p in preds if p.get('is_attack')
        )
        normal  = total - attacks

        avg_conf = (
            sum(p.get('confidence', 0) for p in preds)
            / total
        ) if total > 0 else 0

        avg_quality = (
            sum(
                p.get('data_quality', {}).get(
                    'quality_percent', 0
                )
                for p in preds
            ) / total
        ) if total > 0 else 0

        return {
            "total_predictions":  total,
            "attack_predictions": attacks,
            "normal_predictions": normal,
            "attack_rate":        round(
                attacks / total * 100, 1
            ) if total > 0 else 0,
            "avg_confidence":     round(avg_conf, 1),
            "avg_data_quality":   round(avg_quality, 1),
            "model_info":         self.get_model_info(),
        }

    def clear_history(self):
        self.prediction_history = []
        self.conn_history.clear()