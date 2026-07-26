"""
Report Generation Module
JSON, CSV, and PDF reports
"""
import json
import csv
import os
from datetime import datetime, timedelta


class ReportGenerator:
    def __init__(self, data_dir="data"):
        self.data_dir    = data_dir
        self.reports_dir = os.path.join(data_dir, "reports")
        os.makedirs(self.reports_dir, exist_ok=True)

    def _load_alerts(self):
        try:
            path = os.path.join(
                self.data_dir, "alerts.json"
            )
            with open(path, 'r') as f:
                return json.load(f).get("alerts", [])
        except Exception:
            return []

    def _filter(self, alerts, start=None, end=None,
                severity=None):
        if start:
            try:
                sd = datetime.fromisoformat(start)
                alerts = [
                    a for a in alerts
                    if datetime.fromisoformat(
                        a.get("timestamp", "")
                    ) >= sd
                ]
            except Exception:
                pass
        if end:
            try:
                ed = datetime.fromisoformat(
                    end + "T23:59:59"
                )
                alerts = [
                    a for a in alerts
                    if datetime.fromisoformat(
                        a.get("timestamp", "")
                    ) <= ed
                ]
            except Exception:
                pass
        if severity:
            alerts = [
                a for a in alerts
                if a.get("severity") == severity
            ]
        return alerts

    def generate_json_report(self, start=None,
                             end=None, severity=None):
        alerts  = self._filter(
            self._load_alerts(), start, end, severity
        )
        by_sev  = {}
        by_type = {}
        for a in alerts:
            s = a.get("severity", "unknown")
            t = a.get("type", "unknown")
            by_sev[s]  = by_sev.get(s, 0) + 1
            by_type[t] = by_type.get(t, 0) + 1

        report = {
            "report_type":  "Security Alerts Report",
            "generated_at": datetime.now().isoformat(),
            "period": {
                "start": start or "All time",
                "end":   end or "Present",
            },
            "summary": {
                "total":       len(alerts),
                "by_severity": by_sev,
                "by_type":     by_type,
            },
            "alerts": alerts,
        }
        fname = (
            f"report_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            f".json"
        )
        fpath = os.path.join(self.reports_dir, fname)
        with open(fpath, 'w') as f:
            json.dump(report, f, indent=2)
        return {
            "filename": fname,
            "filepath": fpath,
            "report":   report,
        }

    def generate_csv_report(self, start=None,
                            end=None, severity=None):
        alerts = self._filter(
            self._load_alerts(), start, end, severity
        )
        fname = (
            f"report_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            f".csv"
        )
        fpath   = os.path.join(self.reports_dir, fname)
        headers = [
            "ID", "Timestamp", "Type", "Severity",
            "Source IP", "Destination IP", "Port",
            "Description", "Rule ID", "Rule Name",
            "Status", "Detection Source",
        ]
        with open(fpath, 'w', newline='',
                  encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(headers)
            for a in alerts:
                w.writerow([
                    a.get("id", ""),
                    a.get("timestamp", ""),
                    a.get("type", ""),
                    a.get("severity", ""),
                    a.get("source_ip", ""),
                    a.get("destination_ip", ""),
                    a.get("destination_port", ""),
                    a.get("description", ""),
                    a.get("rule_id", ""),
                    a.get("rule_name", ""),
                    a.get("status", ""),
                    a.get("detection_source", "rule"),
                ])
        return {
            "filename": fname,
            "filepath": fpath,
            "total":    len(alerts),
        }

    def generate_pdf_report(self, start=None,
                            end=None, severity=None):
        """Generate PDF report."""
        try:
            from fpdf import FPDF
        except ImportError:
            return {
                "error": (
                    "fpdf2 not installed. "
                    "Run: pip install fpdf2"
                )
            }

        alerts = self._filter(
            self._load_alerts(), start, end, severity
        )

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 20)
        pdf.cell(
            0, 15, "IDS Security Report", ln=True,
            align="C"
        )
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(
            0, 8,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ln=True, align="C"
        )
        pdf.cell(
            0, 8,
            f"Period: {start or 'All time'} to "
            f"{end or 'Present'}",
            ln=True, align="C"
        )
        pdf.ln(10)

        # Summary
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Summary", ln=True)
        pdf.set_font("Helvetica", "", 11)

        sev_counts = {}
        type_counts = {}
        for a in alerts:
            s = a.get("severity", "unknown")
            t = a.get("type", "unknown")
            sev_counts[s]  = sev_counts.get(s, 0) + 1
            type_counts[t] = type_counts.get(t, 0) + 1

        pdf.cell(
            0, 8, f"Total Alerts: {len(alerts)}",
            ln=True
        )
        for s, c in sorted(
            sev_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            pdf.cell(
                0, 7, f"  {s.upper()}: {c}",
                ln=True
            )

        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Top Threat Types", ln=True)
        pdf.set_font("Helvetica", "", 11)
        for t, c in sorted(
            type_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]:
            pdf.cell(
                0, 7,
                f"  {t.replace('_', ' ').title()}: {c}",
                ln=True,
            )

        # Alert details table
        pdf.ln(5)
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "Alert Details", ln=True)

        # Table header
        pdf.set_font("Helvetica", "B", 8)
        col_w = [15, 35, 30, 25, 20, 60]
        headers = [
            "ID", "Time", "Source IP",
            "Type", "Severity", "Description",
        ]
        for i, h in enumerate(headers):
            pdf.cell(col_w[i], 8, h, border=1)
        pdf.ln()

        # Table rows
        pdf.set_font("Helvetica", "", 7)
        for a in alerts[:200]:  # limit to 200 rows
            row = [
                str(a.get("id", "")),
                a.get("timestamp", "")[:19],
                a.get("source_ip", ""),
                a.get("type", "")[:15],
                a.get("severity", ""),
                a.get("description", "")[:40],
            ]
            for i, val in enumerate(row):
                pdf.cell(col_w[i], 6, val, border=1)
            pdf.ln()

        # Save
        fname = (
            f"report_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            f".pdf"
        )
        fpath = os.path.join(self.reports_dir, fname)
        pdf.output(fpath)

        return {
            "filename": fname,
            "filepath": fpath,
            "total":    len(alerts),
        }

    def generate_summary_report(self):
        alerts = self._load_alerts()
        now    = datetime.now()

        def count_since(hours):
            since = now - timedelta(hours=hours)
            count = 0
            for a in alerts:
                try:
                    t = datetime.fromisoformat(
                        a.get("timestamp", "")
                    )
                    if t >= since:
                        count += 1
                except Exception:
                    pass
            return count

        by_type = {}
        by_ip   = {}
        for a in alerts:
            t  = a.get("type", "unknown")
            ip = a.get("source_ip", "unknown")
            by_type[t]  = by_type.get(t, 0) + 1
            by_ip[ip]   = by_ip.get(ip, 0) + 1

        recs = []
        c = sum(
            1 for a in alerts
            if a.get("severity") == "critical"
        )
        h = sum(
            1 for a in alerts
            if a.get("severity") == "high"
        )
        m = sum(
            1 for a in alerts
            if a.get("severity") == "medium"
        )
        lo = sum(
            1 for a in alerts
            if a.get("severity") == "low"
        )

        if c > 0:
            recs.append(
                "URGENT: Address critical alerts immediately"
            )
        if count_since(24) > 50:
            recs.append(
                "High alert volume in last 24h — investigate"
            )
        top_ip = max(by_ip, key=by_ip.get) if by_ip else None
        if top_ip and by_ip.get(top_ip, 0) > 10:
            recs.append(
                f"Consider blocking {top_ip} — "
                f"{by_ip[top_ip]} alerts"
            )

        return {
            "title":        "Security Summary Report",
            "generated_at": now.isoformat(),
            "overall_stats": {
                "total_alerts": len(alerts),
                "critical": c, "high": h,
                "medium": m, "low": lo,
            },
            "time_based": {
                "last_24_hours": count_since(24),
                "last_7_days":   count_since(168),
                "last_30_days":  count_since(720),
            },
            "top_threat_types": dict(
                sorted(
                    by_type.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:5]
            ),
            "top_source_ips": dict(
                sorted(
                    by_ip.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:5]
            ),
            "recommendations": recs,
        }

    def get_saved_reports(self):
        reports = []
        try:
            for fname in os.listdir(self.reports_dir):
                fpath = os.path.join(
                    self.reports_dir, fname
                )
                stat  = os.stat(fpath)
                reports.append({
                    "filename": fname,
                    "size":     stat.st_size,
                    "created":  datetime.fromtimestamp(
                        stat.st_ctime
                    ).isoformat(),
                    "type": fname.split(".")[-1].upper(),
                })
        except Exception:
            pass
        return sorted(
            reports,
            key=lambda x: x["created"],
            reverse=True,
        )

    def delete_report(self, filename):
        # Sanitize
        filename = os.path.basename(filename)
        fpath    = os.path.join(
            self.reports_dir, filename
        )
        if os.path.exists(fpath):
            os.remove(fpath)
            return True
        return False