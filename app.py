"""Y-SCAN Enterprise Compliance Portal.

Read-only, low-volume checks for domains the operator owns or is authorized to assess.
This is an educational screening tool, not a penetration test or compliance certification.
"""
from __future__ import annotations

import ipaddress
import os
import re
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlunparse

import requests
import urllib3
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template, request, send_file
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# For development targets with untrusted/self-signed certificates only. Production requests
# still use verify=True below; globally muting warnings avoids noisy development consoles.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
REPORT_DIR = Path(os.environ.get("YSCAN_REPORT_DIR", "/tmp/yscan_downloads"))
REPORT_DIR.mkdir(parents=True, exist_ok=True)
MAX_WORKERS = 3
REQUEST_TIMEOUT = 1.5
REQUEST_DELAY = 0.12
PORTS = (21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3389, 5432, 5985, 8080, 9200)
PUBLIC_FILE_PATHS = ("/.env", "/backup.zip", "/config.php")
REPORTS: dict[str, dict] = {}
REPORTS_LOCK = threading.Lock()
RATE_LOCK = threading.Lock()
LAST_REQUEST_BY_IP: dict[str, float] = {}


class AuditInputError(ValueError):
    """Raised when the requested target is not eligible for this safe checker."""


class ComplianceAuditor:
    """Perform a small set of non-intrusive checks on an authorized public hostname."""

    def __init__(self, target: str):
        self.target = self._normalize_target(target)
        self.host = urlparse(self.target).hostname or ""
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Y-SCAN-Compliance-Check/1.0 (authorized defensive assessment)"})
        self._last_http_request = 0.0

    @staticmethod
    def _normalize_target(value: str) -> str:
        raw = (value or "").strip()
        if not raw or len(raw) > 253:
            raise AuditInputError("أدخل اسم نطاق صحيحاً.")
        if not re.match(r"^https?://", raw, re.I):
            raw = "https://" + raw
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
            raise AuditInputError("الرابط غير صالح. استخدم نطاقاً عاماً يبدأ بـ http أو https.")
        if parsed.username or parsed.password or parsed.port not in (None, 80, 443):
            raise AuditInputError("يسمح بنطاق عام ومنفذ الويب الافتراضي فقط.")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise AuditInputError("أدخل اسم النطاق فقط دون مسار أو معاملات.")
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        try:
            ipaddress.ip_address(host)
            raise AuditInputError("لأسباب السلامة، أدخل اسم نطاق لا عنوان IP مباشراً.")
        except ValueError as exc:
            if isinstance(exc, AuditInputError):
                raise
        if host == "localhost" or "." not in host or not re.fullmatch(r"[a-z0-9.-]+", host):
            raise AuditInputError("أدخل اسم نطاق عام صحيحاً.")
        scheme = parsed.scheme.lower()
        return urlunparse((scheme, host, "", "", "", ""))

    def _resolve_public_ips(self) -> list[str]:
        try:
            addresses = socket.getaddrinfo(self.host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise AuditInputError("تعذر العثور على عنوان عام لهذا النطاق.") from exc
        ips = sorted({item[4][0] for item in addresses})
        if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
            raise AuditInputError("يرتبط النطاق بعنوان غير عام؛ أُوقف الفحص لأسباب السلامة.")
        return ips

    def _google_dns(self, record_type: str) -> list[str]:
        try:
            response = requests.get(
                "https://dns.google/resolve",
                params={"name": self.host, "type": record_type},
                headers={"Accept": "application/dns-json", "User-Agent": "Y-SCAN/1.0"},
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            payload = response.json()
            return [entry.get("data", "") for entry in payload.get("Answer", []) if entry.get("data")]
        except (requests.RequestException, ValueError):
            return []

    def _dns_check(self) -> dict:
        return {"ips": self._resolve_public_ips(), "A": self._google_dns("A"),
                "MX": self._google_dns("MX"), "NS": self._google_dns("NS")}

    def _get(self, url: str) -> requests.Response | None:
        elapsed = time.monotonic() - self._last_http_request
        if elapsed < REQUEST_DELAY:
            time.sleep(REQUEST_DELAY - elapsed)
        self._last_http_request = time.monotonic()
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=True,
                                       stream=False)
            # Do not follow redirects: this prevents the checker from being redirected to a private host.
            return response
        except requests.RequestException:
            return None

    def _http_check(self) -> dict:
        response = self._get(self.target)
        if response is None:
            return {"reachable": False, "https": self.target.startswith("https://"),
                    "security_headers": 0, "cookie_flags": [], "firewall": "غير محدد"}
        headers = response.headers
        desired = ("Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options",
                   "X-Frame-Options", "Referrer-Policy")
        security_count = sum(1 for name in desired if name in headers)
        cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
        cookie_flags = []
        for cookie in cookies:
            lowered = cookie.lower()
            cookie_flags.extend(flag for flag, present in (("Secure", "; secure" in lowered),
                                 ("HttpOnly", "; httponly" in lowered),
                                 ("SameSite", "; samesite=" in lowered)) if present)
        server = headers.get("Server", "") + " " + headers.get("CF-Ray", "")
        firewall = "مؤشرات Cloudflare موجودة" if "cloudflare" in server.lower() or "CF-Ray" in headers else "غير مكتشف"
        return {"reachable": True, "https": self.target.startswith("https://"),
                "security_headers": security_count, "cookie_flags": sorted(set(cookie_flags)),
                "firewall": firewall, "cookies_seen": len(cookies)}

    def _public_files_check(self) -> dict:
        found = []
        for path in PUBLIC_FILE_PATHS:
            response = self._get(urljoin(self.target + "/", path.lstrip("/")))
            if response is not None and response.status_code == 200:
                found.append(path)
        return {"checked": len(PUBLIC_FILE_PATHS), "possible_exposures": found}

    def _site_map_check(self) -> dict:
        response = self._get(self.target)
        if response is None or response.status_code >= 400:
            return {"links": [], "count": 0}
        soup = BeautifulSoup(response.text[:500_000], "html.parser")
        links = []
        for anchor in soup.find_all("a", href=True):
            absolute = urljoin(self.target + "/", anchor["href"])
            parsed = urlparse(absolute)
            if parsed.scheme in ("http", "https") and parsed.hostname == self.host and absolute not in links:
                links.append(absolute)
                if len(links) == 5:
                    break
        return {"links": links, "count": len(links)}

    def _check_port(self, port: int) -> tuple[int, bool]:
        try:
            with socket.create_connection((self.host, port), timeout=REQUEST_TIMEOUT):
                return port, True
        except (OSError, socket.timeout):
            return port, False

    def _ports_check(self) -> dict:
        results = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            futures = [pool.submit(self._check_port, port) for port in PORTS]
            for future in as_completed(futures):
                port, is_open = future.result()
                results[str(port)] = "مستجيب" if is_open else "لا يستجيب"
        return results

    @staticmethod
    def _risk_and_compliance(dns: dict, http: dict, files: dict, ports: dict) -> dict:
        score = 45
        score += 10 if http["https"] else 0
        score += min(http["security_headers"] * 5, 25)
        score += 10 if dns["MX"] else 0
        score += 10 if dns["NS"] else 0
        score -= min(len(files["possible_exposures"]) * 15, 30)
        sensitive_open = sum(1 for port in (21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5985, 9200)
                             if ports.get(str(port)) == "مستجيب")
        score -= min(sensitive_open * 5, 20)
        score = max(0, min(100, score))
        # Illustrative only; this is not a business-impact calculation or a financial forecast.
        estimated_impact = round((100 - score) * 1250, -2)
        label = "جاهزية أولية جيدة" if score >= 80 else "تحتاج إلى تحسين" if score >= 55 else "تحتاج إلى مراجعة عاجلة"
        return {"score": score, "label": label, "estimated_impact_usd": estimated_impact,
                "pci": "مؤشرات أولية؛ يتطلب التحقق الرسمي", "iso": "مؤشرات أولية؛ يتطلب التحقق الرسمي",
                "yemen": "لا يمكن إثبات المطابقة آلياً؛ راجع المتطلبات الرسمية"}

    def run(self) -> dict:
        dns = self._dns_check()
        http = self._http_check()
        files = self._public_files_check()
        structure = self._site_map_check()
        ports = self._ports_check()
        risk = self._risk_and_compliance(dns, http, files, ports)
        return {"dns": dns, "http": http, "files": files, "structure": structure,
                "ports": ports, "risk": risk}


def _build_pdf(token: str, target: str, result: dict, filename: Path) -> None:
    page_width, _ = landscape(A4)
    usable_width = page_width - 30 * mm
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("YS_Title", parent=styles["Title"], textColor=colors.HexColor("#10243a"),
                                 fontSize=19, alignment=2, spaceAfter=8)
    body_style = ParagraphStyle("YS_Body", parent=styles["BodyText"], fontSize=8, leading=11)
    small_style = ParagraphStyle("YS_Small", parent=body_style, fontSize=7, leading=9)
    doc = SimpleDocTemplate(str(filename), pagesize=landscape(A4), rightMargin=15*mm, leftMargin=15*mm,
                            topMargin=14*mm, bottomMargin=14*mm, title="Y-SCAN Compliance Summary")
    story = [Paragraph("Y-SCAN | Enterprise Compliance Portal", title_style),
             Paragraph(f"Authorized screening summary &nbsp;|&nbsp; Verification: {token} &nbsp;|&nbsp; "
                       f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", body_style),
             Paragraph("Target: " + target.replace("&", "&amp;"), body_style), Spacer(1, 8)]

    def make_table(rows, widths):
        table = Table(rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#153a56")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"), ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("LEADING", (0, 0), (-1, -1), 10), ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5df")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f6f9")]),
            ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        return table

    risk = result["risk"]
    risk_labels = {"جاهزية أولية جيدة": "Initial readiness: good", "تحتاج إلى تحسين": "Improvement recommended",
                   "تحتاج إلى مراجعة عاجلة": "Urgent review recommended"}
    firewall_summary = "Cloudflare indicators observed" if result["http"]["firewall"] == "مؤشرات Cloudflare موجودة" else "No indicator detected"
    risk_rows = [["Readiness", "Indicative operational impact", "PCI DSS v4.0", "ISO 27001", "Yemen CBI information-security rules"],
                 [f"{risk['score']}/100 — {risk_labels.get(risk['label'], 'Review recommended')}", f"${risk['estimated_impact_usd']:,.0f} (illustrative only)",
                  "Preliminary indicators only; formal validation required",
                  "Preliminary indicators only; formal validation required",
                  "Automated compliance cannot be confirmed; consult official requirements"]]
    story += [Paragraph("1. Compliance dashboard & risk estimate", styles["Heading2"]),
              make_table(risk_rows, [usable_width*0.15, usable_width*0.19, usable_width*0.20,
                                    usable_width*0.18, usable_width*0.28]), Spacer(1, 10)]

    stages = [
        ["Audit stage", "Summary"],
        ["DNS overview", f"Public IPs: {', '.join(result['dns']['ips'])}; A/MX/NS queried via Google DNS."],
        ["HTTP, headers & cookies", f"Reachable: {result['http']['reachable']}; HTTPS: {result['http']['https']}; "
         f"security headers: {result['http']['security_headers']}/5; firewall: {firewall_summary}."],
        ["Public file hygiene", f"{len(result['files']['possible_exposures'])} possible public file(s) returned HTTP 200; verify manually."],
        ["Internal site structure", f"{result['structure']['count']} same-host link(s) sampled (maximum 5)."],
        ["Service availability", f"{sum(v == 'مستجيب' for v in result['ports'].values())} of {len(PORTS)} tested ports responded; treat as a prompt for owner review."],
    ]
    story += [Paragraph("2. Audit stages summary", styles["Heading2"]),
              make_table([[Paragraph(str(cell), small_style) for cell in row] for row in stages],
                         [usable_width*0.23, usable_width*0.77]), Spacer(1, 10)]

    recommendations = [
        ["Observation", "Recommended defensive action"],
        ["Transport security", "Serve the site over HTTPS, enable HSTS after confirming HTTPS readiness, and redirect HTTP to HTTPS." if not result["http"]["https"] else "Review TLS configuration and HSTS policy against organizational requirements."],
        ["Response headers", "Review a restrictive Content-Security-Policy, X-Content-Type-Options, frame protections, and Referrer-Policy."],
        ["Cookies", "Set Secure, HttpOnly, and an appropriate SameSite policy on session cookies."],
        ["Public files", "If any candidate files are intentionally public, verify content; otherwise remove them and block sensitive artifacts at the web server."],
        ["Service exposure", "Confirm every responding service is required; restrict administrative/database services to trusted networks and firewall rules."],
        ["Compliance", "This screening is not an audit, certification, legal opinion, or financial estimate. Use qualified assessors and official control mappings."],
    ]
    story += [Paragraph("3. Configuration recommendations", styles["Heading2"]),
              make_table([[Paragraph(str(cell), small_style) for cell in row] for row in recommendations],
                         [usable_width*0.20, usable_width*0.80]), Spacer(1, 7),
              Paragraph("Confidentiality: this report is stored temporarily on the application server and may be removed at any time. "
                        "Only test domains you own or are explicitly authorized to assess. Results can be incomplete or inaccurate.", small_style)]
    doc.build(story)


def _public_summary(result: dict, token: str) -> dict:
    risk = result["risk"]
    # Do not send IPs, headers, paths, cookies, link inventory or port-by-port results to the browser.
    return {"score": risk["score"], "label": risk["label"], "estimated_impact_usd": risk["estimated_impact_usd"],
            "compliance": {"pci": risk["pci"], "iso": risk["iso"], "yemen": risk["yemen"]},
            "verification_code": token}


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/audit")
def audit():
    payload = request.get_json(silent=True) or {}
    if payload.get("authorized") is not True:
        return jsonify({"error": "يجب تأكيد أنك مالك النطاق أو مفوض صراحةً."}), 400
    client_ip = request.remote_addr or "unknown"
    now = time.monotonic()
    with RATE_LOCK:
        previous = LAST_REQUEST_BY_IP.get(client_ip, 0.0)
        if now - previous < 20:
            return jsonify({"error": "يرجى الانتظار قليلاً قبل بدء فحص جديد."}), 429
        LAST_REQUEST_BY_IP[client_ip] = now
    try:
        auditor = ComplianceAuditor(payload.get("target", ""))
        result = auditor.run()
    except AuditInputError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("Audit failed")
        return jsonify({"error": "تعذر إكمال الفحص. تحقق من النطاق وحاول لاحقاً."}), 502
    token = f"YS-{secrets.randbelow(900000) + 100000}"
    filename = REPORT_DIR / f"{token}.pdf"
    try:
        _build_pdf(token, auditor.target, result, filename)
    except Exception:
        app.logger.exception("PDF generation failed")
        return jsonify({"error": "تعذر إنشاء التقرير حالياً."}), 500
    with REPORTS_LOCK:
        REPORTS[token] = {"path": str(filename), "created": time.time(), "target": auditor.target}
        # Bound in-memory metadata on small instances; the temporary report files may expire on restart.
        for old_token, entry in list(REPORTS.items()):
            if time.time() - entry["created"] > 24 * 3600:
                REPORTS.pop(old_token, None)
    return jsonify(_public_summary(result, token))


@app.get("/report/<token>")
def download_report(token: str):
    if not re.fullmatch(r"YS-\d{6}", token):
        return "Report not found", 404
    with REPORTS_LOCK:
        entry = REPORTS.get(token)
    if not entry or not Path(entry["path"]).is_file():
        return "Report not found or expired", 404
    return send_file(entry["path"], mimetype="application/pdf", as_attachment=True,
                     download_name=f"Y-SCAN-{token}.pdf", max_age=0)


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
