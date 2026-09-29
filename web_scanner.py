"""
Web vulnerability assessment engine (non-intrusive / passive-first).

Features: asset discovery, security-header & TLS checks, cookie/CORS/method checks,
HTML analysis (CSRF, mixed content, SRI, outdated JS libs), exposed-file detection,
configuration-compliance %, CVSS-style severity, risk score, OWASP Top-10 mapping and a
phased remediation plan.  NO exploitation / payload injection is performed.
"""
import concurrent.futures as cf
import random
import re
import socket
import ssl
import string
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from urllib.parse import parse_qs, urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
UA = "VARE-Scanner/1.0 (educational lab; non-intrusive)"

OWASP = {
    "A01": "Broken Access Control", "A02": "Cryptographic Failures", "A03": "Injection",
    "A04": "Insecure Design", "A05": "Security Misconfiguration",
    "A06": "Vulnerable & Outdated Components", "A07": "Identification & Authentication Failures",
    "A08": "Software & Data Integrity Failures", "A09": "Security Logging & Monitoring Failures",
    "A10": "Server-Side Request Forgery",
}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def sev_label(c):
    return ("Critical" if c >= 9 else "High" if c >= 7 else "Medium" if c >= 4
            else "Low" if c > 0 else "Info")


@dataclass
class Finding:
    fid: str
    title: str
    owasp: str
    cvss: float
    exploitability: float      # 0..1  (how easy to exploit)
    evidence: str
    remediation: list
    severity: str = ""
    risk_score: float = 0.0    # 0..100 = CVSS*10 * (0.5 + 0.5*exploitability)

    def __post_init__(self):
        self.severity = sev_label(self.cvss)
        self.risk_score = round(self.cvss * 10 * (0.5 + 0.5 * self.exploitability), 1)


# port -> (service, cvss, exploitability, remediation)
PORTS = {
    21: ("FTP", 5.9, 0.6, "Disable FTP; use SFTP/FTPS."),
    22: ("SSH", 0.0, 0.0, ""),
    23: ("Telnet", 8.1, 0.8, "Disable Telnet; use SSH."),
    25: ("SMTP", 0.0, 0.0, ""),
    53: ("DNS", 0.0, 0.0, ""),
    80: ("HTTP", 0.0, 0.0, ""), 443: ("HTTPS", 0.0, 0.0, ""),
    110: ("POP3", 3.7, 0.4, "Allow only TLS-enabled POP3S/IMAPS."),
    143: ("IMAP", 3.7, 0.4, "Allow only TLS-enabled IMAPS."),
    445: ("SMB", 8.1, 0.7, "Firewall SMB off from the internet."),
    1433: ("MSSQL", 8.6, 0.7, "Do not expose DB ports publicly; use a VPN/private subnet."),
    3306: ("MySQL", 8.6, 0.7, "Do not expose DB ports publicly; use a VPN/private subnet."),
    3389: ("RDP", 8.1, 0.7, "Put RDP behind a VPN/bastion host and enforce MFA."),
    5432: ("PostgreSQL", 8.6, 0.7, "Do not expose DB ports publicly; use a VPN/private subnet."),
    5900: ("VNC", 8.1, 0.7, "Put VNC behind a VPN."),
    6379: ("Redis", 9.1, 0.9, "Enable Redis auth and bind to 127.0.0.1; remove public exposure."),
    8080: ("HTTP-alt", 0.0, 0.0, ""), 8443: ("HTTPS-alt", 0.0, 0.0, ""),
    9200: ("Elasticsearch", 8.6, 0.8, "Run Elasticsearch on a private network with authentication."),
    27017: ("MongoDB", 9.1, 0.9, "Enable MongoDB authentication and remove public exposure."),
}

# path, title, cvss, exploitability, owasp, validator(resp)->bool, remediation
def _not_html(r):
    return r.status_code == 200 and "html" not in r.headers.get("Content-Type", "").lower() and len(r.content) > 0

EXPOSED = [
    ("/.git/HEAD", "Git repository exposed", 9.1, 0.9, "A05", lambda r: r.status_code == 200 and r.text.strip().startswith("ref:"),
     ["Deny access to the .git directory on the web server (location ~ /\\.git { deny all; }).",
      "Remove .git from deploy artifacts; rotate any secrets found in git history."]),
    ("/.env", "Environment file (.env) exposed", 9.8, 0.95, "A05",
     lambda r: _not_html(r) and re.search(r"^[A-Z][A-Z0-9_]+=.+", r.text, re.M) is not None,
     [".env must live outside the web root / deny access to it.", "Immediately rotate all leaked secrets/keys."]),
    ("/.DS_Store", ".DS_Store file exposed", 5.3, 0.6, "A05", lambda r: r.status_code == 200 and r.content[:8] == b"\x00\x00\x00\x01Bud1",
     ["Delete .DS_Store files and exclude them in the deploy pipeline."]),
    ("/phpinfo.php", "phpinfo() page exposed", 7.5, 0.8, "A05", lambda r: r.status_code == 200 and "PHP Version" in r.text,
     ["Remove phpinfo.php.", "Set expose_php=Off in production."]),
    ("/server-status", "Apache server-status exposed", 5.3, 0.6, "A05", lambda r: r.status_code == 200 and "Apache Server Status" in r.text,
     ["Restrict mod_status to localhost/internal IPs only."]),
    ("/backup.zip", "Backup archive exposed", 7.5, 0.8, "A05", _not_html,
     ["Move backups out of the web root; use offline/secured storage."]),
    ("/backup.sql", "Database dump exposed", 9.1, 0.9, "A05", _not_html,
     ["Remove DB dumps from the web root; rotate leaked credentials."]),
    ("/wp-config.php.bak", "Config backup exposed", 9.1, 0.9, "A05", _not_html,
     ["Delete config backups; rotate credentials."]),
    ("/swagger.json", "API documentation publicly exposed", 3.1, 0.5, "A05",
     lambda r: r.status_code == 200 and ('"swagger"' in r.text or '"openapi"' in r.text),
     ["Put API docs behind authentication or restrict them to the internal network."]),
    ("/openapi.json", "OpenAPI schema publicly exposed", 3.1, 0.5, "A05",
     lambda r: r.status_code == 200 and '"openapi"' in r.text,
     ["Put API docs behind authentication."]),
]


class Scanner:
    def __init__(self, url, do_ports=True, do_files=True, timeout=8, progress=None):
        url = url.strip()
        if not re.match(r"^https?://", url, re.I):
            url = "https://" + url
        self.url = url
        p = urlparse(url)
        self.host, self.scheme = p.hostname, p.scheme
        self.port = p.port or (443 if p.scheme == "https" else 80)
        self.do_ports, self.do_files, self.timeout, self.progress = do_ports, do_files, timeout, progress
        self.s = requests.Session()
        self.s.headers["User-Agent"] = UA
        self.findings, self.checks, self.assets, self.surface = [], [], {}, {}
        self.tls_error, self._n, self.r = None, 0, None

    # ------------------------------------------------------------ helpers
    def _p(self, f, msg):
        if self.progress:
            self.progress(f, msg)

    def check(self, name, ok, title=None, owasp="A05", cvss=0.0, expl=0.3, evidence="", fix=None):
        self.checks.append({"check": name, "passed": bool(ok), "owasp": owasp})
        if not ok:
            self._n += 1
            self.findings.append(Finding(f"VARE-{self._n:03d}", title or name, owasp, cvss, expl,
                                         evidence, fix or []))

    def _fetch(self):
        try:
            self.r = self.s.get(self.url, timeout=self.timeout, allow_redirects=True)
        except requests.exceptions.SSLError as e:
            self.tls_error = str(e)[:300]
            self.s.verify = False
            self.r = self.s.get(self.url, timeout=self.timeout, allow_redirects=True)

    # ------------------------------------------------------------ checks
    def check_transport(self):
        final_https = self.r.url.startswith("https://")
        if self.scheme == "http":
            self.check("Site served over HTTPS", final_https, "Site served over plain HTTP", "A02", 7.5, 0.7,
                       f"Final URL: {self.r.url}",
                       ["Install a valid TLS certificate (Let's Encrypt is free).",
                        "Redirect all HTTP requests to HTTPS with a 301.",
                        "Enable HSTS."])
            return
        if self.port == 443:
            try:
                h = requests.get(f"http://{self.host}/", allow_redirects=False, timeout=5, headers={"User-Agent": UA})
                ok = h.status_code in (301, 302, 307, 308) and h.headers.get("Location", "").startswith("https://")
                self.check("HTTP redirects to HTTPS", ok, "HTTP does not redirect to HTTPS", "A02", 4.8, 0.5,
                           f"http:// returned {h.status_code}",
                           ["Configure a 301 redirect to https:// on port 80."])
            except requests.RequestException:
                pass
        self.check("Valid TLS certificate", self.tls_error is None, "TLS certificate validation failed",
                   "A02", 7.4, 0.6, self.tls_error or "",
                   ["Install a valid certificate from a trusted CA (hostname must match).",
                    "Replace expired/self-signed certificates."])
        try:
            ctx = ssl.create_default_context()
            if self.tls_error:
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ss:
                    ver, cert, cipher = ss.version(), ss.getpeercert(), ss.cipher()
            self.assets["tls_version"], self.assets["cipher"] = ver, cipher[0] if cipher else ""
            self.check("Modern TLS (1.2+)", ver in ("TLSv1.2", "TLSv1.3"), "Deprecated TLS version negotiated",
                       "A02", 7.5, 0.5, f"Negotiated: {ver}",
                       ["Disable TLS 1.0/1.1 on the server; keep only TLS 1.2/1.3."])
            if cert:
                days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) / 86400)
                self.assets["cert_expires_in_days"] = days
                self.check("Certificate not near expiry", days > 14, "TLS certificate expires soon", "A02", 5.3, 0.4,
                           f"Expires in {days} days", ["Set up auto-renewal (certbot/ACME)."])
        except Exception as e:
            self.assets["tls_error"] = str(e)[:120]

    def check_headers(self):
        H = self.r.headers
        https = self.r.url.startswith("https://")
        if https:
            self.check("HSTS header", "strict-transport-security" in H, "Missing Strict-Transport-Security",
                       "A05", 5.3, 0.5, "Header absent",
                       ['Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
                        "Test with a small max-age first, then increase it."])
        csp = H.get("Content-Security-Policy", "")
        self.check("Content-Security-Policy present", bool(csp), "Missing Content-Security-Policy", "A05", 6.1, 0.5,
                   "Header absent",
                   ["Define a restrictive CSP, e.g. default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
                    "Test in Content-Security-Policy-Report-Only mode first."])
        if csp:
            bad = re.search(r"unsafe-inline|unsafe-eval|(^|[\s;])\*([\s;]|$)", csp)
            self.check("CSP not overly permissive", not bad, "Weak Content-Security-Policy", "A05", 4.3, 0.4,
                       csp[:160], ["Remove unsafe-inline/unsafe-eval/wildcards and use nonces/hashes."])
        self.check("Clickjacking protection",
                   bool(H.get("X-Frame-Options")) or "frame-ancestors" in csp.lower(),
                   "Missing clickjacking protection", "A05", 4.3, 0.5, "No X-Frame-Options / frame-ancestors",
                   ["Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."])
        self.check("X-Content-Type-Options", H.get("X-Content-Type-Options", "").lower() == "nosniff",
                   "Missing X-Content-Type-Options: nosniff", "A05", 3.7, 0.4, "Header absent/incorrect",
                   ["Add header: X-Content-Type-Options: nosniff"])
        self.check("Referrer-Policy", "referrer-policy" in H, "Missing Referrer-Policy", "A05", 3.1, 0.3,
                   "Header absent", ["Add Referrer-Policy: strict-origin-when-cross-origin"])
        self.check("Permissions-Policy", "permissions-policy" in H, "Missing Permissions-Policy", "A05", 2.6, 0.2,
                   "Header absent", ["Add Permissions-Policy: camera=(), microphone=(), geolocation=()"])
        leaks = [f"{h}: {H[h]}" for h in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version")
                 if h in H and re.search(r"\d", H[h])]
        self.check("No version disclosure", not leaks, "Server/technology version disclosed", "A05", 3.7, 0.5,
                   "; ".join(leaks),
                   ["Nginx: server_tokens off;  Apache: ServerTokens Prod;",
                    "Remove the X-Powered-By header."])
        self.assets["server"] = H.get("Server", "")

    def check_cookies(self):
        try:
            raw = self.r.raw.headers.getlist("Set-Cookie")
        except Exception:
            c = self.r.headers.get("Set-Cookie")
            raw = [c] if c else []
        self.assets["cookies"] = len(raw)
        if not raw:
            return
        https = self.r.url.startswith("https://")
        miss_sec, miss_http, miss_ss = [], [], []
        for c in raw:
            name, low = c.split("=")[0], c.lower()
            if https and "secure" not in low:
                miss_sec.append(name)
            if "httponly" not in low:
                miss_http.append(name)
            if "samesite" not in low:
                miss_ss.append(name)
        self.check("Cookies: Secure flag", not miss_sec, "Cookies without Secure flag", "A02", 5.3, 0.5,
                   ", ".join(miss_sec), ["Add the Secure attribute to Set-Cookie."])
        self.check("Cookies: HttpOnly flag", not miss_http, "Cookies without HttpOnly flag", "A07", 5.0, 0.5,
                   ", ".join(miss_http), ["Set HttpOnly on session cookies (prevents theft via XSS)."])
        self.check("Cookies: SameSite", not miss_ss, "Cookies without SameSite attribute", "A01", 4.3, 0.4,
                   ", ".join(miss_ss), ["Set SameSite=Lax (or Strict) to reduce CSRF risk."])

    def check_cors_methods(self):
        try:
            o = self.s.get(self.url, headers={"Origin": "https://evil.example"}, timeout=self.timeout)
            acao = o.headers.get("Access-Control-Allow-Origin", "")
            creds = o.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            reflect = acao == "https://evil.example"
            if reflect and creds:
                self.check("CORS policy", False, "CORS reflects arbitrary origin with credentials", "A05", 8.1, 0.8,
                           f"ACAO={acao}, ACAC=true", ["Validate Origin against a strict allow-list; never reflect it."])
            elif reflect or acao == "*":
                self.check("CORS policy", False, "Overly permissive CORS", "A05", 4.3, 0.4, f"ACAO={acao}",
                           ["Allow trusted origins only."])
            else:
                self.check("CORS policy", True)
        except requests.RequestException:
            pass
        try:
            o = self.s.options(self.url, timeout=self.timeout)
            allow = (o.headers.get("Allow", "") + "," + o.headers.get("Access-Control-Allow-Methods", "")).upper()
            risky = [m for m in ("TRACE", "PUT", "DELETE", "CONNECT") if m in allow]
            self.check("No risky HTTP methods", not risky, "Risky HTTP methods enabled", "A05",
                       5.3 if "TRACE" in risky else 4.3, 0.5, ", ".join(risky),
                       ["Disable unused methods (TRACE/PUT/DELETE) at the web server level."])
        except requests.RequestException:
            pass

    def check_html(self):
        body = self.r.text[:600_000]
        soup = BeautifulSoup(body, "html.parser")
        base = urlparse(self.r.url)
        forms = soup.find_all("form")
        params, links = set(), 0
        for a in soup.find_all("a", href=True):
            u = urlparse(urljoin(self.r.url, a["href"]))
            if u.hostname == base.hostname:
                links += 1
                params |= set(parse_qs(u.query))
        self.surface = {"forms": len(forms), "inputs": len(soup.find_all("input")), "internal_links": links,
                        "url_parameters": sorted(params)[:20],
                        "external_scripts": len([s for s in soup.find_all("script", src=True)
                                                 if urlparse(urljoin(self.r.url, s["src"])).hostname != base.hostname])}
        # forms
        no_csrf, pw_http = [], []
        for f in forms:
            method = (f.get("method") or "get").lower()
            action = urljoin(self.r.url, f.get("action") or "")
            fields = " ".join((i.get("name") or "") + " " + (i.get("id") or "") for i in f.find_all("input"))
            if method == "post" and not re.search(r"csrf|xsrf|token|nonce|authenticity", fields, re.I):
                no_csrf.append(action)
            if f.find("input", {"type": "password"}) and action.startswith("http://"):
                pw_http.append(action)
        self.check("CSRF tokens on POST forms", not no_csrf, "POST form without anti-CSRF token", "A01", 5.4, 0.5,
                   ", ".join(no_csrf[:3]), ["Add a per-session CSRF token to every state-changing form.",
                                            "Enable the framework's built-in CSRF protection."])
        self.check("Password forms use HTTPS", not pw_http, "Password submitted over HTTP", "A02", 8.1, 0.8,
                   ", ".join(pw_http[:3]), ["Make the login form action https:// and enable HSTS."])
        # mixed content / SRI / libs
        if self.r.url.startswith("https://"):
            mixed = [t.get("src") or t.get("href") for t in soup.find_all(["script", "link", "iframe", "img"])
                     if str(t.get("src") or t.get("href") or "").startswith("http://")]
            self.check("No mixed content", not mixed, "Mixed content (HTTP resources on HTTPS page)", "A02", 4.8, 0.5,
                       ", ".join(map(str, mixed[:3])), ["Load all resources over https://."])
        no_sri = [s["src"] for s in soup.find_all("script", src=True)
                  if urlparse(urljoin(self.r.url, s["src"])).hostname != base.hostname and not s.get("integrity")]
        self.check("SRI on third-party scripts", not no_sri, "Third-party scripts without Subresource Integrity",
                   "A08", 3.7, 0.3, ", ".join(no_sri[:3]),
                   ['<script src="..." integrity="sha384-..." crossorigin="anonymous"> with an integrity hash.'])
        srcs = " ".join(s["src"] for s in soup.find_all("script", src=True))
        old = []
        for lib, rx, minv, cve in [("jQuery", r"jquery[-.@/]v?(\d+\.\d+\.\d+)", (3, 5, 0), "CVE-2020-11022/11023"),
                                   ("Bootstrap", r"bootstrap[-.@/]v?(\d+\.\d+\.\d+)", (4, 3, 1), "CVE-2019-8331"),
                                   ("AngularJS", r"angular(?:js)?[-.@/]v?(1\.\d+\.\d+)", (1, 8, 0), "EOL/multiple XSS")]:
            m = re.search(rx, srcs, re.I)
            if m and tuple(map(int, m.group(1).split("."))) < minv:
                old.append(f"{lib} {m.group(1)} ({cve})")
        self.check("No outdated JS libraries", not old, "Outdated JavaScript libraries with known CVEs", "A06", 6.1, 0.6,
                   "; ".join(old), ["Upgrade libraries to the latest patched version.",
                                    "Add npm audit / Dependabot / Snyk to CI."])
        gen = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        if gen and re.search(r"\d", gen.get("content", "")):
            self.check("No CMS version disclosure", False, "CMS/generator version disclosed in HTML", "A05", 2.7, 0.4,
                       gen["content"], ["Remove the generator meta tag."])
        comments = re.findall(r"<!--(.*?)-->", body, re.S)
        bad = [c.strip()[:60] for c in comments if re.search(r"password|todo|fixme|debug|api[_-]?key|secret", c, re.I)]
        self.check("No sensitive HTML comments", not bad, "Sensitive information in HTML comments", "A05", 3.1, 0.4,
                   " | ".join(bad[:2]), ["Strip comments from production builds."])
        self.check("No directory listing", not re.search(r"<title>\s*Index of /", body, re.I), "Directory listing enabled",
                   "A05", 5.3, 0.7, "Page title 'Index of /'", ["Nginx: autoindex off;  Apache: Options -Indexes"])
        err = re.search(r"Traceback \(most recent call last\)|Warning: mysqli?_|Fatal error:|stack trace:|at [\w.]+\(.*\.java:\d+\)",
                        body, re.I)
        self.check("No verbose error output", not err, "Verbose error / stack trace disclosed", "A05", 5.3, 0.5,
                   err.group(0) if err else "", ["Turn DEBUG off in production; show generic error pages."])

    def check_exposed(self):
        rnd = "/" + "".join(random.choices(string.ascii_lowercase, k=12))
        try:
            base = self.s.get(urljoin(self.r.url, rnd), timeout=self.timeout, allow_redirects=False)
            soft404 = base.status_code == 200
        except requests.RequestException:
            soft404 = False

        def probe(item):
            path = item[0]
            try:
                return item, self.s.get(urljoin(self.r.url, path), timeout=self.timeout, allow_redirects=False)
            except requests.RequestException:
                return item, None

        with cf.ThreadPoolExecutor(6) as ex:
            results = list(ex.map(probe, EXPOSED))
        for (path, title, cvss, expl, owasp, validator, fix), resp in results:
            hit = resp is not None and validator(resp) and not (soft404 and "html" in resp.headers.get("Content-Type", ""))
            self.check(f"Exposed: {path}", not hit, title, owasp, cvss, expl, f"GET {path} -> HTTP {resp.status_code}" if resp is not None else "", fix)
        # robots / security.txt (informational)
        try:
            st = self.s.get(urljoin(self.r.url, "/.well-known/security.txt"), timeout=self.timeout, allow_redirects=False)
            self.check("security.txt present", st.status_code == 200 and "contact" in st.text.lower(),
                       "No security.txt (vulnerability disclosure contact)", "A09", 0.0, 0.0, "",
                       ["Publish /.well-known/security.txt (RFC 9116)."])
        except requests.RequestException:
            pass

    def discover_assets(self):
        try:
            infos = socket.getaddrinfo(self.host, None)
            ips = sorted({i[4][0] for i in infos})
        except socket.gaierror:
            ips = []
        self.assets["host"], self.assets["ips"] = self.host, ips
        try:
            self.assets["reverse_dns"] = socket.gethostbyaddr(ips[0])[0] if ips else ""
        except Exception:
            self.assets["reverse_dns"] = ""
        if not (self.do_ports and ips):
            return

        def tcp(port):
            try:
                with socket.create_connection((ips[0], port), timeout=1.5):
                    return port
            except Exception:
                return None

        with cf.ThreadPoolExecutor(16) as ex:
            open_ports = sorted(p for p in ex.map(tcp, PORTS) if p)
        self.assets["open_ports"] = [{"port": p, "service": PORTS[p][0]} for p in open_ports]
        for p in open_ports:
            svc, cvss, expl, fix = PORTS[p]
            if cvss > 0:
                self.check(f"Port {p}/{svc} not exposed", False, f"{svc} service exposed to internet", "A05", cvss, expl,
                           f"TCP {p} open on {ips[0]}", [fix, "Allow only trusted IPs via firewall/security group."])

    # ------------------------------------------------------------ orchestration
    def run(self):
        t0 = time.time()
        self._p(0.05, "Connecting to target...")
        try:
            self._fetch()
        except Exception as e:
            return {"url": self.url, "error": f"Target not reachable: {e}"}
        steps = [("Transport & TLS", self.check_transport), ("Security headers", self.check_headers),
                 ("Cookies", self.check_cookies), ("CORS & HTTP methods", self.check_cors_methods),
                 ("HTML / attack-surface analysis", self.check_html), ("Asset discovery", self.discover_assets)]
        if self.do_files:
            steps.append(("Exposed files", self.check_exposed))
        for i, (name, fn) in enumerate(steps):
            self._p(0.1 + 0.85 * i / len(steps), name + "...")
            try:
                fn()
            except Exception as e:                       # one failing check must not kill scan
                self.assets.setdefault("check_errors", []).append(f"{name}: {e}")
        self._p(1.0, "Done")
        return self._report(time.time() - t0)

    def _report(self, dur):
        fs = sorted(self.findings, key=lambda f: -f.risk_score)
        prod = 1.0
        for f in fs:
            prod *= 1 - 0.5 * f.risk_score / 100
        score = round(100 * prod)
        grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65 else "D" if score >= 50 else "F"
        passed = sum(c["passed"] for c in self.checks)
        top10 = []
        for k, name in OWASP.items():
            g = [f for f in fs if f.owasp == k]
            top10.append({"OWASP 2021": k, "Category": name, "Findings": len(g),
                          "Worst severity": g[0].severity if g else "-",
                          "Max risk": g[0].risk_score if g else 0})
        return {"url": self.url, "scanned_at": datetime.now().isoformat(timespec="seconds"),
                "duration_s": round(dur, 1), "security_score": score, "grade": grade,
                "overall_risk": 100 - score,
                "compliance_pct": round(100 * passed / max(1, len(self.checks)), 1),
                "checks_total": len(self.checks), "checks_passed": passed,
                "severity_counts": {s: sum(f.severity == s for f in fs) for s in SEV_ORDER},
                "findings": [asdict(f) for f in fs], "checks": self.checks, "owasp_top10": top10,
                "assets": self.assets, "attack_surface": self.surface, "plan": build_plan(fs)}


def build_plan(findings):
    phases = [("Phase 1 - Immediate (0-48 hours)", {"Critical", "High"}),
              ("Phase 2 - Short term (1-2 weeks)", {"Medium"}),
              ("Phase 3 - Hardening & hygiene (30 days)", {"Low", "Info"})]
    plan = []
    for name, sevs in phases:
        items = [{"finding": f.fid, "title": f.title, "severity": f.severity, "risk": f.risk_score,
                  "steps": f.remediation} for f in findings if f.severity in sevs]
        plan.append({"phase": name, "items": items})
    return plan


def to_markdown(r):
    if r.get("error"):
        return f"# Scan failed\n\n{r['error']}\n"
    L = [f"# Vulnerability Assessment Report", f"**Target:** {r['url']}  ", f"**Date:** {r['scanned_at']}  ",
         f"**Security score:** {r['security_score']}/100 (Grade {r['grade']}) | **Risk:** {r['overall_risk']}/100 | "
         f"**Config compliance:** {r['compliance_pct']}%", "", "## Severity summary"]
    L += [f"- {k}: {v}" for k, v in r["severity_counts"].items()]
    L += ["", "## OWASP Top 10 mapping", "| ID | Category | Findings | Worst | Max risk |", "|---|---|---|---|---|"]
    L += [f"| {t['OWASP 2021']} | {t['Category']} | {t['Findings']} | {t['Worst severity']} | {t['Max risk']} |" for t in r["owasp_top10"]]
    L += ["", "## Findings"]
    for f in r["findings"]:
        L += [f"### {f['fid']} - {f['title']}", f"- Severity: **{f['severity']}** (CVSS-style {f['cvss']}), risk score {f['risk_score']}/100",
              f"- OWASP: {f['owasp']} {OWASP[f['owasp']]}", f"- Evidence: {f['evidence'] or '-'}", "- Remediation:"]
        L += [f"  {i}. {s}" for i, s in enumerate(f["remediation"], 1)]
        L.append("")
    L += ["## Remediation plan"]
    for ph in r["plan"]:
        L.append(f"### {ph['phase']}")
        L += [f"- [{it['severity']}] {it['title']} ({it['finding']})" for it in ph["items"]] or ["- (none)"]
    L += ["", "> Automated, non-intrusive scan. Sirf authorised targets par use karein."]
    return "\n".join(L)
