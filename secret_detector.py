#!/usr/bin/python3
# secret_detector.py
'''
@haxshadow
@ibrahimsql
'''

import re
from typing import List, Dict, Tuple
import argparse
from pathlib import Path
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import sys
from tqdm import tqdm
import urllib3
import warnings
import random

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecretDetector:
    def __init__(self):
        # API Keys & Tokens patterns (web-focused)
        self.api_patterns = {
            # Google, Firebase, Maps, Analytics, OAuth
            'Google API Key': r'AIza[0-9A-Za-z-_]{35}',
            'Google OAuth Access Token': r'ya29\.[0-9A-Za-z\-_]+',
            'Google Maps Key': r'AIza[0-9A-Za-z-_]{35}',
            'Google Analytics ID': r'UA-\d{4,10}-\d+',
            'Google Client ID': r'[0-9]+\-([a-z0-9]+\.)+[a-z0-9]+\.apps\.googleusercontent\.com',
            'Google Captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            # Firebase
            'Firebase API Key': r'AAAA[a-zA-Z0-9_-]{7}:[a-zA-Z0-9_-]{140}',
            'Firebase Config': r'AIza[0-9A-Za-z-_]{35}',
            # AWS
            'AWS Access Key': r'A[SK]IA[0-9A-Z]{16}',
            'AWS Secret Key': r'(?i)aws(.{0,20})?(secret|private)?(.{0,20})?([0-9a-zA-Z\/+=]{40})',
            'AWS MWS Token': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            # Facebook
            'Facebook App ID': r'(?i)fb\d{13,16}',
            'Facebook Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            # Twitter
            'Twitter API Key': r'(?i)twitter(.{0,20})?([0-9a-zA-Z]{25,35})',
            'Twitter Secret': r'(?i)twitter(.{0,20})?(secret|private)?(.{0,20})?([0-9a-zA-Z]{35,45})',
            # LinkedIn
            'LinkedIn Client ID': r'86[a-zA-Z0-9]{12,}',
            # Discord & Telegram
            'Discord Token': r'([MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27})',
            'Telegram Bot Token': r'\d{9}:[a-zA-Z0-9_-]{35}',
            # Stripe, PayPal, Square
            'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
            'PayPal Braintree Token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
            'Square Access Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
            # Mailgun, SendGrid, Mailchimp
            'Mailgun API': r'key-[0-9a-zA-Z]{32}',
            'SendGrid API Key': r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
            'Mailchimp API Key': r'([0-9a-f]{32}-us[0-9]{1,2})',
            # Pusher, Algolia, Sentry, Mixpanel
            'Pusher Key': r'pusher:[a-zA-Z0-9]{20,}',
            'Algolia API Key': r'(?i)algolia(.{0,20})?([a-z0-9]{32})',
            'Sentry DSN': r'https://[0-9a-f]+@[a-z0-9\.-]+/[0-9]+',
            'Mixpanel Token': r'[0-9a-f]{32}',
            # Netlify, Vercel, Supabase
            'Netlify Token': r'(?i)netlify(.{0,20})?([a-z0-9]{40})',
            'Vercel Token': r'(?i)vercel(.{0,20})?([a-z0-9]{24,})',
            'Supabase Key': r'sb[a-z0-9]{32,}',
            # Shopify, Zoom
            'Shopify Token': r'shpat_[0-9a-fA-F]{32}',
            'Zoom JWT': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        }

        # Web Auth & Session patterns
        self.auth_patterns = {
            'JWT Token': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'Session Cookie': r'(sessionid|_session|sessid|connect.sid|sid|JSESSIONID|PHPSESSID)=[a-zA-Z0-9-_]{10,}',
            'CSRF Token': r'csrf(_token|middlewaretoken|token)?[=:][\'\"]?[a-zA-Z0-9-_]{8,}',
            'XSRF Token': r'xsrf(_token)?[=:][\'\"]?[a-zA-Z0-9-_]{8,}',
            'Bearer Token': r'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
            'OAuth Access Token': r'ya29\.[0-9A-Za-z\-_]+',
        }

        # Web config & leak patterns
        self.secret_patterns = {
            'API Key/Token': r'(?i)(?:api[_-]?key|access[_-]?token|secret|client[_-]?secret)[=:]\s*[\'\"]([^\'\"\s]{20,})[\'\"]',
            'Password/Secret': r'(?i)(?:password|passwd|pwd|token|secret|passphrase|auth|access)[=:]\s*[\'\"]([^\'\"\s]+)[\'\"]',
            'Hardcoded Secret': r'(?i)(?:secret|token|key|pass)[^\n]{0,30}=[^\n]{0,100}',
            # Web config leaks in JS/JSON
            'Firebase Config Leak': r'apiKey\s*:\s*[\'\"]AIza[0-9A-Za-z-_]{35}[\'\"]',
            'Vercel Env Leak': r'(?i)vercel(.{0,20})?([a-z0-9]{24,})',
            'Netlify Env Leak': r'(?i)netlify(.{0,20})?([a-z0-9]{40})',
            'Supabase Config Leak': r'sb[a-z0-9]{32,}',
            'window.__env__': r'window\.__env__\s*=\s*{[^}]+}',
            'window.env': r'window\.env\s*=\s*{[^}]+}',
            'globalThis.config': r'globalThis\.config\s*=\s*{[^}]+}',
            'Meta Tag Leak': r'<meta\s+name=[\'\"](api|token|key|secret)[\'\"]\s+content=[\'\"][^\'\"]+[\'\"]',
        }

        # Web config/identifier patterns
        self.identifier_patterns = {
            'Email': r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,7}',
            'URL': r'https?://[\w\.-]+(?:/[\w\.-]*)*',
            'IP Address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'UUID': r'\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b',
            'Google Analytics ID': r'UA-\d{4,10}-\d+',
            'Sentry DSN': r'https://[0-9a-f]+@[a-z0-9\.-]+/[0-9]+',
            'Mixpanel Token': r'[0-9a-f]{32}',
        }

    def get_random_user_agent(self):
        """
        Returns a random modern User-Agent string for browsers, bots, and mobile devices.
        """
        user_agents = [
            # Modern browsers
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
            # Mobile browsers
            'Mozilla/5.0 (Linux; Android 12; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1',
            # Bots & crawlers
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'Bingbot/2.0 (+http://www.bing.com/bingbot.htm)',
            'DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)',
            'Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)',
            # Headless
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/123.0.0.0 Safari/537.36',
            # Others
            'Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)',
            'TelegramBot (like TwitterBot)',
            'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
        ]
        return random.choice(user_agents)

    def is_likely_false_positive(self, finding: Dict[str, str]) -> bool:
        """
        Check if a finding is likely to be a false positive.
        """
        value = finding['value'].lower()
        
        # False positive patterns (expanded with code-specific features)
        false_positive_patterns = [
            r'^https?://',  # URLs
            r'\.css$',      # CSS files
            r'\.js$',       # JavaScript files
            r'\.png$',      # Image files
            r'\.jpg$',
            r'\.jpeg$',
            r'\.gif$',
            r'\.ico$',
            r'\.svg$',
            r'/assets/',    # Common asset paths
            r'/images/',
            r'/css/',
            r'/js/',
            r'/static/',
            r'/public/',
            r'wp-content',  # WordPress paths
            r'wp-includes',
            r'themes/',
            r'plugins/',
            r'vendor/',     # Common package paths
            r'node_modules/',
            r'\.min\.',    # Minified files
            r'\.map$',     # Source maps
            r'\.lock$',    # Lock files
            r'\.md$',      # Markdown/docs
            r'\.txt$',     # Text files
            r'\.json$',    # JSON files
            r'\.xml$',     # XML files
            r'\.yml$',     # YAML files
            r'\.toml$',    # TOML files
            r'\.ini$',     # INI files
            r'\.cfg$',     # Config files
            r'\.env$',     # Env files
            r'example',     # Example/template files
            r'test/',       # Test folders
            r'fixture/',    # Fixture folders
            r'sample/',     # Sample folders
            r'__pycache__', # Python cache
            r'\b(?:const|let|var|def|function|class)\b', # Code variable/def lines
            r'\b(?:True|False|null|None)\b', # Common code literals
            r'\b(?:public|private|protected|static|final)\b', # Code keywords
            r'\b(?:import|from|require|include)\b', # Import/include lines
            r'\b(?:return|yield|break|continue|pass)\b', # Control flow
            r'\b(?:if|else|elif|switch|case|for|while|do|try|catch|except|finally)\b', # Control structures
        ]

        # Additional checks for UUIDs
        if finding['type'] == 'UUID':
            # Check if UUID is part of a file path or URL
            if '/' in value or '.' in value:
                return True
            # Check if UUID is surrounded by typical ID field names
            surrounding_text = value[max(0, finding['start']-20):finding['end']+20]
            if any(id_field in surrounding_text.lower() for id_field in ['style', 'class', 'div', 'span', 'image', 'img', 'src']):
                return True

        # Check if the value matches any false positive pattern
        for pattern in false_positive_patterns:
            if re.search(pattern, value):
                return True

        return False

    def scan_text(self, text: str) -> List[Dict[str, str]]:
        """
        Scan text for sensitive information using all patterns.
        Returns a list of dictionaries containing the type of secret and the matched value.
        """
        findings = []
        
        # Combine all patterns into one dictionary
        all_patterns = {
            **self.api_patterns,
            **self.auth_patterns,
            **self.secret_patterns,
            **self.identifier_patterns
        }

        for secret_type, pattern in all_patterns.items():
            matches = re.finditer(pattern, text, re.MULTILINE | re.IGNORECASE)
            for match in matches:
                finding = {
                    'type': secret_type,
                    'value': match.group(0),
                    'start': match.start(),
                    'end': match.end()
                }
                if not self.is_likely_false_positive(finding):
                    findings.append(finding)

        return findings

    def scan_file(self, file_path: str, verbose: bool = False) -> List[Dict[str, str]]:
        """
        Scan a file for sensitive information.
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                lines = content.split('\n')
                
                # Check if file contains URLs (one per line)
                urls = []
                for line in lines:
                    line = line.strip()
                    if line.startswith(('http://', 'https://')):
                        urls.append(line)
                
                # If file contains URLs, scan each URL
                if urls:
                    print(f"\nFound {len(urls)} URLs in file")
                    findings = []
                    session = requests.Session()
                    session.verify = False
                    session.headers.update({
                        'User-Agent': self.get_random_user_agent(),
                        'Accept': '*/*'
                    })
                    
                    with tqdm(total=len(urls), desc="Scanning URLs", unit="url") as pbar:
                        for url in urls:
                            try:
                                response = session.get(url, timeout=10)
                                if response.status_code == 200:
                                    content_type = response.headers.get('content-type', '').lower()
                                    if any(ct in content_type for ct in ['text/', 'application/json', 'application/javascript', 'application/xml']):
                                        temp_findings = self.scan_text(response.text)
                                        for finding in temp_findings:
                                            finding['url'] = url
                                            findings.append(finding)
                                            if verbose:
                                                tqdm.write(f"\nFound in {url}:")
                                                tqdm.write(f"Type: {finding['type']}")
                                                tqdm.write(f"Value: {finding['value']}")
                                                tqdm.write(f"Position: {finding['start']}-{finding['end']}")
                                                tqdm.write("-" * 40)
                            except Exception as e:
                                tqdm.write(f"Error scanning {url}: {str(e)}")
                            pbar.update(1)
                    return findings
                
                # If not a URL file, scan the content directly
                else:
                    print("\nScanning file content...")
                    findings = self.scan_text(content)
                    if verbose and findings:
                        print("\nFindings while scanning:")
                        print("-" * 40)
                        for finding in findings:
                            print(f"Type: {finding['type']}")
                            print(f"Value: {finding['value']}")
                            print(f"Position: {finding['start']}-{finding['end']}")
                            print("-" * 40)
                    return findings
                    
        except Exception as e:
            print(f"\nError scanning file {file_path}: {str(e)}")
            return []

    def scan_website(self, domain: str, max_pages: int = 100, verbose: bool = False) -> List[Dict[str, str]]:
        """
        Scan a website for sensitive information with progress tracking.
        Ignores robots.txt, canonical, noindex, and all robots/SEO restrictions. SSL warnings and errors are always bypassed (verify=False).
        """
        findings = []
        findings_hash_set = set()  # To track unique findings
        urls_to_scan = []
        scanned_urls = set()
        queued_urls = set()  # To track URLs already in the queue
        session = requests.Session()
        
        # Configure session: ignore SSL errors, ignore robots.txt, etc.
        session.verify = False  # Ignore SSL errors
        session.headers.update({
            'User-Agent': self.get_random_user_agent(),
            'Accept': '*/*'
        })
        # Crawler ignores robots.txt, canonical, noindex, etc. by design (no check implemented)
        
        def normalize_url(url: str) -> str:
            """Normalize URL to avoid duplicate scans"""
            try:
                parsed = urlparse(url)
                # Remove fragments and trailing slashes
                url = url.split('#')[0].rstrip('/')
                # Handle default ports
                netloc = parsed.netloc.lower()  # Normalize domain case
                if ':80' in netloc and parsed.scheme == 'http':
                    netloc = netloc.replace(':80', '')
                if ':443' in netloc and parsed.scheme == 'https':
                    netloc = netloc.replace(':443', '')
                # Handle www prefix consistently
                if netloc.startswith('www.'):
                    netloc = netloc[4:]
                # Keep query parameters but sort them for consistency
                query = parsed.query
                if query:
                    params = sorted(query.split('&'))
                    query = '&'.join(params)
                # Reconstruct URL
                base = f"{parsed.scheme}://{netloc}{parsed.path}"
                return f"{base}?{query}" if query else base
            except:
                return url

        def create_finding_hash(finding: Dict[str, str]) -> str:
            """Create a unique hash for a finding to detect duplicates"""
            return f"{finding['type']}:{finding['value']}:{finding.get('url', '')}"

        def is_valid_url(url: str) -> bool:
            """Check if URL should be scanned"""
            try:
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    print(f"[is_valid_url] Rejected (no scheme/netloc): {url}")
                    return False
                
                # Domain matching
                site_domain = domain.lower()
                url_domain = parsed.netloc.lower().split(':')[0]  # Remove port if present
                
                # Check domain match including subdomains
                domain_match = (
                    url_domain == site_domain or
                    url_domain.endswith(f".{site_domain}") or
                    site_domain in url_domain
                )
                
                # Only exclude binary and font files
                excluded_extensions = {
                    '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
                    '.mp4', '.webm', '.mp3', '.wav', '.avi', '.mov',
                    '.zip', '.tar', '.gz', '.rar', '.7z',
                    '.woff', '.woff2', '.ttf', '.eot'
                }
                
                path = parsed.path.lower()
                for ext in excluded_extensions:
                    if path.endswith(ext):
                        print(f"[is_valid_url] Rejected (excluded extension {ext}): {url}")
                        return False
                valid = (
                    domain_match and
                    parsed.scheme in ['http', 'https'] and
                    not any(path.endswith(ext) for ext in excluded_extensions)
                )
                if valid:
                    print(f"[is_valid_url] Accepted: {url}")
                return valid
            except Exception as e:
                print(f"[is_valid_url] Exception for {url}: {e}")
                return False

        def extract_urls(url: str, html_content: str) -> set:
            """Extract all URLs from HTML content"""
            urls = set()
            try:
                # Parse HTML
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Extract URLs from various HTML elements
                for tag in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe']):
                    for attr in ['href', 'src', 'action', 'data-url']:
                        link = tag.get(attr)
                        if link:
                            try:
                                absolute_url = urljoin(url, link)
                                normalized_url = normalize_url(absolute_url)
                                print(f"[extract_urls] Found: {link} -> {normalized_url}")
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                                    print(f"[extract_urls] Added: {normalized_url}")
                            except Exception as e:
                                print(f"[extract_urls] Exception for {link}: {e}")
                                continue
                
                # Extract URLs from onclick attributes
                elements_with_onclick = soup.find_all(attrs={"onclick": True})
                for element in elements_with_onclick:
                    onclick = element.get('onclick', '')
                    matches = re.findall(r'["\']((https?://|/)[^"\']+)["\']', onclick)
                    for match in matches:
                        try:
                            absolute_url = urljoin(url, match[0])
                            normalized_url = normalize_url(absolute_url)
                            print(f"[extract_urls][onclick] Found: {match[0]} -> {normalized_url}")
                            if is_valid_url(normalized_url):
                                urls.add(normalized_url)
                                print(f"[extract_urls][onclick] Added: {normalized_url}")
                        except Exception as e:
                            print(f"[extract_urls][onclick] Exception for {match[0]}: {e}")
                            continue
                
                # Extract URLs from inline JavaScript
                for script in soup.find_all('script'):
                    if script.string:
                        matches = re.findall(r'["\']((https?://|/)[^"\']+)["\']', script.string)
                        for match in matches:
                            try:
                                absolute_url = urljoin(url, match[0])
                                normalized_url = normalize_url(absolute_url)
                                print(f"[extract_urls][script] Found: {match[0]} -> {normalized_url}")
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                                    print(f"[extract_urls][script] Added: {normalized_url}")
                            except Exception as e:
                                print(f"[extract_urls][script] Exception for {match[0]}: {e}")
                                continue
                
                # Extract URLs from CSS
                for style in soup.find_all('style'):
                    if style.string:
                        matches = re.findall(r'url\(["\']?([^)"\']+)["\']?\)', style.string)
                        for match in matches:
                            try:
                                absolute_url = urljoin(url, match)
                                normalized_url = normalize_url(absolute_url)
                                print(f"[extract_urls][style] Found: {match} -> {normalized_url}")
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                                    print(f"[extract_urls][style] Added: {normalized_url}")
                            except Exception as e:
                                print(f"[extract_urls][style] Exception for {match}: {e}")
                                continue
            except Exception as e:
                print(f"\nError extracting URLs from {url}: {str(e)}")
            return urls

        def scan_page(url: str) -> Tuple[List[Dict[str, str]], set]:
            """Scan a single page and return findings and new URLs"""
            page_findings = []
            new_urls = set()
            normalized_url = normalize_url(url)
            
            try:
                response = session.get(url, timeout=15, allow_redirects=True)
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # Process text-based content
                    if any(ct in content_type for ct in ['text/', 'application/json', 'application/javascript', 'application/xml']):
                        content = response.text
                        temp_findings = self.scan_text(content)
                        
                        # Add URL and deduplicate findings
                        for finding in temp_findings:
                            finding['url'] = normalized_url
                            finding_hash = create_finding_hash(finding)
                            if finding_hash not in findings_hash_set:
                                findings_hash_set.add(finding_hash)
                                page_findings.append(finding)
                                if verbose:
                                    tqdm.write(f"\nFound in {normalized_url}:")
                                    tqdm.write(f"Type: {finding['type']}")
                                    tqdm.write(f"Value: {finding['value']}")
                                    tqdm.write(f"Position: {finding['start']}-{finding['end']}")
                                    tqdm.write("-" * 40)
                        
                        # Extract new URLs from HTML content
                        if 'text/html' in content_type:
                            new_urls = extract_urls(url, content)
                
            except Exception as e:
                tqdm.write(f"\nError scanning {url}: {str(e)}")
            
            return page_findings, new_urls

        # Initialize scan with different URL variations
        print(f"\nInitializing scan of {domain}...")
        start_urls = [
            f"https://{domain}",
            f"http://{domain}",
            f"https://www.{domain}",
            f"http://www.{domain}"
        ]
        
        # Find working URL
        for url in start_urls:
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    normalized_url = normalize_url(url)
                    if normalized_url not in queued_urls:
                        urls_to_scan.append(normalized_url)
                        queued_urls.add(normalized_url)
                    break
            except:
                continue
        
        if not urls_to_scan:
            print(f"\nError: Could not connect to {domain}")
            return []

        # Main scanning loop with progress bar
        with tqdm(total=max_pages, desc="Scanning pages", unit="page") as pbar:
            while urls_to_scan and len(scanned_urls) < max_pages:
                # Get next URL to scan
                current_url = urls_to_scan.pop(0)
                normalized_current = normalize_url(current_url)
                
                if normalized_current in scanned_urls:
                    continue
                
                # Scan the page
                print(f"\rScanning: {current_url}", end='', flush=True)
                page_findings, new_urls = scan_page(current_url)
                
                # Process results
                findings.extend(page_findings)
                scanned_urls.add(normalized_current)
                pbar.update(1)
                
                # Add new URLs to scan
                for url in new_urls:
                    normalized_url = normalize_url(url)
                    if normalized_url not in scanned_urls and normalized_url not in queued_urls:
                        urls_to_scan.append(url)
                        queued_urls.add(normalized_url)
                        print(f"[queue] Queued: {normalized_url}")
                time.sleep(0.1)

        print(f"\nScan completed. Scanned {len(scanned_urls)} unique pages.")
        if findings:
            print(f"\nTotal findings: {len(findings)} (unique)")
        return findings

    def scan_website_crawler(self, domain: str, max_pages: int = 100, max_depth: int = 3, verbose: bool = False) -> List[Dict[str, str]]:
        """
        Deep recursive crawler for website secret scanning (respects max_pages and max_depth).
        Ignores robots.txt, canonical, noindex, and all robots/SEO restrictions. SSL warnings and errors are always bypassed (verify=False).
        """
        findings = []
        findings_hash_set = set()
        urls_to_scan = []
        scanned_urls = set()
        queued_urls = set()
        session = requests.Session()
        session.verify = False  # Ignore SSL errors
        session.headers.update({
            'User-Agent': self.get_random_user_agent(),
            'Accept': '*/*'
        })
        # Crawler ignores robots.txt, canonical, noindex, etc. by design (no check implemented)

        def normalize_url(url: str) -> str:
            try:
                parsed = urlparse(url)
                url = url.split('#')[0].rstrip('/')
                netloc = parsed.netloc.lower()
                if ':80' in netloc and parsed.scheme == 'http':
                    netloc = netloc.replace(':80', '')
                if ':443' in netloc and parsed.scheme == 'https':
                    netloc = netloc.replace(':443', '')
                if netloc.startswith('www.'):
                    netloc = netloc[4:]
                query = parsed.query
                if query:
                    params = sorted(query.split('&'))
                    query = '&'.join(params)
                base = f"{parsed.scheme}://{netloc}{parsed.path}"
                return f"{base}?{query}" if query else base
            except:
                return url

        def create_finding_hash(finding: Dict[str, str]) -> str:
            return f"{finding['type']}:{finding['value']}:{finding.get('url', '')}"

        def is_valid_url(url: str) -> bool:
            try:
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    print(f"[is_valid_url] Rejected (no scheme/netloc): {url}")
                    return False
                site_domain = domain.lower()
                url_domain = parsed.netloc.lower().split(':')[0]
                domain_match = (
                    url_domain == site_domain or
                    url_domain.endswith(f".{site_domain}") or
                    site_domain in url_domain
                )
                if not domain_match:
                    print(f"[is_valid_url] Rejected (domain mismatch): {url_domain} vs {site_domain}")
                excluded_extensions = {
                    '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg',
                    '.mp4', '.webm', '.mp3', '.wav', '.avi', '.mov',
                    '.zip', '.tar', '.gz', '.rar', '.7z',
                    '.woff', '.woff2', '.ttf', '.eot'
                }
                path = parsed.path.lower()
                for ext in excluded_extensions:
                    if path.endswith(ext):
                        print(f"[is_valid_url] Rejected (excluded extension {ext}): {url}")
                        return False
                valid = (
                    domain_match and
                    parsed.scheme in ['http', 'https'] and
                    not any(path.endswith(ext) for ext in excluded_extensions)
                )
                if valid:
                    print(f"[is_valid_url] Accepted: {url}")
                return valid
            except Exception as e:
                print(f"[is_valid_url] Exception for {url}: {e}")
                return False

        def extract_urls(url: str, html_content: str) -> set:
            urls = set()
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
                for tag in soup.find_all(['a', 'link', 'script', 'img', 'form', 'iframe']):
                    for attr in ['href', 'src', 'action', 'data-url']:
                        link = tag.get(attr)
                        if link:
                            try:
                                absolute_url = urljoin(url, link)
                                normalized_url = normalize_url(absolute_url)
                                print(f"[extract_urls] Found: {link} -> {normalized_url}")
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                                    print(f"[extract_urls] Added: {normalized_url}")
                            except Exception as e:
                                print(f"[extract_urls] Exception for {link}: {e}")
                                continue
                elements_with_onclick = soup.find_all(attrs={"onclick": True})
                for element in elements_with_onclick:
                    onclick = element.get('onclick', '')
                    matches = re.findall(r'["\']((https?://|/)[^"\']+)["\']', onclick)
                    for match in matches:
                        try:
                            absolute_url = urljoin(url, match[0])
                            normalized_url = normalize_url(absolute_url)
                            print(f"[extract_urls][onclick] Found: {match[0]} -> {normalized_url}")
                            if is_valid_url(normalized_url):
                                urls.add(normalized_url)
                                print(f"[extract_urls][onclick] Added: {normalized_url}")
                        except Exception as e:
                            print(f"[extract_urls][onclick] Exception for {match[0]}: {e}")
                            continue
                for script in soup.find_all('script'):
                    if script.string:
                        matches = re.findall(r'["\']((https?://|/)[^"\']+)["\']', script.string)
                        for match in matches:
                            try:
                                absolute_url = urljoin(url, match[0])
                                normalized_url = normalize_url(absolute_url)
                                print(f"[extract_urls][script] Found: {match[0]} -> {normalized_url}")
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                                    print(f"[extract_urls][script] Added: {normalized_url}")
                            except Exception as e:
                                print(f"[extract_urls][script] Exception for {match[0]}: {e}")
                                continue
                for style in soup.find_all('style'):
                    if style.string:
                        matches = re.findall(r'url\(["\']?([^)"\']+)["\']?\)', style.string)
                        for match in matches:
                            try:
                                absolute_url = urljoin(url, match)
                                normalized_url = normalize_url(absolute_url)
                                print(f"[extract_urls][style] Found: {match} -> {normalized_url}")
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                                    print(f"[extract_urls][style] Added: {normalized_url}")
                            except Exception as e:
                                print(f"[extract_urls][style] Exception for {match}: {e}")
                                continue
            except Exception as e:
                print(f"\nError extracting URLs from {url}: {str(e)}")
            return urls

        def scan_page(url: str, depth: int) -> Tuple[List[Dict[str, str]], set]:
            page_findings = []
            new_urls = set()
            normalized_url = normalize_url(url)
            try:
                response = session.get(url, timeout=15, allow_redirects=True)
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    if any(ct in content_type for ct in ['text/', 'application/json', 'application/javascript', 'application/xml']):
                        content = response.text
                        temp_findings = self.scan_text(content)
                        if temp_findings:
                            print(f"\n[SECRET FOUND] URL: {normalized_url}")
                            for finding in temp_findings:
                                print(f"    Type: {finding['type']}")
                                print(f"    Value: {finding['value']}")
                        for finding in temp_findings:
                            finding['url'] = normalized_url
                            finding_hash = create_finding_hash(finding)
                            if finding_hash not in findings_hash_set:
                                findings_hash_set.add(finding_hash)
                                page_findings.append(finding)
                        if 'text/html' in content_type and depth < max_depth:
                            new_urls = extract_urls(url, content)
            except Exception as e:
                tqdm.write(f"\nError scanning {url}: {str(e)}")
            return page_findings, new_urls

        print(f"\nInitializing crawler scan of {domain} (max_depth={max_depth})...")
        start_urls = [
            f"https://{domain}",
            f"http://{domain}",
            f"https://www.{domain}",
            f"http://www.{domain}"
        ]
        for url in start_urls:
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    normalized_url = normalize_url(url)
                    if normalized_url not in queued_urls:
                        urls_to_scan.append((normalized_url, 0))
                        queued_urls.add(normalized_url)
                    break
            except:
                continue
        if not urls_to_scan:
            print(f"\nError: Could not connect to {domain}")
            return []
        with tqdm(total=max_pages, desc="Scanning pages", unit="page") as pbar:
            while urls_to_scan and len(scanned_urls) < max_pages:
                current_url, current_depth = urls_to_scan.pop(0)
                normalized_current = normalize_url(current_url)
                if normalized_current in scanned_urls or current_depth > max_depth:
                    continue
                print(f"\rCrawling: {current_url} (depth={current_depth})", end='', flush=True)
                page_findings, new_urls = scan_page(current_url, current_depth)
                findings.extend(page_findings)
                scanned_urls.add(normalized_current)
                pbar.update(1)
                for url in new_urls:
                    normalized_url = normalize_url(url)
                    if normalized_url not in scanned_urls and normalized_url not in queued_urls:
                        urls_to_scan.append((url, current_depth + 1))
                        queued_urls.add(normalized_url)
                        print(f"[queue] Queued: {normalized_url} (depth={current_depth + 1})")
                time.sleep(0.1)
        print(f"\nCrawler scan completed. Scanned {len(scanned_urls)} unique pages.")
        if findings:
            print(f"\nTotal findings: {len(findings)} (unique)")
        return findings

    def save_findings_to_file(self, findings: List[Dict[str, str]], output_file: str):
        """Save findings to a text file"""
        try:
            with open(output_file, 'w') as f:
                f.write(f"Secret Detection Results\n")
                f.write(f"=====================\n\n")
                f.write(f"Total findings: {len(findings)}\n\n")
                
                # Group findings by URL
                findings_by_url = {}
                for finding in findings:
                    url = finding.get('url', 'Unknown URL')
                    if url not in findings_by_url:
                        findings_by_url[url] = []
                    findings_by_url[url].append(finding)
                
                # Write findings grouped by URL
                for url, url_findings in findings_by_url.items():
                    f.write(f"\nURL: {url}\n")
                    f.write("=" * (len(url) + 5) + "\n")
                    for finding in url_findings:
                        f.write(f"Type: {finding['type']}\n")
                        f.write(f"Value: {finding['value']}\n")
                        f.write(f"Position: {finding['start']}-{finding['end']}\n")
                        f.write("-" * 50 + "\n")
            
            print(f"\nResults saved to: {output_file}")
        except Exception as e:
            print(f"\nError saving results to {output_file}: {str(e)}")

    def scan_url(self, url: str, verbose: bool = False) -> List[Dict[str, str]]:
        """
        Scan a single URL for sensitive information.
        """
        findings = []
        session = requests.Session()
        session.verify = False
        session.headers.update({
            'User-Agent': self.get_random_user_agent(),
            'Accept': '*/*'
        })

        try:
            print(f"\nScanning URL: {url}")
            response = session.get(url, timeout=15, allow_redirects=True)
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                # Process text-based content
                if any(ct in content_type for ct in ['text/', 'application/json', 'application/javascript', 'application/xml']):
                    content = response.text
                    findings = self.scan_text(content)
                    if verbose and findings:
                        print("\nFindings while scanning:")
                        print("-" * 40)
                        for finding in findings:
                            print(f"Type: {finding['type']}")
                            print(f"Value: {finding['value']}")
                            print(f"Position: {finding['start']}-{finding['end']}")
                            print("-" * 40)
                else:
                    print(f"\nWarning: Content type '{content_type}' not supported for scanning")
            else:
                print(f"\nError: Could not access URL (Status code: {response.status_code})")
                
        except Exception as e:
            print(f"\nError scanning URL: {str(e)}")
        
        return findings

def main():
    parser = argparse.ArgumentParser(
        description='''Secret Detector - A tool to find sensitive information in files, codebases, and websites.
        
This tool can detect various types of secrets including:
- API Keys (Google, AWS, Facebook, Twilio, etc.)
- Authentication Tokens
- Private Keys (RSA, DSA, EC, PGP)
- JWT Tokens
- Passwords and Secrets
- Email Addresses
- IP Addresses
- UUIDs''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Create argument groups for better organization
    website_group = parser.add_argument_group('Website Scanning')
    website_group.add_argument(
        '--domain', '-d',
        help='Domain to scan (e.g., example.com)'
    )
    website_group.add_argument(
        '--all',
        action='store_true',
        help='Scan all pages of the website recursively'
    )
    website_group.add_argument(
        '--max-pages',
        type=int,
        default=100,
        help='Maximum number of pages to scan (default: 100)'
    )
    website_group.add_argument(
        '--list', '-l',
        help='Path to a file containing a list of domains to scan (one per line)'
    )
    website_group.add_argument(
        '--crawler',
        action='store_true',
        help='Enable deep recursive crawling (respects --max-pages and --depth)'
    )
    website_group.add_argument(
        '--depth',
        type=int,
        default=3,
        help='Maximum crawl depth for recursive website scanning (default: 3)'
    )

    file_group = parser.add_argument_group('File Scanning')
    file_group.add_argument(
        '--file', '-f',
        help='Path to the file to scan'
    )

    url_group = parser.add_argument_group('URL Scanning')
    url_group.add_argument(
        '--url', '-u',
        help='URL to scan (e.g., http://example.com/file.js)'
    )

    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '--output', '-o',
        help='Save results to output file'
    )
    output_group.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show findings in real-time while scanning'
    )

    args = parser.parse_args()

    if not any([args.domain, args.file, args.url, args.list]):
        parser.print_help()
        sys.exit(1)

    detector = SecretDetector()
    findings = []

    try:
        if args.url:
            findings = detector.scan_url(args.url, verbose=args.verbose)
        elif args.domain:
            print(f"Starting scan of website: {args.domain}")
            # Use crawler mode if requested
            if args.crawler:
                findings = detector.scan_website_crawler(
                    args.domain,
                    max_pages=args.max_pages,
                    max_depth=args.depth,
                    verbose=args.verbose
                )
            else:
                findings = detector.scan_website(
                    args.domain,
                    max_pages=args.max_pages,
                    verbose=args.verbose
                )
        elif args.list:
            # Scan each domain in the list file
            list_file = args.list
            try:
                with open(list_file, 'r') as lf:
                    domains = [line.strip() for line in lf if line.strip() and not line.strip().startswith('#')]
                all_findings = []
                for domain in tqdm(domains, desc="Scanning domain list", unit="domain"):
                    print(f"\n--- Scanning domain: {domain} ---")
                    domain_findings = detector.scan_website(
                        domain,
                        max_pages=args.max_pages,
                        verbose=args.verbose
                    )
                    # Tag findings with domain for clarity if not already present
                    for finding in domain_findings:
                        if 'url' not in finding:
                            finding['url'] = domain
                    all_findings.extend(domain_findings)
                findings = all_findings
            except Exception as e:
                print(f"\nError reading domain list file: {str(e)}")
                sys.exit(1)
        elif args.file:
            print(f"\nScanning file: {args.file}")
            findings = detector.scan_file(args.file, verbose=args.verbose)
        
        # Process and display findings
        if findings:
            # Save to file if output option specified
            if args.output:
                detector.save_findings_to_file(findings, args.output)
            elif not args.verbose:  # Only show summary if not in verbose mode
                # Group findings by URL for website and URL scans
                if args.domain or args.url or args.list:
                    findings_by_url = {}
                    for finding in findings:
                        url = finding.get('url', 'Unknown URL')
                        if url not in findings_by_url:
                            findings_by_url[url] = []
                        findings_by_url[url].append(finding)
                    
                    print(f"\nFound {len(findings)} potential secrets:")
                    print("-" * 50)
                    
                    for url, url_findings in findings_by_url.items():
                        print(f"\nURL: {url}")
                        for finding in url_findings:
                            print(f"Type: {finding['type']}")
                            print(f"Value: {finding['value']}")
                            print(f"Position: {finding['start']}-{finding['end']}")
                            print("-" * 40)
                else:
                    # Display file scanning results
                    for finding in findings:
                        print(f"Type: {finding['type']}")
                        print(f"Value: {finding['value']}")
                        print(f"Position: {finding['start']}-{finding['end']}")
                        print("-" * 50)
        else:
            print("\nNo secrets found.")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 