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

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecretDetector:
    def __init__(self):
        # API Keys & Tokens patterns
        self.api_patterns = {
            'Google API': r'AIza[0-9A-Za-z-_]{35}',
            'Google Captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            'Google OAuth': r'ya29\.[0-9A-Za-z\-_]+',
            'AWS Access Key': r'A[SK]IA[0-9A-Z]{16}',
            'AWS MWS Token': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'Facebook Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'Mailgun API': r'key-[0-9a-zA-Z]{32}',
            'Twilio API': r'SK[0-9a-fA-F]{32}',
            'Twilio SID': r'AC[a-zA-Z0-9_\-]{32}',
            'Stripe API': r'sk_live_[0-9a-zA-Z]{24}'
        }

        # Authorization patterns
        self.auth_patterns = {
            'Basic Auth': r'basic\s*[a-zA-Z0-9=:_\+\/-]+',
            'Bearer Token': r'bearer\s*[a-zA-Z0-9_\-\.=:_\+\/]+',
            'API Key': r'api[key|\s*]+[a-zA-Z0-9_\-]+'
        }

        # Security Tokens & Credentials
        self.security_patterns = {
            'RSA Private Key': r'-----BEGIN RSA PRIVATE KEY-----',
            'DSA Private Key': r'-----BEGIN DSA PRIVATE KEY-----',
            'EC Private Key': r'-----BEGIN EC PRIVATE KEY-----',
            'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            'JWT': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
            'Bearer JWT': r'Bearer [A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
        }

        # Common Identifiers - improved UUID detection
        self.identifier_patterns = {
            'Email': r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}',
            'IP Address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'UUID': r'\b[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}\b'
        }

        # Secret Detection patterns - improved to reduce false positives
        self.secret_patterns = {
            'Password/Secret': r'(?i)(?:password|passwd|pwd|token|secret)[=:]\s*[\'"]([^\'"\s]+)[\'"]',
            'API Key/Token': r'(?i)(?:api[_-]?key|access[_-]?token|secret)[=:]\s*[\'"]([^\'"\s]{20,})[\'"]'
        }

    def is_likely_false_positive(self, finding: Dict[str, str]) -> bool:
        """
        Check if a finding is likely to be a false positive.
        """
        value = finding['value'].lower()
        
        # Common false positive patterns
        false_positive_patterns = [
            r'^https?://',  # URLs
            r'\.css$',      # CSS files
            r'\.js$',       # JavaScript files
            r'\.png$',      # Image files
            r'\.jpg$',
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
            r'node_modules/'
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
            **self.security_patterns,
            **self.identifier_patterns,
            **self.secret_patterns
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
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
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
        """
        findings = []
        findings_hash_set = set()  # To track unique findings
        urls_to_scan = []
        scanned_urls = set()
        queued_urls = set()  # To track URLs already in the queue
        session = requests.Session()
        
        # Configure session
        session.verify = False
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

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
                return (
                    domain_match and
                    parsed.scheme in ['http', 'https'] and
                    not any(path.endswith(ext) for ext in excluded_extensions)
                )
            except:
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
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                            except:
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
                            if is_valid_url(normalized_url):
                                urls.add(normalized_url)
                        except:
                            continue
                
                # Extract URLs from inline JavaScript
                for script in soup.find_all('script'):
                    if script.string:
                        matches = re.findall(r'["\']((https?://|/)[^"\']+)["\']', script.string)
                        for match in matches:
                            try:
                                absolute_url = urljoin(url, match[0])
                                normalized_url = normalize_url(absolute_url)
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                            except:
                                continue
                
                # Extract URLs from CSS
                for style in soup.find_all('style'):
                    if style.string:
                        matches = re.findall(r'url\(["\']?([^)"\']+)["\']?\)', style.string)
                        for match in matches:
                            try:
                                absolute_url = urljoin(url, match)
                                normalized_url = normalize_url(absolute_url)
                                if is_valid_url(normalized_url):
                                    urls.add(normalized_url)
                            except:
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
                
                # Short delay to prevent overwhelming the server
                time.sleep(0.1)

        print(f"\nScan completed. Scanned {len(scanned_urls)} unique pages.")
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
                        f.write(f"Type: {finding.get('type', 'Unknown')}\n")
                        f.write(f"Value: {finding.get('value', 'Unknown')}\n")
                        f.write(f"Position: {finding.get('start')}-{finding.get('end')}\n")
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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*'
        })

        try:
            print(f"\nScanning URL: {url}")
            response = session.get(url, timeout=15, allow_redirects=True)
            
            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                
                # Process any text-based content
                if any(ct in content_type for ct in ['text/', 'application/json', 'application/javascript', 'application/xml']):
                    content = response.text
                    temp_findings = self.scan_text(content)
                    
                    # Add URL to findings
                    for finding in temp_findings:
                        finding['url'] = url
                        findings.append(finding)
                        if verbose:
                            print(f"\nFound:")
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
        description='''Secret Detector - A tool to find sensitive information in files, URLs, and websites.
        
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

    if not any([args.domain, args.file, args.url]):
        parser.print_help()
        sys.exit(1)

    detector = SecretDetector()
    findings = []

    try:
        if args.url:
            findings = detector.scan_url(args.url, verbose=args.verbose)
            
        elif args.domain:
            print(f"Starting scan of website: {args.domain}")
            findings = detector.scan_website(args.domain, args.max_pages, verbose=args.verbose)
            
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
                if args.domain or args.url:
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