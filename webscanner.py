#!/usr/bin/env python3
"""
Automated Web Application Penetration Testing Tool
A modular CLI tool for scanning web applications for common vulnerabilities
"""

import argparse
import requests
import sys
import json
import logging
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
from typing import List, Dict, Set
import time
import socket
import concurrent.futures
import html

# Global variable for log filename
LOG_FILENAME = f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'

# Configure logging - will be properly initialized in main()
logger = logging.getLogger(__name__)


class SubdomainEnumerator:
    """Class for subdomain enumeration"""
    
    def __init__(self, domain: str, wordlist_path: str = None, threads: int = 10, timeout: int = 3):
        self.domain = domain
        self.timeout = timeout
        self.threads = threads
        self.found_subdomains = set()
        self.wordlist = self._load_wordlist(wordlist_path)
    
    def _load_wordlist(self, wordlist_path: str = None) -> List[str]:
        """Load subdomain wordlist from file or use default"""
        default_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
            'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
            'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my',
            'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums',
            'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en',
            'start', 'sms', 'office', 'exchange', 'ipv4', 'help', 'home', 'library'
        ]
        
        if wordlist_path:
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logger.info(f"[+] Loaded {len(subdomains)} subdomains from {wordlist_path}")
                return subdomains
            except Exception as e:
                logger.warning(f"[!] Error loading subdomain wordlist {wordlist_path}: {str(e)}")
                logger.info(f"[+] Using default subdomain list ({len(default_subdomains)} entries)")
                return default_subdomains
        
        logger.info(f"[+] Using default subdomain list ({len(default_subdomains)} entries)")
        return default_subdomains
    
    def _check_subdomain(self, subdomain: str) -> tuple:
        """Check if a subdomain exists using DNS resolution and HTTP request"""
        full_domain = f"{subdomain}.{self.domain}"
        
        try:
            # Try DNS resolution
            socket.gethostbyname(full_domain)
            
            # Try HTTP/HTTPS connection
            for protocol in ['https', 'http']:
                try:
                    url = f"{protocol}://{full_domain}"
                    response = requests.get(
                        url, 
                        timeout=self.timeout, 
                        verify=False,
                        allow_redirects=True
                    )
                    if response.status_code < 500:  # Consider 4xx and lower as valid
                        logger.info(f"[+] Found subdomain: {full_domain} ({protocol})")
                        return (full_domain, url, response.status_code)
                except requests.RequestException:
                    continue
            
            # DNS resolved but no HTTP response
            logger.info(f"[+] Found subdomain (DNS only): {full_domain}")
            return (full_domain, f"http://{full_domain}", None)
            
        except socket.gaierror:
            # Subdomain does not exist
            return None
        except Exception as e:
            logger.debug(f"Error checking {full_domain}: {str(e)}")
            return None
    
    def enumerate(self) -> Set[str]:
        """Enumerate subdomains using threading"""
        logger.info(f"\n[*] Starting subdomain enumeration for {self.domain}")
        logger.info(f"[*] Testing {len(self.wordlist)} potential subdomains with {self.threads} threads...")
        
        start_time = time.time()
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_subdomain = {
                executor.submit(self._check_subdomain, sub): sub 
                for sub in self.wordlist
            }
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                result = future.result()
                if result:
                    results.append(result)
        
        end_time = time.time()
        duration = end_time - start_time
        
        logger.info(f"\n[+] Subdomain enumeration completed in {duration:.2f} seconds")
        logger.info(f"[+] Found {len(results)} valid subdomains\n")
        
        return results


class WebScanner:
    """Main scanner class for web application security testing"""
    
    def __init__(self, target_url: str, exclude_urls: List[str] = None, 
                 wordlists: Dict[str, str] = None, scan_subdomains: bool = False,
                 subdomain_threads: int = 10):
        self.target_url = target_url if target_url.startswith('http') else f'http://{target_url}'
        self.exclude_urls = exclude_urls or []
        self.base_domain = urlparse(self.target_url).netloc
        self.visited_urls = set()
        self.found_forms = []
        self.vulnerabilities = []
        self.session = requests.Session()
        self.wordlists = wordlists or {}
        self.scan_subdomains = scan_subdomains
        self.subdomain_threads = subdomain_threads
        self.discovered_subdomains = []
        self._load_payloads()
    
    def _load_payloads(self):
        """Load payloads from wordlists or use defaults"""
        # Default SQL Injection payloads
        default_sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "1' OR '1' = '1",
            "' UNION SELECT NULL--",
            "1 AND 1=1",
            "1 AND 1=2",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "1' AND '1'='1",
            "' WAITFOR DELAY '00:00:05'--",
            "1; DROP TABLE users--",
            "' OR 1=1#",
            "' UNION SELECT NULL, NULL--"
        ]
        
        # Default XSS payloads
        default_xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(1)'>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror='alert(1)'>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "'-alert(1)-'",
            "\"><script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        
        # Default LFI payloads
        default_lfi_payloads = [
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "C:\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        # Load from wordlists or use defaults
        self.sql_payloads = self._load_wordlist('sql', default_sql_payloads)
        self.xss_payloads = self._load_wordlist('xss', default_xss_payloads)
        self.lfi_payloads = self._load_wordlist('lfi', default_lfi_payloads)
        
        logger.info(f"[+] Loaded {len(self.sql_payloads)} SQL injection payloads")
        logger.info(f"[+] Loaded {len(self.xss_payloads)} XSS payloads")
        logger.info(f"[+] Loaded {len(self.lfi_payloads)} LFI payloads")
    
    def _load_wordlist(self, wordlist_type: str, default_payloads: List[str]) -> List[str]:
        """Load wordlist from file or return default"""
        if wordlist_type in self.wordlists:
            wordlist_path = self.wordlists[wordlist_type]
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logger.info(f"[+] Loaded {len(payloads)} payloads from {wordlist_path}")
                return payloads
            except Exception as e:
                logger.warning(f"[!] Error loading wordlist {wordlist_path}: {str(e)}")
                logger.info(f"[+] Using default {wordlist_type} payloads")
                return default_payloads
        return default_payloads
    
    def enumerate_subdomains(self) -> List[tuple]:
        """Enumerate subdomains of the target domain"""
        if not self.scan_subdomains:
            return []
        
        # Extract root domain from target URL
        parsed = urlparse(self.target_url)
        domain_parts = parsed.netloc.split('.')
        
        # Get root domain (last two parts for most domains)
        if len(domain_parts) >= 2:
            root_domain = '.'.join(domain_parts[-2:])
        else:
            root_domain = parsed.netloc
        
        enumerator = SubdomainEnumerator(
            root_domain,
            self.wordlists.get('subdomain'),
            threads=self.subdomain_threads
        )
        
        self.discovered_subdomains = enumerator.enumerate()
        return self.discovered_subdomains
    
    def crawl(self, url: str, depth: int = 2) -> Set[str]:
        """Crawl website to discover URLs and forms"""
        if depth == 0 or url in self.visited_urls:
            return self.visited_urls
        
        # Check if URL should be excluded
        if any(exclude in url for exclude in self.exclude_urls):
            logger.info(f"Skipping excluded URL: {url}")
            return self.visited_urls
        
        try:
            logger.info(f"Crawling: {url}")
            response = self.session.get(url, timeout=10, verify=False)
            self.visited_urls.add(url)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            forms = soup.find_all('form')
            for form in forms:
                self.found_forms.append({
                    'url': url,
                    'form': form,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower()
                })
            
            # Extract links
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                parsed = urlparse(next_url)
                
                # Only crawl same domain
                if parsed.netloc == self.base_domain and next_url not in self.visited_urls:
                    self.crawl(next_url, depth - 1)
            
        except Exception as e:
            logger.error(f"Error crawling {url}: {str(e)}")
        
        return self.visited_urls
    
    def test_sql_injection(self) -> List[Dict]:
        """Test for SQL injection vulnerabilities"""
        logger.info("\n[*] Testing for SQL Injection...")
        
        sql_errors = [
            "sql syntax",
            "mysql_fetch",
            "warning: mysql",
            "unclosed quotation",
            "quoted string not properly terminated",
            "ora-01756",
            "sqlite_exception",
            "postgresql",
            "syntax error",
            "mysql error",
            "odbc error"
        ]
        
        vulnerabilities = []
        found_vulns = set()  # Track unique vulnerabilities
        
        # Test URL parameters
        for url in self.visited_urls:
            parsed = urlparse(url)
            if parsed.query:
                for payload in self.sql_payloads[:5]:  # Use subset for URL testing
                    test_url = url.replace(parsed.query, f"{parsed.query}{payload}")
                    try:
                        response = self.session.get(test_url, timeout=10, verify=False)
                        
                        for error in sql_errors:
                            if error in response.text.lower():
                                # Create unique identifier for this vulnerability
                                vuln_id = f"sqli|{url}|{payload}|{error}"
                                if vuln_id not in found_vulns:
                                    found_vulns.add(vuln_id)
                                    vuln = {
                                        'type': 'SQL Injection',
                                        'severity': 'HIGH',
                                        'url': url,
                                        'payload': payload,
                                        'evidence': f"SQL error detected: {error}"
                                    }
                                    vulnerabilities.append(vuln)
                                    logger.warning(f"[!] SQL Injection found: {url}")
                                break
                    except Exception as e:
                        logger.debug(f"Error testing {test_url}: {str(e)}")
        
        # Test forms
        for form_data in self.found_forms:
            form = form_data['form']
            url = form_data['url']
            
            inputs = form.find_all('input')
            for payload in self.sql_payloads[:5]:  # Test with subset
                form_payload = {}
                for inp in inputs:
                    name = inp.get('name')
                    if name:
                        form_payload[name] = payload
                
                try:
                    action_url = urljoin(url, form.get('action', ''))
                    if form_data['method'] == 'post':
                        response = self.session.post(action_url, data=form_payload, timeout=10, verify=False)
                    else:
                        response = self.session.get(action_url, params=form_payload, timeout=10, verify=False)
                    
                    for error in sql_errors:
                        if error in response.text.lower():
                            # Create unique identifier for this vulnerability
                            vuln_id = f"sqli|{action_url}|{payload}|{error}"
                            if vuln_id not in found_vulns:
                                found_vulns.add(vuln_id)
                                vuln = {
                                    'type': 'SQL Injection',
                                    'severity': 'HIGH',
                                    'url': action_url,
                                    'payload': payload,
                                    'evidence': f"SQL error detected in form: {error}"
                                }
                                vulnerabilities.append(vuln)
                                logger.warning(f"[!] SQL Injection found in form: {action_url}")
                            break
                except Exception as e:
                    logger.debug(f"Error testing form: {str(e)}")
        
        return vulnerabilities
    
    def test_lfi(self) -> List[Dict]:
        """Test for Local File Inclusion vulnerabilities"""
        logger.info("\n[*] Testing for LFI...")
        
        lfi_indicators = [
            "root:x:",
            "[extensions]",
            "[fonts]",
            "for 16-bit app support",
            "/bin/bash",
            "/bin/sh"
        ]
        
        vulnerabilities = []
        found_vulns = set()  # Track unique vulnerabilities
        
        # Test URL parameters
        for url in self.visited_urls:
            parsed = urlparse(url)
            if parsed.query:
                # Extract parameters
                params = {}
                for param in parsed.query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[key] = value
                
                # Test each parameter with LFI payloads
                for param_name in params:
                    for payload in self.lfi_payloads[:5]:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        try:
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            response = self.session.get(test_url, params=test_params, timeout=10, verify=False)
                            
                            for indicator in lfi_indicators:
                                if indicator in response.text:
                                    # Create unique identifier for this vulnerability
                                    vuln_id = f"lfi|{url}|{payload}|{indicator}"
                                    if vuln_id not in found_vulns:
                                        found_vulns.add(vuln_id)
                                        vuln = {
                                            'type': 'Local File Inclusion (LFI)',
                                            'severity': 'HIGH',
                                            'url': url,
                                            'payload': payload,
                                            'evidence': f"File content detected: {indicator}"
                                        }
                                        vulnerabilities.append(vuln)
                                        logger.warning(f"[!] LFI vulnerability found: {url}")
                                    break
                        except Exception as e:
                            logger.debug(f"Error testing LFI: {str(e)}")
        
        return vulnerabilities
    
    def test_xss(self) -> List[Dict]:
        """Test for Cross-Site Scripting vulnerabilities"""
        logger.info("\n[*] Testing for XSS...")
        
        vulnerabilities = []
        found_vulns = set()  # Track unique vulnerabilities
        
        # Test forms
        for form_data in self.found_forms:
            form = form_data['form']
            url = form_data['url']
            inputs = form.find_all('input')
            
            for payload in self.xss_payloads[:5]:  # Test with subset
                form_payload = {}
                for inp in inputs:
                    name = inp.get('name')
                    inp_type = inp.get('type', 'text').lower()
                    if name and inp_type not in ['submit', 'button', 'hidden']:
                        form_payload[name] = payload
                
                if not form_payload:
                    continue
                
                try:
                    action_url = urljoin(url, form.get('action', ''))
                    if form_data['method'] == 'post':
                        response = self.session.post(action_url, data=form_payload, timeout=10, verify=False)
                    else:
                        response = self.session.get(action_url, params=form_payload, timeout=10, verify=False)
                    
                    # Check if payload is reflected
                    if payload in response.text:
                        # Create unique identifier for this vulnerability
                        vuln_id = f"xss|{action_url}|{payload}"
                        if vuln_id not in found_vulns:
                            found_vulns.add(vuln_id)
                            vuln = {
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'MEDIUM',
                                'url': action_url,
                                'payload': payload,
                                'evidence': 'Payload reflected in response'
                            }
                            vulnerabilities.append(vuln)
                            logger.warning(f"[!] XSS vulnerability found: {action_url}")
                except Exception as e:
                    logger.debug(f"Error testing XSS: {str(e)}")
        
        return vulnerabilities
    
    def test_csrf(self) -> List[Dict]:
        """Test for CSRF vulnerabilities"""
        logger.info("\n[*] Testing for CSRF...")
        vulnerabilities = []
        found_vulns = set()  # Track unique vulnerabilities
        
        for form_data in self.found_forms:
            form = form_data['form']
            url = form_data['url']
            method = form_data['method']
            
            # Look for CSRF tokens
            csrf_indicators = ['csrf', 'token', '_token', 'authenticity_token', 'csrf_token']
            has_csrf_protection = False
            
            inputs = form.find_all('input')
            for inp in inputs:
                name = inp.get('name', '').lower()
                if any(indicator in name for indicator in csrf_indicators):
                    has_csrf_protection = True
                    break
            
            # State-changing operations without CSRF protection
            if method == 'post' and not has_csrf_protection:
                # Create unique identifier for this vulnerability
                vuln_id = f"csrf|{url}|post"
                if vuln_id not in found_vulns:
                    found_vulns.add(vuln_id)
                    vuln = {
                        'type': 'Cross-Site Request Forgery (CSRF)',
                        'severity': 'MEDIUM',
                        'url': url,
                        'payload': 'N/A',
                        'evidence': 'POST form without CSRF token detected'
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"[!] Potential CSRF vulnerability: {url}")
        
        return vulnerabilities
    
    def test_security_headers(self) -> List[Dict]:
        """Check for missing security headers"""
        logger.info("\n[*] Checking Security Headers...")
        vulnerabilities = []
        
        important_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'Strict-Transport-Security': None,
            'Content-Security-Policy': None,
            'X-XSS-Protection': '1'
        }
        
        try:
            response = self.session.get(self.target_url, timeout=10, verify=False)
            
            for header, expected_value in important_headers.items():
                if header not in response.headers:
                    vuln = {
                        'type': 'Missing Security Header',
                        'severity': 'LOW',
                        'url': self.target_url,
                        'payload': 'N/A',
                        'evidence': f'Missing header: {header}'
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"[!] Missing security header: {header}")
        
        except Exception as e:
            logger.error(f"Error checking headers: {str(e)}")
        
        return vulnerabilities
    
    def run_scan(self) -> Dict:
        """Execute all vulnerability scans"""
        logger.info(f"\n{'='*60}")
        logger.info(f"Starting scan on: {self.target_url}")
        logger.info(f"{'='*60}\n")
        
        start_time = time.time()
        
        # Enumerate subdomains if requested
        subdomain_results = []
        if self.scan_subdomains:
            self.enumerate_subdomains()
            
            # Scan each discovered subdomain
            for subdomain, url, status_code in self.discovered_subdomains:
                logger.info(f"\n[*] Scanning subdomain: {subdomain}")
                
                # Create a temporary scanner for this subdomain
                temp_scanner = WebScanner(
                    url, 
                    self.exclude_urls, 
                    self.wordlists,
                    scan_subdomains=False  # Don't recursively scan subdomains
                )
                
                # Crawl subdomain
                temp_scanner.crawl(url, depth=2)
                
                # Run tests on subdomain
                temp_vulns = []
                temp_vulns.extend(temp_scanner.test_sql_injection())
                temp_vulns.extend(temp_scanner.test_xss())
                temp_vulns.extend(temp_scanner.test_lfi())
                temp_vulns.extend(temp_scanner.test_csrf())
                temp_vulns.extend(temp_scanner.test_security_headers())
                
                subdomain_results.append({
                    'subdomain': subdomain,
                    'url': url,
                    'status_code': status_code,
                    'urls_crawled': len(temp_scanner.visited_urls),
                    'forms_found': len(temp_scanner.found_forms),
                    'vulnerabilities': temp_vulns
                })
                
                # Add to main vulnerabilities list
                self.vulnerabilities.extend(temp_vulns)
        
        # Crawl main website
        logger.info("[*] Crawling main website...")
        self.crawl(self.target_url)
        logger.info(f"[+] Found {len(self.visited_urls)} URLs")
        logger.info(f"[+] Found {len(self.found_forms)} forms")
        
        # Run vulnerability tests on main site
        main_vulns = []
        main_vulns.extend(self.test_sql_injection())
        main_vulns.extend(self.test_xss())
        main_vulns.extend(self.test_lfi())
        main_vulns.extend(self.test_csrf())
        main_vulns.extend(self.test_security_headers())
        
        self.vulnerabilities.extend(main_vulns)
        
        end_time = time.time()
        scan_duration = end_time - start_time
        
        # Calculate total URLs crawled and forms found (main site + subdomains)
        total_urls_crawled = len(self.visited_urls)
        total_forms_found = len(self.found_forms)
        
        for sub_result in subdomain_results:
            total_urls_crawled += sub_result['urls_crawled']
            total_forms_found += sub_result['forms_found']
        
        # Prepare results
        results = {
            'target': self.target_url,
            'scan_date': datetime.now().isoformat(),
            'duration_seconds': round(scan_duration, 2),
            'subdomain_enumeration': self.scan_subdomains,
            'subdomains_found': len(self.discovered_subdomains) if self.scan_subdomains else 0,
            'subdomain_results': subdomain_results if self.scan_subdomains else [],
            'urls_crawled': total_urls_crawled,
            'forms_found': total_forms_found,
            'vulnerabilities': self.vulnerabilities,
            'summary': {
                'total': len(self.vulnerabilities),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
            }
        }
        
        return results


def setup_logging(verbose: bool = False, log_file: str = None):
    """Setup logging configuration"""
    global LOG_FILENAME
    
    if log_file:
        LOG_FILENAME = log_file
    
    # Set logging level
    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # Setup file handler
    file_handler = logging.FileHandler(LOG_FILENAME, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)  # Always log everything to file
    file_handler.setFormatter(detailed_formatter)
    
    # Setup console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(simple_formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    root_logger.handlers = []
    
    # Add handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    logger.info(f"[+] Logging initialized - Log file: {LOG_FILENAME}")
    logger.info(f"[+] Console log level: {logging.getLevelName(log_level)}")
    
    return LOG_FILENAME


# def generate_html_report(results: Dict, output_file: str):
#     """Generate HTML report of scan results"""
#     subdomain_section = ""
#     if results.get('subdomain_enumeration'):
#         subdomain_section = f"""
#             <h2>Subdomain Enumeration</h2>
#             <div class="info">
#                 <p><strong>Subdomains Found:</strong> {results['subdomains_found']}</p>
#             </div>
#             <div class="subdomain-list">
#         """
        
#         for sub_result in results.get('subdomain_results', []):
#             vuln_count = len(sub_result['vulnerabilities'])
#             subdomain_section += f"""
#                 <div class="subdomain-item">
#                     <h3>{sub_result['subdomain']}</h3>
#                     <p><strong>URL:</strong> <code>{sub_result['url']}</code></p>
#                     <p><strong>Status Code:</strong> {sub_result.get('status_code', 'N/A')}</p>
#                     <p><strong>URLs Crawled:</strong> {sub_result['urls_crawled']}</p>
#                     <p><strong>Forms Found:</strong> {sub_result['forms_found']}</p>
#                     <p><strong>Vulnerabilities:</strong> {vuln_count}</p>
#                 </div>
#             """
        
#         subdomain_section += "</div>"
    
#     html_template = f"""
#     <!DOCTYPE html>
#     <html>
#     <head>
#         <meta charset="UTF-8">
#         <title>Web Security Scan Report</title>
#         <style>
#             body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
#             .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
#             h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
#             h2 {{ color: #555; margin-top: 30px; }}
#             .info {{ background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }}
#             .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
#             .stat {{ flex: 1; padding: 20px; border-radius: 5px; text-align: center; }}
#             .stat.high {{ background: #ffebee; color: #c62828; }}
#             .stat.medium {{ background: #fff3e0; color: #ef6c00; }}
#             .stat.low {{ background: #e8f5e9; color: #2e7d32; }}
#             .vulnerability {{ background: #fff; border-left: 4px solid #ccc; padding: 15px; margin: 10px 0; border-radius: 3px; }}
#             .vulnerability.HIGH {{ border-left-color: #c62828; }}
#             .vulnerability.MEDIUM {{ border-left-color: #ef6c00; }}
#             .vulnerability.LOW {{ border-left-color: #2e7d32; }}
#             .severity {{ display: inline-block; padding: 3px 10px; border-radius: 3px; font-weight: bold; font-size: 12px; }}
#             .severity.HIGH {{ background: #c62828; color: white; }}
#             .severity.MEDIUM {{ background: #ef6c00; color: white; }}
#             .severity.LOW {{ background: #2e7d32; color: white; }}
#             code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
#             .subdomain-list {{ margin: 20px 0; }}
#             .subdomain-item {{ background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 3px solid #007bff; border-radius: 3px; }}
#         </style>
#     </head>
#     <body>
#         <div class="container">
#             <h1>Web Application Security Scan Report</h1>
            
#             <div class="info">
#                 <p><strong>Target:</strong> {results['target']}</p>
#                 <p><strong>Scan Date:</strong> {results['scan_date']}</p>
#                 <p><strong>Duration:</strong> {results['duration_seconds']} seconds</p>
#                 <p><strong>Subdomain Enumeration:</strong> {'Enabled' if results.get('subdomain_enumeration') else 'Disabled'}</p>
#                 <p><strong>URLs Crawled:</strong> {results['urls_crawled']}</p>
#                 <p><strong>Forms Found:</strong> {results['forms_found']}</p>
#             </div>
            
#             <h2>Summary</h2>
#             <div class="summary">
#                 <div class="stat high">
#                     <h3>{results['summary']['high']}</h3>
#                     <p>High Severity</p>
#                 </div>
#                 <div class="stat medium">
#                     <h3>{results['summary']['medium']}</h3>
#                     <p>Medium Severity</p>
#                 </div>
#                 <div class="stat low">
#                     <h3>{results['summary']['low']}</h3>
#                     <p>Low Severity</p>
#                 </div>
#             </div>
            
#             {subdomain_section}
            
#             <h2>All Vulnerabilities Found ({results['summary']['total']})</h2>
#     """
    
#     # Display ALL vulnerabilities (from main site and all subdomains)
#     if results['vulnerabilities']:
#         for vuln in results['vulnerabilities']:
#             html_template += f"""
#             <div class="vulnerability {vuln['severity']}">
#                 <h3>{vuln['type']} <span class="severity {vuln['severity']}">{vuln['severity']}</span></h3>
#                 <p><strong>URL:</strong> <code>{vuln['url']}</code></p>
#                 <p><strong>Payload:</strong> <code>{vuln.get('payload', 'N/A')}</code></p>
#                 <p><strong>Evidence:</strong> {vuln['evidence']}</p>
#             </div>
#             """
#     else:
#         html_template += "<p>No vulnerabilities found.</p>"
    
#     html_template += """
#         </div>
#     </body>
#     </html>
#     """
    
#     with open(output_file, 'w', encoding='utf-8') as f:
#         f.write(html_template)
    
#     logger.info(f"\n[+] HTML report generated: {output_file}")

def generate_html_report(results: Dict, output_file: str):
    """Generate HTML report of scan results with proper escaping"""
    subdomain_section = ""
    if results.get('subdomain_enumeration'):
        subdomain_section = f"""
            <h2>Subdomain Enumeration</h2>
            <div class="info">
                <p><strong>Subdomains Found:</strong> {results['subdomains_found']}</p>
            </div>
            <div class="subdomain-list">
        """
        
        for sub_result in results.get('subdomain_results', []):
            vuln_count = len(sub_result['vulnerabilities'])
            # Escape all user-controlled data
            subdomain = html.escape(sub_result['subdomain'])
            url = html.escape(sub_result['url'])
            status = html.escape(str(sub_result.get('status_code', 'N/A')))
            
            subdomain_section += f"""
                <div class="subdomain-item">
                    <h3>{subdomain}</h3>
                    <p><strong>URL:</strong> <code>{url}</code></p>
                    <p><strong>Status Code:</strong> {status}</p>
                    <p><strong>URLs Crawled:</strong> {sub_result['urls_crawled']}</p>
                    <p><strong>Forms Found:</strong> {sub_result['forms_found']}</p>
                    <p><strong>Vulnerabilities:</strong> {vuln_count}</p>
                </div>
            """
        
        subdomain_section += "</div>"
    
    # Escape the target URL and other display data
    target_escaped = html.escape(results['target'])
    scan_date_escaped = html.escape(results['scan_date'])
    
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Web Security Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1 {{ color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }}
            h2 {{ color: #555; margin-top: 30px; }}
            .info {{ background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
            .stat {{ flex: 1; padding: 20px; border-radius: 5px; text-align: center; }}
            .stat.high {{ background: #ffebee; color: #c62828; }}
            .stat.medium {{ background: #fff3e0; color: #ef6c00; }}
            .stat.low {{ background: #e8f5e9; color: #2e7d32; }}
            .vulnerability {{ background: #fff; border-left: 4px solid #ccc; padding: 15px; margin: 10px 0; border-radius: 3px; }}
            .vulnerability.HIGH {{ border-left-color: #c62828; }}
            .vulnerability.MEDIUM {{ border-left-color: #ef6c00; }}
            .vulnerability.LOW {{ border-left-color: #2e7d32; }}
            .severity {{ display: inline-block; padding: 3px 10px; border-radius: 3px; font-weight: bold; font-size: 12px; }}
            .severity.HIGH {{ background: #c62828; color: white; }}
            .severity.MEDIUM {{ background: #ef6c00; color: white; }}
            .severity.LOW {{ background: #2e7d32; color: white; }}
            code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; word-break: break-all; }}
            .subdomain-list {{ margin: 20px 0; }}
            .subdomain-item {{ background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 3px solid #007bff; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Web Application Security Scan Report</h1>
            
            <div class="info">
                <p><strong>Target:</strong> {target_escaped}</p>
                <p><strong>Scan Date:</strong> {scan_date_escaped}</p>
                <p><strong>Duration:</strong> {results['duration_seconds']} seconds</p>
                <p><strong>Subdomain Enumeration:</strong> {'Enabled' if results.get('subdomain_enumeration') else 'Disabled'}</p>
                <p><strong>URLs Crawled:</strong> {results['urls_crawled']}</p>
                <p><strong>Forms Found:</strong> {results['forms_found']}</p>
            </div>
            
            <h2>Summary</h2>
            <div class="summary">
                <div class="stat high">
                    <h3>{results['summary']['high']}</h3>
                    <p>High Severity</p>
                </div>
                <div class="stat medium">
                    <h3>{results['summary']['medium']}</h3>
                    <p>Medium Severity</p>
                </div>
                <div class="stat low">
                    <h3>{results['summary']['low']}</h3>
                    <p>Low Severity</p>
                </div>
            </div>
            
            {subdomain_section}
            
            <h2>All Vulnerabilities Found ({results['summary']['total']})</h2>
    """
    
    # Display ALL vulnerabilities with proper escaping
    if results['vulnerabilities']:
        for vuln in results['vulnerabilities']:
            # Escape ALL user-controlled data to prevent XSS in the report itself
            vuln_type = html.escape(vuln['type'])
            vuln_url = html.escape(vuln['url'])
            vuln_payload = html.escape(vuln.get('payload', 'N/A'))
            vuln_evidence = html.escape(vuln['evidence'])
            vuln_severity = html.escape(vuln['severity'])
            
            html_template += f"""
            <div class="vulnerability {vuln_severity}">
                <h3>{vuln_type} <span class="severity {vuln_severity}">{vuln_severity}</span></h3>
                <p><strong>URL:</strong> <code>{vuln_url}</code></p>
                <p><strong>Payload:</strong> <code>{vuln_payload}</code></p>
                <p><strong>Evidence:</strong> {vuln_evidence}</p>
            </div>
            """
    else:
        html_template += "<p>No vulnerabilities found.</p>"
    
    html_template += """
        </div>
    </body>
    </html>
    """
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_template)
    
    logger.info(f"\n[+] HTML report generated: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Automated Web Application Penetration Testing Tool with Subdomain Enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python scanner.py -u http://example.com
  
  Scan with subdomain enumeration:
    python scanner.py -u http://example.com --scan-subdomains
  
  Scan with custom subdomain wordlist:
    python scanner.py -u http://example.com --scan-subdomains --subdomain-wordlist subdomains.txt
  
  Full scan with all custom wordlists:
    python scanner.py -u http://example.com --scan-subdomains \\
                      --subdomain-wordlist subdomains.txt \\
                      --sql-wordlist sqli.txt \\
                      --xss-wordlist xss.txt \\
                      --lfi-wordlist lfi.txt
  
  Scan with exclusions and custom output:
    python scanner.py -u http://example.com -e /admin,/logout -o custom_report.html
  
  Scan with JSON output and custom log file:
    python scanner.py -u http://example.com --scan-subdomains --json results.json --log-file scan.log
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-e', '--exclude', help='Comma-separated list of URLs to exclude')
    parser.add_argument('-o', '--output', default='report.html', help='Output HTML report file (default: report.html)')
    parser.add_argument('--json', help='Save results as JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output (DEBUG level)')
    parser.add_argument('--log-file', help='Custom log file name (default: scan_YYYYMMDD_HHMMSS.log)')
    
    # Subdomain enumeration options
    parser.add_argument('--scan-subdomains', action='store_true', 
                        help='Enable subdomain enumeration and scanning')
    parser.add_argument('--subdomain-wordlist', help='Custom subdomain wordlist file')
    parser.add_argument('--subdomain-threads', type=int, default=10,
                        help='Number of threads for subdomain enumeration (default: 10)')
    
    # Vulnerability testing wordlists
    parser.add_argument('--sql-wordlist', help='Custom SQL injection wordlist file')
    parser.add_argument('--xss-wordlist', help='Custom XSS wordlist file')
    parser.add_argument('--lfi-wordlist', help='Custom LFI wordlist file')
    
    args = parser.parse_args()
    
    # Initialize logging first
    log_filename = setup_logging(verbose=args.verbose, log_file=args.log_file)
    
    logger.info("="*60)
    logger.info("Web Application Penetration Testing Tool")
    logger.info("="*60)
    
    # Parse exclude URLs
    exclude_urls = []
    if args.exclude:
        exclude_urls = [url.strip() for url in args.exclude.split(',')]
        logger.info(f"[+] Excluded URLs: {', '.join(exclude_urls)}")
    
    # Parse wordlists
    wordlists = {}
    if args.sql_wordlist:
        wordlists['sql'] = args.sql_wordlist
        logger.info(f"[+] SQL wordlist: {args.sql_wordlist}")
    if args.xss_wordlist:
        wordlists['xss'] = args.xss_wordlist
        logger.info(f"[+] XSS wordlist: {args.xss_wordlist}")
    if args.lfi_wordlist:
        wordlists['lfi'] = args.lfi_wordlist
        logger.info(f"[+] LFI wordlist: {args.lfi_wordlist}")
    if args.subdomain_wordlist:
        wordlists['subdomain'] = args.subdomain_wordlist
        logger.info(f"[+] Subdomain wordlist: {args.subdomain_wordlist}")
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        # Run scanner
        scanner = WebScanner(
            args.url, 
            exclude_urls, 
            wordlists,
            scan_subdomains=args.scan_subdomains,
            subdomain_threads=args.subdomain_threads
        )
        results = scanner.run_scan()
        
        # Add log file info to results
        results['log_file'] = log_filename
        
        # Print summary
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        if args.scan_subdomains:
            print(f"Subdomains Found: {results['subdomains_found']}")
        print(f"Total Vulnerabilities: {results['summary']['total']}")
        print(f"  High: {results['summary']['high']}")
        print(f"  Medium: {results['summary']['medium']}")
        print(f"  Low: {results['summary']['low']}")
        print(f"{'='*60}")
        print(f"Log File: {log_filename}")
        print(f"{'='*60}\n")
        
        # Log summary to file
        logger.info("="*60)
        logger.info("SCAN SUMMARY")
        logger.info("="*60)
        logger.info(f"Target: {results['target']}")
        logger.info(f"Duration: {results['duration_seconds']} seconds")
        if args.scan_subdomains:
            logger.info(f"Subdomains Found: {results['subdomains_found']}")
        logger.info(f"URLs Crawled: {results['urls_crawled']}")
        logger.info(f"Forms Found: {results['forms_found']}")
        logger.info(f"Total Vulnerabilities: {results['summary']['total']}")
        logger.info(f"  - High Severity: {results['summary']['high']}")
        logger.info(f"  - Medium Severity: {results['summary']['medium']}")
        logger.info(f"  - Low Severity: {results['summary']['low']}")
        logger.info("="*60)
        
        # Generate reports
        generate_html_report(results, args.output)
        
        if args.json:
            with open(args.json, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
            logger.info(f"[+] JSON results saved: {args.json}")
        
        logger.info("\n[+] Scan completed successfully!")
        logger.info(f"[+] All scan details have been saved to: {log_filename}")
        
    except KeyboardInterrupt:
        logger.warning("\n[!] Scan interrupted by user")
        logger.info(f"[+] Partial logs saved to: {log_filename}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"\n[!] Error during scan: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        logger.info(f"[+] Error details saved to: {log_filename}")
        sys.exit(1)


if __name__ == '__main__':
    main()