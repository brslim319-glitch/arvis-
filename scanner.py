"""
Vulnerability Scanner Module for ARVIS
Handles SQL injection, XSS, CSRF, open redirects, CORS, directory traversal, and security checks
"""
import requests
import re
import urllib3
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import concurrent.futures
from config import (
    SQL_PAYLOADS, XSS_PAYLOADS, ADMIN_PATHS, SENSITIVE_PATHS,
    SECURITY_HEADERS, TIMEOUT, USER_AGENT
)
from utils import print_status, normalize_path, logger


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VulnerabilityScanner:
    """Scanner for detecting common web vulnerabilities"""
    
    def __init__(self, url):
        """
        Initialize vulnerability scanner
        
        Args:
            url (str): Target URL
        """
        self.url = url
        self.base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
    
    def run_full_scan(self):
        """
        Run complete vulnerability scan
        
        Returns:
            list: List of discovered vulnerabilities
        """
        print_status(f"Starting vulnerability scan on {self.url}", 'info')
        
        
        print_status("Checking security headers...", 'info')
        self.check_security_headers()
        
        
        print_status("Checking SSL/TLS configuration...", 'info')
        self.check_ssl_config()
        
        
        print_status("Checking CORS configuration...", 'info')
        self.check_cors()
        
        
        print_status("Scanning for exposed admin panels...", 'info')
        self.scan_admin_panels()
        
        
        print_status("Scanning for sensitive files...", 'info')
        self.scan_sensitive_files()
        
        
        forms = self.get_forms()
        
        if forms:
            
            print_status("Testing for SQL injection...", 'info')
            self.test_sql_injection(forms)
            
            
            print_status("Testing for XSS vulnerabilities...", 'info')
            self.test_xss(forms)
            
            
            print_status("Checking for CSRF protection...", 'info')
            self.test_csrf(forms)
        else:
            print_status("No forms found for injection testing", 'warning')
        
        
        print_status("Testing for open redirects...", 'info')
        self.test_open_redirect()
        
        
        print_status("Testing for directory traversal...", 'info')
        self.test_directory_traversal()
        
        print_status(f"Vulnerability scan completed! Found {len(self.vulnerabilities)} issues", 
                    'success' if len(self.vulnerabilities) == 0 else 'warning')
        
        return self.vulnerabilities
    
    def add_vulnerability(self, title, description, severity, evidence='', recommendation=''):
        """
        Add vulnerability to results
        
        Args:
            title (str): Vulnerability title
            description (str): Detailed description
            severity (str): Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            evidence (str): Proof of vulnerability
            recommendation (str): Fix recommendation
        """
        vuln = {
            'title': title,
            'description': description,
            'severity': severity,
            'evidence': evidence,
            'recommendation': recommendation,
            'url': self.url
        }
        self.vulnerabilities.append(vuln)
        print_status(f"[{severity}] {title}", 'warning' if severity in ['CRITICAL', 'HIGH'] else 'info')
    
    def check_security_headers(self):
        """Check for missing security headers"""
        try:
            response = self.session.get(self.url, timeout=TIMEOUT, verify=False)
            headers = response.headers
            
            missing_headers = []
            
            for header in SECURITY_HEADERS:
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                self.add_vulnerability(
                    title="Missing Security Headers",
                    description=f"The following security headers are missing: {', '.join(missing_headers)}",
                    severity="MEDIUM",
                    evidence=f"Missing headers: {', '.join(missing_headers)}",
                    recommendation="Implement all recommended security headers to prevent common attacks."
                )
            
            
            x_frame = headers.get('X-Frame-Options', '').upper()
            if x_frame not in ['DENY', 'SAMEORIGIN']:
                self.add_vulnerability(
                    title="Weak X-Frame-Options Configuration",
                    description="X-Frame-Options is missing or improperly configured",
                    severity="MEDIUM",
                    evidence=f"X-Frame-Options: {x_frame or 'Not set'}",
                    recommendation="Set X-Frame-Options to DENY or SAMEORIGIN to prevent clickjacking."
                )
            
            
            if 'X-XSS-Protection' not in headers:
                self.add_vulnerability(
                    title="Missing X-XSS-Protection Header",
                    description="X-XSS-Protection header is not set",
                    severity="LOW",
                    evidence="X-XSS-Protection header not found",
                    recommendation="Add 'X-XSS-Protection: 1; mode=block' header."
                )
                
        except Exception as e:
            logger.error(f"Security headers check error: {str(e)}")
    
    def check_ssl_config(self):
        """Check SSL/TLS configuration"""
        try:
            if not self.url.startswith('https://'):
                self.add_vulnerability(
                    title="Unencrypted HTTP Connection",
                    description="The website is accessible over unencrypted HTTP",
                    severity="HIGH",
                    evidence=f"URL: {self.url}",
                    recommendation="Implement HTTPS and redirect all HTTP traffic to HTTPS."
                )
                return
            
            response = self.session.get(self.url, timeout=TIMEOUT, verify=False)
            
            
            hsts = response.headers.get('Strict-Transport-Security', '')
            if not hsts:
                self.add_vulnerability(
                    title="Missing HSTS Header",
                    description="HTTP Strict Transport Security (HSTS) is not enabled",
                    severity="MEDIUM",
                    evidence="Strict-Transport-Security header not found",
                    recommendation="Add HSTS header with appropriate max-age directive."
                )
                
        except Exception as e:
            logger.error(f"SSL configuration check error: {str(e)}")
    
    def check_cors(self):
        """Check CORS configuration"""
        try:
            headers = {
                'Origin': 'https://evil.com',
                'User-Agent': USER_AGENT
            }
            
            response = self.session.get(self.url, headers=headers, timeout=TIMEOUT, verify=False)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == '*' and acac.lower() == 'true':
                self.add_vulnerability(
                    title="Insecure CORS Configuration",
                    description="CORS allows any origin with credentials",
                    severity="HIGH",
                    evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                    recommendation="Restrict CORS to specific trusted origins, avoid using wildcard with credentials."
                )
            elif acao == 'https://evil.com':
                self.add_vulnerability(
                    title="CORS Reflects Arbitrary Origins",
                    description="CORS configuration reflects the Origin header value",
                    severity="MEDIUM",
                    evidence=f"Sent Origin: https://evil.com, Received: {acao}",
                    recommendation="Implement whitelist of allowed origins instead of reflecting Origin header."
                )
                
        except Exception as e:
            logger.error(f"CORS check error: {str(e)}")
    
    def scan_admin_panels(self):
        """Scan for exposed admin panels"""
        found_panels = []
        
        def check_path(path):
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 401, 403]:
                    return {'path': path, 'status': response.status_code, 'url': url}
                return None
            except:
                return None
        
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_path, path) for path in ADMIN_PATHS[:20]]  
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_panels.append(result)
        
        if found_panels:
            evidence = '\n'.join([f"{p['url']} - Status: {p['status']}" for p in found_panels])
            self.add_vulnerability(
                title="Exposed Admin Panels",
                description=f"Found {len(found_panels)} potentially accessible admin panel(s)",
                severity="MEDIUM",
                evidence=evidence,
                recommendation="Restrict access to admin panels using IP whitelisting, VPN, or strong authentication."
            )
    
    def scan_sensitive_files(self):
        """Scan for sensitive files"""
        found_files = []
        
        def check_file(path):
            try:
                url = urljoin(self.base_url, path)
                response = self.session.get(url, timeout=5, verify=False)
                
                if response.status_code == 200 and len(response.content) > 0:
                    return {'path': path, 'url': url, 'size': len(response.content)}
                return None
            except:
                return None
        
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_file, path) for path in SENSITIVE_PATHS[:15]]  
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_files.append(result)
        
        if found_files:
            evidence = '\n'.join([f"{f['url']} - Size: {f['size']} bytes" for f in found_files])
            severity = "HIGH" if any('.env' in f['path'] or '.git' in f['path'] for f in found_files) else "MEDIUM"
            
            self.add_vulnerability(
                title="Sensitive Files Exposed",
                description=f"Found {len(found_files)} exposed sensitive file(s)",
                severity=severity,
                evidence=evidence,
                recommendation="Remove or restrict access to sensitive files. Add them to .gitignore and use proper access controls."
            )
    
    def get_forms(self):
        """Extract all forms from the page"""
        try:
            response = self.session.get(self.url, timeout=TIMEOUT, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            return forms
        except Exception as e:
            logger.error(f"Form extraction error: {str(e)}")
            return []
    
    def test_sql_injection(self, forms):
        """Test for SQL injection vulnerabilities"""
        tested = False
        
        for form in forms[:3]:  
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(self.url, action)
            
            inputs = form.find_all('input')
            
            for payload in SQL_PAYLOADS[:5]:  
                data = {}
                for input_tag in inputs:
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    
                    if input_name:
                        if input_type == 'text' or input_type == 'search':
                            data[input_name] = payload
                        else:
                            data[input_name] = 'test'
                
                try:
                    if method == 'post':
                        response = self.session.post(form_url, data=data, timeout=TIMEOUT, verify=False)
                    else:
                        response = self.session.get(form_url, params=data, timeout=TIMEOUT, verify=False)
                    
                    
                    sql_errors = [
                        'sql syntax', 'mysql', 'sqlite', 'postgresql', 'oracle',
                        'syntax error', 'unterminated', 'unexpected', 'database error'
                    ]
                    
                    response_text = response.text.lower()
                    
                    if any(error in response_text for error in sql_errors):
                        tested = True
                        self.add_vulnerability(
                            title="Possible SQL Injection",
                            description=f"SQL injection may be possible in form at {form_url}",
                            severity="CRITICAL",
                            evidence=f"Payload: {payload}\nForm action: {form_url}\nMethod: {method}",
                            recommendation="Use parameterized queries (prepared statements) and input validation."
                        )
                        break
                        
                except Exception as e:
                    logger.error(f"SQL injection test error: {str(e)}")
            
            if tested:
                break
    
    def test_xss(self, forms):
        """Test for XSS vulnerabilities"""
        tested = False
        
        for form in forms[:3]:  
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(self.url, action)
            
            inputs = form.find_all('input')
            
            for payload in XSS_PAYLOADS[:3]:  
                data = {}
                for input_tag in inputs:
                    input_name = input_tag.get('name')
                    input_type = input_tag.get('type', 'text')
                    
                    if input_name:
                        if input_type in ['text', 'search', 'email']:
                            data[input_name] = payload
                        else:
                            data[input_name] = 'test'
                
                try:
                    if method == 'post':
                        response = self.session.post(form_url, data=data, timeout=TIMEOUT, verify=False)
                    else:
                        response = self.session.get(form_url, params=data, timeout=TIMEOUT, verify=False)
                    
                    
                    if payload in response.text:
                        tested = True
                        self.add_vulnerability(
                            title="Possible XSS Vulnerability",
                            description=f"XSS may be possible in form at {form_url}",
                            severity="HIGH",
                            evidence=f"Payload: {payload}\nForm action: {form_url}\nPayload reflected in response",
                            recommendation="Implement input validation and output encoding. Use Content Security Policy."
                        )
                        break
                        
                except Exception as e:
                    logger.error(f"XSS test error: {str(e)}")
            
            if tested:
                break
    
    def test_csrf(self, forms):
        """Check for CSRF protection"""
        for form in forms[:5]:  
            method = form.get('method', 'get').lower()
            
            if method == 'post':
                
                csrf_indicators = ['csrf', 'token', '_token', 'authenticity_token', 'csrfmiddlewaretoken']
                
                has_csrf = False
                for input_tag in form.find_all('input'):
                    input_name = input_tag.get('name', '').lower()
                    if any(indicator in input_name for indicator in csrf_indicators):
                        has_csrf = True
                        break
                
                if not has_csrf:
                    action = form.get('action', '')
                    form_url = urljoin(self.url, action)
                    
                    self.add_vulnerability(
                        title="Missing CSRF Protection",
                        description=f"Form at {form_url} may lack CSRF protection",
                        severity="MEDIUM",
                        evidence=f"POST form without apparent CSRF token at {form_url}",
                        recommendation="Implement CSRF tokens for all state-changing operations."
                    )
    
    def test_open_redirect(self):
        """Test for open redirect vulnerabilities"""
        redirect_params = ['url', 'redirect', 'next', 'return', 'returnUrl', 'redirect_uri', 'continue']
        evil_url = 'https://evil.com'
        
        parsed = urlparse(self.url)
        query_params = parse_qs(parsed.query)
        
        for param in redirect_params:
            test_url = f"{self.url}{'&' if query_params else '?'}{param}={evil_url}"
            
            try:
                response = self.session.get(test_url, timeout=TIMEOUT, verify=False, allow_redirects=False)
                
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if evil_url in location:
                        self.add_vulnerability(
                            title="Open Redirect Vulnerability",
                            description="Application redirects to arbitrary URLs",
                            severity="MEDIUM",
                            evidence=f"Test URL: {test_url}\nRedirect Location: {location}",
                            recommendation="Validate redirect URLs against a whitelist of allowed destinations."
                        )
                        break
            except Exception as e:
                logger.error(f"Open redirect test error: {str(e)}")
    
    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities"""
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd'
        ]
        
        parsed = urlparse(self.url)
        
        for payload in traversal_payloads[:2]:  
            test_url = f"{self.url}{'&' if parsed.query else '?'}file={payload}"
            
            try:
                response = self.session.get(test_url, timeout=TIMEOUT, verify=False)
                
                
                indicators = ['root:x:', '[extensions]', 'for 16-bit app support']
                
                if any(indicator in response.text for indicator in indicators):
                    self.add_vulnerability(
                        title="Directory Traversal Vulnerability",
                        description="Application may be vulnerable to directory traversal",
                        severity="CRITICAL",
                        evidence=f"Payload: {payload}\nSensitive file content detected in response",
                        recommendation="Validate and sanitize file path inputs. Use absolute paths and whitelist allowed files."
                    )
                    break
            except Exception as e:
                logger.error(f"Directory traversal test error: {str(e)}")


def run_vulnerability_scan(url):
    """
    Main function to run vulnerability scan
    
    Args:
        url (str): Target URL
        
    Returns:
        list: List of vulnerabilities
    """
    scanner = VulnerabilityScanner(url)
    return scanner.run_full_scan()
