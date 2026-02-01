"""
Reconnaissance Module for ARVIS
Handles DNS enumeration, subdomain discovery, WHOIS, SSL analysis, tech detection, and port scanning
"""
import socket
import dns.resolver
import whois
import ssl
import OpenSSL
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
import json
import subprocess
import concurrent.futures
from config import SUBDOMAIN_WORDLIST, COMMON_PORTS, TIMEOUT, USER_AGENT
from utils import print_status, extract_domain, extract_emails, extract_phone_numbers, logger


class ReconScanner:
    """Reconnaissance scanner for gathering target information"""
    
    def __init__(self, url):
        """
        Initialize reconnaissance scanner
        
        Args:
            url (str): Target URL
        """
        self.url = url
        self.domain = extract_domain(url)
        self.results = {
            'dns': {},
            'subdomains': [],
            'whois': {},
            'ssl': {},
            'technologies': {},
            'ports': [],
            'emails': [],
            'phones': [],
            'endpoints': []
        }
    
    def run_full_scan(self):
        """
        Run complete reconnaissance scan
        
        Returns:
            dict: All reconnaissance results
        """
        print_status(f"Starting reconnaissance scan on {self.domain}", 'info')
        
        
        print_status("Performing DNS enumeration...", 'info')
        self.dns_enumeration()
        
        
        print_status("Discovering subdomains...", 'info')
        self.subdomain_discovery()
        
        
        print_status("Fetching WHOIS information...", 'info')
        self.whois_lookup()
        
        
        print_status("Analyzing SSL certificate...", 'info')
        self.ssl_analysis()
        
        
        print_status("Detecting technologies...", 'info')
        self.detect_technologies()
        
        
        print_status("Scanning common ports...", 'info')
        self.port_scan()
        
        
        print_status("Extracting contact information...", 'info')
        self.extract_contact_info()
        
        print_status("Reconnaissance scan completed!", 'success')
        return self.results
    
    def dns_enumeration(self):
        """Enumerate DNS records"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.domain, record_type)
                self.results['dns'][record_type] = [str(rdata) for rdata in answers]
                print_status(f"Found {len(answers)} {record_type} record(s)", 'success')
            except dns.resolver.NoAnswer:
                self.results['dns'][record_type] = []
            except dns.resolver.NXDOMAIN:
                print_status(f"Domain {self.domain} does not exist", 'error')
                break
            except Exception as e:
                logger.error(f"DNS enumeration error for {record_type}: {str(e)}")
                self.results['dns'][record_type] = []
    
    def subdomain_discovery(self):
        """Discover subdomains using wordlist"""
        found_subdomains = []
        
        def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{self.domain}"
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in SUBDOMAIN_WORDLIST]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print_status(f"Found subdomain: {result}", 'success')
        
        self.results['subdomains'] = found_subdomains
    
    def whois_lookup(self):
        """Perform WHOIS lookup"""
        try:
            w = whois.whois(self.domain)
            self.results['whois'] = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else [],
                'emails': w.emails if w.emails else [],
                'org': w.org if hasattr(w, 'org') else None,
                'country': w.country if hasattr(w, 'country') else None
            }
            print_status("WHOIS information retrieved", 'success')
        except Exception as e:
            logger.error(f"WHOIS lookup error: {str(e)}")
            self.results['whois'] = {'error': str(e)}
    
    def ssl_analysis(self):
        """Analyze SSL certificate"""
        try:
            hostname = self.domain
            port = 443
            
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                    
                    self.results['ssl'] = {
                        'subject': dict(x[0] for x in cert.get_subject().get_components()),
                        'issuer': dict(x[0] for x in cert.get_issuer().get_components()),
                        'version': cert.get_version(),
                        'serial_number': cert.get_serial_number(),
                        'not_before': datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ').isoformat(),
                        'not_after': datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').isoformat(),
                        'has_expired': cert.has_expired(),
                        'signature_algorithm': cert.get_signature_algorithm().decode('utf-8')
                    }
                    
                    
                    expiry_date = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                    days_until_expiry = (expiry_date - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        print_status(f"SSL certificate expires in {days_until_expiry} days!", 'warning')
                    else:
                        print_status("SSL certificate is valid", 'success')
                    
        except Exception as e:
            logger.error(f"SSL analysis error: {str(e)}")
            self.results['ssl'] = {'error': str(e)}
    
    def detect_technologies(self):
        """Detect technologies used by the website"""
        try:
            headers = {'User-Agent': USER_AGENT}
            response = requests.get(self.url, headers=headers, timeout=TIMEOUT, verify=False)
            
            
            server = response.headers.get('Server', 'Unknown')
            self.results['technologies']['server'] = server
            
            
            powered_by = response.headers.get('X-Powered-By', 'Unknown')
            self.results['technologies']['powered_by'] = powered_by
            
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            cms_indicators = {
                'WordPress': ['/wp-content/', '/wp-includes/', 'wordpress'],
                'Joomla': ['/components/', '/modules/', 'joomla'],
                'Drupal': ['/sites/all/', '/sites/default/', 'drupal'],
                'Magento': ['/skin/frontend/', 'mage', 'magento'],
                'Shopify': ['cdn.shopify.com', 'shopify'],
                'Wix': ['wix.com', 'wixstatic.com'],
                'Squarespace': ['squarespace.com', 'sqsp']
            }
            
            detected_cms = []
            html_content = response.text.lower()
            
            for cms, indicators in cms_indicators.items():
                if any(indicator.lower() in html_content for indicator in indicators):
                    detected_cms.append(cms)
            
            self.results['technologies']['cms'] = detected_cms if detected_cms else ['Unknown']
            
            
            js_libraries = []
            scripts = soup.find_all('script', src=True)
            
            lib_patterns = {
                'jQuery': 'jquery',
                'React': 'react',
                'Angular': 'angular',
                'Vue.js': 'vue',
                'Bootstrap': 'bootstrap',
                'Modernizr': 'modernizr'
            }
            
            for script in scripts:
                src = script.get('src', '').lower()
                for lib, pattern in lib_patterns.items():
                    if pattern in src and lib not in js_libraries:
                        js_libraries.append(lib)
            
            self.results['technologies']['javascript_libraries'] = js_libraries
            
            
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator:
                self.results['technologies']['generator'] = meta_generator.get('content', 'Unknown')
            
            print_status(f"Detected: {server}, {', '.join(detected_cms)}", 'success')
            
        except Exception as e:
            logger.error(f"Technology detection error: {str(e)}")
            self.results['technologies'] = {'error': str(e)}
    
    def port_scan(self):
        """Scan common ports"""
        open_ports = []
        
        
        try:
            ip = socket.gethostbyname(self.domain)
        except socket.gaierror:
            print_status(f"Could not resolve {self.domain}", 'error')
            return
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = 'unknown'
                    return {'port': port, 'service': service, 'state': 'open'}
                return None
            except Exception as e:
                return None
        
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan_port, port) for port in COMMON_PORTS]
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print_status(f"Port {result['port']} ({result['service']}) is open", 'success')
        
        self.results['ports'] = open_ports
    
    def extract_contact_info(self):
        """Extract emails and phone numbers from the website"""
        try:
            headers = {'User-Agent': USER_AGENT}
            response = requests.get(self.url, headers=headers, timeout=TIMEOUT, verify=False)
            
            
            emails = extract_emails(response.text)
            self.results['emails'] = emails
            
            
            phones = extract_phone_numbers(response.text)
            self.results['phones'] = phones
            
            if emails:
                print_status(f"Found {len(emails)} email(s)", 'success')
            if phones:
                print_status(f"Found {len(phones)} phone number(s)", 'success')
            
        except Exception as e:
            logger.error(f"Contact extraction error: {str(e)}")


def run_recon(url):
    """
    Main function to run reconnaissance
    
    Args:
        url (str): Target URL
        
    Returns:
        dict: Reconnaissance results
    """
    scanner = ReconScanner(url)
    return scanner.run_full_scan()
