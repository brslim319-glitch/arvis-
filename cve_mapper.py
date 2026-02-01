"""
CVE Mapper Module for ARVIS
Maps discovered vulnerabilities to CVE IDs using NIST NVD API
"""
import requests
import time
from datetime import datetime
from config import NVD_API_KEY, NVD_API_URL, CVE_SEARCH_TIMEOUT
from utils import print_status, get_severity_from_cvss, logger


class CVEMapper:
    """Maps vulnerabilities to CVE database"""
    
    def __init__(self, api_key=None):
        """
        Initialize CVE mapper
        
        Args:
            api_key (str): NIST NVD API key (optional but recommended)
        """
        self.api_key = api_key or NVD_API_KEY
        self.base_url = NVD_API_URL
        self.headers = {}
        
        if self.api_key:
            self.headers['apiKey'] = self.api_key
    
    def search_cve(self, keyword, max_results=5):
        """
        Search for CVEs related to a keyword
        
        Args:
            keyword (str): Search keyword
            max_results (int): Maximum number of results
            
        Returns:
            list: List of relevant CVEs
        """
        try:
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': max_results
            }
            
            response = requests.get(
                self.base_url,
                params=params,
                headers=self.headers,
                timeout=CVE_SEARCH_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'vulnerabilities' in data:
                    cves = []
                    
                    for item in data['vulnerabilities'][:max_results]:
                        cve_data = item.get('cve', {})
                        cve_id = cve_data.get('id', '')
                        
                        
                        metrics = cve_data.get('metrics', {})
                        cvss_score = 0.0
                        cvss_vector = ''
                        
                        
                        if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            cvss_vector = cvss_data.get('vectorString', '')
                        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            cvss_vector = cvss_data.get('vectorString', '')
                        elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                            cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                            cvss_score = cvss_data.get('baseScore', 0.0)
                            cvss_vector = cvss_data.get('vectorString', '')
                        
                        
                        descriptions = cve_data.get('descriptions', [])
                        description = ''
                        for desc in descriptions:
                            if desc.get('lang') == 'en':
                                description = desc.get('value', '')
                                break
                        
                        
                        references = []
                        ref_data = cve_data.get('references', [])
                        for ref in ref_data[:3]:  
                            references.append(ref.get('url', ''))
                        
                        
                        published = cve_data.get('published', '')
                        
                        cve_info = {
                            'cve_id': cve_id,
                            'description': description,
                            'cvss_score': cvss_score,
                            'cvss_vector': cvss_vector,
                            'severity': get_severity_from_cvss(cvss_score),
                            'published': published,
                            'references': references
                        }
                        
                        cves.append(cve_info)
                    
                    return cves
                
            elif response.status_code == 403:
                logger.warning("NVD API rate limit exceeded or invalid API key")
            else:
                logger.error(f"NVD API error: {response.status_code}")
                
            return []
            
        except Exception as e:
            logger.error(f"CVE search error: {str(e)}")
            return []
    
    def map_vulnerability_to_cve(self, vulnerability):
        """
        Map a vulnerability to relevant CVEs
        
        Args:
            vulnerability (dict): Vulnerability information
            
        Returns:
            dict: Vulnerability with CVE mappings
        """
        title = vulnerability.get('title', '')
        
        
        keywords = self._extract_keywords(title)
        
        if not keywords:
            vulnerability['cves'] = []
            return vulnerability
        
        print_status(f"Searching CVEs for: {title}", 'info')
        
        
        cves = self.search_cve(keywords, max_results=3)
        
        vulnerability['cves'] = cves
        
        if cves:
            print_status(f"Found {len(cves)} related CVE(s)", 'success')
        
        
        time.sleep(0.6)  
        
        return vulnerability
    
    def _extract_keywords(self, title):
        """
        Extract search keywords from vulnerability title
        
        Args:
            title (str): Vulnerability title
            
        Returns:
            str: Search keywords
        """
        keyword_mapping = {
            'SQL Injection': 'sql injection',
            'XSS': 'cross-site scripting',
            'CSRF': 'cross-site request forgery',
            'Directory Traversal': 'directory traversal path',
            'Open Redirect': 'open redirect',
            'CORS': 'cors misconfiguration',
            'SSL': 'ssl tls',
            'Security Headers': 'security headers',
            'Admin Panel': 'admin panel exposure',
            'Sensitive Files': 'information disclosure'
        }
        
        title_lower = title.lower()
        
        for key, keyword in keyword_mapping.items():
            if key.lower() in title_lower:
                return keyword
        
        
        words = title.split()[:3]
        return ' '.join(words)
    
    def enrich_vulnerabilities(self, vulnerabilities):
        """
        Enrich all vulnerabilities with CVE data
        
        Args:
            vulnerabilities (list): List of vulnerabilities
            
        Returns:
            list: Enriched vulnerabilities
        """
        print_status("Mapping vulnerabilities to CVE database...", 'info')
        
        enriched = []
        
        for vuln in vulnerabilities:
            enriched_vuln = self.map_vulnerability_to_cve(vuln)
            enriched.append(enriched_vuln)
        
        print_status(f"CVE mapping completed for {len(enriched)} vulnerabilities", 'success')
        
        return enriched
    
    def get_cve_by_id(self, cve_id):
        """
        Get detailed information about a specific CVE
        
        Args:
            cve_id (str): CVE ID (e.g., CVE-2021-12345)
            
        Returns:
            dict: CVE details
        """
        try:
            url = f"{self.base_url}?cveId={cve_id}"
            
            response = requests.get(
                url,
                headers=self.headers,
                timeout=CVE_SEARCH_TIMEOUT
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'vulnerabilities' in data and data['vulnerabilities']:
                    cve_data = data['vulnerabilities'][0].get('cve', {})
                    
                    
                    metrics = cve_data.get('metrics', {})
                    cvss_score = 0.0
                    
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss_score = metrics['cvssMetricV31'][0]['cvssData'].get('baseScore', 0.0)
                    elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                        cvss_score = metrics['cvssMetricV30'][0]['cvssData'].get('baseScore', 0.0)
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss_score = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore', 0.0)
                    
                    descriptions = cve_data.get('descriptions', [])
                    description = ''
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    return {
                        'cve_id': cve_id,
                        'description': description,
                        'cvss_score': cvss_score,
                        'severity': get_severity_from_cvss(cvss_score)
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"CVE lookup error for {cve_id}: {str(e)}")
            return None


def map_vulnerabilities_to_cves(vulnerabilities, api_key=None):
    """
    Main function to map vulnerabilities to CVEs
    
    Args:
        vulnerabilities (list): List of vulnerabilities
        api_key (str): NIST NVD API key (optional)
        
    Returns:
        list: Vulnerabilities enriched with CVE data
    """
    mapper = CVEMapper(api_key)
    return mapper.enrich_vulnerabilities(vulnerabilities)
