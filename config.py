import os
from dotenv import load_dotenv

load_dotenv()

SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
NVD_API_KEY = os.getenv('NVD_API_KEY', '')

MAX_THREADS = int(os.getenv('MAX_THREADS', 10))
TIMEOUT = int(os.getenv('TIMEOUT', 10))
USER_AGENT = os.getenv('USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')

SUBDOMAIN_WORDLIST = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'api', 'dev', 'staging',
    'test', 'admin', 'portal', 'blog', 'shop', 'store', 'app', 'mobile', 'm',
    'secure', 'vpn', 'remote', 'cloud', 'backup', 'git', 'beta', 'demo'
]

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]

ADMIN_PATHS = [
    '/admin', '/administrator', '/admin.php', '/login', '/wp-admin', '/wp-login.php',
    '/cpanel', '/phpmyadmin', '/pma', '/admin/login', '/user/login', '/dashboard',
    '/admin/dashboard', '/adminpanel', '/controlpanel', '/admin/cp', '/moderator',
    '/webadmin', '/adminarea', '/bb-admin', '/adminLogin', '/admin_area', '/panel',
    '/instadmin', '/memberadmin', '/administratorlogin', '/adm', '/account', '/admin/account',
    '/admin/index', '/admin/login.php', '/admin/admin', '/admin_area/admin',
    '/admin_area/login', '/siteadmin', '/siteadmin/login', '/admin/home', '/admincp'
]

SENSITIVE_PATHS = [
    '/.git', '/.env', '/.env.local', '/.env.production', '/config.php', '/configuration.php',
    '/settings.php', '/database.yml', '/config.yml', '/web.config', '/.htaccess',
    '/phpinfo.php', '/info.php', '/test.php', '/debug', '/.DS_Store', '/backup',
    '/.git/config', '/.svn', '/composer.json', '/package.json', '/.gitignore'
]

SQL_PAYLOADS = [
    "'", "1' OR '1'='1", "1 OR 1=1", "' OR '1'='1' --", "admin' --",
    "' UNION SELECT NULL--", "1' AND 1=1--", "' OR 'a'='a", "') OR ('1'='1"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'>"
]

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Content-Security-Policy',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Permissions-Policy'
]

REPORT_DIR = 'reports'
LOG_LEVEL = 'INFO'

NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CVE_SEARCH_TIMEOUT = 30

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'