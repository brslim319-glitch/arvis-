"""
Utility functions for ARVIS scanner
"""
import re
import socket
import validators
from urllib.parse import urlparse, urljoin
from datetime import datetime
import logging
from colorama import init, Fore, Style


init(autoreset=True)


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('arvis.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('ARVIS')


def print_banner():
    """Print the ARVIS banner"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     █████╗ ██████╗ ██╗   ██╗██╗███████╗                     ║
║    ██╔══██╗██╔══██╗██║   ██║██║██╔════╝                     ║
║    ███████║██████╔╝██║   ██║██║███████╗                     ║
║    ██╔══██║██╔══██╗╚██╗ ██╔╝██║╚════██║                     ║
║    ██║  ██║██║  ██║ ╚████╔╝ ██║███████║                     ║
║    ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝                     ║
║                                                               ║
║    Automated Reconnaissance & Vulnerability Intelligence     ║
║                      Scanner v1.0                             ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)


def validate_url(url):
    """
    Validate and normalize URL
    
    Args:
        url (str): URL to validate
        
    Returns:
        str: Normalized URL or None if invalid
    """
    if not url:
        return None
    
   
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    
    if validators.url(url):
        return url
    return None


def extract_domain(url):
    """
    Extract domain from URL
    
    Args:
        url (str): URL to parse
        
    Returns:
        str: Domain name
    """
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def is_valid_ip(ip):
    """
    Check if string is a valid IP address
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid IP
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def extract_emails(text):
    """
    Extract email addresses from text
    
    Args:
        text (str): Text to search
        
    Returns:
        list: List of unique email addresses
    """
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    return list(set(emails))


def extract_phone_numbers(text):
    """
    Extract phone numbers from text
    
    Args:
        text (str): Text to search
        
    Returns:
        list: List of unique phone numbers
    """
    phone_pattern = r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
    phones = re.findall(phone_pattern, text)
    return list(set([''.join(p) if isinstance(p, tuple) else p for p in phones]))


def normalize_path(base_url, path):
    """
    Normalize and join URL path
    
    Args:
        base_url (str): Base URL
        path (str): Path to join
        
    Returns:
        str: Complete URL
    """
    return urljoin(base_url, path)


def get_severity_color(severity):
    """
    Get color for severity level
    
    Args:
        severity (str): Severity level
        
    Returns:
        str: Color code
    """
    severity_colors = {
        'CRITICAL': Fore.RED,
        'HIGH': Fore.LIGHTRED_EX,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.BLUE,
        'INFO': Fore.CYAN
    }
    return severity_colors.get(severity.upper(), Fore.WHITE)


def get_severity_from_cvss(score):
    """
    Get severity level from CVSS score
    
    Args:
        score (float): CVSS score (0-10)
        
    Returns:
        str: Severity level
    """
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score > 0:
        return 'LOW'
    else:
        return 'INFO'


def format_timestamp(timestamp=None):
    """
    Format timestamp for reports
    
    Args:
        timestamp (datetime): Timestamp to format (default: now)
        
    Returns:
        str: Formatted timestamp
    """
    if timestamp is None:
        timestamp = datetime.now()
    return timestamp.strftime('%Y-%m-%d %H:%M:%S')


def sanitize_filename(filename):
    """
    Sanitize filename by removing invalid characters
    
    Args:
        filename (str): Filename to sanitize
        
    Returns:
        str: Sanitized filename
    """
    
    filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
    
    filename = filename.strip('. ')
    return filename


def print_status(message, status='info'):
    """
    Print colored status message
    
    Args:
        message (str): Message to print
        status (str): Status type (info, success, warning, error)
    """
    status_colors = {
        'info': Fore.CYAN,
        'success': Fore.GREEN,
        'warning': Fore.YELLOW,
        'error': Fore.RED
    }
    
    status_symbols = {
        'info': '[*]',
        'success': '[+]',
        'warning': '[!]',
        'error': '[-]'
    }
    
    color = status_colors.get(status, Fore.WHITE)
    symbol = status_symbols.get(status, '[*]')
    
    print(f"{color}{symbol} {message}{Style.RESET_ALL}")
    
    
    log_level = {
        'info': logging.INFO,
        'success': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR
    }.get(status, logging.INFO)
    
    logger.log(log_level, message)


def chunks(lst, n):
    """
    Yield successive n-sized chunks from list
    
    Args:
        lst (list): List to chunk
        n (int): Chunk size
        
    Yields:
        list: Chunks of size n
    """
    for i in range(0, len(lst), n):
        yield lst[i:i + n]
