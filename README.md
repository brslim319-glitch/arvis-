# ARVIS - Automated Reconnaissance & Vulnerability Intelligence Scanner

![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

ARVIS is a comprehensive security reconnaissance and vulnerability scanning tool designed for authorized security assessments. It combines automated reconnaissance, vulnerability scanning, CVE mapping, and professional PDF report generation into a single streamlined workflow.

## 🚀 Features

- **Automated Reconnaissance**
  - DNS record enumeration (A, AAAA, MX, NS, TXT, SOA)
  - Subdomain discovery
  - WHOIS lookup
  - Email harvesting
  - Port scanning
  - SSL/TLS certificate analysis
  - HTTP headers and security analysis

- **Vulnerability Scanning**
  - SQL injection detection
  - XSS (Cross-Site Scripting) testing
  - Directory/admin panel discovery
  - Sensitive file exposure detection
  - Security header analysis
  - HTTP method testing

- **CVE Mapping**
  - Automatic CVE lookup via NIST NVD API
  - Vulnerability severity classification
  - CVSS scoring integration

- **Professional Reporting**
  - PDF report generation with charts
  - Severity-based vulnerability categorization
  - Executive summary
  - Detailed findings with remediation advice

- **Interactive Console**
  - Metasploit-style command interface
  - Built-in help system
  - Command history and autocomplete

## 📋 Requirements

- Python 3.8 or higher
- Windows/Linux/macOS
- Internet connection (for API lookups and scanning)

## 🔧 Installation

### 1. Clone or Download the Repository

```bash
cd arvis
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Keys (Optional but Recommended)

Create a `.env` file in the project root directory:

```bash
# API Keys (optional)
SHODAN_API_KEY=your_shodan_api_key_here
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
NVD_API_KEY=your_nvd_api_key_here

# Scanner Settings
MAX_THREADS=10
TIMEOUT=10
USER_AGENT=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

**Getting API Keys:**
- **NVD API Key** (Recommended): [Register at NIST NVD](https://nvd.nist.gov/developers/request-an-api-key)
- **Shodan API Key** (Optional): [Get from Shodan](https://account.shodan.io/)
- **VirusTotal API Key** (Optional): [Sign up at VirusTotal](https://www.virustotal.com/gui/join-us)

### 4. Install Nmap (Required for Port Scanning)

**Windows:**
- Download and install from [nmap.org](https://nmap.org/download.html)
- Add Nmap to your system PATH

**Linux:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**macOS:**
```bash
brew install nmap
```

## 📖 Usage

### Basic Usage

#### Interactive Mode (Recommended for Beginners)

```bash
python ARVIS.py
```

You will be prompted to enter the target URL and authorize the scan.

#### Command-Line Mode

```bash
python ARVIS.py --url https://example.com
```

### Advanced Usage Examples

#### Full Scan with Custom Output

```bash
python ARVIS.py --url https://example.com --full-scan --output my_report.pdf
```

#### Skip Specific Phases

```bash
# Skip reconnaissance phase
python ARVIS.py --url https://example.com --skip-recon

# Skip vulnerability scanning
python ARVIS.py --url https://example.com --skip-vuln-scan

# Skip CVE mapping
python ARVIS.py --url https://example.com --skip-cve
```

#### Using Custom NVD API Key

```bash
python ARVIS.py --url https://example.com --api-key YOUR_NVD_API_KEY
```

#### Interactive Console Mode

```bash
python ARVIS.py --console
```

In console mode, you can use commands like:
```
arvis> set TARGET https://example.com
arvis> run
arvis> show options
arvis> help
arvis> exit
```

### Command-Line Options

```
Options:
  --url URL              Target URL to scan (e.g., https://example.com)
  --output PATH          Custom output PDF file path
  --skip-recon           Skip reconnaissance phase
  --skip-vuln-scan       Skip vulnerability scanning phase
  --skip-cve             Skip CVE mapping phase
  --full-scan            Perform comprehensive scan (may take longer)
  --api-key KEY          NIST NVD API key for CVE lookups
  --console              Launch interactive console (Metasploit-style)
  -h, --help             Show help message
```

## 📊 Example Workflow

### Example 1: Quick Security Assessment

```bash
# 1. Run a basic scan
python ARVIS.py --url https://testsite.com

# 2. Review the generated PDF report in the reports/ directory

# 3. Analyze findings and prioritize remediation
```

### Example 2: Comprehensive Enterprise Scan

```bash
# 1. Set up your API keys in .env file
# 2. Run full scan with all phases
python ARVIS.py --url https://corporate-site.com --full-scan

# 3. Review reconnaissance data
# 4. Analyze CVE mappings and CVSS scores
# 5. Generate action items from report
```

### Example 3: Targeted Vulnerability Assessment

```bash
# Skip recon if you already have the infrastructure info
python ARVIS.py --url https://webapp.com --skip-recon --output webapp_vulns.pdf
```

## 📁 Project Structure

```
arvis/
├── ARVIS.py              # Main entry point
├── config.py             # Configuration settings
├── recon.py              # Reconnaissance module
├── scanner.py            # Vulnerability scanning module
├── cve_mapper.py         # CVE mapping and enrichment
├── report_generator.py   # PDF report generation
├── utils.py              # Utility functions
├── requirements.txt      # Python dependencies
├── .env                  # API keys and settings (create this)
├── reports/              # Generated PDF reports
└── __pycache__/          # Python cache files
```

## 🛡️ Security Best Practices

1. **Authorization**: Always obtain written permission before scanning
2. **Rate Limiting**: Use API keys to avoid rate limits
3. **Scope**: Stay within the authorized scope of testing
4. **Data Protection**: Secure your API keys and scan results
5. **Responsible Disclosure**: Report findings through proper channels

## 🐛 Troubleshooting

### Common Issues

**Issue: "No module named 'nmap'"**
```bash
pip install python-nmap
# Also ensure nmap is installed on your system
```

**Issue: "Rate limited by NVD API"**
- Register for a free NVD API key
- Add it to your `.env` file

**Issue: "Permission denied" on Linux**
```bash
# Some features may require root privileges
sudo python ARVIS.py --url https://example.com
```

**Issue: Port scanning not working**
- Ensure Nmap is installed and in your PATH
- On Linux, you may need sudo for certain port scans


## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.







---

**Remember: With great power comes great responsibility. Use ARVIS ethically and legally.**
