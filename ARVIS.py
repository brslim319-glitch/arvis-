"""
ARVIS - Automated Reconnaissance & Vulnerability Intelligence Scanner
Main entry point for the application
"""
import argparse
import sys
import os
import cmd
import shlex
from datetime import datetime


from utils import (
    print_banner, print_status, validate_url,
    logger
)
from recon import run_recon
from scanner import run_vulnerability_scan
from cve_mapper import map_vulnerabilities_to_cves
from report_generator import generate_pdf_report
from config import NVD_API_KEY


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='ARVIS - Automated Reconnaissance & Vulnerability Intelligence Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py
  python main.py --url https://example.com
  python main.py --url https://example.com --skip-recon
  python main.py --url https://example.com --output custom_report.pdf
  python main.py --url https://example.com --full-scan
        """
    )
    
    parser.add_argument(
        '--url',
        type=str,
        help='Target URL to scan'
    )
    
    parser.add_argument(
        '--output',
        type=str,
        help='Output PDF file path'
    )
    
    parser.add_argument(
        '--skip-recon',
        action='store_true',
        help='Skip reconnaissance phase'
    )
    
    parser.add_argument(
        '--skip-vuln-scan',
        action='store_true',
        help='Skip vulnerability scanning phase'
    )
    
    parser.add_argument(
        '--skip-cve',
        action='store_true',
        help='Skip CVE mapping'
    )
    
    parser.add_argument(
        '--full-scan',
        action='store_true',
        help='Perform comprehensive scan (may take longer)'
    )
    
    parser.add_argument(
        '--api-key',
        type=str,
        help='NIST NVD API key for CVE lookups'
    )

    parser.add_argument(
        '--console',
        action='store_true',
        help='Launch interactive ARVIS console (Metasploit-style)'
    )
    
    return parser.parse_args()


def get_user_input():
    """Get target URL from user"""
    print("\n" + "="*60)
    print("  Welcome to ARVIS Security Scanner")
    print("="*60 + "\n")
    
    while True:
        url = input("Enter target URL (e.g., https://example.com): ").strip()
        
        if not url:
            print_status("URL cannot be empty. Please try again.", 'error')
            continue
        
        validated_url = validate_url(url)
        
        if validated_url:
            return validated_url
        else:
            print_status("Invalid URL format. Please try again.", 'error')


def display_summary(recon_data, vulnerabilities):
    """Display scan summary"""
    print("\n" + "="*60)
    print("  SCAN SUMMARY")
    print("="*60 + "\n")
    
    
    if recon_data:
        print_status("Reconnaissance Results:", 'info')
        print(f"  • DNS Records: {len([v for v in recon_data.get('dns', {}).values() if v])}")
        print(f"  • Subdomains Found: {len(recon_data.get('subdomains', []))}")
        print(f"  • Open Ports: {len(recon_data.get('ports', []))}")
        print(f"  • Emails Found: {len(recon_data.get('emails', []))}")
        print()
    
    
    if vulnerabilities:
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print_status("Vulnerability Summary:", 'warning' if len(vulnerabilities) > 0 else 'success')
        print(f"  • Total Findings: {len(vulnerabilities)}")
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in severity_counts:
                print(f"  • {severity}: {severity_counts[severity]}")
        print()
    else:
        print_status("No vulnerabilities detected!", 'success')
        print()


def confirm_authorization():
    """Show legal disclaimer and confirm authorization"""
    print("="*60)
    print("  LEGAL DISCLAIMER")
    print("="*60)
    print("""
⚠️  This tool is for educational and authorized security testing only.
    Only scan systems you own or have explicit permission to test.
    Unauthorized scanning may be illegal in your jurisdiction.
    The authors are not responsible for misuse of this tool.
     """)

    response = input("Do you have authorization to scan this target? (yes/no): ").strip().lower()
    return response in ['yes', 'y']


def run_scan_pipeline(
    target_url,
    *,
    output_path=None,
    skip_recon=False,
    skip_vuln_scan=False,
    skip_cve=False,
    full_scan=False,
    api_key=None,
    prompt_to_open=True
):
    """Execute the full ARVIS workflow with the provided options"""

    recon_data = {}
    vulnerabilities = []

    start_time = datetime.now()

    print_status(f"Target: {target_url}", 'info')
    if full_scan:
        print_status("Full scan flag enabled (extended checks where supported)", 'info')

    if not skip_recon:
        print("\n" + "="*60)
        print("  PHASE 1: RECONNAISSANCE")
        print("="*60 + "\n")

        recon_data = run_recon(target_url)

        print()
        print_status("Reconnaissance phase completed!", 'success')
    else:
        print_status("Skipping reconnaissance phase", 'info')

    if not skip_vuln_scan:
        print("\n" + "="*60)
        print("  PHASE 2: VULNERABILITY SCANNING")
        print("="*60 + "\n")

        vulnerabilities = run_vulnerability_scan(target_url)

        print()
        print_status("Vulnerability scanning completed!", 'success')
    else:
        print_status("Skipping vulnerability scanning phase", 'info')

    if vulnerabilities and not skip_cve:
        print("\n" + "="*60)
        print("  PHASE 3: CVE MAPPING")
        print("="*60 + "\n")

        api_key_to_use = api_key or NVD_API_KEY

        if not api_key_to_use:
            print_status("No NVD API key provided. CVE lookups may be rate-limited.", 'warning')

        vulnerabilities = map_vulnerabilities_to_cves(vulnerabilities, api_key_to_use)

        print()
        print_status("CVE mapping completed!", 'success')
    elif skip_cve:
        print_status("Skipping CVE mapping phase", 'info')

    display_summary(recon_data, vulnerabilities)

    print("\n" + "="*60)
    print("  PHASE 4: REPORT GENERATION")
    print("="*60 + "\n")

    report_path = generate_pdf_report(target_url, recon_data, vulnerabilities, output_path)

    elapsed_time = (datetime.now() - start_time).total_seconds()

    print()
    print("="*60)
    print("  SCAN COMPLETED")
    print("="*60)
    print(f"\n✓ Report saved to: {report_path}")
    print(f"✓ Scan duration: {elapsed_time:.2f} seconds")
    print(f"✓ Total findings: {len(vulnerabilities)}")
    print()

    if prompt_to_open and os.path.exists(report_path):
        open_report = input("Would you like to open the report? (yes/no): ").strip().lower()
        if open_report in ['yes', 'y']:
            import subprocess
            import platform

            if platform.system() == 'Windows':
                os.startfile(report_path)
            elif platform.system() == 'Darwin':
                subprocess.run(['open', report_path])
            else:
                subprocess.run(['xdg-open', report_path])

    return {
        'recon_data': recon_data,
        'vulnerabilities': vulnerabilities,
        'report_path': report_path,
        'elapsed': elapsed_time
    }


class ArvisConsole(cmd.Cmd):
    """Metasploit-style interactive console for ARVIS"""

    intro = "Launching ARVIS console. Type 'help' for commands."
    prompt = "arvis> "

    def __init__(self):
        super().__init__()
        self.options = {
            'target': None,
            'output': None,
            'skip_recon': False,
            'skip_vuln_scan': False,
            'skip_cve': False,
            'full_scan': False,
            'api_key': NVD_API_KEY
        }
        self.last_results = None
        print_banner()
        print_status(self.intro, 'info')

    def do_options(self, arg):
        """Show current options"""
        print("\nCurrent options:")
        for key, value in self.options.items():
            print(f"  {key:14} : {value}")
        print()

    def do_set(self, arg):
        """Set an option. Usage: set <option> <value>"""
        try:
            parts = shlex.split(arg)
        except ValueError:
            print_status("Invalid quoting in arguments", 'error')
            return

        if len(parts) < 2:
            print_status("Usage: set <option> <value>", 'warning')
            return

        key = parts[0].lower()
        value = ' '.join(parts[1:])

        if key not in self.options:
            print_status(f"Unknown option: {key}", 'error')
            return

        if isinstance(self.options[key], bool):
            self.options[key] = value.lower() in ['1', 'true', 'yes', 'y', 'on']
        else:
            self.options[key] = value

        print_status(f"Set {key} to {self.options[key]}", 'success')

    def do_unset(self, arg):
        """Unset an option (resets to default). Usage: unset <option>"""
        key = arg.strip().lower()
        defaults = {
            'target': None,
            'output': None,
            'skip_recon': False,
            'skip_vuln_scan': False,
            'skip_cve': False,
            'full_scan': False,
            'api_key': NVD_API_KEY
        }

        if key not in defaults:
            print_status(f"Unknown option: {key}", 'error')
            return

        self.options[key] = defaults[key]
        print_status(f"Reset {key}", 'info')

    def do_run(self, arg):
        """Run scan with current options"""
        target = self.options.get('target')
        if not target:
            print_status("Set a target first: set target https://example.com", 'error')
            return

        validated = validate_url(target)
        if not validated:
            print_status("Invalid target URL", 'error')
            return

        if not confirm_authorization():
            print_status("Scan cancelled by user", 'warning')
            return

        self.last_results = run_scan_pipeline(
            validated,
            output_path=self.options.get('output'),
            skip_recon=self.options.get('skip_recon'),
            skip_vuln_scan=self.options.get('skip_vuln_scan'),
            skip_cve=self.options.get('skip_cve'),
            full_scan=self.options.get('full_scan'),
            api_key=self.options.get('api_key'),
            prompt_to_open=False
        )

    def do_last(self, arg):
        """Show summary of last run"""
        if not self.last_results:
            print_status("No runs yet", 'warning')
            return

        print_status(f"Report: {self.last_results['report_path']}", 'info')
        print_status(f"Findings: {len(self.last_results['vulnerabilities'])}", 'info')

    def do_exit(self, arg):
        """Exit the console"""
        print_status("Exiting ARVIS console", 'info')
        return True

    def do_quit(self, arg):
        """Exit the console"""
        return self.do_exit(arg)

    def do_EOF(self, arg):  # noqa: N802
        """Exit on Ctrl+D/Ctrl+Z"""
        print()
        return self.do_exit(arg)


def run_console():
    """Start the interactive console"""
    console = ArvisConsole()
    console.cmdloop()


def main():
    """Main application function"""
    args = parse_arguments()

    if args.console:
        run_console()
        return

    print_banner()

    try:
        if args.url:
            target_url = validate_url(args.url)
            if not target_url:
                print_status("Invalid URL provided.", 'error')
                sys.exit(1)
        else:
            target_url = get_user_input()

        if not confirm_authorization():
            print_status("Scan cancelled by user.", 'warning')
            sys.exit(0)

        run_scan_pipeline(
            target_url,
            output_path=args.output,
            skip_recon=args.skip_recon,
            skip_vuln_scan=args.skip_vuln_scan,
            skip_cve=args.skip_cve,
            full_scan=args.full_scan,
            api_key=args.api_key,
            prompt_to_open=True
        )

        print_status("Thank you for using ARVIS!", 'success')

    except KeyboardInterrupt:
        print("\n")
        print_status("Scan interrupted by user.", 'warning')
        sys.exit(0)

    except Exception as e:
        print()
        print_status(f"An error occurred: {str(e)}", 'error')
        logger.exception("Fatal error in main function")
        sys.exit(1)


if __name__ == '__main__':
    main()
