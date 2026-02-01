"""
PDF Report Generator Module for ARVIS
Generates professional security assessment reports
"""
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from config import REPORT_DIR
from utils import print_status, format_timestamp, sanitize_filename, logger


class ReportGenerator:
    """Generates PDF security assessment reports"""
    
    def __init__(self, url, recon_data, vulnerabilities):
        """
        Initialize report generator
        
        Args:
            url (str): Target URL
            recon_data (dict): Reconnaissance results
            vulnerabilities (list): List of vulnerabilities
        """
        self.url = url
        self.recon_data = recon_data
        self.vulnerabilities = vulnerabilities
        self.timestamp = datetime.now()
        self.styles = getSampleStyleSheet()
        self._setup_styles()
    
    def _setup_styles(self):
        """Setup custom paragraph styles"""
        
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        
        self.styles.add(ParagraphStyle(
            name='SubsectionHeader',
            parent=self.styles['Heading3'],
            fontSize=13,
            textColor=colors.HexColor('#34495e'),
            spaceAfter=10,
            fontName='Helvetica-Bold'
        ))
        
        
        self.styles.add(ParagraphStyle(
            name='VulnTitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#c0392b'),
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
    
    def generate_report(self, output_path=None):
        """
        Generate complete PDF report
        
        Args:
            output_path (str): Output file path (optional)
            
        Returns:
            str: Path to generated report
        """
        print_status("Generating PDF report...", 'info')
        
        
        os.makedirs(REPORT_DIR, exist_ok=True)
        
        
        if not output_path:
            domain = self.url.replace('https://', '').replace('http://', '').replace('/', '_')
            domain = sanitize_filename(domain)
            timestamp = self.timestamp.strftime('%Y-%m-%d')
            filename = f"Recon-Report_{domain}_{timestamp}.pdf"
            output_path = os.path.join(REPORT_DIR, filename)
        
        
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        
        story = []
        
        
        story.extend(self._create_cover_page())
        story.append(PageBreak())
        
        
        story.extend(self._create_executive_summary())
        story.append(PageBreak())
        
        
        story.extend(self._create_recon_section())
        story.append(PageBreak())
        
        
        story.extend(self._create_vulnerabilities_section())
        story.append(PageBreak())
        
        
        story.extend(self._create_conclusion())
        
        
        try:
            doc.build(story)
            print_status(f"Report generated successfully: {output_path}", 'success')
            return output_path
        except Exception as e:
            logger.error(f"Report generation error: {str(e)}")
            raise
    
    def _create_cover_page(self):
        """Create cover page"""
        elements = []
        
        elements.append(Spacer(1, 2*inch))
        
        
        title = Paragraph("SECURITY ASSESSMENT REPORT", self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.5*inch))
        
       
        url_text = f"<b>Target:</b> {self.url}"
        elements.append(Paragraph(url_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        
        date_text = f"<b>Date:</b> {format_timestamp(self.timestamp)}"
        elements.append(Paragraph(date_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        
        author_text = "<b>Generated by:</b> ARVIS v1.0"
        elements.append(Paragraph(author_text, self.styles['Normal']))
        elements.append(Spacer(1, 1*inch))
        
        
        disclaimer = """
        <b>CONFIDENTIAL</b><br/><br/>
        This report contains sensitive security information. Distribution should be limited to 
        authorized personnel only. The findings in this report are based on automated scanning 
        and should be verified manually before taking action.
        """
        elements.append(Paragraph(disclaimer, self.styles['Normal']))
        
        return elements
    
    def _create_executive_summary(self):
        """Create executive summary section"""
        elements = []
        
        elements.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        
        total_vulns = len(self.vulnerabilities)
        severity_counts = self._count_by_severity()
        
        summary_text = f"""
        This report presents the findings of a comprehensive security assessment conducted on 
        <b>{self.url}</b>. The assessment included reconnaissance activities and vulnerability 
        scanning to identify potential security weaknesses.
        <br/><br/>
        <b>Total Findings:</b> {total_vulns}<br/>
        <b>Critical:</b> {severity_counts.get('CRITICAL', 0)}<br/>
        <b>High:</b> {severity_counts.get('HIGH', 0)}<br/>
        <b>Medium:</b> {severity_counts.get('MEDIUM', 0)}<br/>
        <b>Low:</b> {severity_counts.get('LOW', 0)}<br/>
        <b>Informational:</b> {severity_counts.get('INFO', 0)}
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        
        if total_vulns > 0:
            chart = self._create_severity_pie_chart(severity_counts)
            elements.append(chart)
        
        return elements
    
    def _create_recon_section(self):
        """Create reconnaissance findings section"""
        elements = []
        
        elements.append(Paragraph("Reconnaissance Findings", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        
        elements.append(Paragraph("DNS Records", self.styles['SubsectionHeader']))
        dns_data = self.recon_data.get('dns', {})
        
        dns_table_data = [['Record Type', 'Values']]
        for record_type, values in dns_data.items():
            if values:
                values_str = '<br/>'.join(values[:5])  
                dns_table_data.append([record_type, Paragraph(values_str, self.styles['Normal'])])
        
        if len(dns_table_data) > 1:
            dns_table = Table(dns_table_data, colWidths=[1.5*inch, 4.5*inch])
            dns_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(dns_table)
        elements.append(Spacer(1, 0.2*inch))
        
        
        subdomains = self.recon_data.get('subdomains', [])
        if subdomains:
            elements.append(Paragraph("Discovered Subdomains", self.styles['SubsectionHeader']))
            subdomain_text = '<br/>'.join(subdomains[:10])  
            elements.append(Paragraph(subdomain_text, self.styles['Normal']))
            elements.append(Spacer(1, 0.2*inch))
        
        
        elements.append(Paragraph("WHOIS Information", self.styles['SubsectionHeader']))
        whois_data = self.recon_data.get('whois', {})
        
        if 'error' not in whois_data:
            whois_table_data = [['Field', 'Value']]
            
            fields = ['registrar', 'creation_date', 'expiration_date', 'org', 'country']
            for field in fields:
                value = whois_data.get(field, 'N/A')
                if value and value != 'None':
                    whois_table_data.append([field.replace('_', ' ').title(), str(value)])
            
            if len(whois_table_data) > 1:
                whois_table = Table(whois_table_data, colWidths=[2*inch, 4*inch])
                whois_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                elements.append(whois_table)
        elements.append(Spacer(1, 0.2*inch))
        
        
        elements.append(Paragraph("Detected Technologies", self.styles['SubsectionHeader']))
        tech_data = self.recon_data.get('technologies', {})
        
        if 'error' not in tech_data:
            tech_items = []
            
            if 'server' in tech_data:
                tech_items.append(f"<b>Server:</b> {tech_data['server']}")
            if 'cms' in tech_data:
                tech_items.append(f"<b>CMS:</b> {', '.join(tech_data['cms'])}")
            if 'powered_by' in tech_data and tech_data['powered_by'] != 'Unknown':
                tech_items.append(f"<b>Powered By:</b> {tech_data['powered_by']}")
            if 'javascript_libraries' in tech_data and tech_data['javascript_libraries']:
                tech_items.append(f"<b>JS Libraries:</b> {', '.join(tech_data['javascript_libraries'])}")
            
            tech_text = '<br/>'.join(tech_items)
            elements.append(Paragraph(tech_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        
        ports = self.recon_data.get('ports', [])
        if ports:
            elements.append(Paragraph("Open Ports", self.styles['SubsectionHeader']))
            
            port_table_data = [['Port', 'Service', 'State']]
            for port_info in ports[:15]: 
                port_table_data.append([
                    str(port_info['port']),
                    port_info['service'],
                    port_info['state']
                ])
            
            port_table = Table(port_table_data, colWidths=[1*inch, 2*inch, 1*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            elements.append(port_table)
        
        return elements
    
    def _create_vulnerabilities_section(self):
        """Create vulnerabilities section"""
        elements = []
        
        elements.append(Paragraph("Security Vulnerabilities", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        if not self.vulnerabilities:
            elements.append(Paragraph("No vulnerabilities detected.", self.styles['Normal']))
            return elements
        
        
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        grouped = {}
        
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            if severity not in grouped:
                grouped[severity] = []
            grouped[severity].append(vuln)
        
        
        for severity in severity_order:
            if severity not in grouped:
                continue
            
            vulns = grouped[severity]
            
            
            color_map = {
                'CRITICAL': colors.red,
                'HIGH': colors.orange,
                'MEDIUM': colors.yellow,
                'LOW': colors.blue,
                'INFO': colors.grey
            }
            
            severity_header = Paragraph(
                f"{severity} Severity ({len(vulns)})",
                self.styles['SubsectionHeader']
            )
            elements.append(severity_header)
            elements.append(Spacer(1, 0.1*inch))
            
            
            for i, vuln in enumerate(vulns, 1):
                vuln_elements = self._create_vulnerability_entry(vuln, i, color_map[severity])
                elements.extend(vuln_elements)
                
                if i < len(vulns):
                    elements.append(Spacer(1, 0.15*inch))
            
            elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _create_vulnerability_entry(self, vuln, index, color):
        """Create a single vulnerability entry"""
        elements = []
        
        
        title = f"{index}. {vuln.get('title', 'Unknown Vulnerability')}"
        elements.append(Paragraph(title, self.styles['VulnTitle']))
        
        
        description = vuln.get('description', 'No description available.')
        elements.append(Paragraph(f"<b>Description:</b> {description}", self.styles['Normal']))
        
        
        evidence = vuln.get('evidence', '')
        if evidence:
            evidence_text = evidence.replace('\n', '<br/>')
            elements.append(Paragraph(f"<b>Evidence:</b><br/>{evidence_text}", self.styles['Normal']))
        
        
        cves = vuln.get('cves', [])
        if cves:
            elements.append(Paragraph("<b>Related CVEs:</b>", self.styles['Normal']))
            
            for cve in cves[:3]:  
                cve_id = cve.get('cve_id', 'N/A')
                cvss_score = cve.get('cvss_score', 0.0)
                cve_severity = cve.get('severity', 'INFO')
                
                cve_text = f"• {cve_id} - CVSS: {cvss_score} ({cve_severity})"
                elements.append(Paragraph(cve_text, self.styles['Normal']))
                
                cve_desc = cve.get('description', '')
                if cve_desc:
                    short_desc = cve_desc[:200] + '...' if len(cve_desc) > 200 else cve_desc
                    elements.append(Paragraph(f"  {short_desc}", self.styles['Normal']))
                
                refs = cve.get('references', [])
                if refs:
                    ref_text = f"  References: {refs[0]}"
                    elements.append(Paragraph(ref_text, self.styles['Normal']))
        
        
        recommendation = vuln.get('recommendation', '')
        if recommendation:
            elements.append(Paragraph(f"<b>Recommendation:</b> {recommendation}", self.styles['Normal']))
        
        return elements
    
    def _create_conclusion(self):
        """Create conclusion section"""
        elements = []
        
        elements.append(Paragraph("Conclusion & Recommendations", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        severity_counts = self._count_by_severity()
        critical = severity_counts.get('CRITICAL', 0)
        high = severity_counts.get('HIGH', 0)
        
        
        if critical > 0:
            risk_level = "CRITICAL"
            risk_color = "red"
        elif high > 0:
            risk_level = "HIGH"
            risk_color = "orange"
        elif severity_counts.get('MEDIUM', 0) > 0:
            risk_level = "MEDIUM"
            risk_color = "yellow"
        else:
            risk_level = "LOW"
            risk_color = "green"
        
        conclusion_text = f"""
        Based on the security assessment conducted on <b>{self.url}</b>, the overall risk level 
        is assessed as <b>{risk_level}</b>.
        <br/><br/>
        The assessment identified <b>{len(self.vulnerabilities)}</b> security finding(s) that require 
        attention. Immediate action should be taken to address critical and high severity issues.
        <br/><br/>
        <b>General Recommendations:</b><br/>
        • Address all critical and high severity vulnerabilities immediately<br/>
        • Implement security best practices for web application development<br/>
        • Regular security assessments and penetration testing<br/>
        • Keep all software and dependencies up to date<br/>
        • Implement a Web Application Firewall (WAF)<br/>
        • Enable comprehensive logging and monitoring<br/>
        • Conduct security awareness training for development team
        """
        
        elements.append(Paragraph(conclusion_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))
        
        
        risk_score = self._calculate_risk_score()
        risk_text = f"<b>Calculated Risk Score:</b> {risk_score}/100"
        elements.append(Paragraph(risk_text, self.styles['Normal']))
        
        return elements
    
    def _count_by_severity(self):
        """Count vulnerabilities by severity"""
        counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            counts[severity] = counts.get(severity, 0) + 1
        return counts
    
    def _calculate_risk_score(self):
        """Calculate overall risk score (0-100)"""
        severity_weights = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 8,
            'LOW': 3,
            'INFO': 1
        }
        
        score = 0
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'INFO')
            score += severity_weights.get(severity, 1)
        
        
        return min(score, 100)
    
    def _create_severity_pie_chart(self, severity_counts):
        """Create pie chart for severity distribution"""
        drawing = Drawing(400, 200)
        
        pie = Pie()
        pie.x = 150
        pie.y = 50
        pie.width = 100
        pie.height = 100
        
        
        labels = []
        data = []
        colors_list = []
        
        color_map = {
            'CRITICAL': colors.red,
            'HIGH': colors.orange,
            'MEDIUM': colors.yellow,
            'LOW': colors.blue,
            'INFO': colors.grey
        }
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in severity_counts:
                labels.append(f"{severity}: {severity_counts[severity]}")
                data.append(severity_counts[severity])
                colors_list.append(color_map[severity])
        
        pie.data = data
        pie.labels = labels
        pie.slices.strokeWidth = 0.5
        
        for i, color in enumerate(colors_list):
            pie.slices[i].fillColor = color
        
        drawing.add(pie)
        
        return drawing


def generate_pdf_report(url, recon_data, vulnerabilities, output_path=None):
    """
    Main function to generate PDF report
    
    Args:
        url (str): Target URL
        recon_data (dict): Reconnaissance results
        vulnerabilities (list): List of vulnerabilities
        output_path (str): Output file path (optional)
        
    Returns:
        str: Path to generated report
    """
    generator = ReportGenerator(url, recon_data, vulnerabilities)
    return generator.generate_report(output_path)
