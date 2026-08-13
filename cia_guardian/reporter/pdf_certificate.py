"""
PDF Certificate Generator
Generates formal security certification documents using FPDF2.
"""

import os
from datetime import datetime, timedelta
from typing import Dict, Any


class PDFCertificate:
    """
    Generates formal PDF security certificates using FPDF2.
    Features letterhead format with executive sign-off section.
    """
    
    def __init__(self):
        """Initialize the PDF Certificate generator."""
        try:
            from fpdf import FPDF
            self.FPDF = FPDF
        except ImportError:
            raise ImportError("fpdf2 is required for PDF generation. Install with: pip install fpdf2")
    
    def _get_grade_color(self, grade: str) -> tuple:
        """Get RGB color for letter grade."""
        colors = {
            'A': (25, 135, 84),    # Green
            'B': (32, 201, 151),   # Teal
            'C': (255, 193, 7),    # Yellow
            'D': (253, 126, 20),   # Orange
            'F': (220, 53, 69),    # Red
        }
        return colors.get(grade, (108, 117, 125))
    
    def generate(self, audit_data: Dict[str, Any], output_path: str) -> str:
        """
        Generate PDF security certificate.
        
        Args:
            audit_data: Dictionary containing audit results
            output_path: Path to write the PDF file
            
        Returns:
            Path to the generated PDF file
        """
        from fpdf import FPDF
        
        summary = audit_data.get('summary', {})
        system_info = audit_data.get('system_info', {})
        results = audit_data.get('results', [])
        
        # Create PDF
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        
        # Get page dimensions
        page_width = pdf.w
        page_height = pdf.h
        
        # ===== HEADER / LETTERHEAD =====
        # Top border line
        pdf.set_fill_color(102, 126, 234)  # Purple gradient start
        pdf.rect(0, 0, page_width, 8, 'F')
        
        # Organization header
        pdf.set_y(15)
        pdf.set_font('Helvetica', 'B', 24)
        pdf.set_text_color(102, 126, 234)
        pdf.cell(0, 10, 'CIA-GUARDIAN', 0, 1, 'C')
        
        pdf.set_font('Helvetica', '', 12)
        pdf.set_text_color(108, 117, 125)
        pdf.cell(0, 6, 'Windows Security Assessment Platform', 0, 1, 'C')
        
        # Horizontal separator
        pdf.set_y(35)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(20, 35, page_width - 20, 35)
        
        # ===== CERTIFICATE TITLE =====
        pdf.set_y(45)
        pdf.set_font('Helvetica', 'B', 20)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 10, 'WINDOWS SECURITY CERTIFICATION', 0, 1, 'C')
        
        pdf.set_font('Helvetica', 'I', 11)
        pdf.set_text_color(108, 117, 125)
        pdf.cell(0, 6, 'Based on CIA Triad Security Framework', 0, 1, 'C')
        
        # ===== SECURITY SCORE SECTION =====
        pdf.set_y(70)
        
        # Score circle
        grade = summary.get('letter_grade', 'F')
        score = summary.get('security_score', 0)
        grade_color = self._get_grade_color(grade)
        
        # Draw score box
        box_x = (page_width - 60) / 2
        pdf.set_fill_color(*grade_color)
        pdf.set_draw_color(*grade_color)
        pdf.rect(box_x, 70, 60, 35, 'D')
        
        pdf.set_xy(box_x, 72)
        pdf.set_font('Helvetica', 'B', 36)
        pdf.set_text_color(*grade_color)
        pdf.cell(60, 18, grade, 0, 1, 'C')
        
        pdf.set_xy(box_x, 90)
        pdf.set_font('Helvetica', '', 14)
        pdf.cell(60, 8, f'{score:.1f}%', 0, 1, 'C')
        
        # Score label
        pdf.set_y(110)
        pdf.set_font('Helvetica', 'B', 12)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 6, 'SECURITY SCORE', 0, 1, 'C')
        
        # ===== SYSTEM DETAILS =====
        pdf.set_y(125)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 8, 'CERTIFIED SYSTEM', 0, 1, 'C')
        
        pdf.set_font('Helvetica', '', 10)
        pdf.set_text_color(73, 80, 87)
        
        hostname = system_info.get('hostname', 'Unknown')
        os_info = f"{system_info.get('os_name', '')} {system_info.get('os_version', '')}"
        domain = system_info.get('domain', '')
        
        pdf.cell(0, 5, f'Hostname: {hostname}', 0, 1, 'C')
        pdf.cell(0, 5, f'Operating System: {os_info}', 0, 1, 'C')
        if domain:
            pdf.cell(0, 5, f'Domain: {domain}', 0, 1, 'C')
        
        # ===== COMPLIANCE SUMMARY =====
        pdf.set_y(155)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 8, 'COMPLIANCE SUMMARY', 0, 1, 'C')
        
        # Summary table
        table_x = 40
        col_width = (page_width - 80) / 5  # 5 columns now for timeouts
        
        pdf.set_xy(table_x, 165)
        pdf.set_font('Helvetica', 'B', 8)  # Smaller font for 5 columns
        pdf.set_fill_color(248, 249, 250)
        
        headers = ['Total', 'Compliant', 'Remediated', 'Non-Compliant', 'Timeouts']
        values = [
            str(summary.get('total_controls', 0)),
            str(summary.get('compliant', 0)),
            str(summary.get('remediated', 0)),
            str(summary.get('non_compliant', 0)),
            str(summary.get('timeouts', 0))  # v2.1: Include timeouts
        ]
        
        for header in headers:
            pdf.cell(col_width, 8, header, 1, 0, 'C', True)
        pdf.ln()
        
        pdf.set_font('Helvetica', '', 9)
        pdf.set_x(table_x)
        for value in values:
            pdf.cell(col_width, 8, value, 1, 0, 'C')
        pdf.ln()
        
        # ===== CIA TRIAD BREAKDOWN =====
        pdf.set_y(190)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 8, 'CIA TRIAD ASSESSMENT', 0, 1, 'C')
        
        category_scores = summary.get('category_scores', {})
        categories = [
            ('Confidentiality', category_scores.get('Confidentiality', 0), (111, 66, 193)),
            ('Integrity', category_scores.get('Integrity', 0), (13, 110, 253)),
            ('Availability', category_scores.get('Availability', 0), (32, 201, 151)),
        ]
        
        bar_width = 100
        bar_height = 8
        bar_x = (page_width - bar_width - 60) / 2
        
        pdf.set_y(200)
        for name, score, color in categories:
            pdf.set_x(bar_x)
            pdf.set_font('Helvetica', '', 9)
            pdf.set_text_color(73, 80, 87)
            pdf.cell(60, bar_height, name, 0, 0)
            
            # Background bar
            pdf.set_fill_color(233, 236, 239)
            pdf.rect(bar_x + 60, pdf.get_y(), bar_width, bar_height, 'F')
            
            # Score bar
            pdf.set_fill_color(*color)
            score_width = (score / 100) * bar_width
            pdf.rect(bar_x + 60, pdf.get_y(), score_width, bar_height, 'F')
            
            # Score text
            pdf.set_x(bar_x + 165)
            pdf.set_text_color(*color)
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(20, bar_height, f'{score:.0f}%', 0, 1)
        
        # ===== CONTROL RESULTS TABLE =====
        pdf.set_y(235)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 8, 'CONTROL ASSESSMENT DETAILS', 0, 1, 'C')
        
        # Table headers
        pdf.set_xy(15, 245)
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_fill_color(248, 249, 250)
        
        col_widths = [25, 55, 35, 25, 40]
        headers = ['ID', 'Control Name', 'Category', 'Risk', 'Status']
        
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 7, header, 1, 0, 'C', True)
        pdf.ln()
        
        # Table rows (limit to fit on page)
        pdf.set_font('Helvetica', '', 7)
        max_rows = min(len(results), 8)  # Limit rows to fit
        
        for i, result in enumerate(results[:max_rows]):
            pdf.set_x(15)
            
            # Alternate row colors
            if i % 2 == 0:
                pdf.set_fill_color(255, 255, 255)
            else:
                pdf.set_fill_color(248, 249, 250)
            
            # Status color
            status = result.get('status', '')
            if status in ['Compliant', 'Remediated']:
                pdf.set_text_color(25, 135, 84)  # Green
            elif status == 'Non-Compliant':
                pdf.set_text_color(220, 53, 69)  # Red
            elif status == 'Timeout':
                pdf.set_text_color(253, 126, 20)  # Orange for timeout
            else:
                pdf.set_text_color(108, 117, 125)  # Gray
            
            pdf.cell(col_widths[0], 6, result.get('control_id', ''), 1, 0, 'C', True)
            
            pdf.set_text_color(33, 37, 41)
            name = result.get('name', '')[:25]  # Truncate
            pdf.cell(col_widths[1], 6, name, 1, 0, 'L', True)
            
            pdf.cell(col_widths[2], 6, result.get('category', ''), 1, 0, 'C', True)
            pdf.cell(col_widths[3], 6, result.get('risk_level', ''), 1, 0, 'C', True)
            
            # Status with color
            if status in ['Compliant', 'Remediated']:
                pdf.set_text_color(25, 135, 84)  # Green
            elif status == 'Non-Compliant':
                pdf.set_text_color(220, 53, 69)  # Red
            elif status == 'Timeout':
                pdf.set_text_color(253, 126, 20)  # Orange for timeout
            else:
                pdf.set_text_color(108, 117, 125)  # Gray
            
            pdf.cell(col_widths[4], 6, status, 1, 1, 'C', True)
        
        if len(results) > max_rows:
            pdf.set_x(15)
            pdf.set_text_color(108, 117, 125)
            pdf.set_font('Helvetica', 'I', 7)
            pdf.cell(sum(col_widths), 6, f'... and {len(results) - max_rows} more controls (see full report)', 0, 1, 'C')
        
        # ===== VALIDITY & SIGNATURE SECTION =====
        # Add new page for signature section
        pdf.add_page()
        
        pdf.set_y(20)
        pdf.set_font('Helvetica', 'B', 14)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 10, 'CERTIFICATION STATEMENT', 0, 1, 'C')
        
        pdf.set_y(35)
        pdf.set_font('Helvetica', '', 10)
        pdf.set_text_color(73, 80, 87)
        
        cert_text = (
            f"This certifies that the system identified as '{hostname}' has undergone "
            f"a comprehensive security assessment based on the CIA Triad framework "
            f"(Confidentiality, Integrity, Availability). The assessment evaluated "
            f"{summary.get('total_controls', 0)} security controls and achieved a "
            f"security score of {score:.1f}% (Grade: {grade})."
        )
        
        pdf.multi_cell(0, 6, cert_text, 0, 'J')
        
        # Validity dates
        pdf.set_y(70)
        assessment_date = datetime.now()
        expiry_date = assessment_date + timedelta(days=90)
        
        pdf.set_font('Helvetica', 'B', 10)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 8, 'VALIDITY PERIOD', 0, 1, 'C')
        
        pdf.set_font('Helvetica', '', 10)
        pdf.set_text_color(73, 80, 87)
        pdf.cell(0, 6, f'Assessment Date: {assessment_date.strftime("%B %d, %Y")}', 0, 1, 'C')
        pdf.cell(0, 6, f'Valid Until: {expiry_date.strftime("%B %d, %Y")}', 0, 1, 'C')
        
        # Watermark for validity
        pdf.set_font('Helvetica', 'B', 8)
        pdf.set_text_color(200, 200, 200)
        pdf.set_xy(page_width - 60, 10)
        pdf.cell(50, 5, 'VALID 90 DAYS', 0, 0, 'R')
        
        # ===== EXECUTIVE SIGN-OFF =====
        pdf.set_y(100)
        pdf.set_font('Helvetica', 'B', 11)
        pdf.set_text_color(33, 37, 41)
        pdf.cell(0, 8, 'EXECUTIVE AUTHORIZATION', 0, 1, 'C')
        
        # Signature boxes
        sig_y = 115
        
        # Left signature
        pdf.set_xy(25, sig_y)
        pdf.set_draw_color(200, 200, 200)
        pdf.line(25, sig_y + 25, 90, sig_y + 25)
        pdf.set_font('Helvetica', '', 9)
        pdf.set_text_color(73, 80, 87)
        pdf.set_xy(25, sig_y + 27)
        pdf.cell(65, 5, 'Security Officer', 0, 1, 'C')
        pdf.set_x(25)
        pdf.cell(65, 5, 'Date: ________________', 0, 1, 'C')
        
        # Right signature
        pdf.set_xy(120, sig_y)
        pdf.line(120, sig_y + 25, 185, sig_y + 25)
        pdf.set_xy(120, sig_y + 27)
        pdf.cell(65, 5, 'IT Director', 0, 1, 'C')
        pdf.set_x(120)
        pdf.cell(65, 5, 'Date: ________________', 0, 1, 'C')
        
        # ===== DISCLAIMER =====
        pdf.set_y(160)
        pdf.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(108, 117, 125)
        
        disclaimer = (
            "DISCLAIMER: This security assessment provides a point-in-time evaluation of the "
            "system's security posture. Security is an ongoing process and this certification "
            "should be renewed periodically. The organization is responsible for maintaining "
            "security controls and addressing any identified vulnerabilities. This report is "
            "generated automatically by CIA-Guardian and should be reviewed by qualified "
            "security personnel."
        )
        
        pdf.multi_cell(0, 4, disclaimer, 0, 'J')
        
        # ===== FOOTER =====
        pdf.set_y(page_height - 20)
        pdf.set_font('Helvetica', '', 8)
        pdf.set_text_color(108, 117, 125)
        pdf.cell(0, 5, f'Generated by CIA-Guardian v{audit_data.get("tool_version", "1.0.0")}', 0, 1, 'C')
        pdf.cell(0, 5, f'Report ID: CG-{assessment_date.strftime("%Y%m%d%H%M%S")}-{hostname[:8].upper()}', 0, 1, 'C')
        
        # Save PDF
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        pdf.output(output_path)
        
        return output_path
