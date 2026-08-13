"""Reporter package for HTML and PDF generation."""

from .html_dashboard import HTMLDashboard
from .pdf_certificate import PDFCertificate

__all__ = ['HTMLDashboard', 'PDFCertificate']
