"""
HTML Dashboard Reporter
Generates responsive Bootstrap 5 HTML reports with dark/light theme toggle.
"""

import os
from datetime import datetime
from typing import Dict, Any


# Embedded HTML template (no external file dependency)
HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CIA-Guardian Security Report</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --cia-primary: #0d6efd;
            --cia-success: #198754;
            --cia-danger: #dc3545;
            --cia-warning: #ffc107;
            --cia-info: #0dcaf0;
        }
        
        .score-circle {
            width: 150px;
            height: 150px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            font-weight: bold;
            margin: 0 auto;
            border: 8px solid;
        }
        
        .score-a { border-color: var(--cia-success); color: var(--cia-success); }
        .score-b { border-color: #20c997; color: #20c997; }
        .score-c { border-color: var(--cia-warning); color: var(--cia-warning); }
        .score-d { border-color: #fd7e14; color: #fd7e14; }
        .score-f { border-color: var(--cia-danger); color: var(--cia-danger); }
        
        .metric-card {
            transition: transform 0.2s;
        }
        
        .metric-card:hover {
            transform: translateY(-5px);
        }
        
        .risk-badge {
            font-size: 0.75rem;
            padding: 0.25rem 0.5rem;
        }
        
        .status-compliant { color: var(--cia-success); }
        .status-remediated { color: #20c997; }
        .status-non-compliant { color: var(--cia-danger); }
        .status-error { color: var(--cia-warning); }
        .status-timeout { color: #fd7e14; }  /* v2.1: Orange for TIMEOUT */
        .status-na { color: #6c757d; }
        
        .progress-bar-confidentiality { background-color: #6f42c1; }
        .progress-bar-integrity { background-color: #0d6efd; }
        .progress-bar-availability { background-color: #20c997; }
        
        .control-row:hover {
            background-color: rgba(0,0,0,0.05);
        }
        
        [data-bs-theme="dark"] .control-row:hover {
            background-color: rgba(255,255,255,0.05);
        }
        
        .theme-toggle {
            cursor: pointer;
            font-size: 1.5rem;
        }
        
        .header-banner {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
        }
        
        .evidence-text {
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
            background-color: rgba(0,0,0,0.05);
            padding: 0.5rem;
            border-radius: 4px;
            max-height: 100px;
            overflow-y: auto;
        }
        
        [data-bs-theme="dark"] .evidence-text {
            background-color: rgba(255,255,255,0.1);
        }
        
        .export-btn {
            margin-right: 0.5rem;
        }
        
        @media print {
            .no-print { display: none !important; }
            .header-banner { background: #333 !important; -webkit-print-color-adjust: exact; }
        }
    </style>
</head>
<body>
    <!-- Header Banner -->
    <div class="header-banner no-print">
        <div class="container">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <h1 class="mb-0"><i class="bi bi-shield-check me-2"></i>CIA-Guardian</h1>
                    <p class="mb-0 opacity-75">Windows Security Hardening Report</p>
                </div>
                <div class="d-flex align-items-center">
                    <span class="theme-toggle me-3" onclick="toggleTheme()" title="Toggle Theme">
                        <i class="bi bi-sun-fill" id="theme-icon"></i>
                    </span>
                    <div class="dropdown">
                        <button class="btn btn-light dropdown-toggle" type="button" data-bs-toggle="dropdown">
                            <i class="bi bi-download me-1"></i>Export
                        </button>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="window.print()"><i class="bi bi-printer me-2"></i>Print / PDF</a></li>
                            <li><a class="dropdown-item" href="#" onclick="exportJSON()"><i class="bi bi-filetype-json me-2"></i>JSON</a></li>
                            <li><a class="dropdown-item" href="#" onclick="exportCSV()"><i class="bi bi-filetype-csv me-2"></i>CSV</a></li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="container py-4">
        <!-- System Info Bar -->
        <div class="card mb-4">
            <div class="card-body py-2">
                <div class="row text-center text-md-start">
                    <div class="col-md-3">
                        <small class="text-muted">Hostname</small>
                        <div class="fw-bold">{{ system_info.hostname }}</div>
                    </div>
                    <div class="col-md-3">
                        <small class="text-muted">Operating System</small>
                        <div class="fw-bold">{{ system_info.os_name }} {{ system_info.os_version }}</div>
                    </div>
                    <div class="col-md-3">
                        <small class="text-muted">User</small>
                        <div class="fw-bold">{{ system_info.domain }}\\{{ system_info.username }}</div>
                    </div>
                    <div class="col-md-3">
                        <small class="text-muted">Report Generated</small>
                        <div class="fw-bold">{{ generated_at }}</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="row mb-4">
            <!-- Security Score -->
            <div class="col-lg-4 mb-3">
                <div class="card h-100 metric-card">
                    <div class="card-body text-center">
                        <h5 class="card-title">Security Score</h5>
                        <div class="score-circle score-{{ summary.letter_grade|lower }}">
                            <span>{{ summary.letter_grade }}</span>
                            <small style="font-size: 0.8rem;">{{ summary.security_score }}%</small>
                        </div>
                        <p class="text-muted mt-2 mb-0">Overall security posture</p>
                    </div>
                </div>
            </div>
            
            <!-- Compliance Stats -->
            <div class="col-lg-4 mb-3">
                <div class="card h-100 metric-card">
                    <div class="card-body">
                        <h5 class="card-title text-center">Compliance Status</h5>
                        <div class="progress mb-3" style="height: 25px;">
                            <div class="progress-bar bg-success" style="width: {{ (summary.compliant / summary.total_controls * 100)|round }}%">
                                {{ summary.compliant }} Compliant
                            </div>
                            {% if summary.remediated > 0 %}
                            <div class="progress-bar" style="width: {{ (summary.remediated / summary.total_controls * 100)|round }}%; background-color: #20c997;">
                                {{ summary.remediated }} Fixed
                            </div>
                            {% endif %}
                            {% if summary.non_compliant > 0 %}
                            <div class="progress-bar bg-danger" style="width: {{ (summary.non_compliant / summary.total_controls * 100)|round }}%">
                                {{ summary.non_compliant }} Fail
                            </div>
                            {% endif %}
                        </div>
                        <div class="row text-center small">
                            <div class="col">
                                <div class="text-success fw-bold fs-4">{{ summary.compliant }}</div>
                                <div class="text-muted">Compliant</div>
                            </div>
                            <div class="col">
                                <div class="fw-bold fs-4" style="color: #20c997;">{{ summary.remediated }}</div>
                                <div class="text-muted">Remediated</div>
                            </div>
                            <div class="col">
                                <div class="text-danger fw-bold fs-4">{{ summary.non_compliant }}</div>
                                <div class="text-muted">Non-Compliant</div>
                            </div>
                            <div class="col">
                                <div class="fw-bold fs-4" style="color: #fd7e14;">{{ summary.timeouts|default(0) }}</div>
                                <div class="text-muted">Timeouts</div>
                            </div>
                            <div class="col">
                                <div class="text-warning fw-bold fs-4">{{ summary.errors }}</div>
                                <div class="text-muted">Errors</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Category Breakdown -->
            <div class="col-lg-4 mb-3">
                <div class="card h-100 metric-card">
                    <div class="card-body">
                        <h5 class="card-title text-center">CIA Triad Scores</h5>
                        {% for category, score in summary.category_scores.items() %}
                        <div class="mb-3">
                            <div class="d-flex justify-content-between mb-1">
                                <span>{{ category }}</span>
                                <span class="fw-bold">{{ score }}%</span>
                            </div>
                            <div class="progress" style="height: 10px;">
                                <div class="progress-bar progress-bar-{{ category|lower }}" style="width: {{ score }}%"></div>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                </div>
            </div>
        </div>

        <!-- Risk Summary -->
        {% if summary.risk_summary %}
        <div class="card mb-4">
            <div class="card-header">
                <h5 class="mb-0"><i class="bi bi-exclamation-triangle me-2"></i>Risk Summary</h5>
            </div>
            <div class="card-body">
                <div class="row">
                    {% for risk, count in summary.risk_summary.items() %}
                    <div class="col-md-3 col-6 mb-2">
                        <div class="d-flex align-items-center">
                            <span class="badge risk-badge me-2 
                                {% if risk == 'Critical' %}bg-danger
                                {% elif risk == 'High' %}bg-warning text-dark
                                {% elif risk == 'Medium' %}bg-info text-dark
                                {% else %}bg-secondary{% endif %}">
                                {{ risk }}
                            </span>
                            <span class="fw-bold">{{ count }} issue{% if count != 1 %}s{% endif %}</span>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        {% endif %}

        <!-- Detailed Results -->
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h5 class="mb-0"><i class="bi bi-list-check me-2"></i>Control Details</h5>
                <div class="btn-group no-print" role="group">
                    <button type="button" class="btn btn-outline-secondary btn-sm active" onclick="filterResults('all')">All</button>
                    <button type="button" class="btn btn-outline-danger btn-sm" onclick="filterResults('fail')">Failed</button>
                    <button type="button" class="btn btn-outline-success btn-sm" onclick="filterResults('pass')">Passed</button>
                </div>
            </div>
            <div class="card-body p-0">
                <div class="table-responsive">
                    <table class="table table-hover mb-0" id="results-table">
                        <thead>
                            <tr>
                                <th style="width: 100px;">Control ID</th>
                                <th>Name</th>
                                <th style="width: 120px;">Category</th>
                                <th style="width: 80px;">Risk</th>
                                <th style="width: 120px;">Status</th>
                                <th>Evidence</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for result in results %}
                            <tr class="control-row" data-status="{{ result.status }}">
                                <td><code>{{ result.control_id }}</code></td>
                                <td>
                                    <strong>{{ result.name }}</strong>
                                    {% if result.details %}
                                    <br><small class="text-muted">{{ result.details }}</small>
                                    {% endif %}
                                </td>
                                <td>
                                    <span class="badge 
                                        {% if result.category == 'Confidentiality' %}bg-purple text-white" style="background-color: #6f42c1;
                                        {% elif result.category == 'Integrity' %}bg-primary
                                        {% else %}bg-success{% endif %}">
                                        {{ result.category }}
                                    </span>
                                </td>
                                <td>
                                    <span class="badge risk-badge
                                        {% if result.risk_level == 'Critical' %}bg-danger
                                        {% elif result.risk_level == 'High' %}bg-warning text-dark
                                        {% elif result.risk_level == 'Medium' %}bg-info text-dark
                                        {% else %}bg-secondary{% endif %}">
                                        {{ result.risk_level }}
                                    </span>
                                </td>
                                <td>
                                    {% if result.status == 'Compliant' %}
                                    <span class="status-compliant"><i class="bi bi-check-circle-fill me-1"></i>Compliant</span>
                                    {% elif result.status == 'Remediated' %}
                                    <span class="status-remediated"><i class="bi bi-arrow-repeat me-1"></i>Remediated</span>
                                    {% elif result.status == 'Non-Compliant' %}
                                    <span class="status-non-compliant"><i class="bi bi-x-circle-fill me-1"></i>Non-Compliant</span>
                                    {% elif result.status == 'Timeout' %}
                                    <span class="status-timeout"><i class="bi bi-clock-history me-1"></i>Timeout</span>
                                    {% elif result.status == 'Error' %}
                                    <span class="status-error"><i class="bi bi-exclamation-triangle-fill me-1"></i>Error</span>
                                    {% else %}
                                    <span class="status-na"><i class="bi bi-dash-circle me-1"></i>N/A</span>
                                    {% endif %}
                                </td>
                                <td>
                                    <div class="evidence-text">{{ result.evidence }}</div>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="text-center mt-4 text-muted small">
            <p>Generated by CIA-Guardian v{{ tool_version }} | Report valid for 90 days from generation date</p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Theme toggle
        function toggleTheme() {
            const html = document.documentElement;
            const icon = document.getElementById('theme-icon');
            if (html.getAttribute('data-bs-theme') === 'dark') {
                html.setAttribute('data-bs-theme', 'light');
                icon.className = 'bi bi-sun-fill';
            } else {
                html.setAttribute('data-bs-theme', 'dark');
                icon.className = 'bi bi-moon-fill';
            }
        }

        // Filter results
        function filterResults(type) {
            const rows = document.querySelectorAll('.control-row');
            rows.forEach(row => {
                const status = row.getAttribute('data-status');
                if (type === 'all') {
                    row.style.display = '';
                } else if (type === 'fail') {
                    row.style.display = (status === 'Non-Compliant' || status === 'Error' || status === 'Timeout') ? '' : 'none';
                } else if (type === 'pass') {
                    row.style.display = (status === 'Compliant' || status === 'Remediated') ? '' : 'none';
                }
            });
        }

        // Export functions
        const auditData = {{ audit_data_json|safe }};
        
        function exportJSON() {
            const blob = new Blob([JSON.stringify(auditData, null, 2)], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'cia_guardian_report.json';
            a.click();
        }
        
        function exportCSV() {
            let csv = 'Control ID,Name,Category,Risk Level,Status,Evidence\\n';
            auditData.results.forEach(r => {
                csv += `"${r.control_id}","${r.name}","${r.category}","${r.risk_level}","${r.status}","${r.evidence}"\\n`;
            });
            const blob = new Blob([csv], {type: 'text/csv'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'cia_guardian_report.csv';
            a.click();
        }
    </script>
</body>
</html>'''


class HTMLDashboard:
    """
    Generates HTML dashboard reports using Jinja2 templating.
    Features Bootstrap 5 responsive design with dark/light theme toggle.
    """
    
    def __init__(self):
        """Initialize the HTML Dashboard generator."""
        try:
            from jinja2 import Environment, BaseLoader
            self.jinja_env = Environment(loader=BaseLoader())
            self.template = self.jinja_env.from_string(HTML_TEMPLATE)
        except ImportError:
            raise ImportError("Jinja2 is required for HTML report generation. Install with: pip install jinja2")
    
    def generate(self, audit_data: Dict[str, Any], output_path: str) -> str:
        """
        Generate HTML dashboard report.
        
        Args:
            audit_data: Dictionary containing audit results
            output_path: Path to write the HTML file
            
        Returns:
            Path to the generated HTML file
        """
        import json
        
        # Format timestamp for display
        generated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Render the template
        html_content = self.template.render(
            system_info=audit_data.get('system_info', {}),
            summary=audit_data.get('summary', {}),
            results=audit_data.get('results', []),
            generated_at=generated_at,
            tool_version=audit_data.get('tool_version', '1.0.0'),
            audit_data_json=json.dumps(audit_data, default=str)
        )
        
        # Write to file
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return output_path
