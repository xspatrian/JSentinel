"""
JSentinel Reporter Module
Generates beautiful HTML reports with charts and visualizations.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any
from collections import Counter

from jinja2 import Template

from core.analyzer import Finding


class HTMLReporter:
    """Generates interactive HTML reports with charts."""

    def __init__(self, template_path: str = "templates/report.html"):
        self.template_path = template_path
        self.template = self._load_template()

    def _load_template(self) -> Template:
        """Load or create HTML template."""
        if os.path.exists(self.template_path):
            with open(self.template_path, 'r', encoding='utf-8') as f:
                return Template(f.read())

        # Return default template
        return Template(self._get_default_template())

    def generate(self, findings: List[Finding], output_path: str = "output/report.html",
                 scan_metadata: Dict[str, Any] = None):
        """Generate HTML report."""

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Prepare data for charts
        chart_data = self._prepare_chart_data(findings)

        # Prepare findings data
        findings_data = [f.to_dict() for f in findings]

        # Sort by severity
        severity_order = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}
        findings_data.sort(key=lambda x: severity_order.get(x['severity'], 99))

        # Render template
        html = self.template.render(
            scan_metadata=scan_metadata or {},
            findings=findings_data,
            chart_data=chart_data,
            total_findings=len(findings),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            p1_count=sum(1 for f in findings if f.severity == 'P1'),
            p2_count=sum(1 for f in findings if f.severity == 'P2'),
            p3_count=sum(1 for f in findings if f.severity == 'P3'),
            p4_count=sum(1 for f in findings if f.severity == 'P4'),
            p5_count=sum(1 for f in findings if f.severity == 'P5'),
        )

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"\n[+] HTML report saved: {output_path}")
        return output_path

    def _prepare_chart_data(self, findings: List[Finding]) -> Dict[str, Any]:
        """Prepare data for charts."""

        # Severity distribution
        severity_counts = Counter(f.severity for f in findings)
        severity_data = {
            "labels": ['P1 (Critical)', 'P2 (High)', 'P3 (Medium)', 'P4 (Low)', 'P5 (Info)'],
            "data": [
                severity_counts.get('P1', 0),
                severity_counts.get('P2', 0),
                severity_counts.get('P3', 0),
                severity_counts.get('P4', 0),
                severity_counts.get('P5', 0),
            ],
            "colors": ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d']
        }

        # Category distribution (top 10)
        category_counts = Counter(f.category for f in findings)
        top_categories = category_counts.most_common(10)
        category_data = {
            "labels": [c[0] for c in top_categories],
            "data": [c[1] for c in top_categories],
        }

        # File distribution (top 10)
        file_counts = Counter(f.file_url for f in findings)
        top_files = file_counts.most_common(10)
        file_data = {
            "labels": [self._truncate_url(f[0], 40) for f in top_files],
            "data": [f[1] for f in top_files],
        }

        # AI confidence distribution
        confidence_ranges = {"High (0.8-1.0)": 0, "Medium (0.5-0.8)": 0, "Low (0.0-0.5)": 0, "Not Analyzed": 0}
        for f in findings:
            if f.ai_confidence >= 0.8:
                confidence_ranges["High (0.8-1.0)"] += 1
            elif f.ai_confidence >= 0.5:
                confidence_ranges["Medium (0.5-0.8)"] += 1
            elif f.ai_confidence > 0:
                confidence_ranges["Low (0.0-0.5)"] += 1
            else:
                confidence_ranges["Not Analyzed"] += 1

        confidence_data = {
            "labels": list(confidence_ranges.keys()),
            "data": list(confidence_ranges.values()),
            "colors": ['#28a745', '#ffc107', '#dc3545', '#6c757d']
        }

        return {
            "severity": severity_data,
            "category": category_data,
            "files": file_data,
            "confidence": confidence_data,
        }

    def _truncate_url(self, url: str, max_len: int) -> str:
        """Truncate URL for display."""
        if len(url) <= max_len:
            return url
        return url[:max_len//2] + "..." + url[-max_len//2:]

    def _get_default_template(self) -> str:
        """Return default HTML template with embedded charts."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JSentinel Security Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0f172a;
            color: #e2e8f0;
            line-height: 1.6;
        }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            border: 1px solid #334155;
        }
        header h1 {
            font-size: 2.5em;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }
        header .subtitle { color: #94a3b8; font-size: 1.1em; }
        header .meta { margin-top: 15px; color: #64748b; font-size: 0.9em; }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #1e293b;
            padding: 25px;
            border-radius: 12px;
            border: 1px solid #334155;
            text-align: center;
            transition: transform 0.2s;
        }
        .stat-card:hover { transform: translateY(-3px); }
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .stat-card .label { color: #94a3b8; font-size: 0.9em; text-transform: uppercase; }
        .stat-card.p1 { border-left: 4px solid #dc3545; }
        .stat-card.p1 .number { color: #dc3545; }
        .stat-card.p2 { border-left: 4px solid #fd7e14; }
        .stat-card.p2 .number { color: #fd7e14; }
        .stat-card.p3 { border-left: 4px solid #ffc107; }
        .stat-card.p3 .number { color: #ffc107; }
        .stat-card.p4 { border-left: 4px solid #17a2b8; }
        .stat-card.p4 .number { color: #17a2b8; }
        .stat-card.p5 { border-left: 4px solid #6c757d; }
        .stat-card.p5 .number { color: #6c757d; }
        .stat-card.total { border-left: 4px solid #38bdf8; }
        .stat-card.total .number { color: #38bdf8; }

        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .chart-card {
            background: #1e293b;
            padding: 25px;
            border-radius: 12px;
            border: 1px solid #334155;
        }
        .chart-card h3 {
            color: #e2e8f0;
            margin-bottom: 15px;
            font-size: 1.1em;
        }
        .chart-container { position: relative; height: 300px; }

        .findings-section { margin-top: 30px; }
        .findings-section h2 {
            color: #e2e8f0;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #334155;
        }

        .finding-card {
            background: #1e293b;
            border-radius: 12px;
            border: 1px solid #334155;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .finding-header {
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }
        .finding-header.p1 { background: rgba(220, 53, 69, 0.15); border-left: 4px solid #dc3545; }
        .finding-header.p2 { background: rgba(253, 126, 20, 0.15); border-left: 4px solid #fd7e14; }
        .finding-header.p3 { background: rgba(255, 193, 7, 0.15); border-left: 4px solid #ffc107; }
        .finding-header.p4 { background: rgba(23, 162, 184, 0.15); border-left: 4px solid #17a2b8; }
        .finding-header.p5 { background: rgba(108, 117, 125, 0.15); border-left: 4px solid #6c757d; }

        .finding-title { font-weight: 600; color: #e2e8f0; }
        .finding-meta { display: flex; gap: 15px; align-items: center; }
        .badge {
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge.p1 { background: #dc3545; color: white; }
        .badge.p2 { background: #fd7e14; color: white; }
        .badge.p3 { background: #ffc107; color: #000; }
        .badge.p4 { background: #17a2b8; color: white; }
        .badge.p5 { background: #6c757d; color: white; }
        .badge.category { background: #334155; color: #94a3b8; }

        .finding-body {
            padding: 20px;
            display: none;
            border-top: 1px solid #334155;
        }
        .finding-body.active { display: block; }

        .evidence-box {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            color: #a5b4fc;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .ai-analysis {
            background: rgba(56, 189, 248, 0.1);
            border: 1px solid rgba(56, 189, 248, 0.3);
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }
        .ai-analysis h4 { color: #38bdf8; margin-bottom: 8px; }
        .ai-analysis p { color: #cbd5e1; font-size: 0.9em; }
        .confidence-bar {
            height: 6px;
            background: #334155;
            border-radius: 3px;
            margin-top: 8px;
            overflow: hidden;
        }
        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #38bdf8, #818cf8);
            border-radius: 3px;
            transition: width 0.5s ease;
        }

        .recommendation-box {
            background: rgba(34, 197, 94, 0.1);
            border: 1px solid rgba(34, 197, 94, 0.3);
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
        }
        .recommendation-box h4 { color: #22c55e; margin-bottom: 8px; }
        .recommendation-box pre {
            background: #0f172a;
            padding: 10px;
            border-radius: 6px;
            overflow-x: auto;
            color: #a5b4fc;
            font-size: 0.85em;
        }

        .filter-bar {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .filter-btn {
            padding: 8px 16px;
            border: 1px solid #334155;
            background: #1e293b;
            color: #94a3b8;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }
        .filter-btn:hover, .filter-btn.active {
            background: #334155;
            color: #e2e8f0;
        }

        footer {
            text-align: center;
            padding: 30px;
            color: #64748b;
            border-top: 1px solid #334155;
            margin-top: 40px;
        }

        @media (max-width: 768px) {
            .charts-grid { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>JSentinel Security Report</h1>
            <p class="subtitle">JavaScript Security Reconnaissance & Bug Bounty Intelligence</p>
            <p class="meta">
                Generated: {{ generated_at }} | 
                Total Findings: {{ total_findings }} | 
                Files Analyzed: {{ scan_metadata.get('files_analyzed', 'N/A') }}
            </p>
        </header>

        <div class="stats-grid">
            <div class="stat-card total">
                <div class="number">{{ total_findings }}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="stat-card p1">
                <div class="number">{{ p1_count }}</div>
                <div class="label">P1 Critical</div>
            </div>
            <div class="stat-card p2">
                <div class="number">{{ p2_count }}</div>
                <div class="label">P2 High</div>
            </div>
            <div class="stat-card p3">
                <div class="number">{{ p3_count }}</div>
                <div class="label">P3 Medium</div>
            </div>
            <div class="stat-card p4">
                <div class="number">{{ p4_count }}</div>
                <div class="label">P4 Low</div>
            </div>
            <div class="stat-card p5">
                <div class="number">{{ p5_count }}</div>
                <div class="label">P5 Info</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-card">
                <h3>Severity Distribution</h3>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>Top Categories</h3>
                <div class="chart-container">
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>Findings per File</h3>
                <div class="chart-container">
                    <canvas id="fileChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>AI Confidence</h3>
                <div class="chart-container">
                    <canvas id="confidenceChart"></canvas>
                </div>
            </div>
        </div>

        <div class="findings-section">
            <h2>Detailed Findings</h2>

            <div class="filter-bar">
                <button class="filter-btn active" onclick="filterFindings('all')">All</button>
                <button class="filter-btn" onclick="filterFindings('P1')">P1 Critical</button>
                <button class="filter-btn" onclick="filterFindings('P2')">P2 High</button>
                <button class="filter-btn" onclick="filterFindings('P3')">P3 Medium</button>
                <button class="filter-btn" onclick="filterFindings('P4')">P4 Low</button>
                <button class="filter-btn" onclick="filterFindings('P5')">P5 Info</button>
            </div>

            {% for finding in findings %}
            <div class="finding-card" data-severity="{{ finding.severity }}">
                <div class="finding-header {{ finding.severity.lower() }}" onclick="toggleFinding(this)">
                    <span class="finding-title">{{ finding.description }}</span>
                    <div class="finding-meta">
                        <span class="badge category">{{ finding.category }}</span>
                        <span class="badge {{ finding.severity.lower() }}">{{ finding.severity }}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <p><strong>File:</strong> <a href="{{ finding.file_url }}" target="_blank" style="color:#38bdf8;">{{ finding.file_url }}</a></p>
                    <p><strong>Line:</strong> {{ finding.line_number }} | <strong>Pattern:</strong> {{ finding.pattern_name }}</p>

                    <h4 style="margin-top:15px;color:#94a3b8;">Evidence</h4>
                    <div class="evidence-box">{{ finding.evidence }}</div>

                    {% if finding.ai_analysis %}
                    <div class="ai-analysis">
                        <h4>AI Analysis (Confidence: {{ "%.0f"|format(finding.ai_confidence * 100) }}%)</h4>
                        <p>{{ finding.ai_analysis }}</p>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: {{ finding.ai_confidence * 100 }}%"></div>
                        </div>
                        <p style="margin-top:10px;"><strong>Exploitability:</strong> {{ finding.exploitability }}/10 | <strong>Impact:</strong> {{ finding.impact }}/10</p>
                    </div>
                    {% endif %}

                    {% if finding.ai_recommendation %}
                    <div class="recommendation-box">
                        <h4>Exploitation Guide</h4>
                        <pre>{{ finding.ai_recommendation }}</pre>
                    </div>
                    {% endif %}

                    {% if finding.historical_reference %}
                    <p style="margin-top:10px;color:#94a3b8;"><strong>Historical Reference:</strong> {{ finding.historical_reference }}</p>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </div>

        <footer>
            <p>Generated by JSentinel - JavaScript Security Reconnaissance Agent</p>
            <p>Powered by Gemini AI + 180+ validated bug bounty patterns</p>
        </footer>
    </div>

    <script>
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {
            type: 'doughnut',
            data: {
                labels: {{ chart_data.severity.labels | tojson }},
                datasets: [{
                    data: {{ chart_data.severity.data | tojson }},
                    backgroundColor: {{ chart_data.severity.colors | tojson }},
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }
            }
        });

        // Category Chart
        new Chart(document.getElementById('categoryChart'), {
            type: 'bar',
            data: {
                labels: {{ chart_data.category.labels | tojson }},
                datasets: [{
                    label: 'Findings',
                    data: {{ chart_data.category.data | tojson }},
                    backgroundColor: '#38bdf8',
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
                    x: { ticks: { color: '#94a3b8' }, grid: { display: false } }
                }
            }
        });

        // File Chart
        new Chart(document.getElementById('fileChart'), {
            type: 'bar',
            data: {
                labels: {{ chart_data.files.labels | tojson }},
                datasets: [{
                    label: 'Findings',
                    data: {{ chart_data.files.data | tojson }},
                    backgroundColor: '#818cf8',
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { color: '#94a3b8' }, grid: { color: '#334155' } },
                    x: { ticks: { color: '#94a3b8' }, grid: { display: false } }
                }
            }
        });

        // Confidence Chart
        new Chart(document.getElementById('confidenceChart'), {
            type: 'pie',
            data: {
                labels: {{ chart_data.confidence.labels | tojson }},
                datasets: [{
                    data: {{ chart_data.confidence.data | tojson }},
                    backgroundColor: {{ chart_data.confidence.colors | tojson }},
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }
            }
        });

        // Toggle finding details
        function toggleFinding(header) {
            const body = header.nextElementSibling;
            body.classList.toggle('active');
        }

        // Filter findings
        function filterFindings(severity) {
            const cards = document.querySelectorAll('.finding-card');
            const buttons = document.querySelectorAll('.filter-btn');

            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            cards.forEach(card => {
                if (severity === 'all' || card.dataset.severity === severity) {
                    card.style.display = 'block';
                } else {
                    card.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>
"""


class JSONReporter:
    """Generates JSON report for programmatic consumption."""

    def generate(self, findings: List[Finding], output_path: str = "output/report.json",
                 scan_metadata: Dict[str, Any] = None):
        """Generate JSON report."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        data = {
            "scan_info": {
                "tool": "JSentinel",
                "version": "1.0",
                "timestamp": datetime.now().isoformat(),
                **(scan_metadata or {})
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": {},
                "by_category": {}
            },
            "findings": [f.to_dict() for f in findings]
        }

        for f in findings:
            data["summary"]["by_severity"][f.severity] = data["summary"]["by_severity"].get(f.severity, 0) + 1
            data["summary"]["by_category"][f.category] = data["summary"]["by_category"].get(f.category, 0) + 1

        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

        print(f"[+] JSON report saved: {output_path}")
        return output_path
