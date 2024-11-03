# modules/report/templates/markdown_report.md
# NAST Security Analysis Report
Generated: {{ timestamp }}

## Executive Summary
{{ summary }}

## Key Findings
{% for finding in findings %}
- {{ finding }}
{% endfor %}

## Vulnerabilities
{% for vuln in vulnerabilities %}
### {{ vuln.name }}
- **Severity:** {{ vuln.severity }}
- **Description:** {{ vuln.description }}
{% if vuln.remediation %}
- **Remediation:** {{ vuln.remediation }}
{% endif %}

{% endfor %}

## Network Analysis
{% for host in hosts %}
### Host: {{ host.ip }}
- **Open Ports:** {{ host.ports | join(', ') }}
- **Services:** {{ host.services | join(', ') }}
- **Risk Level:** {{ host.risk }}

{% endfor %}

## Recommendations
{% for rec in recommendations %}
### {{ rec.title }}
{{ rec.description }}

Steps:
{% for step in rec.steps %}
1. {{ step }}
{% endfor %}

{% endfor %}

## Additional Details
{{ details }}
