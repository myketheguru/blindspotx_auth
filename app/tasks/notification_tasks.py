# app/tasks/notification_tasks.py
"""
Celery Tasks for Notifications
-----------------------------
Handle sending alerts and notifications for drift detection events.
"""

import logging
import json
from datetime import datetime
from typing import List, Dict, Any
import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from app.core.celery_app import celery_app
from app.core.config import settings

logger = logging.getLogger(__name__)


@celery_app.task(bind=True, max_retries=3)
def send_webhook_alert(self, reports: List[Dict[str, Any]]):
    """
    Send webhook notifications for drift alerts.
    """
    if not settings.DRIFT_ALERT_WEBHOOK:
        logger.info("No webhook URL configured, skipping webhook alert")
        return
    
    try:
        payload = {
            "event": "drift_detected",
            "timestamp": datetime.utcnow().isoformat(),
            "reports": reports,
            "summary": {
                "total_reports": len(reports),
                "critical_count": len([r for r in reports if r.get("severity") == "critical"]),
                "high_count": len([r for r in reports if r.get("severity") == "high"])
            }
        }
        
        # Send webhook
        import requests
        response = requests.post(
            settings.DRIFT_ALERT_WEBHOOK,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        if response.status_code == 200:
            logger.info(f"Webhook alert sent successfully for {len(reports)} reports")
        else:
            logger.warning(f"Webhook alert failed with status {response.status_code}: {response.text}")
            self.retry(countdown=60 * (self.request.retries + 1))
            
    except Exception as e:
        logger.error(f"Error sending webhook alert: {str(e)}")
        self.retry(countdown=60 * (self.request.retries + 1))


@celery_app.task(bind=True, max_retries=3)
def send_email_alert(self, reports: List[Dict[str, Any]]):
    """
    Send email notifications for drift alerts.
    """
    if not settings.DRIFT_ALERT_EMAIL:
        logger.info("No email address configured, skipping email alert")
        return
    
    try:
        # Create email content
        subject = f"Drift Detection Alert - {len(reports)} Changes Detected"
        
        # Create HTML email body
        html_body = create_alert_email_html(reports)
        text_body = create_alert_email_text(reports)
        
        # Send email using configured SMTP settings
        send_html_email(
            to_email=settings.DRIFT_ALERT_EMAIL,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )
        
        logger.info(f"Email alert sent successfully for {len(reports)} reports")
        
    except Exception as e:
        logger.error(f"Error sending email alert: {str(e)}")
        self.retry(countdown=60 * (self.request.retries + 1))


@celery_app.task(bind=True, max_retries=2)
def send_analytics_email(self, analytics: Dict[str, Any]):
    """
    Send periodic analytics report via email.
    """
    if not settings.DRIFT_ALERT_EMAIL:
        logger.info("No email address configured, skipping analytics email")
        return
    
    try:
        subject = f"Drift Detection Analytics Report - {analytics.get('total_reports', 0)} Reports"
        
        html_body = create_analytics_email_html(analytics)
        text_body = create_analytics_email_text(analytics)
        
        send_html_email(
            to_email=settings.DRIFT_ALERT_EMAIL,
            subject=subject,
            html_body=html_body,
            text_body=text_body
        )
        
        logger.info("Analytics email sent successfully")
        
    except Exception as e:
        logger.error(f"Error sending analytics email: {str(e)}")
        self.retry(countdown=300)


def create_alert_email_html(reports: List[Dict[str, Any]]) -> str:
    """Create HTML email body for drift alerts."""
    critical_reports = [r for r in reports if r.get("severity") == "critical"]
    high_reports = [r for r in reports if r.get("severity") == "high"]
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #f44336; color: white; padding: 15px; border-radius: 5px; }}
            .critical {{ background-color: #ffebee; border-left: 4px solid #f44336; padding: 10px; margin: 10px 0; }}
            .high {{ background-color: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 10px 0; }}
            .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2>🚨 Drift Detection Alert</h2>
            <p>Detected {len(reports)} configuration changes requiring attention</p>
        </div>
        
        <div class="summary">
            <h3>Summary</h3>
            <ul>
                <li><strong>Critical Changes:</strong> {len(critical_reports)}</li>
                <li><strong>High Severity Changes:</strong> {len(high_reports)}</li>
                <li><strong>Total Changes:</strong> {len(reports)}</li>
                <li><strong>Detection Time:</strong> {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</li>
            </ul>
        </div>
        
        {_render_reports_section("Critical Changes", critical_reports, "critical")}
        {_render_reports_section("High Severity Changes", high_reports, "high")}
        
        <div style="margin-top: 20px; padding: 15px; background-color: #e3f2fd; border-radius: 5px;">
            <h4>Next Steps</h4>
            <ol>
                <li>Review the changes in your drift detection dashboard</li>
                <li>Verify that critical changes were authorized</li>
                <li>Update security policies if needed</li>
                <li>Mark reviewed changes as acknowledged</li>
            </ol>
        </div>
    </body>
    </html>
    """
    return html


def _render_reports_section(title: str, reports: List[Dict], css_class: str) -> str:
    """Helper function to render a section of reports."""
    if not reports:
        return ""
    
    rows = ""
    for report in reports:
        rows += f"""
        <tr>
            <td>{report.get('category', 'Unknown')}</td>
            <td>{report.get('change_type', 'Unknown')}</td>
            <td>{report.get('timestamp', 'Unknown')}</td>
            <td>{report.get('security_impact', 'Unknown')}</td>
        </tr>
        """
    
    return f"""
    <div class="{css_class}">
        <h3>{title}</h3>
        <table>
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Change Type</th>
                    <th>Timestamp</th>
                    <th>Security Impact</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </div>
    """


def create_alert_email_text(reports: List[Dict[str, Any]]) -> str:
    """Create plain text email body for drift alerts."""
    critical_count = len([r for r in reports if r.get("severity") == "critical"])
    high_count = len([r for r in reports if r.get("severity") == "high"])
    
    text = f"""
DRIFT DETECTION ALERT

Detected {len(reports)} configuration changes requiring attention.

SUMMARY:
- Critical Changes: {critical_count}
- High Severity Changes: {high_count}
- Total Changes: {len(reports)}
- Detection Time: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC

CHANGES DETECTED:
"""
    
    for i, report in enumerate(reports, 1):
        text += f"""
{i}. Category: {report.get('category', 'Unknown')}
   Change Type: {report.get('change_type', 'Unknown')}
   Severity: {report.get('severity', 'Unknown')}
   Timestamp: {report.get('timestamp', 'Unknown')}
   Security Impact: {report.get('security_impact', 'Unknown')}
"""
    
    text += """
NEXT STEPS:
1. Review the changes in your drift detection dashboard
2. Verify that critical changes were authorized
3. Update security policies if needed
4. Mark reviewed changes as acknowledged

This is an automated alert from your drift detection system.
"""
    return text


def create_analytics_email_html(analytics: Dict[str, Any]) -> str:
    """Create HTML email body for analytics report."""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #2196f3; color: white; padding: 15px; border-radius: 5px; }}
            .metric-card {{ background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px; padding: 15px; margin: 10px 0; }}
            .metric-value {{ font-size: 24px; font-weight: bold; color: #2196f3; }}
            .metric-label {{ color: #6c757d; }}
            .insights {{ background-color: #fff3cd; border: 1px solid #ffeaa7; border-radius: 5px; padding: 15px; margin: 15px 0; }}
            table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2>📊 Drift Detection Analytics Report</h2>
            <p>30-day configuration change analysis</p>
        </div>
        
        <div style="display: flex; flex-wrap: wrap; gap: 15px; margin: 20px 0;">
            <div class="metric-card">
                <div class="metric-value">{analytics.get('total_reports', 0)}</div>
                <div class="metric-label">Total Changes</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{analytics.get('unresolved_critical_count', 0)}</div>
                <div class="metric-label">Unresolved Critical</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{analytics.get('security_related_changes', 0)}</div>
                <div class="metric-label">Security Changes</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{analytics.get('avg_daily_changes', 0):.1f}</div>
                <div class="metric-label">Avg Daily Changes</div>
            </div>
        </div>
        
        {_render_analytics_insights(analytics.get('insights', []))}
        {_render_category_breakdown(analytics.get('reports_by_category', {}))}
        {_render_severity_breakdown(analytics.get('reports_by_severity', {}))}
        
    </body>
    </html>
    """
    return html


def _render_analytics_insights(insights: List[Dict]) -> str:
    """Render insights section for analytics email."""
    if not insights:
        return ""
    
    insights_html = """
    <div class="insights">
        <h3>🔍 Key Insights</h3>
        <ul>
    """
    
    for insight in insights:
        severity_color = {"high": "#f44336", "medium": "#ff9800", "low": "#4caf50"}.get(
            insight.get("severity", "low"), "#6c757d"
        )
        insights_html += f"""
        <li style="margin: 10px 0;">
            <strong style="color: {severity_color};">{insight.get('type', 'Unknown').replace('_', ' ').title()}:</strong>
            {insight.get('message', 'No message')}
            <br><em style="color: #6c757d;">Recommendation: {insight.get('recommendation', 'No recommendation')}</em>
        </li>
        """
    
    insights_html += "</ul></div>"
    return insights_html


def _render_category_breakdown(categories: Dict[str, int]) -> str:
    """Render category breakdown table."""
    if not categories:
        return ""
    
    rows = ""
    for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
        rows += f"<tr><td>{category}</td><td>{count}</td></tr>"
    
    return f"""
    <h3>Changes by Category</h3>
    <table>
        <thead>
            <tr><th>Category</th><th>Count</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
    """


def _render_severity_breakdown(severities: Dict[str, int]) -> str:
    """Render severity breakdown table."""
    if not severities:
        return ""
    
    rows = ""
    severity_order = ["critical", "high", "medium", "low", "info"]
    for severity in severity_order:
        if severity in severities:
            count = severities[severity]
            color = {"critical": "#f44336", "high": "#ff9800", "medium": "#2196f3", "low": "#4caf50", "info": "#6c757d"}.get(severity, "#6c757d")
            rows += f'<tr><td style="color: {color}; font-weight: bold;">{severity.title()}</td><td>{count}</td></tr>'
    
    return f"""
    <h3>Changes by Severity</h3>
    <table>
        <thead>
            <tr><th>Severity</th><th>Count</th></tr>
        </thead>
        <tbody>{rows}</tbody>
    </table>
    """


def create_analytics_email_text(analytics: Dict[str, Any]) -> str:
    """Create plain text email body for analytics report."""
    text = f"""
DRIFT DETECTION ANALYTICS REPORT
30-day Configuration Change Analysis

KEY METRICS:
- Total Changes: {analytics.get('total_reports', 0)}
- Unresolved Critical: {analytics.get('unresolved_critical_count', 0)}
- Security-Related Changes: {analytics.get('security_related_changes', 0)}
- Average Daily Changes: {analytics.get('avg_daily_changes', 0):.1f}

INSIGHTS:
"""
    
    for insight in analytics.get('insights', []):
        text += f"""
- {insight.get('type', 'Unknown').replace('_', ' ').title()}: {insight.get('message', '')}
  Recommendation: {insight.get('recommendation', 'No recommendation')}
"""
    
    # Add category breakdown
    categories = analytics.get('reports_by_category', {})
    if categories:
        text += "\nCHANGES BY CATEGORY:\n"
        for category, count in sorted(categories.items(), key=lambda x: x[1], reverse=True):
            text += f"- {category}: {count}\n"
    
    # Add severity breakdown
    severities = analytics.get('reports_by_severity', {})
    if severities:
        text += "\nCHANGES BY SEVERITY:\n"
        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in severities:
                text += f"- {severity.title()}: {severities[severity]}\n"
    
    text += "\nThis is an automated analytics report from your drift detection system.\n"
    return text


def send_html_email(to_email: str, subject: str, html_body: str, text_body: str):
    """
    Send HTML email using SMTP.
    Requires SMTP settings to be configured in your settings.
    """
    # You'll need to add these to your settings
    smtp_server = getattr(settings, 'SMTP_SERVER', 'localhost')
    smtp_port = getattr(settings, 'SMTP_PORT', 587)
    smtp_username = getattr(settings, 'SMTP_USERNAME', None)
    smtp_password = getattr(settings, 'SMTP_PASSWORD', None)
    from_email = getattr(settings, 'FROM_EMAIL', 'noreply@yourcompany.com')
    
    # Create message
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = from_email
    msg['To'] = to_email
    
    # Attach text and HTML parts
    text_part = MIMEText(text_body, 'plain')
    html_part = MIMEText(html_body, 'html')
    
    msg.attach(text_part)
    msg.attach(html_part)
    
    # Send email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if smtp_username and smtp_password:
                server.starttls()
                server.login(smtp_username, smtp_password)
            
            server.send_message(msg)
            logger.info(f"Email sent successfully to {to_email}")
            
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        raise