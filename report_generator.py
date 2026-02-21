"""
PhishGuard - Report Generator
==============================
Creates professional analysis reports in both text and HTML formats.

Text reports include:
    - Header with timestamp and tool version
    - Target URL or email filename
    - Overall risk score with visual bar
    - Breakdown of each finding with explanation
    - Recommendations
    - Disclaimer footer

HTML reports include:
    - Professional CSS styling with colour-coded risk levels
    - Large, prominent risk score display
    - Visual progress bar for risk level
    - Expandable sections for each finding
    - Recommendations section
    - "Analyzed by PhishGuard" footer
"""

import os
from datetime import datetime

VERSION = "1.0.0"


def generate_text_report(risk_score):
    """
    Generate a professional text-based analysis report.

    Args:
        risk_score: A RiskScore object from scoring.py

    Returns:
        String containing the formatted text report
    """
    summary = risk_score.get_summary()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []

    # Header
    lines.append("=" * 70)
    lines.append("                    PHISHGUARD ANALYSIS REPORT")
    lines.append("=" * 70)
    lines.append(f"  Generated:      {now}")
    lines.append(f"  Tool Version:   PhishGuard v{VERSION}")
    lines.append(f"  Analysis Type:  {summary['analysis_type'].upper()}")
    lines.append(f"  Target:         {summary['target']}")
    lines.append("=" * 70)
    lines.append("")

    # Risk Score Section
    lines.append("-" * 70)
    lines.append("  RISK ASSESSMENT")
    lines.append("-" * 70)
    lines.append(f"  {summary['risk_icon']} Risk Level:  {summary['risk_level']}")
    lines.append(f"  Score:        {summary['score_bar']}")
    lines.append(f"  Description:  {summary['risk_description']}")
    lines.append(f"  Confidence:   {summary['confidence']} ({summary['confidence_percentage']}%)")
    lines.append(f"  Findings:     {summary['findings_count']} indicator(s) detected")
    lines.append("-" * 70)
    lines.append("")

    # Findings Breakdown
    if summary["findings"]:
        lines.append("-" * 70)
        lines.append("  DETAILED FINDINGS")
        lines.append("-" * 70)
        lines.append("")

        for i, finding in enumerate(summary["findings"], 1):
            lines.append(f"  [{i}] {finding['description']}")
            lines.append(f"      Category:    {finding['category']}")
            lines.append(f"      Risk Points: +{finding['points']}")
            lines.append(f"      Details:     {finding['explanation']}")
            lines.append("")
    else:
        lines.append("  No suspicious indicators were detected.")
        lines.append("")

    # Recommendations
    if summary["recommendations"]:
        lines.append("-" * 70)
        lines.append("  RECOMMENDATIONS")
        lines.append("-" * 70)
        for rec in summary["recommendations"]:
            lines.append(f"  * {rec}")
        lines.append("")

    # Footer
    lines.append("=" * 70)
    lines.append("  Analyzed by PhishGuard v{} | {}".format(VERSION, now))
    lines.append("  ")
    lines.append("  DISCLAIMER: This analysis is automated and should be used")
    lines.append("  as one input in your security assessment. No automated tool")
    lines.append("  can guarantee 100% accuracy. When in doubt, consult your")
    lines.append("  IT/Security team.")
    lines.append("=" * 70)

    return "\n".join(lines)


def generate_html_report(risk_score):
    """
    Generate a professional HTML analysis report with CSS styling.

    Args:
        risk_score: A RiskScore object from scoring.py

    Returns:
        String containing the complete HTML report
    """
    summary = risk_score.get_summary()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Determine colours based on risk level
    colour_map = {
        "green":   ("#27ae60", "#2ecc71", "#e8f8f0"),
        "yellow":  ("#f39c12", "#f1c40f", "#fef9e7"),
        "orange":  ("#e67e22", "#f39c12", "#fdf2e9"),
        "red":     ("#e74c3c", "#c0392b", "#fdedec"),
        "magenta": ("#8e44ad", "#9b59b6", "#f4ecf7"),
    }
    primary, secondary, bg = colour_map.get(
        summary["risk_color"], ("#e74c3c", "#c0392b", "#fdedec")
    )

    # Build findings HTML
    findings_html = ""
    if summary["findings"]:
        for i, finding in enumerate(summary["findings"], 1):
            findings_html += f"""
            <details class="finding">
                <summary>
                    <span class="finding-number">#{i}</span>
                    <span class="finding-title">{finding['description']}</span>
                    <span class="finding-points">+{finding['points']} pts</span>
                </summary>
                <div class="finding-details">
                    <p><strong>Category:</strong> {finding['category']}</p>
                    <p><strong>Risk Points:</strong> +{finding['points']}</p>
                    <div class="finding-explanation">
                        <strong>Why this is suspicious:</strong>
                        <p>{finding['explanation']}</p>
                    </div>
                </div>
            </details>"""
    else:
        findings_html = '<p class="no-findings">No suspicious indicators were detected.</p>'

    # Build recommendations HTML
    recs_html = ""
    for rec in summary["recommendations"]:
        recs_html += f"<li>{rec}</li>\n"

    # Score bar percentage
    score_pct = summary["total_score"]

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishGuard Analysis Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                         'Helvetica Neue', Arial, sans-serif;
            background: #f5f6fa;
            color: #2c3e50;
            line-height: 1.6;
            padding: 20px;
        }}

        .report-container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }}

        .report-header {{
            background: linear-gradient(135deg, #2c3e50, #34495e);
            color: white;
            padding: 30px;
            text-align: center;
        }}

        .report-header h1 {{
            font-size: 28px;
            margin-bottom: 5px;
            letter-spacing: 2px;
        }}

        .report-header .subtitle {{
            opacity: 0.8;
            font-size: 14px;
        }}

        .report-meta {{
            display: flex;
            justify-content: space-between;
            padding: 15px 30px;
            background: #ecf0f1;
            font-size: 13px;
            color: #7f8c8d;
        }}

        .score-section {{
            text-align: center;
            padding: 40px 30px;
            background: {bg};
        }}

        .score-circle {{
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: {primary};
            color: white;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin: 0 auto 20px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }}

        .score-number {{
            font-size: 48px;
            font-weight: bold;
            line-height: 1;
        }}

        .score-label {{
            font-size: 12px;
            opacity: 0.9;
            margin-top: 4px;
        }}

        .risk-level {{
            font-size: 24px;
            font-weight: bold;
            color: {primary};
            margin-bottom: 10px;
        }}

        .risk-description {{
            color: #555;
            margin-bottom: 20px;
        }}

        .score-bar-container {{
            max-width: 400px;
            margin: 0 auto;
            background: #ddd;
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
        }}

        .score-bar-fill {{
            height: 100%;
            width: {score_pct}%;
            background: linear-gradient(90deg, {secondary}, {primary});
            border-radius: 10px;
            transition: width 1s ease;
        }}

        .confidence {{
            margin-top: 15px;
            font-size: 14px;
            color: #777;
        }}

        .target-section {{
            padding: 20px 30px;
            background: #fafafa;
            border-top: 1px solid #eee;
            border-bottom: 1px solid #eee;
        }}

        .target-section strong {{
            color: #2c3e50;
        }}

        .target-url {{
            word-break: break-all;
            font-family: 'Courier New', monospace;
            background: #f0f0f0;
            padding: 8px 12px;
            border-radius: 4px;
            margin-top: 5px;
            display: block;
            font-size: 13px;
        }}

        .findings-section {{
            padding: 30px;
        }}

        .findings-section h2 {{
            color: #2c3e50;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid {primary};
        }}

        .finding {{
            margin-bottom: 10px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }}

        .finding summary {{
            padding: 15px;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
            background: #fafafa;
            transition: background 0.2s;
        }}

        .finding summary:hover {{
            background: #f0f0f0;
        }}

        .finding-number {{
            background: {primary};
            color: white;
            width: 28px;
            height: 28px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: bold;
            flex-shrink: 0;
        }}

        .finding-title {{
            flex: 1;
            font-weight: 500;
        }}

        .finding-points {{
            background: {bg};
            color: {primary};
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }}

        .finding-details {{
            padding: 15px 15px 15px 53px;
            border-top: 1px solid #eee;
        }}

        .finding-explanation {{
            margin-top: 10px;
            padding: 12px;
            background: #f8f9fa;
            border-left: 3px solid {primary};
            border-radius: 0 4px 4px 0;
        }}

        .finding-explanation p {{
            margin-top: 5px;
            font-size: 14px;
            color: #555;
        }}

        .recommendations-section {{
            padding: 30px;
            background: #f8f9fa;
        }}

        .recommendations-section h2 {{
            color: #2c3e50;
            margin-bottom: 15px;
        }}

        .recommendations-section ul {{
            list-style: none;
            padding: 0;
        }}

        .recommendations-section li {{
            padding: 10px 15px;
            margin-bottom: 8px;
            background: white;
            border-radius: 6px;
            border-left: 4px solid {primary};
            font-size: 14px;
        }}

        .no-findings {{
            text-align: center;
            padding: 30px;
            color: #27ae60;
            font-size: 16px;
        }}

        .report-footer {{
            text-align: center;
            padding: 20px;
            background: #2c3e50;
            color: #95a5a6;
            font-size: 12px;
        }}

        .report-footer .disclaimer {{
            max-width: 600px;
            margin: 10px auto 0;
            font-size: 11px;
            opacity: 0.7;
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="report-header">
            <h1>PHISHGUARD</h1>
            <div class="subtitle">Phishing Detection Analysis Report</div>
        </div>

        <div class="report-meta">
            <span>Generated: {now}</span>
            <span>Version: v{VERSION}</span>
            <span>Type: {summary['analysis_type'].upper()} Analysis</span>
        </div>

        <div class="target-section">
            <strong>Target Analyzed:</strong>
            <span class="target-url">{summary['target']}</span>
        </div>

        <div class="score-section">
            <div class="score-circle">
                <div class="score-number">{summary['total_score']}</div>
                <div class="score-label">/ 100</div>
            </div>
            <div class="risk-level">{summary['risk_icon']} {summary['risk_level']}</div>
            <div class="risk-description">{summary['risk_description']}</div>
            <div class="score-bar-container">
                <div class="score-bar-fill"></div>
            </div>
            <div class="confidence">
                Confidence: {summary['confidence']} ({summary['confidence_percentage']}%)
                | {summary['findings_count']} indicator(s) detected
            </div>
        </div>

        <div class="findings-section">
            <h2>Detailed Findings</h2>
            {findings_html}
        </div>

        <div class="recommendations-section">
            <h2>Recommendations</h2>
            <ul>
                {recs_html}
            </ul>
        </div>

        <div class="report-footer">
            <div>Analyzed by PhishGuard v{VERSION}</div>
            <div class="disclaimer">
                DISCLAIMER: This analysis is automated and should be used as one
                input in your security assessment. No automated tool can guarantee
                100% accuracy. When in doubt, consult your IT/Security team.
                This tool is for educational purposes and authorized security
                analysis only.
            </div>
        </div>
    </div>
</body>
</html>"""

    return html


def save_report(risk_score, output_dir=".", fmt="both"):
    """
    Save the analysis report to file(s).

    Args:
        risk_score: RiskScore object
        output_dir: Directory to save the report (default: current dir)
        fmt: Format - "text", "html", or "both"

    Returns:
        List of file paths that were created
    """
    summary = risk_score.get_summary()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Sanitize target for filename
    target_name = summary["target"].replace("://", "_").replace("/", "_")
    target_name = "".join(c for c in target_name if c.isalnum() or c in "_-.")[:50]

    files_created = []

    if fmt in ("text", "both"):
        text_report = generate_text_report(risk_score)
        text_path = os.path.join(output_dir, f"phishguard_report_{target_name}_{timestamp}.txt")
        with open(text_path, "w", encoding="utf-8") as f:
            f.write(text_report)
        files_created.append(text_path)

    if fmt in ("html", "both"):
        html_report = generate_html_report(risk_score)
        html_path = os.path.join(output_dir, f"phishguard_report_{target_name}_{timestamp}.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_report)
        files_created.append(html_path)

    return files_created
