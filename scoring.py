"""
PhishGuard - Risk Scoring Engine
================================
Combines all findings from URL and email analyzers into a single,
easy-to-understand risk score (0-100).

Scoring Levels:
    0-20:   LOW RISK      - Likely legitimate
    21-40:  MODERATE RISK  - Some suspicious elements
    41-60:  HIGH RISK      - Multiple phishing indicators
    61-80:  VERY HIGH      - Strong phishing indicators
    81-100: CRITICAL       - Almost certainly phishing
"""


class RiskScore:
    """Represents a complete risk assessment with score, findings, and explanations."""

    # Risk level thresholds and their labels/colors
    RISK_LEVELS = [
        (20,  "LOW RISK",      "green",   "Likely legitimate"),
        (40,  "MODERATE RISK", "yellow",  "Some suspicious elements, proceed with caution"),
        (60,  "HIGH RISK",     "orange",  "Multiple phishing indicators detected"),
        (80,  "VERY HIGH",     "red",     "Strong phishing indicators, likely malicious"),
        (100, "CRITICAL",      "magenta", "Almost certainly a phishing attempt"),
    ]

    # Risk level icons for terminal display
    RISK_ICONS = {
        "LOW RISK":      "\u2705",  # green checkmark
        "MODERATE RISK": "\U0001f7e1",  # yellow circle
        "HIGH RISK":     "\U0001f7e0",  # orange circle
        "VERY HIGH":     "\U0001f534",  # red circle
        "CRITICAL":      "\U0001f6a8",  # rotating light
    }

    def __init__(self):
        """Initialize a new risk score with empty findings."""
        self.findings = []       # List of (points, category, description, explanation)
        self.total_score = 0
        self.target = ""         # The URL or email being analyzed
        self.analysis_type = ""  # "url" or "email"

    def add_finding(self, points, category, description, explanation):
        """
        Add a finding that contributes to the risk score.

        Args:
            points: Risk points to add (e.g., 25)
            category: Category of the finding (e.g., "URL Structure")
            description: Short description (e.g., "IP address used as URL")
            explanation: Detailed explanation of why this is suspicious
        """
        self.findings.append({
            "points": points,
            "category": category,
            "description": description,
            "explanation": explanation,
        })
        self.total_score = min(100, self.total_score + points)

    def get_risk_level(self):
        """
        Determine the risk level based on the total score.

        Returns:
            Tuple of (label, color, description)
        """
        for threshold, label, color, description in self.RISK_LEVELS:
            if self.total_score <= threshold:
                return label, color, description
        # Default to highest risk if somehow over 100
        return self.RISK_LEVELS[-1][1], self.RISK_LEVELS[-1][2], self.RISK_LEVELS[-1][3]

    def get_risk_icon(self):
        """Get the icon/emoji for the current risk level."""
        label, _, _ = self.get_risk_level()
        return self.RISK_ICONS.get(label, "\u2753")

    def get_confidence(self):
        """
        Calculate confidence rating based on number of findings.

        More findings = higher confidence in the assessment.

        Returns:
            Tuple of (confidence_label, confidence_percentage)
        """
        num_findings = len(self.findings)

        if num_findings == 0:
            return "Low", 30
        elif num_findings == 1:
            return "Low", 40
        elif num_findings <= 3:
            return "Medium", 60
        elif num_findings <= 5:
            return "High", 80
        else:
            return "Very High", 95

    def get_score_bar(self, width=30):
        """
        Create a visual progress bar for the risk score.

        Args:
            width: Width of the bar in characters (default 30)

        Returns:
            String representing the score bar, e.g. [████████░░░░░░░░░░] 45/100
        """
        filled = int((self.total_score / 100) * width)
        empty = width - filled

        bar = "\u2588" * filled + "\u2591" * empty
        return f"[{bar}] {self.total_score}/100"

    def get_summary(self):
        """
        Generate a complete summary of the risk assessment.

        Returns:
            Dictionary with all assessment details
        """
        label, color, description = self.get_risk_level()
        confidence_label, confidence_pct = self.get_confidence()

        return {
            "target": self.target,
            "analysis_type": self.analysis_type,
            "total_score": self.total_score,
            "risk_level": label,
            "risk_color": color,
            "risk_description": description,
            "risk_icon": self.get_risk_icon(),
            "confidence": confidence_label,
            "confidence_percentage": confidence_pct,
            "score_bar": self.get_score_bar(),
            "findings": self.findings,
            "findings_count": len(self.findings),
            "recommendations": self._generate_recommendations(),
        }

    def _generate_recommendations(self):
        """
        Generate actionable recommendations based on the risk level and findings.

        Returns:
            List of recommendation strings
        """
        label, _, _ = self.get_risk_level()
        recommendations = []

        if label == "LOW RISK":
            recommendations.append(
                "This appears to be legitimate, but always exercise caution."
            )
            recommendations.append(
                "Verify the sender if the email was unexpected."
            )

        elif label == "MODERATE RISK":
            recommendations.append(
                "Proceed with caution - some elements are suspicious."
            )
            recommendations.append(
                "Do NOT enter any personal information or credentials."
            )
            recommendations.append(
                "Verify the sender through an independent channel (e.g., call them directly)."
            )

        elif label == "HIGH RISK":
            recommendations.append(
                "Do NOT click any links or download attachments from this source."
            )
            recommendations.append(
                "Do NOT enter any credentials or personal information."
            )
            recommendations.append(
                "Report this to your IT/Security team if received at work."
            )
            recommendations.append(
                "If you already clicked a link, change your passwords immediately."
            )

        elif label in ("VERY HIGH", "CRITICAL"):
            recommendations.append(
                "DO NOT interact with this email/URL in any way."
            )
            recommendations.append(
                "Report this immediately to your IT/Security team."
            )
            recommendations.append(
                "If you entered credentials, change ALL passwords immediately."
            )
            recommendations.append(
                "Enable multi-factor authentication on all your accounts."
            )
            recommendations.append(
                "Monitor your accounts for unauthorized activity."
            )
            recommendations.append(
                "Consider reporting to: https://www.ic3.gov (FBI) or "
                "https://reportfraud.ftc.gov (FTC)"
            )

        # Add finding-specific recommendations
        categories_found = {f["category"] for f in self.findings}

        if "Typosquatting" in categories_found:
            recommendations.append(
                "The domain appears to impersonate a legitimate website. "
                "Always type URLs directly into your browser."
            )

        if "Suspicious Attachment" in categories_found:
            recommendations.append(
                "NEVER open attachments from unknown senders, especially "
                ".exe, .js, .vbs, or .scr files."
            )

        if "Threat Intelligence" in categories_found:
            recommendations.append(
                "This domain/URL has been flagged by threat intelligence sources "
                "as known malicious."
            )

        return recommendations

    def __str__(self):
        """Human-readable string representation of the risk score."""
        label, _, description = self.get_risk_level()
        icon = self.get_risk_icon()
        return (
            f"{icon} {label}: {self.total_score}/100 - {description} "
            f"({len(self.findings)} findings)"
        )


def create_risk_score(target, analysis_type):
    """
    Factory function to create a new RiskScore object.

    Args:
        target: The URL or email filename being analyzed
        analysis_type: Either "url" or "email"

    Returns:
        A new RiskScore instance
    """
    score = RiskScore()
    score.target = target
    score.analysis_type = analysis_type
    return score
