"""
finding.py — Core data model for vulnerability findings.

All scanner modules return List[Finding] instead of writing directly
to files. This eliminates thread-safety issues and makes the data easy
to export in any format (HTML, JSON, TXT).
"""

from dataclasses import dataclass, field
from typing import Optional


SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class Finding:
    severity: str           # HIGH | MEDIUM | LOW | INFO
    category: str           # e.g. "XSS", "SQL Injection", "Missing Header"
    title: str              # Short human-readable title
    description: str        # What was found
    url: str                # The URL where it was found
    evidence: Optional[str] = None          # Payload / keyword / header value
    recommendation: Optional[str] = None    # How to fix it
    parameter: Optional[str] = None         # Affected parameter if applicable

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "parameter": self.parameter,
        }

    def __lt__(self, other: "Finding") -> bool:
        return SEVERITY_ORDER.get(self.severity, 99) < SEVERITY_ORDER.get(other.severity, 99)
