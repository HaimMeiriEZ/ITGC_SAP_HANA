from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

@dataclass
class AuditPeriod:
    """מייצג תקופת ביקורת (למשל 2025-Q1)"""
    name: str
    status: str = "Open"  # Open, Locked, Closed
    description: Optional[str] = None

@dataclass
class Control:
    """מייצג בקרת ITGC מתוך מטריצת הבקרות"""
    control_number: str
    process_description: str
    risk_description: str
    control_description: str
    is_key_control: bool = True
    nature: str = "Manual"  # Automated, Semi-Automated, Manual
    control_type: str = "Preventive"  # Preventive, Detective
    frequency: str = "Quarterly"
    owner: Optional[str] = None

@dataclass
class Finding:
    """מייצג ממצא בודד שהופק על ידי מנוע הביקורת"""
    period_id: str
    category: str
    title: str
    description: str
    risk_level: str  # High, Medium, Low
    status: str = "Non-Compliant"  # Non-Compliant, Compliant, Exception Approved
    source_slot: Optional[str] = None
    actual_value: Optional[str] = None
    expected_value: Optional[str] = None
    comparison_rule: Optional[str] = None
    remediation_owner: Optional[str] = None
    evidence_ref: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class WhitelistRule:
    """חוק החרגה לאישור חריגים ידועים"""
    object_type: str  # User, Role, Privilege
    object_name: str
    justification: str
    approved_by: str
    approval_date: str = field(default_factory=lambda: datetime.now().date().isoformat())