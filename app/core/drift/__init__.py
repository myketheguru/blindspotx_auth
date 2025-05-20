"""
Drift Detection System
---------------------
This module provides a comprehensive system for detecting and classifying drift 
in configuration and security settings.

Drift refers to unexpected changes in configurations, permissions, or other settings
that might indicate security issues or unauthorized modifications.
"""

from app.core.drift.detector import compare_objects
from app.core.drift.severity import calculate_severity, SeverityLevel
from app.core.drift.types import DriftCategory, DriftType, DriftChange
from app.core.drift.scheduler import start_scheduler, schedule_drift_detection

__all__ = [
    'compare_objects',
    'calculate_severity',
    'SeverityLevel',
    'DriftCategory',
    'DriftType',
    'DriftChange',
    'start_scheduler',
    'schedule_drift_detection'
]

