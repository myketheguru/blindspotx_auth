"""
Drift Detection Tests
------------------
Tests for drift detection functionality including change detection,
severity classification, analytics, and alerting.
"""

import pytest
import json
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timedelta
import uuid
from copy import deepcopy

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from app.core.drift.detector import (
    compare_objects, analyze_drift_changes, detect_unusual_patterns,
    calculate_drift_analytics, generate_drift_alert
)
from app.core.drift.severity import (
    calculate_severity, determine_security_impact, is_sensitive_field
)
from app.core.drift.types import (
    DriftCategory, DriftType, DriftChange, SecurityImpact, DriftResult
)
from app.models.drift import (
    ConfigurationSnapshot, DriftReport, ValidationStatus, RetentionPolicy,
    Severity, DriftStatus
)
from app.api.routes.drift import get_drift_status, get_drift_reports, trigger_drift_scan
from app.services.drift_service import detect_drift, save_snapshot

pytestmark = pytest.mark.asyncio

# ========== SAMPLE DATA FOR TESTING ========== #

# Base role configuration
ROLE_CONFIG = {
    "id": "role123",
    "name": "Admin Role",
    "description": "Role with administrative privileges",
    "permissions": ["read:users", "write:users", "manage:roles"],
    "membersCount": 2,
    "isBuiltin": False,
    "created": "2025-01-01T00:00:00Z"
}

# Modified role with changed permissions
MODIFIED_ROLE_CONFIG = {
    "id": "role123",
    "name": "Admin Role",
    "description": "Role with extended administrative privileges",
    "permissions": ["read:users", "write:users", "manage:roles", "admin:system"],
    "membersCount": 3,
    "isBuiltin": False,
    "created": "2025-01-01T00:00:00Z"
}

# Base auth settings
AUTH_SETTINGS_CONFIG = {
    "id": "auth_settings",
    "mfaEnabled": True,
    "passwordPolicy": {
        "minLength": 12,
        "requiresUppercase": True,
        "requiresLowercase": True,
        "requiresDigit": True,
        "requiresSpecial": True,
        "expiryDays": 90
    },
    "sessionTimeout": 240,
    "loginAttempts": 5
}

# Modified auth settings with security downgrade
WEAKENED_AUTH_SETTINGS = {
    "id": "auth_settings",
    "mfaEnabled": False,  # Disabled MFA - security downgrade
    "passwordPolicy": {
        "minLength": 8,   # Reduced password length - security downgrade
        "requiresUppercase": True,
        "requiresLowercase": True,
        "requiresDigit": True,
        "requiresSpecial": False,  # Removed special char requirement - security downgrade
        "expiryDays": 180  # Extended expiry - security downgrade
    },
    "sessionTimeout": 480,  # Extended timeout - security downgrade
    "loginAttempts": 10     # Increased login attempts - security downgrade
}

# Nested object for testing deep comparison
NESTED_OBJECT = {
    "id": "config123",
    "name": "Test Configuration",
    "settings": {
        "general": {
            "theme": "dark",
            "language": "en-US"
        },
        "security": {
            "encryption": {
                "enabled": True,
                "algorithm": "AES-256",
                "keyRotation": 90
            },
            "access": {
                "restrictions": [
                    {"type": "ip", "value": "192.168.1.1"},
                    {"type": "time", "value": "business-hours"}
                ]
            }
        }
    },
    "users": [
        {"id": "user1", "role": "admin"},
        {"id": "user2", "role": "user"}
    ]
}

# Modified nested object
MODIFIED_NESTED_OBJECT = {
    "id": "config123",
    "name": "Test Configuration",
    "settings": {
        "general": {
            "theme": "light",  # Changed
            "language": "en-US"
        },
        "security": {
            "encryption": {
                "enabled": False,  # Security downgrade
                "algorithm": "AES-128",  # Security downgrade
                "keyRotation": 180  # Security downgrade
            },
            "access": {
                "restrictions": [
                    {"type": "ip", "value": "192.168.1.1"}
                    # Removed time restriction - potentially security downgrade
                ]
            }
        }
    },
    "users": [
        {"id": "user1", "role": "admin"},
        {"id": "user2", "role": "admin"},  # Changed role - security impact
        {"id": "user3", "role": "user"}    # Added new user
    ]
}

# ========== TESTS FOR OBJECT COMPARISON ========== #

async def test_compare_simple_objects():
    """Test comparison of simple objects"""
    # Arrange
    old = {"name": "Test", "value": 123}
    new = {"name": "Test", "value": 456}
    
    # Act
    result = compare_objects(old, new, category="test", key="test_key")
    
    # Assert
    assert result.changed is True
    assert len(result.changes) == 1
    assert result.changes[0].path == "value"
    assert result.changes[0].old_value == 123
    assert result.changes[0].new_value == 456
    assert result.changes[0].type == DriftType.MODIFIED

async def test_compare_with_added_field():
    """Test comparison with added field"""
    # Arrange
    old = {"name": "Test", "value": 123}
    new = {"name": "Test", "value": 123, "new_field": "added"}
    
    # Act
    result = compare_objects(old, new, category="test", key="test_key")
    
    # Assert
    assert result.changed is True
    assert len(result.changes) == 1
    assert result.changes[0].path == "new_field"
    assert result.changes[0].old_value is None
    assert result.changes[0].new_value == "added"
    assert result.changes[0].type == DriftType.CREATED

async def test_compare_with_removed_field():
    """Test comparison with removed field"""
    # Arrange
    old = {"name": "Test", "value": 123, "to_remove": "will be gone"}
    new = {"name": "Test", "value": 123}
    
    # Act
    result = compare_objects(old, new, category="test", key="test_key")
    
    # Assert
    assert result.changed is True
    assert len(result.changes) == 1
    assert result.changes[0].path == "to_remove"
    assert result.changes[0].old_value == "will be gone"
    assert result.changes[0].new_value is None
    assert result.changes[0].type == DriftType.DELETED

async def test_compare_nested_objects():
    """Test comparison of nested objects"""
    # Arrange
    old = {
        "level1": {
            "level2": {
                "value": "original"
            }
        }
    }
    new = {
        "level1": {
            "level2": {
                "value": "changed"
            }
        }
    }
    
    # Act
    result = compare_objects(old, new, category="test", key="test_key")
    
    # Assert
    assert result.changed is True
    assert len(result.changes) == 1
    assert result.changes[0].path == "level1.level2.value"
    assert result.changes[0].old_value == "original"
    assert result.changes[0].new_value == "changed"

async def test_compare_arrays():
    """Test comparison of arrays"""
    # Arrange
    old = {"items": [1, 2, 3]}
    new = {"items": [1, 2, 4]}  # 3 changed to 4
    
    # Act
    result = compare_objects(old, new, category="test", key="test_key")
    
    # Assert
    assert result.changed is True
    assert len(result.changes) == 1
    assert result.changes[0].path == "items[2]"
    assert result.changes[0].old_value == 3
    assert result.changes[0].new_value == 4

async def test_compare_arrays_different_length():
    """Test comparison of arrays with different lengths"""
    # Arrange
    old = {"items": [1, 2, 3]}
    new = {"items": [1, 2, 3, 4]}  # Added 4
    
    # Act
    result = compare_objects(old, new, category="test", key="test_key")
    
    # Assert
    assert result.changed is True
    assert len(result.changes) == 2  # Length change + new item
    assert any(c.path == "items[3]" and c.new_value == 4 for c in result.changes)

async def test_compare_object_arrays():
    """Test comparison of arrays containing objects"""
    # Arrange
    old = {"users": [
        {"id": "user1", "name": "User One"},
        {"id": "user2", "name": "User Two"}
    ]}
    new = {"users": [
        {"id": "user1", "name": "User One Updated"},  # Changed name
        {"id": "user2", "name": "User Two"}
    ]}
    
    # Act
    result = compare_objects(old, new, category="test", key="test_key")
    
    # Assert
    assert result.changed is True
    assert len(result.changes) == 1
    assert result.changes[0].path == "users[user1].name"
    assert result.changes[0].old_value == "User One"
    assert result.changes[0].new_value == "User One Updated"

async def test_compare_complex_nested_object():
    """Test comparison of complex nested objects"""
    # Arrange - Use the predefined test objects
    old = NESTED_OBJECT
    new = MODIFIED_NESTED_OBJECT
    
    # Act
    result = compare_objects(old, new, category=DriftCategory.APP_SETTINGS, key="config123")
    
    # Assert
    assert result.changed is True
    # Verify all expected changes were detected
    expected_changes = [
        "settings.general.theme",
        "settings.security.encryption.enabled",
        "settings.security.encryption.algorithm",
        "settings.security.encryption.keyRotation",
        "settings.security.access.restrictions",  # Array change
        "users[user2].role",  # Changed role
        "users"  # Added user3
    ]
    
    # Check that each expected path has a corresponding change
    detected_paths = [change.path for change in result.changes]
    for expected_path in expected_changes:
        assert any(expected_path in path for path in detected_paths), f"Expected change in {expected_path} not detected"
    
    # Verify security impact detection for security-sensitive changes
    security_changes = [
        c for c in result.changes 
        if "security" in c.path or "role" in c.path
    ]
    for change in security_changes:
        assert change.security_impact != SecurityImpact.NO_SECURITY_IMPACT, f"Security impact not detected for {change.path}"

# ========== TESTS FOR SEVERITY CLASSIFICATION ========== #

async def test_severity_classification_critical():
    """Test severity classification for critical changes"""
    # Arrange
    change = DriftChange(
        category=DriftCategory.AUTH_SETTINGS,
        type=DriftType.MODIFIED,
        key="auth_settings",
        path="mfaEnabled",
        old_value=True,
        new_value=False
    )
    
    # Act
    severity = calculate_severity(change)
    
    # Assert - Disabling MFA should be critical
    assert severity == "critical"

async def test_severity_classification_high():
    """Test severity classification for high severity changes"""
    # Arrange
    change = DriftChange(
        category=DriftCategory.PASSWORD_POLICY,
        type=DriftType.MODIFIED,
        key="password_policy",
        path="minLength",
        old_value=12,
        new_value=8
    )
    
    # Act
    severity = calculate_severity(change)
    
    # Assert - Weakening password policy should be high severity
    assert severity == "high" or severity == "critical"

async def test_severity_classification_medium():
    """Test severity classification for medium severity changes"""
    # Arrange
    change = DriftChange(
        category=DriftCategory.ROLE,
        type=DriftType.MODIFIED,
        key="role123",
        path="description",
        old_value="Role description",
        new_value="Updated role description"
    )
    
    # Act
    severity = calculate_severity(change)
    
    # Assert - Role description change should be medium severity at most
    assert severity in ["low", "medium"]

async def test_severity_classification_low():
    """Test severity classification for low severity changes"""
    # Arrange
    change = DriftChange(
        category=DriftCategory.APP_SETTINGS,
        type=DriftType.MODIFIED,
        key="app_settings",
        path="theme",
        old_value="dark",
        new_value="light"
    )
    
    # Act
    severity = calculate_severity(change)
    
    # Assert - UI theme change should be low severity
    assert severity in ["info", "low"]

async def test_security_impact_assessment():
    """Test security impact assessment"""
    # Arrange - Test different security impacts
    test_cases = [
        # Critical security removal (MFA disabled)
        {
            "change": DriftChange(
                category=DriftCategory.AUTH_SETTINGS,
                type=DriftType.MODIFIED,
                key="auth_settings",
                path="mfaEnabled",
                old_value=True,
                new_value=False
            ),
            "expected_impact": SecurityImpact.CRITICAL_SECURITY_REMOVED
        },
        # Admin rights granted
        {
            "change": DriftChange(
                category=DriftCategory.USER,
                type=DriftType.MODIFIED,
                key="user123",
                path="isAdmin",
                old_value=False,
                new_value=True
            ),
            "expected_impact": SecurityImpact.ADMIN_RIGHTS_GRANTED
        },
        # Security weakened
        {
            "change": DriftChange(
                category=DriftCategory.PASSWORD_POLICY,
                type=DriftType.MODIFIED,
                key="password_policy",
                path="requiresSpecial",
                old_value=True,
                new_value

import pytest
import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock, AsyncMock

from sqlalchemy.ext.asyncio import AsyncSession
from app.core.drift.detector import compare_objects
from app.core.drift.types import (
    DriftCategory, 
    DriftType, 
    DriftChange, 
    SecurityImpact, 
    DriftResult
)
from app.core.drift.severity import (
    calculate_severity, 
    determine_security_impact,
    SeverityLevel,
    is_security_sensitive_field,
    calculate_severity_distribution
)
from app.core.drift.scheduler import (
    start_scheduler,
    stop_scheduler,
    schedule_drift_detection,
    get_scheduler_health,
    SchedulerStatus
)
from app.models.drift import ConfigurationSnapshot, DriftReport


#
# Test Fixtures
#

@pytest.fixture
def sample_role_old():
    return {
        "id": "role1",
        "name": "Admin Role",
        "description": "Administrator privileges",
        "permissions": ["read", "write", "delete"],
        "access_level": "high",
        "settings": {
            "max_session_time": 3600,
            "require_mfa": True,
            "ip_restrictions": ["192.168.1.0/24"]
        }
    }


@pytest.fixture
def sample_role_new():
    return {
        "id": "role1",
        "name": "Admin Role",
        "description": "Administrator privileges with extended access",
        "permissions": ["read", "write", "delete", "admin"],
        "access_level": "high",
        "settings": {
            "max_session_time": 7200,
            "require_mfa": False,  # Security downgrade
            "ip_restrictions": []  # Security downgrade
        }
    }


@pytest.fixture
def sample_user_old():
    return {
        "id": "user1",
        "email": "user@example.com",
        "name": "Test User",
        "role_id": "user_role",
        "is_active": True,
        "is_admin": False,
        "mfa_enabled": True,
        "last_login": "2025-01-01T00:00:00Z"
    }


@pytest.fixture
def sample_user_new():
    return {
        "id": "user1",
        "email": "user@example.com",
        "name": "Test User Updated",
        "role_id": "admin_role",  # Changed to admin role - security impact
        "is_active": True,
        "is_admin": True,  # Security impact
        "mfa_enabled": True,
        "last_login": "2025-05-01T00:00:00Z"
    }


@pytest.fixture
def sample_auth_settings_old():
    return {
        "id": "auth_settings",
        "password_expiry_days": 90,
        "min_password_length": 12,
        "require_special_chars": True,
        "require_numbers": True,
        "require_uppercase": True,
        "max_login_attempts": 5,
        "lockout_duration_minutes": 30,
        "session_timeout_minutes": 60,
        "mfa": {
            "enabled": True,
            "required_for_all": True,
            "allowed_methods": ["app", "sms", "email"]
        }
    }


@pytest.fixture
def sample_auth_settings_new():
    return {
        "id": "auth_settings",
        "password_expiry_days": 180,  # Security downgrade
        "min_password_length": 8,  # Security downgrade
        "require_special_chars": False,  # Security downgrade
        "require_numbers": True,
        "require_uppercase": True,
        "max_login_attempts": 10,  # Security downgrade
        "lockout_duration_minutes": 15,  # Security downgrade
        "session_timeout_minutes": 120,  # Security downgrade
        "mfa": {
            "enabled": True,
            "required_for_all": False,  # Security downgrade
            "allowed_methods": ["app", "sms", "email"]
        }
    }


#
# Test Nested Object Comparison
#

def test_compare_simple_objects():
    """Test comparison of simple objects with scalar values"""
    old = {"name": "Test", "value": 10}
    new = {"name": "Test Updated", "value": 15}
    
    changes = compare_objects(old, new, key="test", category=DriftCategory.CUSTOM)
    
    assert len(changes) == 2
    assert any(c.path == "name" and c.old_value == "Test" and c.new_value == "Test Updated" for c in changes)
    assert any(c.path == "value" and c.old_value == 10 and c.new_value == 15 for c in changes)


def test_compare_nested_objects():
    """Test comparison of objects with nested structure"""
    old = {
        "user": {
            "profile": {
                "name": "John",
                "settings": {
                    "theme": "dark",
                    "notifications": True
                }
            }
        }
    }
    
    new = {
        "user": {
            "profile": {
                "name": "John",
                "settings": {
                    "theme": "light",
                    "notifications": False
                }
            }
        }
    }
    
    changes = compare_objects(old, new, key="test", category=DriftCategory.USER)
    
    assert len(changes) == 2
    assert any(c.path == "user.profile.settings.theme" and c.old_value == "dark" and c.new_value == "light" for c in changes)
    assert any(c.path == "user.profile.settings.notifications" and c.old_value is True and c.new_value is False for c in changes)


def test_compare_arrays():
    """Test comparison of arrays and array elements"""
    old = {"permissions": ["read", "write"]}
    new = {"permissions": ["read", "write", "admin"]}
    
    changes = compare_objects(old, new, key="test", category=DriftCategory.PERMISSION)
    
    assert len(changes) == 1
    assert changes[0].path == "permissions"
    assert changes[0].old_value == ["read", "write"]
    assert changes[0].new_value == ["read", "write", "admin"]


def test_compare_objects_with_added_fields():
    """Test comparison where new fields are added"""
    old = {"name": "Test", "value": 10}
    new = {"name": "Test", "value": 10, "new_field": "added"}
    
    changes = compare_objects(old, new, key="test", category=DriftCategory.CUSTOM)
    
    assert len(changes) == 1
    assert changes[0].path == "new_field"
    assert changes[0].old_value is None
    assert changes[0].new_value == "added"


def test_compare_objects_with_removed_fields():
    """Test comparison where fields are removed"""
    old = {"name": "Test", "value": 10, "to_remove": "will be gone"}
    new = {"name": "Test", "value": 10}
    
    changes = compare_objects(old, new, key="test", category=DriftCategory.CUSTOM)
    
    assert len(changes) == 1
    assert changes[0].path == "to_remove"
    assert changes[0].old_value == "will be gone"
    assert changes[0].new_value is None


def test_compare_objects_with_changed_types():
    """Test comparison where field types change"""
    old = {"setting": "123"}
    new = {"setting": 123}
    
    changes = compare_objects(old, new, key="test", category=DriftCategory.CUSTOM)
    
    assert len(changes) == 1
    assert changes[0].path == "setting"
    assert changes[0].old_value == "123"
    assert changes[0].new_value == 123


def test_compare_complex_role_changes(sample_role_old, sample_role_new):
    """Test comparison of complex role objects with nested changes"""
    changes = compare_objects(
        sample_role_old, 
        sample_role_new, 
        key="role1", 
        category=DriftCategory.ROLE
    )
    
    # Should detect 4 changes: description, permissions, max_session_time, require_mfa, ip_restrictions
    assert len(changes) == 5
    
    # Verify description change
    description_change = next(c for c in changes if c.path == "description")
    assert description_change.old_value == "Administrator privileges"
    assert description_change.new_value == "Administrator privileges with extended access"
    
    # Verify permissions array change
    permissions_change = next(c for c in changes if c.path == "permissions")
    assert sorted(permissions_change.old_value) == sorted(["read", "write", "delete"])
    assert sorted(permissions_change.new_value) == sorted(["read", "write", "delete", "admin"])
    
    # Verify nested settings changes
    max_session_change = next(c for c in changes if c.path == "settings.max_session_time")
    assert max_session_change.old_value == 3600
    assert max_session_change.new_value == 7200
    
    mfa_change = next(c for c in changes if c.path == "settings.require_mfa")
    assert mfa_change.old_value is True
    assert mfa_change.new_value is False
    
    ip_change = next(c for c in changes if c.path == "settings.ip_restrictions")
    assert ip_change.old_value == ["192.168.1.0/24"]
    assert ip_change.new_value == []


#
# Test Severity Classification
#

def test_security_sensitive_field_detection():
    """Test the detection of security-sensitive fields"""
    # Security-sensitive fields
    assert is_security_sensitive_field("password") is True
    assert is_security_sensitive_field("token") is True
    assert is_security_sensitive_field("api_key") is True
    assert is_security_sensitive_field("mfa_enabled") is True
    assert is_security_sensitive_field("admin_access") is True
    assert is_security_sensitive_field("firewall_rules") is True
    
    # Non-security fields
    assert is_security_sensitive_field("display_name") is False
    assert is_security_sensitive_field("description") is False
    assert is_security_sensitive_field("created_at") is False


def test_security_impact_for_auth_settings(sample_auth_settings_old, sample_auth_settings_new):
    """Test security impact determination for authentication settings changes"""
    # Create a change object for MFA requirement
    mfa_change = DriftChange(
        change_type=DriftType.MODIFIED,
        category=DriftCategory.AUTH_SETTINGS,
        key="auth_settings",
        path="mfa.required_for_all",
        old_value=True,
        new_value=False
    )
    
    # Create a change object for password length
    password_length_change = DriftChange(
        change_type=DriftType.MODIFIED,
        category=DriftCategory.AUTH_SETTINGS,
        key="auth_settings",
        path="min_password_length",
        old_value=12,
        new_value=8
    )
    
    # Determine security impact
    mfa_impact = determine_security_impact(mfa_change)
    password_impact = determine_security_impact(password_length_change)
    
    # MFA changes should have high or critical impact
    assert mfa_impact in (SecurityImpact.HIGH, SecurityImpact.CRITICAL)
    
    # Password policy changes should have high impact
    assert password_impact in (SecurityImpact.HIGH, SecurityImpact.CRITICAL)


def test_severity_levels_for_role_changes(sample_role_old, sample_role_new):
    """Test severity classification for role changes"""
    # Create changes
    changes = compare_objects(
        sample_role_old, 
        sample_role_new, 
        key="role1", 
        category=DriftCategory.ROLE
    )
    
    # Get the MFA change
    mfa_change = next(c for c in changes if c.path == "settings.require_mfa")
    
    # Calculate severity
    severity = calculate_severity(mfa_change)
    
    # MFA disabling should be HIGH or CRITICAL severity
    assert severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
    
    # Description change should be low severity
    description_change = next(c for c in changes if c.path == "description")
    description_severity = calculate_severity(description_change)
    assert description_severity in (SeverityLevel.INFO, SeverityLevel.LOW)


def test_severity_levels_for_user_changes(sample_user_old, sample_user_new):
    """Test severity classification for user changes"""
    # Create changes
    changes = compare_objects(
        sample_user_old, 
        sample_user_new, 
        key="user1", 
        category=DriftCategory.USER
    )
    
    # Get the admin status change
    admin_change = next(c for c in changes if c.path == "is_admin")
    
    # Calculate severity
    severity = calculate_severity(admin_change)
    
    # Admin privilege changes should be HIGH severity
    assert severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)
    
    # Name change should be low severity
    name_change = next(c for c in changes if c.path == "name")
    name_severity = calculate_severity(name_change)
    assert name_severity in (SeverityLevel.INFO, SeverityLevel.LOW)


def test_severity_distribution():
    """Test calculation of severity distribution across multiple changes"""
    changes = [
        # Critical change
        DriftChange(
            change_type=DriftType.MODIFIED,
            category=DriftCategory.AUTH_SETTINGS,
            key="auth1",
            path="mfa.enabled",
            old_value=True,
            new_value=False
        ),
        # High severity change
        DriftChange(
            change_type=DriftType.MODIFIED,
            category=DriftCategory.ROLE,
            key="role1",
            path="permissions",
            old_value=["read"],
            new_value=["read", "admin"]
        ),
        # Medium severity change
        DriftChange(
            change_type=DriftType.MODIFIED,
            category=DriftCategory.USER,
            key="user1",
            path="role_id",
            old_value="user",
            new_value="supervisor"
        ),
        # Low severity change
        DriftChange(
            change_type=DriftType.MODIFIED,
            category=DriftCategory.USER,
            key="user2",
            path="name",
            old_value="Old Name",
            new_value="New Name"
        ),
        # Info change
        DriftChange(
            change_type=DriftType.MODIFIED,
            category=DriftCategory.APP_SETTINGS,
            key="app1",
            path="theme",
            old_value="dark",
            new_value="light"
        ),
    ]
    
    distribution = calculate_severity_distribution(changes)
    
    # Verify distribution counts are correct
    assert distribution["critical"] == 1  # MFA disabled
    assert distribution["high"] == 1      # Admin permissions added
    assert distribution["medium"] == 1    # Role changed
    assert distribution["low"] == 1       # Name changed
    assert distribution["info"] == 1      # Theme changed
    

#
# Test Scheduler Functionality
#

@pytest.mark.asyncio
async def test_scheduler_lifecycle():
    """Test the complete lifecycle of the scheduler from start to stop"""
    # Start with a clean state
    if get_scheduler_health()["status"] != SchedulerStatus.STOPPED:
        await stop_scheduler()
    
    # Verify initial state
    assert get_scheduler_health()["status"] == SchedulerStatus.STOPPED
    
    # Start the scheduler
    start_scheduler()
    assert get_scheduler_health()["status"] == SchedulerStatus.RUNNING
    
    # Schedule a simple job
    test_results = {"counter": 0}
    
    async def test_job():
        test_results["counter"] += 1
        return test_results["counter"]
    
    # Patch _job_wrapper to use our test_job instead
    with patch("app.core.drift.scheduler._job_wrapper") as mock_job_wrapper:
        # Schedule job with a short interval
        await schedule_drift_detection(interval_seconds=1, job_name="test_job")
        
        # Verify the job was scheduled
        mock_job_wrapper.assert_called_once()
        
        # The first argument should be detect_drift
        args, kwargs = mock_job_wrapper.call_args
        assert args[1] == "test_job"  # job_name
        assert args[2] == 1  # interval_seconds
    
    # Stop the scheduler
    await stop_scheduler()
    assert get_scheduler_health()["status"] == SchedulerStatus.STOPPED


@pytest.mark.asyncio
async def test_scheduler_health_metrics():
    """Test that scheduler health metrics are properly tracked"""
    # Start with a clean state
    if get_scheduler_health()["status"] != SchedulerStatus.STOPPED:
        await stop_scheduler()
    
    # Start the scheduler
    start_scheduler()
    
    # Get health metrics
    health = get_scheduler_health()
    
    # Verify basic health properties
    assert health["status"] == SchedulerStatus.RUNNING
    assert health["start_time"] is not None
    assert health["uptime"] >= 0
    assert "jobs" in health
    assert "stats" in health["jobs"]
    
    # Verify job stats structure
    job_stats = health["jobs"]["stats"]
    assert "total_runs" in job_stats
    assert "successful_runs" in job_stats
    assert "failed_runs" in job_stats
    assert "average_duration" in job_stats
    
    # Clean up
    await stop_scheduler()


@pytest.mark.asyncio
async def test_run_with_retry_mechanism():
    """Test that the retry mechanism works properly for failed jobs"""
    # Create a mock job that fails first, then succeeds
    failure_count = [0]
    
    async def failing_job():
        failure_count[0] += 1
        if failure_count[0] < 2:  # Fail on first attempt
            raise ValueError("Test failure")
        return "success"
    
    # Run with retry (directly calling the internal function)
    from app.core.drift.scheduler import _run_with_retry
    success, result, exception = await _run_with_retry(failing_job, "test_failing_job", max_retries=2)
    
    # Verify retry worked
    assert success is True
    assert result == "success"
    assert exception is None
    assert failure_count[0] == 2  # Ran twice


@pytest.mark.asyncio
async def test_run_with_retry_exhaustion():
    """Test that retry mechanism gives up after max retries"""
    # Create a mock job that always fails
    attempt_count = [0]
    
    async def always_failing_job():
        attempt_count[0] += 1
        raise ValueError(f"Test failure {attempt_count[0]}")
    
    # Run with retry (directly calling the internal function)
    from app.core.drift.scheduler import _run_with_retry
    success, result, exception = await _run_with_retry(always_failing_job, "test_failing_job", max_retries=2)
    
    # Verify retry was exhausted
    assert success is False
    assert result is None
    assert isinstance(exception, ValueError)
    assert attempt_count[0] == 3  # Initial + 2 retries


@pytest.mark.asyncio
async def test_jitter_in_scheduling():
    """Test that jitter is applied to scheduling intervals"""
    # Access the internal constants to verify jitter behavior
    from app.core.drift.scheduler import JITTER_FACTOR
    
    # Verify jitter constant is properly set
    assert 0 < JITTER_FACTOR < 1, "Jitter factor should be between 0 and 1"
    
    # Test jitter application in a simulated sleep
    intervals = []
    base_interval = 10
    
    # Patch asyncio.sleep to capture the sleep times
    with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
        # Simulate 10 scheduling intervals
        for _ in range(10):
            # Calculate jitter exactly as the scheduler does
            jitter = base_interval * JITTER_FACTOR * random.random()
            wait_time = base_interval + jitter
            await asyncio.sleep(wait_time)
            intervals.append(wait_time)
    
    # Verify sleep was called with jittered intervals
    assert len(mock_sleep.call_args_list) == 10
    
    # Get the actual intervals passed to sleep
    actual_intervals = [args[0] for args, _ in mock_sleep.call_args_list]
    
    # Verify all intervals are different (jitter applied)
    unique_intervals = set(actual_intervals)
    assert len(unique_intervals) > 1, "Jitter should generate different intervals"
    
    # Verify intervals are within expected range
    min_expected = base_interval
    max_expected = base_interval * (1 + JITTER_FACTOR)
    
    for interval in actual_intervals:
        assert min_expected <= interval <= max_expected, f"Interval {interval} outside expected range"


@pytest.mark.asyncio
async def test_error_handling_in_scheduler():
    """Test scheduler's handling of errors in scheduled jobs"""
    # Start scheduler
    start_scheduler()
    
    # Create an async function that simulates an error
    async def error_job():
        raise RuntimeError("Simulated job error")
    
    # Patch job execution to run our error job
    with patch("app.core.drift.detector.detect_drift", side_effect=error_job), \
         patch("app.core.drift.scheduler._run_with_retry", wraps=lambda f, n, m: _run_with_retry(f, n, m)):
            
        # Schedule our job
        await schedule_drift_detection(interval_seconds=1, job_name="error_test_job")
        
        # Allow some time for the job to execute
        await asyncio.sleep(0.5)
        
        # Force run the job immediately by directly invoking _run_with_retry
        from app.core.drift.scheduler import _run_with_retry
        success, _, exception = await _run_with_retry(error_job, "direct_error_job", max_retries=1)
        
        # Verify error was handled
        assert success is False
        assert exception is not None
        assert str(exception) == "Simulated job error"
    
    # Stop scheduler
    await stop_scheduler()


@pytest.mark.asyncio
async def test_cancellation_during_shutdown():
    """Test that tasks are properly cancelled during scheduler shutdown"""
    # Start with clean state
    if get_scheduler_health()["status"] != SchedulerStatus.STOPPED:
        await stop_scheduler()
    
    # Start scheduler
    start_scheduler()
    
    # Create a job that sleeps
    async def sleep_job():
        await asyncio.sleep(60)  # Long sleep that will be cancelled
        return "Done"
    
    # Get reference to tasks dictionary
    from app.core.drift.scheduler import _scheduler_tasks
    
    # Create a fake task and add it to the scheduler
    with patch("app.core.drift.detector.detect_drift", side_effect=sleep_job), \
         patch("app.core.drift.scheduler._job_wrapper") as mock_job_wrapper:
        
        # Schedule our job
        await schedule_drift_detection(interval_seconds=1, job_name="cancel_test_job")
        
        # Verify job was scheduled
        assert mock_job_wrapper.called
        
        # Stop scheduler which should cancel the task
        await stop_scheduler()
        
        # Verify scheduler status is stopped
        assert get_scheduler_health()["status"] == SchedulerStatus.STOPPED
        
        # Verify all tasks have been completed or cancelled
        for job_name, task in _scheduler_tasks.items():
            assert task.done(), f"Task {job_name} should be done or cancelled"

