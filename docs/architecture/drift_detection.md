# Drift Detection

## Overview

The Drift Detection module is a core security component of the BlindspotX Authentication System. It continuously monitors for changes in configurations, permissions, role assignments, and security settings to identify potentially unauthorized modifications or security-impacting changes that might indicate a security breach or misconfiguration.

## Purpose

The primary purposes of drift detection are:

1. **Security Monitoring**: Detect unauthorized changes to security-critical configurations
2. **Compliance Verification**: Ensure configuration remains compliant with security policies
3. **Change Tracking**: Maintain an auditable history of all configuration changes
4. **Early Warning System**: Alert administrators about potentially harmful changes
5. **Anomaly Detection**: Identify unusual patterns that might indicate compromised accounts

## Architecture

The Drift Detection module consists of the following components:

```
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│                  │      │                  │      │                  │
│  Configuration   │─────>│  Comparison      │─────>│  Analysis &      │
│  Snapshot        │      │  Engine          │      │  Classification  │
│                  │      │                  │      │                  │
└──────────────────┘      └──────────────────┘      └──────────────────┘
         │                                                   │
         │                                                   │
         ▼                                                   ▼
┌──────────────────┐                              ┌──────────────────┐
│                  │                              │                  │
│  Encrypted       │                              │  Notification    │
│  Storage         │                              │  System          │
│                  │                              │                  │
└──────────────────┘                              └──────────────────┘
```

### Components

1. **Configuration Snapshot**: Regularly captures the current state of critical configurations
2. **Comparison Engine**: Compares recent snapshots to detect changes
3. **Analysis & Classification**: Analyzes detected changes and classifies them by severity and impact
4. **Encrypted Storage**: Securely stores configuration snapshots and drift reports
5. **Notification System**: Alerts administrators about critical changes

## Drift Categories

The system monitors for drift across several categories:

1. **Authentication Settings**
   - Identity provider configurations
   - MFA settings
   - Password policies
   
2. **Authorization Changes**
   - Role definitions
   - Permission assignments
   - Role-user assignments
   
3. **User Management**
   - User creation/deletion
   - User property changes
   - Administrative privilege changes
   
4. **System Configuration**
   - Security settings
   - API configurations
   - Infrastructure settings

## Detection Process

The drift detection process follows these steps:

1. **Snapshot Collection**
   - Regular snapshots (scheduled intervals)
   - Event-triggered snapshots (after administrative actions)
   - On-demand snapshots (manually triggered)

2. **Deep Comparison**
   - Field-by-field comparison of configuration objects
   - Detection of added, removed, and modified elements
   - Path tracking for nested changes

3. **Change Classification**
   - Severity assessment (Critical, High, Medium, Low)
   - Security impact analysis
   - Affected component identification

4. **Response Actions**
   - Logging all detected changes
   - Alerting on critical changes
   - Optional auto-remediation for certain changes
   - Creating detailed reports for investigation

## Severity Classification

Changes are classified into severity levels:

| Severity | Description | Examples |
|----------|-------------|----------|
| Critical | Changes that could lead to immediate security compromise | Adding a new administrator, disabling MFA |
| High | Significant security impact but not immediate compromise | Role permission expansion, security setting changes |
| Medium | Moderate security impact requiring review | User property changes, non-critical setting modifications |
| Low | Minor changes with minimal security impact | Documentation updates, cosmetic changes |

## Integration Points

The Drift Detection module integrates with:

1. **Microsoft Graph API**: To retrieve current configuration from Microsoft Entra ID
2. **Database**: To store snapshots and drift reports
3. **Alerting Systems**: To notify administrators of critical changes
4. **Audit Log**: To maintain a comprehensive record of all changes
5. **RBAC System**: To verify that changes are authorized based on user roles

## Implementation Details

### Snapshot Management

- **Snapshot Format**: JSON-based configuration objects with metadata
- **Identification**: Each snapshot has a unique ID and timestamp
- **Batch Processing**: Related snapshots are grouped by batch ID
- **Retention Policy**: Configurable retention periods based on criticality

### Comparison Algorithm

The comparison algorithm:

1. First identifies created and deleted objects by comparing object IDs
2. For modified objects, performs a recursive deep comparison
3. Tracks the exact paths of changes within complex objects
4. Optimizes performance by using hash-based quick comparisons first

### Security Analysis

The security analysis component:

1. Evaluates the security impact of each change
2. Considers the context of the change (who made it, when, etc.)
3. Identifies potentially suspicious patterns (unusual timing, multiple changes)
4. Correlates related changes to understand the broader impact

## User Interface

The system provides interfaces for:

1. **Drift Dashboard**: Overview of recent changes with severity indicators
2. **Detailed Reports**: In-depth analysis of specific changes
3. **Configuration Comparison**: Side-by-side view of before/after states
4. **Resolution Workflow**: Tools to review, approve, or remediate changes

## Best Practices

For optimal use of the Drift Detection system:

1. **Regular Review**: Schedule regular reviews of detected changes
2. **Baseline Updates**: Update accepted baselines after approved changes
3. **Alert Tuning**: Configure alerting thresholds to prevent alert fatigue
4. **Integration**: Connect with other security monitoring systems
5. **Documentation**: Document investigation and resolution of significant drifts

## Related Documentation

- [System Architecture](./system_architecture.md)
- [Authentication Flow](./auth_flow.md)
- [Authorization Flow](./authorization_flow.md)
- [Security Overview](../security/overview.md)

# Drift Detection Architecture

This document describes the architecture and implementation of the Drift Detection system within BlindspotX Auth.

## Overview

Drift detection monitors changes in configurations, permissions, and security settings to identify potentially unauthorized or security-impacting modifications. It provides a comprehensive audit trail of system changes and alerts on security-critical modifications.

## Architectural Components

The drift detection system consists of the following components:

1. **Snapshot Manager**: Captures and stores configuration snapshots at scheduled intervals
2. **Differential Analyzer**: Compares current configuration with previous snapshots to identify changes
3. **Severity Classifier**: Categorizes and assigns severity levels to detected changes
4. **Alert Notifier**: Generates notifications based on severity and configuration
5. **Reporting Service**: Provides API endpoints for accessing drift reports and analytics

## System Flow

The drift detection process follows this flow:

1. **Snapshot Collection**: Configuration snapshots are taken at regular intervals
2. **Differential Analysis**: Current state is compared with previous snapshots
3. **Classification**: Changes are categorized and assigned severity levels
4. **Alerting**: Significant changes trigger notifications based on severity
5. **Reporting**: Comprehensive drift reports are available through the API and UI

## Drift Detection Flow Diagram

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│              │     │              │     │              │     │              │
│  Scheduled   │────>│ Configuration│────>│  Snapshot    │────>│ Differential │
│    Trigger   │     │  Collection  │     │   Storage    │     │   Analysis   │
│              │     │              │     │              │     │              │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
                                                                       │
                                                                       ▼
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│              │     │              │     │              │     │              │
│   Report     │<────│ Notification │<────│   Severity   │<────│    Change    │
│  Generation  │     │  Dispatcher  │     │ Classification│     │  Detection   │
│              │     │              │     │              │     │              │
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
```

## Deep Comparison Algorithm

The differential analyzer implements a recursive deep comparison algorithm:

1. **Initialization**: Load previous snapshot and current configuration
2. **Type Detection**: Determine data types (scalar, array, object)
3. **Recursive Comparison**:
   - For objects: Compare nested properties
   - For arrays: Match items and detect adds/removes/changes
   - For scalars: Direct value comparison
4. **Path Tracking**: Record complete dot-notation paths for changed fields
5. **Change Recording**: Document old and new values with metadata

## Severity Classification

Changes are classified into severity levels based on several factors:

| Severity | Description | Examples | Response Time |
|----------|-------------|----------|---------------|
| **CRITICAL** | Changes with immediate security impact | MFA disabled, admin rights granted, password policy disabled | Immediate |
| **HIGH** | Significant security changes | Permission escalation, firewall rule changes | Within hours |
| **MEDIUM** | Notable changes with potential security implications | Role modifications, new user accounts | Within 24 hours |
| **LOW** | Minor security-related changes | User profile updates, non-critical setting changes | Within 72 hours |
| **INFO** | Informational changes with no security impact | Cosmetic changes, documentation updates | Routine review |

The classification algorithm weighs multiple factors:

- Category of the change
- Type of operation (create, update, delete)
- Field sensitivity
- Security impact assessment

## Security-Focused Categories

The system prioritizes security-related configuration categories:

| Category | Priority | Description | Examples |
|----------|----------|-------------|----------|
| **AUTH_SETTINGS** | Critical | Authentication configuration |

