from app.core.config import settings

def verify_drift_settings():
    print("Drift Detection Settings Verification:")
    print(f"Enabled: {settings.DRIFT_DETECTION_ENABLED}")
    print(f"Check Interval: {settings.DRIFT_CHECK_INTERVAL} seconds")
    print(f"Retention Policy: {settings.DRIFT_RETENTION_POLICY}")
    print(f"Alerts Enabled: {settings.DRIFT_ALERT_ENABLED}")
    print(f"Security Alerts: {settings.DRIFT_SECURITY_ALERTS}")

if __name__ == "__main__":
    verify_drift_settings()

