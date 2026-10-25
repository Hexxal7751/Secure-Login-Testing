"""
Security logging module for tracking security events and potential threats
"""
import logging
import os
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler
from flask import request, session, has_request_context

# Configure security logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

# Set up rotating file handler for security logs
security_handler = RotatingFileHandler(
    'logs/security.log',
    maxBytes=10485760,  # 10MB
    backupCount=10
)

# Define log format
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
security_handler.setFormatter(formatter)
security_logger.addHandler(security_handler)


def log_security_event(event_type, details, level='INFO'):
    """
    Log a security event with standardized format

    Args:
        event_type: Type of security event (login_success, login_failure, etc.)
        details: Dict containing event details
        level: Logging level (INFO, WARNING, ERROR, CRITICAL)
    """
    in_request = has_request_context()
    ip = request.remote_addr if in_request else 'unknown'
    user_agent = request.headers.get('User-Agent', 'unknown') if in_request else 'unknown'
    user_id = session.get('user_id', 'anonymous') if in_request else 'anonymous'

    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': ip,
        'user_agent': user_agent,
        'details': details
    }

    log_message = json.dumps(log_entry)
    if level == 'WARNING':
        security_logger.warning(log_message)
    elif level == 'ERROR':
        security_logger.error(log_message)
    elif level == 'CRITICAL':
        security_logger.critical(log_message)
    else:
        security_logger.info(log_message)


# Security event types
LOGIN_SUCCESS = 'login_success'
LOGIN_FAILURE = 'login_failure'
REGISTRATION = 'user_registration'
PASSWORD_CHANGE = 'password_change'
ACCOUNT_LOCKOUT = 'account_lockout'
ACCOUNT_DELETED = 'account_deleted'
SUSPICIOUS_ACTIVITY = 'suspicious_activity'
PERMISSION_DENIED = 'permission_denied'
ADMIN_ACTION = 'admin_action'
