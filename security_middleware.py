"""
Security middleware for input validation and sanitization
"""
import re
import html
from functools import wraps
from flask import request, abort, g

def sanitize_input(input_string):
    """Sanitize input string to prevent XSS attacks"""
    if input_string is None:
        return None
    return html.escape(str(input_string))

def validate_email(email):
    """Validate email format"""
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_username(username):
    """Validate username format"""
    if not username:
        return False
    # Alphanumeric with underscores and hyphens, 3-30 characters
    pattern = r'^[a-zA-Z0-9_-]{3,30}$'
    return bool(re.match(pattern, username))

def validate_password_strength(password):
    """
    Validate password strength
    - At least 8 characters
    - Contains uppercase, lowercase, number, and special character
    """
    if not password or len(password) < 8:
        return False
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    return has_upper and has_lower and has_digit and has_special

def validate_request_json(required_fields=None, field_validators=None):
    """
    Decorator to validate JSON request data
    
    Args:
        required_fields: List of required fields
        field_validators: Dict mapping field names to validator functions
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Check if request has JSON data
            if not request.is_json:
                abort(400, description="Request must be JSON")
            
            data = request.get_json()
            
            # Validate required fields
            if required_fields:
                for field in required_fields:
                    if field not in data or data[field] is None:
                        abort(400, description=f"Missing required field: {field}")
            
            # Apply field-specific validators
            if field_validators:
                for field, validator in field_validators.items():
                    if field in data and data[field] is not None:
                        if not validator(data[field]):
                            abort(400, description=f"Invalid value for field: {field}")
            
            # Store sanitized data in g for the route to use
            g.validated_data = {
                k: sanitize_input(v) if isinstance(v, str) else v 
                for k, v in data.items()
            }
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Example usage:
# @app.route('/api/register', methods=['POST'])
# @validate_request_json(
#     required_fields=['username', 'email', 'password'],
#     field_validators={
#         'username': validate_username,
#         'email': validate_email,
#         'password': validate_password_strength
#     }
# )
# def register():
#     # Access validated and sanitized data
#     data = g.validated_data
#     # Process registration...