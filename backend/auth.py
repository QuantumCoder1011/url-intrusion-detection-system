import os
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify

JWT_SECRET = os.environ.get('JWT_SECRET') or 'super-secret-ids-key-change-in-prod'
JWT_ALGORITHM = 'HS256'

def generate_token(user_id: int, role: str):
    payload = {
        'user_id': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=12)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Allow skipping auth in TESTING_MODE if desired, but let's keep it secure
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Missing or invalid token'}), 401
            
            token = auth_header.split(' ')[1]
            payload = decode_token(token)
            
            if not payload:
                return jsonify({'error': 'Token is invalid or expired'}), 401
                
            if role and payload.get('role') != role:
                return jsonify({'error': 'Unauthorized for this role'}), 403
                
            # Attach user info to request
            request.user = payload
            return f(*args, **kwargs)
        return decorated_function
    return decorator
