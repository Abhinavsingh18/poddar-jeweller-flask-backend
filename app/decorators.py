# In app/decorators.py (or at the top of app/routes.py)
from functools import wraps
import jwt
from flask import request, jsonify, current_app

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '): # Check for 'Bearer ' prefix
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            secret_key = current_app.config['SECRET_KEY']
            # Specify the algorithm used during encoding
            data = jwt.decode(token, secret_key, algorithms=["HS256"])
            # You can add more checks here, e.g., if data['role'] == 'admin'
            if data.get('role') != 'admin':
                 current_app.logger.warning(f"Token validated for user {data.get('username')} but role is not admin.")
                 return jsonify({'message': 'Admin privileges required!'}), 403
            # You might want to pass the user ID or username to the route if needed
            # g.user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            current_app.logger.warning("Attempt to use an expired token.")
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            current_app.logger.warning("Attempt to use an invalid token.")
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            current_app.logger.error(f"Token validation/decoding error: {e}", exc_info=True)
            return jsonify({'message': 'Token processing error'}), 500

        return f(*args, **kwargs)
    return decorated
