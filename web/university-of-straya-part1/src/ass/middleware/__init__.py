from functools import wraps
from flask import request
from utils import json_response
from utils.auth import validate_token
from models.users import User

def is_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return json_response("Look at this monga, couldn't even send me a JSON document! 🤣", status="error")
        return f(*args, **kwargs)
    return decorated_function

def has_json_keys(list_of_keys: list):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            json_body: dict = request.get_json()
            for key, key_type in list_of_keys:
                in_json = json_body.get(key, None)
                if not isinstance(in_json, key_type):
                    return json_response(
                        "Ya Dope! You sent a goofed request! 🤦‍♀️",
                        status="error"
                    )
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        access_token = request.headers.get("Authorization", None)
        if access_token is None:
            return json_response(
                "You need to be authenticated to access this API!",
                status="error"
            )

        access_token = access_token.replace("Bearer ", "")

        try:
            user_token: str = validate_token(access_token)
        except Exception as e:
            return json_response(
                "M8 you broke something: {}".format(e),
                status="error"
            )
            
        user = User.query.get(user_token['id'])
        if user is None:
            return json_response(
                "I wouldn't have any clue how you goofed up so badly that you have a valid token but no user...",
                status="error"
            )
        request.user = user
        return f(*args, **kwargs)
    return decorated_function

def has_permission(role: str):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = request.user
            user_role = user.role
            if user_role == 'admin':
                return f(*args, **kwargs)
            elif user_role == 'staff' and (role == 'staff' or role == 'student'):
                return f(*args, **kwargs)
            elif user_role == role:
                return f(*args, **kwargs)
            return json_response("Fob off ya nob head! You don't have permission!", status="error")
        return decorated_function
    return decorator

def has_permission_or_is_user(role: str, sub: str) -> bool:
    user = request.user
    user_role = user.role
    if user_role == 'admin':
        return True
    elif user_role == 'staff' and (role == 'staff' or role == 'student'):
        return True
    elif user_role == role:
        return True
    return False

def had_admin_privs() -> bool:
    return request.user.role == 'admin'