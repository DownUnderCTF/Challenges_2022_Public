from flask import jsonify, request
from models.users import User

def json_response(data, status="success"):
    return jsonify({"status": status, "result": data})

def get_user() -> User:
    return request.user

def status_404():
    return json_response("This path has gone walkabout!", status="error")

def status_403():
    return json_response("Oi! You aren't allowed to do that!", status="error")