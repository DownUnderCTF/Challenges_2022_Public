from flask import Blueprint, request, session
import middleware
import utils
from models import db
from models.users import User

user_blueprint = Blueprint('user', __name__, url_prefix='/api/users')

@user_blueprint.route('/<user_id>', methods=["GET"])
@middleware.logged_in
def get_user(user_id: str):
    if not middleware.has_permission_or_is_user("admin", user_id):
        return utils.json_response("Fob off ya nob head! You don't have permission!", status="error")

    user = User.query.get(user_id)

    if user is None:
        return utils.status_404()

    return utils.json_response(user.serialize())

@user_blueprint.route('/', methods=["GET"])
@middleware.logged_in
@middleware.has_permission("admin")
def get_users():
    users = User.query.all()
    return utils.json_response(User.serialize_list(users))
    
