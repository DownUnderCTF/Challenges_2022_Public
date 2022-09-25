from flask import Blueprint, request, send_file, current_app, redirect
import middleware
import utils
import utils.auth as auth_utils
from models import db
from models.users import User
import bcrypt

auth_blueprint = Blueprint('auth', __name__, url_prefix='/api/auth')

@auth_blueprint.route('/access', methods=["GET"])
@middleware.logged_in
def has_access():
    if request.user.role in ["admin", "staff", "student"]:
        return utils.json_response(
            "You can access this ass!"
        )
    return utils.json_response(
        "You cannot access this ass!",
        status="error"
    )

@auth_blueprint.route('/isstaff', methods=["GET"])
@middleware.logged_in
def is_admin():
    if request.user.role in ["admin", "staff"]:
        return utils.json_response(
            "DUCTF{iSs_t0_h0vSt0n_c4n_U_h3r3_uS_oR_r_w3_b31nG_r3dIrEcTeD!1!}"
        )
    return utils.json_response(
        "Bugger off pleb",
        status="error"
    )

@auth_blueprint.route('/login', methods=["POST"])
@middleware.is_json
@middleware.has_json_keys([("email", str), ("password", str)])
def login():
    args: dict = request.get_json()
    email: str = args["email"]
    password: str = args["password"]

    attempted_user = User.query.filter(User.email == email).first()
    if attempted_user is None:
        return utils.json_response(
            "Invalid email or password ya drongo!",
            status="error"
        )

    if bcrypt.checkpw(password.encode(), attempted_user.password.encode()):
        resp = utils.json_response({
            "msg": "Welcome to ASS!", 
            "id": attempted_user.id,
            "access_token": auth_utils.login_user(attempted_user.id)
        })
        # resp.set_cookie('jwt_token', auth_utils.login_user(attempted_user.id), httponly=True)
        return resp
    return utils.json_response(
        "Invalid email or password ya drongo!",
        status="error"
    )

@auth_blueprint.route('/register', methods=["POST"])
@middleware.is_json
@middleware.has_json_keys([("email", str), ("username", str), ("password", str)])
def register():
    args: dict = request.get_json()
    email: str = args["email"]
    username: str = args["username"]
    password: str = args["password"]

    if len(User.query.filter(User.email == email).all()) > 0:
        return utils.json_response(
            "Someone has already registered with that email!",
            status="error"
        )
    
    new_user = User(
        email=email,
        username=username,
        password=bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=6)).decode()
    )
    db.session.add(new_user)
    db.session.commit()
    return utils.json_response(
        "Successfully created your account!"
    )

@auth_blueprint.route('/logout', methods=["GET"])
def logout():
    # Keep this route incase we need to log logouts in the future
    redirect_path = request.args.get("redirect", "/logout")
    return redirect(redirect_path)

@auth_blueprint.route('/pub-key', methods=["GET"])
def get_pub_key():
    return send_file(current_app.config["API_PUBLIC_KEY"])