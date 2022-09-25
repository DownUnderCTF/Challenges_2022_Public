from flask_sqlalchemy import SQLAlchemy
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash
from flask_jwt_extended import create_access_token, set_access_cookies, unset_jwt_cookies,current_user, jwt_required, JWTManager
from werkzeug.security import generate_password_hash, check_password_hash
import os


app = Flask(__name__)


app.config['SECRET_KEY'] = 'onepiece'
app.config["JWT_SECRET_KEY"] = "onepiece"  # Change this!
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies", "json", "query_string"]

jwt = JWTManager(app)
db = SQLAlchemy(app)

@app.before_first_request
def create_tables():
    db.create_all()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    description = db.Column(db.String(1000))


@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

@app.route('/login')
def login():
    return render_template('login.html', current_user=current_user)

@app.route('/')
@jwt_required(optional=True)
def index():
    return render_template('index.html', current_user=current_user)

@app.route('/signup')
def signup():
    return render_template('signup.html', current_user=current_user)

@app.route('/profile')
@jwt_required()
def profile():
    return render_template('profile.html', name=current_user.name, description=current_user.description, current_user=current_user)

@app.route("/login", methods=["POST"])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('login'))

    access_token = create_access_token(identity=user)
    response = redirect(url_for('profile'))
    set_access_cookies(response, access_token)
    return response

@app.route('/logout')
@jwt_required()
def logout():
    response = redirect(url_for('login'))
    unset_jwt_cookies(response)
    print('made it')
    return response

@app.route('/signup', methods=['POST'])
def signup_post():
    username = request.form.get('username')
    name = request.form.get('name')
    password = request.form.get('password')
    description = request.form.get('description')

    user = User.query.filter_by(username=username).first()

    if user:
        flash('Username already exists')
        return redirect(url_for('signup'))

    new_user = User(username=username, name=name, description=description, password=generate_password_hash(password, method='sha256'))

    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))


if __name__ == "__main__":
    port = int(os.environ.get('PORT', 1337))
    app.run(debug=False, host='0.0.0.0', port=port)
