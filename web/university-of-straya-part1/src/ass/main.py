from flask import Flask
from models import db
from blueprints import *
from models.users import User
from models.units import Unit
from models.assessments import Assessment
import utils.assessments as assessment_utils
from utils.cache import cache
import bcrypt

import os, random, datetime, argparse

app = Flask(
    __name__,
    static_url_path='/',
    static_folder='static/'    
)

cache.init_app(app, config={'CACHE_TYPE': 'SimpleCache'})

app.secret_key = os.urandom(128)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////tmp/ass.db"
with open('/etc/assapi/private.pem', 'r') as f:
    app.config['API_PRIVATE_KEY'] = f.read()
app.config['API_PUBLIC_KEY'] = "/etc/assapi/public.pem"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return app.send_static_file("index.html")

@app.route('/dashboard')
def dashboard():
    return app.send_static_file("dashboard.html")

@app.route('/admin')
def admin():
    return app.send_static_file("admin.html")

@app.route('/logout')
def logout():
    return app.send_static_file("logout.html")

app.register_blueprint(auth_blueprint)
app.register_blueprint(user_blueprint)
app.register_blueprint(unit_blueprint)
app.register_blueprint(assessment_blueprint)

def setup_db():
    admin = User(username="Jeff", email="admin@ass.com", role="admin", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode())
    staff = User(username="Kevin Rudd", email="kevin07@murdochcansuckafatschlong.com", role="staff", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode())

    students = [
        User(username="Sassy the Sasquatch", email="sassy@sasquatch.com", role="student", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode()),
        User(username="Ash", email="barty@gmail.com", role="student", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode()),
        User(username="Donny the Dealer", email="donny@sasquatch.com", role="student", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode()),
        User(username="Barry", email="bazza@gmail.com", role="student", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode()),
        User(username="Nigel Brown", email="nigel.brown@gmail.com", role="student", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode()),
        User(username="Grace O'Neill", email="grace@gmail.com", role="student", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode()),
        User(username="Sharon Smith", email="shazza@gmail.com", role="student", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode()),
        User(username="Clarence", email="fkwit@loser.com", role="student", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode()),
        User(username="John", email="john@gmail.com", role="student", password=bcrypt.hashpw(os.urandom(16).hex().encode(), bcrypt.gensalt(rounds=6)).decode())
    ]

    users = [admin, staff] + students

    for u in users:
        db.session.add(u)

    units = [
        Unit(code="PHIL1021", name="How to not be an eshay", description="How to not be a eshay and be a decent person", coordinator=staff),
        Unit(code="CITS1070", name="Python for Monkes", description="How to write code in the easiest programming language.", coordinator=staff),
        Unit(code="COOK3804", name="Advanced Chiko Roll Cooking Techniques", description="Master the art of cooking chiko roles", coordinator=staff),
        Unit(code="MATH3013", name="Advanced Arithmetic", description="Learn how to solve 2+2", coordinator=staff),
        Unit(code="ARTS2102", name="Finger Painting", description="Professional finger painting unit", coordinator=staff),
        Unit(code="PHIL2200", name="Professional Banter", description="Yea nah, cheers for the hecs for doing this unit", coordinator=staff),
        Unit(code="CITS3200", name="Capstone Project", description="Where computer students go to cry trying to work together as a team on a project and 75% of the team does jack all.", coordinator=staff)
    ]

    for u in units:
        db.session.add(u)
        for s in random.choices(students, k=5):
            u.students.append(s)

        for i in range(4):
            a = Assessment(
                name="Assessment {}".format(i+1), 
                submission_type=random.choice([
                    assessment_utils.ARCHIVE_TYPE,
                    assessment_utils.FILE_TYPE
                ]),
                total_marks=25,
                deadline = datetime.datetime.utcnow() + datetime.timedelta(weeks=random.randint(1,9))
            )
            db.session.add(a)
            u.assessments.append(a)

    db.session.commit()
    
def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--setup',
        help='Run setup script for database',
        action='store_true'
    )

    parser.add_argument(
        '--debug',
        help='Run in debug mode',
        action='store_true'
    )

    return parser.parse_args()

def main(args):
    if args.setup:
        with app.app_context():
            setup_db()
        return
    else:
        app.run(host="0.0.0.0", port=8080, debug=args.debug)

if __name__ == "__main__":
    args = parse_args()
    main(args)