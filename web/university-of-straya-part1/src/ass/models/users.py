from models import db, BaseModel

class User(BaseModel):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False, unique=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(80), default="student")

    coordinator_of = db.relationship("Unit", back_populates="coordinator")
    submissions = db.relationship("AssessmentSubmission", back_populates="user")

    def __repr__(self):
        return '<User username=%r>' % self.username

    def serialize(self) -> dict:
        result = super().serialize()
        result.pop('password')
        new_coordinator_of = [unit.id for unit in result['coordinator_of']]
        new_submissions = [submission.id for submission in result['submissions']]
        new_units = [unit.id for unit in result['units']]

        result['coordinator_of'] = new_coordinator_of
        result['submissions'] = new_submissions
        result['units'] = new_units
            
        return result

    def serialize_no_email(self):
        result = self.serialize()
        result.pop('email')
        return result