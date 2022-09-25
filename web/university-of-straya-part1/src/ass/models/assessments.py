from models import db, BaseModel
from datetime import datetime

class Assessment(BaseModel):
    __tablename__ = "assessments"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(1024), nullable=True)
    submission_type = db.Column(db.String(21), nullable=False)
    total_marks = db.Column(db.Integer, nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    start = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    unit_id = db.Column(db.Integer, db.ForeignKey('units.id'))

    unit = db.relationship("Unit", back_populates="assessments", uselist=False)
    submissions = db.relationship("AssessmentSubmission", back_populates="assessment")

    def __repr__(self):
        return '<Assessment id=%r>' % self.id

    def serialize(self):
        result = super().serialize()
        result.pop("submissions")
        result.pop("unit")
        return result

class AssessmentSubmission(BaseModel):
    __tablename__ = "submissions"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    path = db.Column(db.String(256), nullable=False)
    submitted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    file_type = db.Column(db.String(80), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessments.id'))

    user = db.relationship('User', back_populates="submissions", uselist=False)
    assessment = db.relationship('Assessment', back_populates="submissions", uselist=False)

    def serialize(self) -> dict:
        result = super().serialize()
        result.pop("user")
        result.pop("assessment")
        result.pop("path")
        return result

    def __repr__(self):
        return '<AssessmentSubmission id=%r>' % self.id