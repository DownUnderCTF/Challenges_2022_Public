from models import db, BaseModel

class Unit(BaseModel):
    __tablename__ = "units"

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(8), unique=True, nullable=False)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(256), default='')
    coordinator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    
    coordinator = db.relationship("User", back_populates="coordinator_of", uselist=False)
    students = db.relationship("User", secondary="enrollments", backref="units")
    assessments = db.relationship("Assessment", back_populates="unit")

    def __repr__(self):
        return '<Unit code=%r>' % self.code

    def serialize(self) -> dict:
        result = super().serialize()

        # Already have ID stored
        result.pop("coordinator")

        new_students = [student.id for student in result['students']]
        new_assessments = [assessment.id for assessment in result['assessments']]

        result['students'] = new_students
        result['assessments'] = new_assessments

        return result