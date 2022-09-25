from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect

db = SQLAlchemy()

def get_or_create(model, **kwargs) -> tuple:
    instance = db.session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance, False
    else:
        instance = model(**kwargs)
        db.session.add(instance)
        db.session.commit()
        return instance, True

class BaseModel(db.Model):
    __abstract__ = True

    def serialize(self) -> dict:
        return {c: getattr(self, c) for c in inspect(self).attrs.keys()}

    @staticmethod
    def serialize_list(l) -> list:
        return [m.serialize() for m in l]

enrollments_association = db.Table(
    'enrollments',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('unit_id', db.Integer, db.ForeignKey('units.id'))
)