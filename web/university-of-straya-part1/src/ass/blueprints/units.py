from flask import Blueprint, request
import middleware
import utils
import utils.assessments as assessment_utils
from models import db
from models.users import User
from models.units import Unit
from models.assessments import Assessment
from datetime import datetime

unit_blueprint = Blueprint('unit', __name__, url_prefix='/api/units')

@unit_blueprint.route('/', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('student')
def get_units():
    if middleware.had_admin_privs():
        units = Unit.query.all()
    else:
        user = utils.get_user()
        units = user.coordinator_of + user.units

    return utils.json_response(Unit.serialize_list(units))

@unit_blueprint.route('/<id>', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('student')
def get_unit(id: int):
    unit = Unit.query.get(id)
    if unit is None:
        return utils.status_404()

    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not (user in unit.students or user == unit.coordinator):
            return utils.status_404()
    
    return utils.json_response(unit.serialize())

@unit_blueprint.route('/<id>/assessments', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('student')
def get_unit_assessments(id: int):
    unit = Unit.query.get(id)
    if unit is None:
        return utils.status_404()

    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not (user in unit.students or user == unit.coordinator):
            return utils.status_404()
    
    return utils.json_response(Assessment.serialize_list(unit.assessments))
        
@unit_blueprint.route('/<id>/addstudent', methods=['POST'])
@middleware.logged_in
@middleware.has_permission('staff')
@middleware.is_json
@middleware.has_json_keys([('student_id', int)])
def add_student(id: int):
    unit = Unit.query.get(id)
    if unit is None:
        return utils.status_404()

    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not user == unit.coordinator:
            return utils.status_403()

    student_id = request.get_json()['student_id']
    student_user = User.query.get(student_id)

    unit.students.append(student_user)
    db.session.commit()
    return utils.json_response("Success!")

@unit_blueprint.route('/<id>/access', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('staff')
def has_admin_access(id: int):
    unit = Unit.query.get(id)
    if unit is None:
        return utils.status_404()

    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not user == unit.coordinator:
            return utils.status_403()
    return utils.json_response("You are admin for this unit!")

@unit_blueprint.route('/<id>/students', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('student')
def get_students_for_unit(id: int):
    unit = Unit.query.get(id)
    if unit is None:
        return utils.status_404()

    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not (user in unit.students or user == unit.coordinator):
            return utils.status_404()

    users = unit.students

    return utils.json_response([u.serialize_no_email() for u in users])

@unit_blueprint.route('/<id>/addassessment', methods=['POST'])
@middleware.logged_in
@middleware.has_permission('staff')
@middleware.is_json
@middleware.has_json_keys([
    ('name', str),
    ('description', str),
    ('submission_type', str),
    ('total_marks', int),
    ('deadline_epoch', int)
])
def add_assessment(id: int):
    unit = Unit.query.get(id)
    if unit is None:
        return utils.status_404()

    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not user == unit.coordinator:
            return utils.status_403()

    args = request.get_json()
    name = args['name']
    description = args['description']
    submission_type = args['submission_type']

    if not submission_type in assessment_utils.ASSESSMENT_TYPES:
        return utils.json_response("bruh how did you even send an incorrect assessment type???", status="error")

    total_marks = args['total_marks']
    deadline = datetime.fromtimestamp(args['deadline_epoch'])

    assessment = Assessment(
        name=name,
        description=description,
        submission_type=submission_type,
        total_marks=total_marks,
        deadline=deadline,
        unit=unit
    )

    db.session.add(assessment)
    db.session.commit()

    return utils.json_response(assessment.serialize())