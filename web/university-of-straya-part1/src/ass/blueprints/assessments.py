from flask import Blueprint, request, send_from_directory, send_file
import middleware
import utils
import utils.assessments as assessment_utils
from models import db
from models.assessments import Assessment, AssessmentSubmission

import base64, os


assessment_blueprint = Blueprint('assessment', __name__, url_prefix='/api/assessments')

@assessment_blueprint.route('/', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('student')
def get_assessments():
    if not middleware.had_admin_privs():
        user = utils.get_user()
        units = user.coordinator_of + user.units
        units = [u.id for u in units]
        assessments = Assessment.query.filter(Assessment.unit_id.in_(units)).all()
    else:
        assessments = Assessment.query.all()

    return utils.json_response(Assessment.serialize_list(assessments))

@assessment_blueprint.route('/<assessment_id>', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('student')
def get_assessment(assessment_id: int):
    assessment = Assessment.query.get(assessment_id)
    if assessment is None:
        return utils.status_404()
    unit = assessment.unit

    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not (user in unit.students or user == unit.coordinator):
            return utils.status_404()

    return utils.json_response(assessment.serialize())

@assessment_blueprint.route('/<assessment_id>/submit', methods=['POST'])
@middleware.logged_in
@middleware.has_permission('student')
@middleware.is_json
@middleware.has_json_keys([
    ('name', str),
    ('base64_file', str)
])
def submit_assessment(assessment_id: int):
    assessment = Assessment.query.get(assessment_id)
    if assessment is None:
        return utils.status_404()

    args = request.get_json()
    name = args['name']
    base64_file = args['base64_file']

    try:
        data = base64.b64decode(base64_file.encode())
    except:
        return utils.json_response("Ya monga! The file sent was goofed up!", status="error")

    file_type = assessment_utils.get_file_type(data)

    if assessment.submission_type == assessment_utils.ARCHIVE_TYPE or assessment.submission_type == assessment_utils.JAVA_TYPE:
        if not file_type in assessment_utils.ALLOWED_MIMES:
            return utils.json_response("You are such a monga! Upload only a zip, tar or tar.gz file!", status="error")

    folder, filename = assessment_utils.save_to_random_file(data)
    path = os.path.join(folder, filename)

    if assessment.submission_type == assessment_utils.ARCHIVE_TYPE or assessment.submission_type == assessment_utils.JAVA_TYPE:
        path = assessment_utils.extract_file(path, file_type)

    if assessment.submission_type == assessment_utils.JAVA_TYPE:
        if not assessment_utils.check_java_is_valid(path):
            return utils.json_response("Lol you cannot even program Java! We couldn't compile your code!", status="error")
    
    submission = AssessmentSubmission(
        name=name,
        path=path,
        file_type=file_type,
        user=utils.get_user(),
        assessment=assessment
    )

    db.session.add(submission)
    db.session.commit()

    return utils.json_response(submission.serialize())

@assessment_blueprint.route('/submissions', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('student')
def get_all_assessment_submissions():
    user = utils.get_user()
    if middleware.had_admin_privs():
        submissions = AssessmentSubmission.query.all()
    else:
        ##
        # Need to allow coordinators to list all submissions
        ##
        user = utils.get_user()
        submissions = AssessmentSubmission.query.filter(AssessmentSubmission.user_id == user.id).all()

    return utils.json_response(AssessmentSubmission.serialize_list(submissions))

@assessment_blueprint.route('/<assessment_id>/submissions', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('student')
def get_assessment_submissions(assessment_id: int):
    assessment = Assessment.query.get(assessment_id)
    if assessment is None:
        return utils.status_404()

    user = utils.get_user()
    submissions = AssessmentSubmission.query.filter(AssessmentSubmission.assessment_id == assessment.id)
    if middleware.had_admin_privs() or assessment.assessment.unit in user.coordinator_of:
        submissions = submissions.filter(AssessmentSubmission.user_id == user.id)

    return utils.json_response(AssessmentSubmission.serialize_list(submissions.all()))

@assessment_blueprint.route('/submissions/<submission_id>', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('student')
def get_submission_info(submission_id: int):
    submission = AssessmentSubmission.query.get(submission_id)
    if submission is None:
        return utils.status_404()
    
    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not submission.assessment.unit in user.coordinator_of:
            if not submission.user == user:
                return utils.status_404()
            
    return utils.json_response(submission.serialize())

@assessment_blueprint.route('/submissions/<submission_id>/files', methods=['GET'])
@middleware.logged_in
@middleware.has_permission('student')
def get_submission(submission_id: int):
    submission = AssessmentSubmission.query.get(submission_id)
    if submission is None:
        return utils.status_404()
    
    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not submission.assessment.unit in user.coordinator_of:
            if not submission.user == user:
                return utils.status_404()
            
    assessment_type = submission.assessment.submission_type

    if assessment_type == assessment_utils.JAVA_TYPE or assessment_type == assessment_utils.ARCHIVE_TYPE:
        path = submission.path
        return utils.json_response(assessment_utils.list_files(path))
    return utils.json_response("Oi ya cannot list files! This assessment only excepts single file uploads!", status="error")

@assessment_blueprint.route('/submissions/<submission_id>/download')
@middleware.logged_in
@middleware.has_permission('student')
def download_submission(submission_id: int):
    submission = AssessmentSubmission.query.get(submission_id)
    if submission is None:
        return utils.status_404()
    
    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not submission.assessment.unit in user.coordinator_of:
            if not submission.user == user:
                return utils.status_404()

    assessment_type = submission.assessment.submission_type

    if assessment_type == assessment_utils.JAVA_TYPE or assessment_type == assessment_utils.ARCHIVE_TYPE:
        return utils.json_response("You can only download individual files for this assessment type!", status="error")

    return send_file(submission.path, as_attachment=True)

@assessment_blueprint.route('/submissions/<submission_id>/download/<path:filename>')
@middleware.logged_in
@middleware.has_permission('student')
def download_archive_submission_file(submission_id: int, filename: str):
    submission = AssessmentSubmission.query.get(submission_id)
    if submission is None:
        return utils.status_404()
    
    if not middleware.had_admin_privs():
        user = utils.get_user()
        if not submission.assessment.unit in user.coordinator_of:
            if not submission.user == user:
                return utils.status_404()

    assessment_type = submission.assessment.submission_type

    if not (assessment_type == assessment_utils.JAVA_TYPE or assessment_type == assessment_utils.ARCHIVE_TYPE):
        return utils.json_response("This assessment type does not allow downloading specific files!", status="error")

    return send_from_directory(submission.path, filename, as_attachment=True)