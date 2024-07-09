from flask import Blueprint, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from start.models import User, Organisation, OrganisationUsers

from start import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/index', methods=['GET'])
def index():
    return jsonify({'errors': 'Trying'})


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    required_fields = ['firstName', 'lastName', 'email', 'password', 'phone']
    errors = []

    for field in required_fields:
        if field not in data:
            errors.append({'field': field, 'message': f'{field} is required'})

    if errors:
        return jsonify({'errors': errors}), 422

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'errors': [{'field': 'email', 'message': 'Email already registered'}]}), 422

    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(
        firstName=data['firstName'],
        lastName=data['lastName'],
        email=data['email'],
        password=hashed_password,
        phone=data['phone']
    )

    db.session.add(new_user)
    db.session.commit()

    new_org = Organisation(name=f"{data['firstName']}'s Organisation")
    db.session.add(new_org)
    db.session.commit()

    association = OrganisationUsers(user_id=new_user.userId, org_id=new_org.orgId)
    db.session.add(association)
    db.session.commit()

    access_token = create_access_token(identity=new_user.email)
    return jsonify({
        "status": "success",
        "message": "Registration successful",
        "data": {
            "accessToken": access_token,
            "user": {
                "userId": new_user.userId,
                "firstName": new_user.firstName,
                "lastName": new_user.lastName,
                "email": new_user.email,
                "phone": new_user.phone
            }
        }
    }), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify({'status': 'Bad request', 'message': 'Authentication failed', 'statusCode': 401}), 401

    access_token = create_access_token(identity=user.email)
    return jsonify({
        "status": "success",
        "message": "Login successful",
        "data": {
            "accessToken": access_token,
            "user": {
                "userId": user.userId,
                "firstName": user.firstName,
                "lastName": user.lastName,
                "email": user.email,
                "phone": user.phone
            }
        }
    }), 200

@auth_bp.route('/api/users/<id>', methods=['GET'])
@jwt_required()
def get_user(id):
    current_user = get_jwt_identity()
    user = User.query.filter_by(userId=id).first()

    if not user or user.email != current_user:
        return jsonify({'status': 'Bad request', 'message': 'User not found or unauthorized access', 'statusCode': 401}), 401

    return jsonify({
        "status": "success",
        "message": "User retrieved",
        "data": {
            "userId": user.userId,
            "firstName": user.firstName,
            "lastName": user.lastName,
            "email": user.email,
            "phone": user.phone
        }
    }), 200

@auth_bp.route('/api/organisations', methods=['GET'])
@jwt_required()
def get_organisations():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user).first()
    organisations = user.organisations

    orgs_data = [
        {
            "orgId": org.orgId,
            "name": org.name,
            "description": org.description
        }
        for org in organisations
    ]

    return jsonify({
        "status": "success",
        "message": "Organisations retrieved",
        "data": {"organisations": orgs_data}
    }), 200

@auth_bp.route('/api/organisations/<org_id>', methods=['GET'])
@jwt_required()
def get_organisation(org_id):
    current_user = get_jwt_identity()
    organisation = Organisation.query.filter_by(orgId=org_id).first()

    if not organisation or current_user not in [user.email for user in organisation.users]:
        return jsonify({'status': 'Bad request', 'message': 'Organisation not found or unauthorized access', 'statusCode': 401}), 401

    return jsonify({
        "status": "success",
        "message": "Organisation retrieved",
        "data": {
            "orgId": organisation.orgId,
            "name": organisation.name,
            "description": organisation.description
        }
    }), 200

@auth_bp.route('/api/organisations', methods=['POST'])
@jwt_required()
def create_organisation():
    data = request.json
    current_user = get_jwt_identity()

    if not all(key in data for key in ('name', 'description')):
        return jsonify(status="Bad request", message="Client error", statusCode=400), 400

    new_org = Organisation(
        name=data['name'],
        description=data['description']
    )
    db.session.add(new_org)
    db.session.commit()

    user = User.query.filter_by(email=current_user).first()
    association = OrganisationUsers(user_id=user.userId, org_id=new_org.orgId)
    db.session.add(association)
    db.session.commit()

    return jsonify(status="success", message="Organisation created successfully", data={
        "orgId": new_org.orgId,
        "name": new_org.name,
        "description": new_org.description
    }), 201

@auth_bp.route('/api/organisations/<org_id>/users', methods=['POST'])
@jwt_required()
def add_user_to_organisation(org_id):
    data = request.json
    current_user = get_jwt_identity()
    user_to_add = User.query.filter_by(userId=data['userId']).first()
    organisation = Organisation.query.filter_by(orgId=org_id).first()

    if not user_to_add or not organisation or current_user not in [user.email for user in organisation.users]:
        return jsonify(status="Bad request", message="Client error", statusCode=400), 400

    association = OrganisationUsers(user_id=user_to_add.userId, org_id=organisation.orgId)
    db.session.add(association)
    db.session.commit()

    return jsonify(status="success", message="User added to organisation successfully"), 200
