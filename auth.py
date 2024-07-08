from werkzeug.security import generate_password_hash
import app
from models import User, Organisation, OrganisationUsers

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    if not all(key in data for key in ('firstName', 'lastName', 'email', 'password', 'phone')):
        return jsonify(status="Bad request", message="Registration unsuccessful", statusCode=400), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify(status="Bad request", message="Email already registered", statusCode=400), 400

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(
        first_name=data['firstName'],
        last_name=data['lastName'],
        email=data['email'],
        password=hashed_password,
        phone=data['phone']
    )
    db.session.add(new_user)
    db.session.commit()

    new_org = Organisation(
        name=f"{data['firstName']}'s Organisation"
    )
    db.session.add(new_org)
    db.session.commit()

    association = OrganisationUsers(user_id=new_user.user_id, org_id=new_org.org_id)
    db.session.add(association)
    db.session.commit()

    access_token = create_access_token(identity=new_user.email)
    return jsonify(status="success", message="Registration successful", data={
        "accessToken": access_token,
        "user": {
            "userId": new_user.user_id,
            "firstName": new_user.first_name,
            "lastName": new_user.last_name,
            "email": new_user.email,
            "phone": new_user.phone
        }
    }), 201


@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(email=data['email']).first()

    if not user or not check_password_hash(user.password, data['password']):
        return jsonify(status="Bad request", message="Authentication failed", statusCode=401), 401

    access_token = create_access_token(identity=user.email)
    return jsonify(status="success", message="Login successful", data={
        "accessToken": access_token,
        "user": {
            "userId": user.user_id,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "email": user.email,
            "phone": user.phone
        }
    }), 200

@app.route('/api/users/<id>', methods=['GET'])
@jwt_required()
def get_user(id):
    current_user = get_jwt_identity()
    user = User.query.filter_by(user_id=id).first()

    if not user or user.email != current_user:
        return jsonify(status="Bad request", message="User not found or unauthorized access", statusCode=401), 401

    return jsonify(status="success", message="User retrieved", data={
        "userId": user.user_id,
        "firstName": user.first_name,
        "lastName": user.last_name,
        "email": user.email,
        "phone": user.phone
    }), 200


@app.route('/api/organisations', methods=['GET'])
@jwt_required()
def get_organisations():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user).first()
    organisations = user.organisations

    orgs_data = [
        {
            "orgId": org.org_id,
            "name": org.name,
            "description": org.description
        }
        for org in organisations
    ]

    return jsonify(status="success", message="Organisations retrieved", data={"organisations": orgs_data}), 200


@app.route('/api/organisations/<org_id>', methods=['GET'])
@jwt_required()
def get_organisation(org_id):
    current_user = get_jwt_identity()
    organisation = Organisation.query.filter_by(org_id=org_id).first()

    if not organisation or current_user not in [user.email for user in organisation.users]:
        return jsonify(status="Bad request", message="Organisation not found or unauthorized access", statusCode=401), 401

    return jsonify(status="success", message="Organisation retrieved", data={
        "orgId": organisation.org_id,
        "name": organisation.name,
        "description": organisation.description
    }), 200


@app.route('/api/organisations', methods=['POST'])
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
    association = OrganisationUsers(user_id=user.user_id, org_id=new_org.org_id)
    db.session.add(association)
    db.session.commit()

    return jsonify(status="success", message="Organisation created successfully", data={
        "orgId": new_org.org_id,
        "name": new_org.name,
        "description": new_org.description
    }), 201


@app.route('/api/organisations/<org_id>/users', methods=['POST'])
@jwt_required()
def add_user_to_organisation(org_id):
    data = request.json
    current_user = get_jwt_identity()
    user_to_add = User.query.filter_by(user_id=data['userId']).first()
    organisation = Organisation.query.filter_by(org_id=org_id).first()

    if not user_to_add or not organisation or current_user not in [user.email for user in organisation.users]:
        return jsonify(status="Bad request", message="Client error", statusCode=400), 400

    association = OrganisationUsers(user_id=user_to_add.user_id, org_id=organisation.org_id)
    db.session.add(association)
    db.session.commit()

    return jsonify(status="success", message="User added to organisation successfully"), 200

