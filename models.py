# models.py
from app import db
from sqlalchemy.dialects.postgresql import UUID
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    __tablename__ = 'users'

    userId = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    firstName = db.Column(db.String(50), nullable=False)
    lastName = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    phone = db.Column(db.String(20))

    def set_password(self, pwd):
        self.password = generate_password_hash(pwd)

    def check_password(self, pwd):
        return check_password_hash(self.password, pwd)

    def validate_user_data(self):
        errors = []
        if not self.firstName:
            errors.append({'field': 'firstName', 'message': 'First name is required'})
        if not self.lastName:
            errors.append({'field': 'lastName', 'message': 'Last name is required'})
        if not self.email:
            errors.append({'field': 'email', 'message': 'Email is required'})
        if not self.password:
            errors.append({'field': 'password', 'message': 'Password is required'})
        return jsonify(errors), 422


class Organisation(db.Model):
    __tablename__ = 'organisations'

    orgId = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))


class OrganisationUsers(db.Model):
    __tablename__ = 'organisation_users'
    user_id = db.Column(db.String(36), db.ForeignKey('users.userId'), primary_key=True)
    org_id = db.Column(db.String(36), db.ForeignKey('organisations.orgId'), primary_key=True)
