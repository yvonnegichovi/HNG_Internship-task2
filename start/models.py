# models.py
from start import db
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
    organisations = db.relationship('Organisation', secondary='organisation_users',
                                    backref=db.backref('users', lazy='dynamic'))
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
        return errors


class Organisation(db.Model):
    __tablename__ = 'organisations'

    orgId = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()), unique=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))

    @staticmethod
    def generate_name(firstName):
        return f"{firstName}'s Organisation"


class OrganisationUsers(db.Model):
    __tablename__ = 'organisation_users'
    user_id = db.Column(db.String(36), db.ForeignKey('users.userId'), primary_key=True)
    org_id = db.Column(db.String(36), db.ForeignKey('organisations.orgId'), primary_key=True)
