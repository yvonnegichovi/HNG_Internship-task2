# app.py
from flask import Flask, jsonify, request, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config.from_object('start.config.Config')
db = SQLAlchemy(app)
jwt = JWTManager(app)

from start.auth import auth_bp
app.register_blueprint(auth_bp, url_prefix='/auth')
from start import auth
