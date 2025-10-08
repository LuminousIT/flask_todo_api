from flask import Blueprint, request, jsonify, abort
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from app.services.user_service import UserService

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        abort(400, description="Username and password required")
    try:
        user = UserService.create_user(data['username'], data['password'])
        return jsonify(message=f"User {user.username} created"), 201
    except ValueError as e:
        abort(400, description=str(e))


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = UserService.authenticate(data['username'], data['password'])
    if not user:
        abort(401, description="Invalid credentials")

    return jsonify(
        access_token=create_access_token(identity=str(user.id)),
        refresh_token=create_refresh_token(identity=str(user.id))
    )


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    return jsonify(access_token=create_access_token(identity=str(user_id)))
