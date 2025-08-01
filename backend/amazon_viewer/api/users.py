# backend/amazon_viewer/api/users.py
from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash
from flask_jwt_extended import jwt_required, get_jwt_identity
from amazon_viewer.helpers.db import get_db_connection # Absolute import
from amazon_viewer.helpers.decorators import admin_required # Absolute import
from psycopg2.errors import UniqueViolation
import logging

bp = Blueprint('users', __name__, url_prefix='/api/admin')

@bp.route("/users", methods=['GET'])
@admin_required()
def get_users():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, role FROM users ORDER BY username")
                users = [{"id": row[0], "username": row[1], "role": row[2]} for row in cur.fetchall()]
        return jsonify(users), 200
    except Exception:
        logging.exception("Failed to fetch users.")
        return jsonify({"error": "Failed to fetch users."}), 500

@bp.route("/users/<uuid:user_id>/password", methods=['PUT'])
@admin_required()
def update_user_password(user_id):
    try:
        data = request.get_json()
        new_password = data.get('password')
        if not new_password:
            return jsonify({"error": "New password is required."}), 400
        
        hashed_password = generate_password_hash(new_password)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET hashed_password = %s WHERE id = %s", (hashed_password, str(user_id)))
        return jsonify({"message": "Password updated successfully."}), 200
    except Exception:
        logging.exception("Failed to update password.")
        return jsonify({"error": "Failed to update password."}), 500

@bp.route("/users/<uuid:user_id>", methods=['DELETE'])
@admin_required()
def delete_user(user_id):
    try:
        current_user_id = get_jwt_identity()
        if str(user_id) == current_user_id:
            return jsonify({"error": "You cannot delete your own account."}), 403

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM users WHERE id = %s", (str(user_id),))
        return jsonify({"message": "User deleted successfully."}), 200
    except Exception:
        logging.exception("Failed to delete user.")
        return jsonify({"error": "Failed to delete user."}), 500

@bp.route("/create-user", methods=['POST'])
@admin_required()
def create_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')
        if not username or not password:
            return jsonify({"error": "Username and password are required."}), 400

        hashed_password = generate_password_hash(password)
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO users (username, hashed_password, role) VALUES (%s, %s, %s)", (username, hashed_password, role))
        return jsonify({"message": f"User '{username}' created successfully."}), 201
    except UniqueViolation:
        return jsonify({"error": "Username already taken."}), 409
    except Exception:
        logging.exception("An unexpected error occurred during user creation.")
        return jsonify({"error": "An unexpected server error occurred."}), 500
