# backend/amazon_viewer/api/auth.py
from flask import Blueprint, jsonify, request
from werkzeug.security import check_password_hash
from flask_jwt_extended import create_access_token
from amazon_viewer.helpers.db import get_db_connection # Absolute import
import logging

bp = Blueprint('auth', __name__, url_prefix='/api')

@bp.route("/login", methods=['POST'])
def login_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({"error": "Username and password are required."}), 400

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, hashed_password, role FROM users WHERE username = %s", (username,))
                user_record = cur.fetchone()

        if user_record and check_password_hash(user_record[1], password):
            user_id = str(user_record[0])
            user_role = user_record[2]
            additional_claims = {"role": user_role}
            access_token = create_access_token(identity=user_id, additional_claims=additional_claims)
            return jsonify(access_token=access_token)
        else:
            return jsonify({"error": "Invalid username or password"}), 401
    except Exception:
        logging.exception("An unexpected error occurred during login.")
        return jsonify({"error": "An unexpected server error occurred."}), 500
