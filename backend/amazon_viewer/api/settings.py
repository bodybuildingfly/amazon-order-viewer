# backend/amazon_viewer/api/settings.py
from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from amazon_viewer.extensions import fernet
from amazon_viewer.helpers.db import get_db_connection
from amazon_viewer.helpers.amazon import get_amazon_session # Import the helper
from amazonorders.session import AmazonSession
import logging
import os

bp = Blueprint('settings', __name__, url_prefix='/api')

# --- Amazon Session Management Endpoint ---

@bp.route("/amazon/force-logout", methods=['POST'])
@jwt_required()
def amazon_force_logout():
    """
    Attempts to forcefully log out of any active Amazon session.
    This is useful for clearing a potentially stuck or invalid session.
    """
    current_user_id = get_jwt_identity()
    try:
        # We still need credentials to initialize a session object to log out.
        session = get_amazon_session(current_user_id)
        session.logout()
        logging.info("Amazon force logout successful.")
        return jsonify({"message": "Amazon session has been logged out."}), 200
    except Exception as e:
        logging.exception("Amazon force logout failed.")
        # Return a success message even on failure, as the session is likely invalid anyway.
        return jsonify({"message": "Could not definitively log out, but session is likely invalid."}), 200

# --- User Settings Endpoints ---

@bp.route("/settings", methods=['GET'])
@jwt_required()
def get_settings():
    try:
        current_user_id = get_jwt_identity()
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT amazon_email, amazon_otp_secret_key FROM user_settings WHERE user_id = %s", (current_user_id,))
                settings = cur.fetchone()
        if settings:
            return jsonify({
                "amazon_email": settings[0] or '',
                "amazon_otp_secret_key": settings[1] or ''
            }), 200
        else:
            return jsonify({"amazon_email": "", "amazon_otp_secret_key": ""}), 200
    except Exception:
        logging.exception("An unexpected error occurred in get_settings.")
        return jsonify({"error": "An unexpected server error occurred."}), 500

@bp.route("/settings", methods=['POST'])
@jwt_required()
def save_settings():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        amazon_email = data.get('amazon_email')
        amazon_password = data.get('amazon_password')
        amazon_otp_secret_key = data.get('amazon_otp_secret_key')

        if not amazon_email or not amazon_password:
            return jsonify({"error": "Amazon email and password are required."}), 400

        encrypted_password = fernet.encrypt(amazon_password.encode())
        
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO user_settings (user_id, amazon_email, amazon_password_encrypted, amazon_otp_secret_key)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (user_id) DO UPDATE SET
                        amazon_email = EXCLUDED.amazon_email,
                        amazon_password_encrypted = EXCLUDED.amazon_password_encrypted,
                        amazon_otp_secret_key = EXCLUDED.amazon_otp_secret_key,
                        updated_at = CURRENT_TIMESTAMP;
                """, (current_user_id, amazon_email, encrypted_password, amazon_otp_secret_key))
        return jsonify({"message": "Settings saved successfully."}), 200
    except Exception:
        logging.exception("An unexpected error occurred in save_settings.")
        return jsonify({"error": "An unexpected server error occurred."}), 500

@bp.route("/test-credentials", methods=['POST'])
@jwt_required()
def test_credentials():
    try:
        data = request.get_json()
        amazon_email = data.get('amazon_email')
        amazon_password = data.get('amazon_password')
        amazon_otp_secret_key = data.get('amazon_otp_secret_key')

        if not amazon_email or not amazon_password:
            return jsonify({"error": "Amazon email and password are required."}), 400

        logging.info(f"Testing credentials for {amazon_email}...")
        amazon_session = AmazonSession(
            username=amazon_email,
            password=amazon_password,
            otp_secret_key=amazon_otp_secret_key
        )
        amazon_session.login()
        amazon_session.logout()
        logging.info("Credential test successful.")
        return jsonify({"message": "Credentials are valid!"}), 200
    except Exception as e:
        logging.error(f"Credential test failed: {e}")
        return jsonify({"error": "Amazon login failed. Please check your credentials."}), 401
