# backend/app.py

import os
import psycopg2
import logging
import json
from datetime import timedelta, date
from functools import wraps
from flask import Flask, jsonify, request, Response, send_from_directory
from flask_cors import CORS
from psycopg2.errors import UniqueViolation
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt
from cryptography.fernet import Fernet
from amazonorders.session import AmazonSession
from amazonorders.orders import AmazonOrders
from amazonorders.transactions import AmazonTransactions
import requests
import hashlib
import base64
import subprocess
from db import init_pool, get_db_cursor

# --- Flask App Initialization ---
app = Flask(__name__, static_folder='../build', static_url_path='/')

# --- Basic Logging Configuration ---
logging.basicConfig(level=logging.INFO)

# --- Extension Initialization ---
CORS(
    app,
    supports_credentials=True,
    origins="http://localhost:3000",
    allow_headers=["Authorization", "Content-Type"]
)

# --- Configuration ---
jwt_secret_key = os.environ.get('JWT_SECRET_KEY')
if not jwt_secret_key:
    raise ValueError("No JWT_SECRET_KEY set for Flask application")

app.config["JWT_SECRET_KEY"] = jwt_secret_key
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["JWT_TOKEN_LOCATION"] = ["headers", "query_string"]
app.config["JWT_QUERY_STRING_NAME"] = "token"
jwt = JWTManager(app)

# --- Fernet Encryption Key Setup ---
encryption_passphrase = os.environ.get('ENCRYPTION_KEY')
if not encryption_passphrase:
    raise ValueError("No ENCRYPTION_KEY set for Flask application")

key_digest = hashlib.sha256(encryption_passphrase.encode('utf-8')).digest()
derived_key = base64.urlsafe_b64encode(key_digest)
fernet = Fernet(derived_key)


# --- Custom JWT Error Handlers ---
@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({"error": "Invalid token", "message": str(error)}), 422

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token has expired"}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({"error": "Authorization header is missing", "message": str(error)}), 401

# --- Admin Required Decorator ---
def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get("role") == "admin":
                return fn(*args, **kwargs)
            else:
                return jsonify(error="Admins only!"), 403
        return decorator
    return wrapper

# --- AI Summarization Function (Bulk Version) ---
def summarize_titles_bulk(titles):
    # ... (This function is unchanged)
    if not titles:
        return {}
    ollama_url = os.environ.get("OLLAMA_URL")
    api_key = os.environ.get("OLLAMA_API_KEY")
    model_name = os.environ.get("OLLAMA_MODEL")
    if not all([ollama_url, api_key, model_name]):
        app.logger.error("Ollama configuration is missing from environment variables.")
        return {}
    titles_json_string = json.dumps(titles, indent=2)
    prompt = f"""
    Your task is to summarize product titles into a concise, 3-5 word summary.
    Focus on the main product name and brand.
    You MUST ignore supplemental information like sizes, quantities, colors, and marketing phrases (e.g., "Supports Overall Wellbeing", "Dietary Supplement").

    Return the output as a single, valid JSON object that maps each original title to its summarized version.
    Do not provide any additional text or explanation outside of the JSON object itself.

    Example Input:
    [
      "Nature's Answer Alcohol-Free Cleavers Herb, 1-Fluid Ounce | Supports Overall Wellbeing | Dietary Supplement",
      "Another Item Name, 24 Ounce, Red Color"
    ]

    Example Output:
    {{
      "Nature's Answer Alcohol-Free Cleavers Herb, 1-Fluid Ounce | Supports Overall Wellbeing | Dietary Supplement": "Nature's Answer Cleavers Herb",
      "Another Item Name, 24 Ounce, Red Color": "Red Item 24 Ounce"
    }}

    Here are the titles to summarize:
    {titles_json_string}
    """
    payload = {"model": model_name, "messages": [{"role": "user", "content": prompt}]}
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        response = requests.post(ollama_url, json=payload, headers=headers)
        response.raise_for_status()
        response_data = response.json()
        if response_data.get("choices") and len(response_data["choices"]) > 0:
            content = response_data["choices"][0].get("message", {}).get("content", "").strip()
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0].strip()
            summaries_map = json.loads(content)
            return summaries_map
        return {}
    except json.JSONDecodeError:
        app.logger.exception("Failed to decode JSON from AI response.")
        return {}
    except Exception:
        app.logger.exception("An error occurred during bulk title summarization.")
        return {}

# --- Database Initialization Logic ---
def init_db():
    app.logger.info("Attempting to initialize database...")
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    try:
        with open(schema_path, 'r') as f:
            schema_sql = f.read()
        with get_db_cursor(commit=True) as cur:
            cur.execute(schema_sql)
            admin_user = os.environ.get("ADMIN_USERNAME", "admin")
            admin_pass = os.environ.get("ADMIN_PASSWORD", "changeme")
            
            cur.execute("SELECT id FROM users WHERE username = %s", (admin_user,))
            if cur.fetchone() is None:
                app.logger.info(f"Creating admin user: {admin_user}")
                hashed_password = generate_password_hash(admin_pass)
                cur.execute(
                    "INSERT INTO users (username, hashed_password, role) VALUES (%s, %s, 'admin')",
                    (admin_user, hashed_password)
                )
                app.logger.info("Admin user created successfully.")
        app.logger.info("Database schema check/initialization complete.")
    except Exception:
        app.logger.exception("An error occurred during DB initialization.")

with app.app_context():
    init_pool()
    init_db()

# --- API Endpoints ---

@app.route("/api/orders", methods=['GET'])
@jwt_required()
def get_orders_and_transactions():
    
    current_user_id = get_jwt_identity()
    days_to_fetch = request.args.get('days', default=7, type=int)

    def generate_events(user_id, days):
        session = None
        
        def send_event(event_type, data):
            event_data = json.dumps({"type": event_type, "payload": data})
            yield f"data: {event_data}\n\n"

        try:
            yield from send_event("status", "Fetching your settings...")
            with get_db_cursor() as cur:
                cur.execute(
                    "SELECT amazon_email, amazon_password_encrypted, amazon_otp_secret_key FROM user_settings WHERE user_id = %s",
                    (user_id,)
                )
                settings = cur.fetchone()

            if not settings or not settings[0] or not settings[1]:
                yield from send_event("error", "Amazon credentials not configured.")
                return

            amazon_email, encrypted_password, amazon_otp_secret_key = settings
            decrypted_password = fernet.decrypt(bytes(encrypted_password)).decode()

            yield from send_event("status", f"Logging into Amazon for {amazon_email}...")
            session = AmazonSession(
                username=amazon_email,
                password=decrypted_password,
                otp_secret_key=amazon_otp_secret_key
            )
            session.login()
            yield from send_event("status", "Amazon login successful.")

            amazon_orders = AmazonOrders(session)
            amazon_transactions = AmazonTransactions(session)
            
            yield from send_event("status", f"Fetching transactions for the last {days} days...")
            transactions = amazon_transactions.get_transactions(days=days)
            
            order_numbers = {trans.order_number for trans in transactions if trans.order_number}
            total_orders = len(order_numbers)
            
            yield from send_event("progress_max", total_orders + 1)
            yield from send_event("status", f"Found {total_orders} unique orders to process.")

            all_order_details = []
            all_titles_to_summarize = []
            processed_orders = 0
            for order_num in order_numbers:
                processed_orders += 1
                yield from send_event("status", f"Fetching details for order {processed_orders} of {total_orders}...")
                order_details = amazon_orders.get_order(order_id=order_num)
                if order_details:
                    all_order_details.append(order_details)
                    if order_details.items:
                        for item in order_details.items:
                            all_titles_to_summarize.append(item.title)
                yield from send_event("progress_update", processed_orders)

            yield from send_event("status", f"Summarizing {len(all_titles_to_summarize)} item titles...")
            summaries_map = summarize_titles_bulk(all_titles_to_summarize)
            
            yield from send_event("progress_update", total_orders + 1)
            yield from send_event("status", "Finalizing order data...")

            combined_data = []
            for order_details in all_order_details:
                if order_details.items:
                    
                    discount_text = None
                    if order_details.subscription_discount is not None:
                        try:
                            discount_amount = float(order_details.subscription_discount)
                            discount_text = f"Subscribe & Save discount: ${discount_amount:.2f}"
                        except (ValueError, TypeError):
                            discount_text = order_details.subscription_discount

                    order_data = {
                        "order_number": order_details.order_number,
                        "order_placed_date": order_details.order_placed_date.isoformat() if order_details.order_placed_date else None,
                        "grand_total": f"${order_details.grand_total:.2f}" if order_details.grand_total is not None else None,
                        "subscription_discount": discount_text,
                        "recipient": order_details.recipient.name if order_details.recipient else None,
                        "items": []
                    }

                    for item in order_details.items:
                        summary = summaries_map.get(item.title, item.title)
                        
                        full_link = item.link
                        if full_link and not full_link.startswith('http'):
                            full_link = f"[https://www.amazon.com](https://www.amazon.com){full_link}"
                        
                        order_data["items"].append({
                            "title": summary,
                            "link": full_link,
                            "price": f"${item.price:.2f}" if item.price is not None else None,
                            "quantity": item.quantity if item.quantity is not None else 1
                        })
                    
                    combined_data.append(order_data)
            
            app.logger.info("Sorting orders by date...")
            combined_data.sort(key=lambda x: x.get('order_placed_date'), reverse=True)

            yield from send_event("data", combined_data)
            yield from send_event("status", "Done.")

        except Exception as e:
            app.logger.exception("An error occurred while fetching Amazon data.")
            error_msg = str(e) if str(e) else "An unexpected error occurred. Check logs for details."
            yield from send_event("error", error_msg)
        finally:
            if session and session.is_authenticated:
                app.logger.info("Logging out of Amazon session.")
                session.logout()

    response = Response(generate_events(current_user_id, days_to_fetch), mimetype='text/event-stream')
    response.headers['Content-Type'] = 'text/event-stream; charset=utf-8'
    response.headers['Cache-Control'] = 'no-cache, no-transform'
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Content-Encoding'] = 'none'
    return response

@app.route("/api/login", methods=['POST'])
def login_user():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({"error": "Username and password are required."}), 400
        with get_db_cursor() as cur:
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
        app.logger.exception("An unexpected error occurred during login.")
        return jsonify({"error": "An unexpected server error occurred."}), 500

# --- Admin Endpoints ---

@app.route("/api/admin/users", methods=['GET'])
@admin_required()
def get_users():
    try:
        with get_db_cursor() as cur:
            cur.execute("SELECT id, username, role FROM users ORDER BY username")
            users = [{"id": row[0], "username": row[1], "role": row[2]} for row in cur.fetchall()]
        return jsonify(users), 200
    except Exception:
        app.logger.exception("Failed to fetch users.")
        return jsonify({"error": "Failed to fetch users."}), 500

@app.route("/api/admin/users/<uuid:user_id>/password", methods=['PUT'])
@admin_required()
def update_user_password(user_id):
    try:
        data = request.get_json()
        new_password = data.get('password')
        if not new_password:
            return jsonify({"error": "New password is required."}), 400
        
        hashed_password = generate_password_hash(new_password)
        with get_db_cursor(commit=True) as cur:
            cur.execute("UPDATE users SET hashed_password = %s WHERE id = %s", (hashed_password, str(user_id)))
        return jsonify({"message": "Password updated successfully."}), 200
    except Exception:
        app.logger.exception("Failed to update password.")
        return jsonify({"error": "Failed to update password."}), 500

@app.route("/api/admin/users/<uuid:user_id>", methods=['DELETE'])
@admin_required()
def delete_user(user_id):
    try:
        current_user_id = get_jwt_identity()
        if str(user_id) == current_user_id:
            return jsonify({"error": "You cannot delete your own account."}), 403

        with get_db_cursor(commit=True) as cur:
            cur.execute("DELETE FROM users WHERE id = %s", (str(user_id),))
        return jsonify({"message": "User deleted successfully."}), 200
    except Exception:
        app.logger.exception("Failed to delete user.")
        return jsonify({"error": "Failed to delete user."}), 500


@app.route("/api/admin/create-user", methods=['POST'])
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
        with get_db_cursor(commit=True) as cur:
            cur.execute("INSERT INTO users (username, hashed_password, role) VALUES (%s, %s, %s)", (username, hashed_password, role))
        return jsonify({"message": f"User '{username}' created successfully."}), 201
    except UniqueViolation:
        return jsonify({"error": "Username already taken."}), 409
    except Exception:
        app.logger.exception("An unexpected error occurred during user creation.")
        return jsonify({"error": "An unexpected server error occurred."}), 500

@app.route("/api/amazon-logout", methods=['POST'])
@jwt_required()
def amazon_logout():
    try:
        command = ["amazon-orders", "logout"]
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            check=True
        )
        app.logger.info(f"Successfully executed 'amazon-orders logout'. Output: {result.stdout}")
        return jsonify({"message": "Amazon logout command executed successfully.", "output": result.stdout}), 200
    except FileNotFoundError:
        app.logger.error("'amazon-orders' command not found in container's PATH.")
        return jsonify({"error": "'amazon-orders' command not found."}), 500
    except subprocess.CalledProcessError as e:
        app.logger.error(f"Error executing 'amazon-orders logout'. Stderr: {e.stderr}")
        return jsonify({"error": "Command failed to execute.", "details": e.stderr}), 500
    except Exception:
        app.logger.exception("An unexpected error occurred during amazon_logout.")
        return jsonify({"error": "An unexpected server error occurred."}), 500

@app.route("/api/test-credentials", methods=['POST'])
def test_credentials():
    try:
        data = request.get_json()
        amazon_email = data.get('amazon_email')
        amazon_password = data.get('amazon_password')
        amazon_otp_secret_key = data.get('amazon_otp_secret_key')

        if not amazon_email or not amazon_password:
            return jsonify({"error": "Amazon email and password are required."}), 400

        app.logger.info(f"Testing credentials for {amazon_email}...")
        amazon_session = AmazonSession(
            username=amazon_email,
            password=amazon_password,
            otp_secret_key=amazon_otp_secret_key
        )
        amazon_session.login()
        amazon_session.logout()
        app.logger.info("Credential test successful.")
        return jsonify({"message": "Credentials are valid!"}), 200
    except Exception as e:
        app.logger.error(f"Credential test failed: {e}")
        return jsonify({"error": "Amazon login failed. Please check your credentials."}), 401


@app.route("/api/settings", methods=['GET'])
@jwt_required()
def get_settings():
    try:
        current_user_id = get_jwt_identity()
        with get_db_cursor() as cur:
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
        app.logger.exception("An unexpected error occurred in get_settings.")
        return jsonify({"error": "An unexpected server error occurred."}), 500

@app.route("/api/settings", methods=['POST'])
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
        
        with get_db_cursor(commit=True) as cur:
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
        app.logger.exception("An unexpected error occurred in save_settings.")
        return jsonify({"error": "An unexpected server error occurred."}), 500

# --- Serve React App ---
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
