# backend/app.py
from gevent import monkey
monkey.patch_all()

import os
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
from amazonorders.exception import AmazonOrdersError
import requests
import hashlib
import base64
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from db import init_pool, get_db_cursor

# --- Flask App Initialization ---
app = Flask(__name__, static_folder='build', static_url_path='/')

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
def summarize_titles_bulk(titles, progress_start=0, progress_end=1):
    """
    Summarizes a list of product titles in batches, yielding progress events.
    Returns a dictionary mapping original titles to their summaries.
    """
    if not titles:
        return {}

    # Use dict.fromkeys to get unique titles while preserving order
    unique_titles = list(dict.fromkeys(titles))
    
    ollama_url = os.environ.get("OLLAMA_URL")
    api_key = os.environ.get("OLLAMA_API_KEY")
    model_name = os.environ.get("OLLAMA_MODEL")

    if not all([ollama_url, model_name]):
        app.logger.error("Ollama configuration is missing from environment variables.")
        yield "error", "Ollama summarization service is not configured on the server."
        return {}

    if "localhost" in ollama_url or "127.0.0.1" in ollama_url:
        app.logger.warning(
            "OLLAMA_URL is set to a loopback address. This will not work inside a Docker container. "
            "If running Docker on Mac/Windows, use 'host.docker.internal'. On Linux, use your host's IP address."
        )

    all_summaries = {}
    batch_size = 10
    num_batches = (len(unique_titles) + batch_size - 1) // batch_size
    progress_range = progress_end - progress_start

    yield "status", f"Summarizing {len(unique_titles)} titles..."

    MAX_SUMMARY_RETRIES = 3  # Initial attempt + 2 retries
    for i in range(num_batches):
        batch_start_index = i * batch_size
        batch_end_index = batch_start_index + batch_size
        batch_titles = unique_titles[batch_start_index:batch_end_index]
        
        yield "sub_status", f"(Batch {i + 1} of {num_batches})"
        
        titles_to_process = list(batch_titles)

        for attempt in range(MAX_SUMMARY_RETRIES):
            if not titles_to_process:
                break

            titles_json_string = json.dumps(titles_to_process, indent=2)

            prompt = f"""
            You are an expert product catalog summarizer. Your goal is to create a very short, human-readable summary for each product title provided in the input list. The summary must be strictly between 3 and 5 words.

            **CRITICAL INSTRUCTIONS:**
            1.  Your output MUST be a single, valid JSON object.
            2.  The JSON object must have a key for EVERY product title from the input list.
            3.  The value for each key must be the new, summarized title.

            **SUMMARIZATION RULES:**
            1.  **Identify Core Product & Brand**: Find the brand (e.g., "Elmer's") and the main product (e.g., "Craft Glue").
            2.  **Combine and Refine**: Combine them into a natural phrase (e.g., "Elmer's Craft Glue"). Add a key attribute if necessary (e.g., "Clear").
            3.  **Strictly Exclude**: You MUST remove all of the following:
                -   Sizes, weights, volumes (e.g., "4 oz", "1 Gallon")
                -   Counts, packs (e.g., "2-pack")
                -   Marketing claims (e.g., "Helps Moisture Soften and Nourish")
                -   Model numbers or identifiers (e.g., "E431")
                -   Superfluous descriptors (e.g., "for School Supplies")

            ---
            **Examples**

            **Input:**
            [
              "Oars + Alps Aluminum Free Deodorant for Men and Women, Dermatologist Tested and Made with Clean Ingredients, Travel Size, Variety, 3 Pack, 2.6 Oz Each",
              "Elmer's E431 Craft Bond Fabric and Paper Glue, 4 oz, Clear"
            ]

            **Output:**
            {{
              "Oars + Alps Aluminum Free Deodorant for Men and Women, Dermatologist Tested and Made with Clean Ingredients, Travel Size, Variety, 3 Pack, 2.6 Oz Each": "Oars + Alps Deodorant",
              "Elmer's E431 Craft Bond Fabric and Paper Glue, 4 oz, Clear": "Elmer's Clear Craft Glue"
            }}
            ---

            **Titles to Summarize:**
            {titles_json_string}
            """

            payload = {
                "model": model_name,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "format": "json"
            }
            headers = { "Authorization": f"Bearer {api_key}", "Content-Type": "application/json" } if api_key else {}

            app.logger.info(f"Starting Ollama summarization for batch {i+1}/{num_batches} (Attempt {attempt + 1}) to {ollama_url}...")

            try:
                response = requests.post(ollama_url, json=payload, headers=headers, timeout=60)
                response.raise_for_status()
                response_data = response.json()
                
                batch_summaries = {}
                if response_data.get("message"):
                    content = response_data.get("message", {}).get("content", "")
                    batch_summaries = json.loads(content)

                failed_titles = []
                for title in titles_to_process:
                    summary = batch_summaries.get(title)
                    if not summary or len(summary.split()) > 5:
                        failed_titles.append(title)
                    else:
                        all_summaries[title] = summary
                
                if not failed_titles:
                    break  # All titles in this batch succeeded
                
                titles_to_process = failed_titles
                app.logger.warning(f"Summarization failed validation for {len(titles_to_process)} titles on attempt {attempt + 1}. Retrying them.")
                if attempt == MAX_SUMMARY_RETRIES - 1:
                    app.logger.error(f"Using original title as fallback for {len(titles_to_process)} titles after all retries.")
                    for title in titles_to_process:
                        all_summaries[title] = title

            except requests.exceptions.Timeout:
                app.logger.error(f"Connection to Ollama timed out for batch {i+1}.")
                yield "error", f"AI summarization timed out on batch {i+1}. Some titles may not be summarized."
                if attempt == MAX_SUMMARY_RETRIES - 1:
                    app.logger.error(f"Using original title as fallback for {len(titles_to_process)} titles after timeout on last retry.")
                    for title in titles_to_process:
                        all_summaries[title] = title
                continue
            except requests.exceptions.ConnectionError as e:
                app.logger.error(f"Could not connect to Ollama for batch {i+1}: {e}")
                yield "error", "Could not connect to the AI summarization service."
                # Don't retry on connection error, just fail the whole process
                return all_summaries
            except json.JSONDecodeError:
                app.logger.exception(f"Failed to decode JSON from AI response for batch {i+1}.")
                yield "error", f"AI service returned an invalid response for batch {i+1}."
                if attempt == MAX_SUMMARY_RETRIES - 1:
                    app.logger.error(f"Using original title as fallback for {len(titles_to_process)} titles after JSON error on last retry.")
                    for title in titles_to_process:
                        all_summaries[title] = title
                continue
            except Exception:
                app.logger.exception(f"An unexpected error occurred during summarization for batch {i+1}.")
                yield "error", "An unexpected error occurred during summarization."
                if attempt == MAX_SUMMARY_RETRIES - 1:
                    app.logger.error(f"Using original title as fallback for {len(titles_to_process)} titles after unexpected error on last retry.")
                    for title in titles_to_process:
                        all_summaries[title] = title
                continue
        
        progress_fraction = (i + 1) / num_batches
        current_progress = progress_start + (progress_fraction * progress_range)
        yield "progress_update", current_progress

    yield "sub_status", "" # Clear the sub-status when done
    return all_summaries

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
    should_summarize = request.args.get('summarize', 'true', type=str).lower() == 'true'

    def generate_events(user_id, days, summarize):
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
            
            progress_max = total_orders + 1 if summarize else total_orders
            yield from send_event("progress_max", progress_max)
            yield from send_event("status", f"Found {total_orders} unique orders to process.")

            processed_orders = 0
            MAX_CONCURRENT_REQUESTS = 5

            def fetch_order_with_retries(order_num_to_fetch):
                """
                Fetches a single order with retry logic.
                Returns the order details object on success, or the exception on failure.
                """
                MAX_RETRIES = 3
                RETRY_DELAY = 2  # seconds
                for attempt in range(MAX_RETRIES):
                    try:
                        return amazon_orders.get_order(order_id=order_num_to_fetch)
                    except (requests.exceptions.RequestException, AmazonOrdersError) as e:
                        app.logger.warning(f"Attempt {attempt + 1} for order {order_num_to_fetch} failed: {e}")
                        if attempt < MAX_RETRIES - 1:
                            time.sleep(RETRY_DELAY * (2 ** attempt))
                        else:
                            app.logger.error(f"All retries failed for order {order_num_to_fetch}.")
                            return e

            yield from send_event("status", f"Fetching and processing {total_orders} orders...")

            with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_REQUESTS) as executor:
                future_to_order_num = {
                    executor.submit(fetch_order_with_retries, order_num): order_num
                    for order_num in order_numbers
                }

                for future in as_completed(future_to_order_num):
                    order_num = future_to_order_num[future]
                    
                    try:
                        order_details = future.result()

                        if isinstance(order_details, Exception):
                            app.logger.error(f"Failed to fetch order {order_num} after retries: {order_details}")
                            yield from send_event("status", f"Failed to fetch details for order {order_num}. Skipping.")
                            continue

                        if not order_details or not order_details.items:
                            app.logger.warning(f"Received no details or items for order {order_num}, skipping.")
                            continue

                        summaries_map = {}
                        if summarize:
                            titles_to_summarize = [item.title for item in order_details.items]
                            if titles_to_summarize:
                                yield from send_event("sub_status", f"Order {order_num}: Summarizing titles...")
                                summarizer = summarize_titles_bulk(titles=titles_to_summarize)
                                while True:
                                    try:
                                        event_type, data = next(summarizer)
                                        if event_type == "error":
                                            yield from send_event("error", data)
                                    except StopIteration as e:
                                        summaries_map = e.value
                                        break
                                yield from send_event("sub_status", "")

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
                                full_link = f"https://www.amazon.com{full_link}"
                            
                            order_data["items"].append({
                                "title": summary,
                                "link": full_link,
                                "price": f"${item.price:.2f}" if item.price is not None else None,
                                "quantity": item.quantity if item.quantity is not None else 1
                            })
                        
                        yield from send_event("order_data", order_data)

                    except Exception as e:
                        app.logger.exception(f"An unexpected error occurred while processing future for order {order_num}.")
                        yield from send_event("status", f"Error processing order {order_num}: {e}. Skipping.")
                    finally:
                        processed_orders += 1
                        yield from send_event("progress_update", processed_orders)
            
            if not summarize:
                yield from send_event("status", "Skipping title summarization.")
                if progress_max > processed_orders:
                    yield from send_event("progress_update", progress_max)

            app.logger.info("Finished processing all orders.")
            yield from send_event("status", "Done.")

        except Exception as e:
            app.logger.exception("An error occurred while fetching Amazon data.")
            error_msg = str(e) if str(e) else "An unexpected error occurred. Check logs for details."
            yield from send_event("error", error_msg)
        finally:
            if session and session.is_authenticated:
                app.logger.info("Logging out of Amazon session.")
                session.logout()

    response = Response(generate_events(current_user_id, days_to_fetch, should_summarize), mimetype='text/event-stream')
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
