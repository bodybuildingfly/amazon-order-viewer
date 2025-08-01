# backend/amazon_viewer/__init__.py

import os
import logging
import psycopg2
from flask import Flask
from werkzeug.security import generate_password_hash
from amazon_viewer.extensions import cors, jwt, fernet # Absolute import

def create_app():
    """Application factory function."""
    app = Flask(__name__, static_folder='../../build', static_url_path='/')

    # --- Configuration ---
    app.config["JWT_SECRET_KEY"] = "a-static-super-secret-key-for-dev"
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 3600)
    app.config["JWT_TOKEN_LOCATION"] = ["headers", "query_string"]
    app.config["JWT_QUERY_STRING_NAME"] = "token"

    # --- Initialize Extensions ---
    cors.init_app(app)
    jwt.init_app(app)

    # --- Register Blueprints ---
    from amazon_viewer.api import auth, orders, settings, users # Absolute import
    app.register_blueprint(auth.bp)
    app.register_blueprint(orders.bp)
    app.register_blueprint(settings.bp)
    app.register_blueprint(users.bp)

    # --- Database and Admin User Initialization ---
    with app.app_context():
        init_db()

    return app

def init_db():
    logging.info("Attempting to initialize database...")
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    try:
        with open(schema_path, 'r') as f:
            schema_sql = f.read()
        
        conn = psycopg2.connect(
            dbname=os.environ.get('POSTGRES_DB'),
            user=os.environ.get('POSTGRES_USER'),
            password=os.environ.get('POSTGRES_PASSWORD'),
            host=os.environ.get('POSTGRES_HOST'),
            port=os.environ.get('POSTGRES_PORT')
        )
        with conn.cursor() as cur:
            cur.execute(schema_sql)
            admin_user = os.environ.get("ADMIN_USERNAME", "admin")
            admin_pass = os.environ.get("ADMIN_PASSWORD", "changeme")
            
            cur.execute("SELECT id FROM users WHERE username = %s", (admin_user,))
            if cur.fetchone() is None:
                logging.info(f"Creating admin user: {admin_user}")
                hashed_password = generate_password_hash(admin_pass)
                cur.execute(
                    "INSERT INTO users (username, hashed_password, role) VALUES (%s, %s, 'admin')",
                    (admin_user, hashed_password)
                )
                logging.info("Admin user created successfully.")
        conn.commit()
        conn.close()
        logging.info("Database schema check/initialization complete.")
    except Exception as e:
        logging.exception(f"An error occurred during DB initialization: {e}")
