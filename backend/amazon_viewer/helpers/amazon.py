# backend/amazon_viewer/helpers/amazon.py
import os
from amazonorders.session import AmazonSession
from amazon_viewer.helpers.db import get_db_connection
from amazon_viewer.extensions import fernet

def get_amazon_session(user_id):
    """Retrieves user credentials and returns a new AmazonSession instance."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT amazon_email, amazon_password_encrypted, amazon_otp_secret_key FROM user_settings WHERE user_id = %s",
                (user_id,)
            )
            settings = cur.fetchone()
    if not settings or not settings[0] or not settings[1]:
        raise ValueError("Amazon credentials not configured.")
    
    amazon_email, encrypted_password, amazon_otp_secret_key = settings
    decrypted_password = fernet.decrypt(bytes(encrypted_password)).decode()

    # Return a new, non-persistent session object
    return AmazonSession(
        username=amazon_email,
        password=decrypted_password,
        otp_secret_key=amazon_otp_secret_key
    )
