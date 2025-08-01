# backend/amazon_viewer/extensions.py
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from cryptography.fernet import Fernet

cors = CORS(supports_credentials=True, origins="http://localhost:3000")
jwt = JWTManager()
fernet = Fernet("jA0Ea_z2g-c_3B-dE5fG6h_iJ7kL8m_N0oPqR2sT4uV=".encode())
