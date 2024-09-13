import os
from flask import Flask, request, jsonify, g
from flask_socketio import SocketIO
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import logging
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
from datetime import timedelta
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token, get_jwt
from flask_mail import Mail
import secrets
from urllib.parse import urlparse
from contextlib import contextmanager
import time
from mysql.connector.errors import PoolError
from functools import wraps
from flask_session import Session
from tenacity import retry, stop_after_attempt, wait_fixed

load_dotenv()  # Load environment variables

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Password validation function
def validate_password(password):
    return (len(password) >= 8 and
            re.search(r"\d", password) and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

def generate_bcrypt_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_bcrypt_hash(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def set_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(stored_password, provided_password):
    # Convert stored_password to bytes if it's a string
    if isinstance(stored_password, str):
        stored_password = stored_password.encode('utf-8')
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

# Define db_config before using it
db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'connection_timeout': 60,  # close connection after 60 seconds of inactivity
}

connection_pool = None

def create_connection_pool(max_attempts=3):
    pool_size = 5  # Reduced from 10 to 5
    for attempt in range(max_attempts):
        try:
            return mysql.connector.pooling.MySQLConnectionPool(
                pool_name="mypool",
                pool_size=pool_size,
                pool_reset_session=True,
                **db_config,
                autocommit=True
            )
        except mysql.connector.Error as err:
            print(f"Attempt {attempt + 1} failed to create connection pool: {err}")
            if attempt < max_attempts - 1:
                time.sleep(2)  # Wait for 2 seconds before retrying
            else:
                raise

@contextmanager
def get_db_connection():
    connection = connection_pool.get_connection()
    try:
        yield connection
    finally:
        connection.close()

def create_app(testing=False):
    global connection_pool
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    app.config['SESSION_TYPE'] = 'filesystem'
    Session(app)
    CORS(app, resources={r"/*": {"origins": ["http://127.0.0.1:5501", "http://localhost:5501"]}})
    socketio = SocketIO(app, cors_allowed_origins="*")

    # Parse JAWSDB_URL
    if os.getenv('JAWSDB_URL'):
        url = urlparse(os.getenv('JAWSDB_URL'))
        db_config.update({
            'host': url.hostname,
            'user': url.username,
            'password': url.password,
            'database': url.path[1:],
            'port': url.port,
        })

    # Close any existing connections
    mysql.connector.connect(**db_config).close()

    connection_pool = create_connection_pool()

    # Configure upload folder for profile pictures
    UPLOAD_FOLDER = 'static/profile_pictures'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    if os.getenv('FLASK_ENV') == 'production':
        redis_url = os.getenv('REDIS_URL', 'redis://localhost:6379')
        storage_uri = redis_url
    else:
        storage_uri = "memory://"

    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri=storage_uri,
        storage_options={"socket_connect_timeout": 30},
        default_limits=["200 per day", "50 per hour"]
    )
    limiter.init_app(app)

    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

    jwt = JWTManager(app)
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

    # Configure application to store JWTs in cookies
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_CSRF_PROTECT'] = True
    app.config['JWT_COOKIE_SECURE'] = True  # for production, use HTTPS
    app.config['JWT_ACCESS_COOKIE_PATH'] = '/api/'
    app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_payload):
        return jsonify({"error": "Token has expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify({"error": "Invalid token"}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({"error": "Authorization token is missing"}), 401

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        return jsonify({"error": "Token has been revoked"}), 401

    revoked_tokens = set()

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        return jti in revoked_tokens

    @app.route('/register', methods=['POST'])
    @limiter.limit("5 per minute")
    def register():
        data = request.json
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        city = data.get('city')

        if not all([name, email, password, city]):
            return jsonify({"error": "Missing required fields"}), 400

        if not validate_password(password):
            return jsonify({"error": "Password not strong enough"}), 400

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM installer WHERE email = %s", (email,))
                if cursor.fetchone():
                    return jsonify({"error": "Email already registered"}), 409
                
                hashed_password = set_password(password)
                cursor.execute("INSERT INTO installer (name, email, password, city) VALUES (%s, %s, %s, %s)",
                               (name, email, hashed_password, city))
                conn.commit()
            return jsonify({"message": "Installer registered successfully!"}), 201
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            return jsonify({"error": "An internal error occurred"}), 500

    @app.route('/login', methods=['POST'])
    @limiter.limit("5 per minute")
    def login():
        data = request.json
        email = data.get('email')
        password = data.get('password')

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM installer WHERE email = %s", (email,))
                user = cursor.fetchone()

            if user and check_password(user['password'], password):
                access_token = create_access_token(identity=email)
                response = jsonify({"message": "Login successful", "access_token": access_token})
                response.headers.add('Access-Control-Allow-Origin', 'http://127.0.0.1:5501')
                return response, 200
            else:
                return jsonify({"error": "Invalid credentials"}), 401
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            return jsonify({"error": "An internal error occurred"}), 500

    @app.route('/refresh', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh():
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        return jsonify(access_token=access_token), 200

    @app.route('/protected', methods=['GET'])
    @jwt_required()
    def protected():
        current_user = get_jwt_identity()
        return jsonify(logged_in_as=current_user), 200

    @app.route('/user-profile')
    @jwt_required()
    def user_profile():
        current_user = get_jwt_identity()
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT name, email, city FROM installer WHERE email = %s", (current_user,))
            user_data = cursor.fetchone()
        if user_data:
            return jsonify(user_data), 200
        else:
            return jsonify({"error": "User not found"}), 404

    @app.route('/logout', methods=['POST'])
    @jwt_required()
    def logout():
        jti = get_jwt()["jti"]
        revoked_tokens.add(jti)
        return jsonify(message="Successfully logged out"), 200

    @app.route('/search-skillsets', methods=['GET'])
    def search_skillsets():
        skillset = request.args.get('skillset', '')
        city = request.args.get('city', '')
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                query = """
                SELECT i.name, i.email, i.city, s.skillset
                FROM installer i
                JOIN installer_skills s ON i.id = s.installer_id
                WHERE s.skillset LIKE %s AND i.city LIKE %s
                """
                cursor.execute(query, (f'%{skillset}%', f'%{city}%'))
                results = cursor.fetchall()
            return jsonify(results), 200
        except Exception as e:
            logging.error(f"Error searching skillsets: {str(e)}")
            return jsonify({"error": "An error occurred while searching"}), 500

    @app.route('/search-jobs', methods=['GET'])
    def search_jobs():
        job_type = request.args.get('job_type', '')
        city = request.args.get('city', '')
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                query = """
                SELECT i.name, i.email, i.city, j.job_type
                FROM installer i
                JOIN installer_jobs j ON i.id = j.installer_id
                WHERE j.job_type LIKE %s AND i.city LIKE %s
                """
                cursor.execute(query, (f'%{job_type}%', f'%{city}%'))
                results = cursor.fetchall()
            return jsonify(results), 200
        except Exception as e:
            logging.error(f"Error searching jobs: {str(e)}")
            return jsonify({"error": "An error occurred while searching"}), 500

    @app.route('/apply', methods=['POST'])
    def apply():
        data = request.form
        files = request.files.getlist('photos')

        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                
                query = """
                INSERT INTO installer (company_name, first_name, last_name, address, city, state, zip_code, 
                                       main_phone, mobile_phone, email, password, skills, other_skills, 
                                       years_experience, has_insurance, insurance_type, has_certification, 
                                       certification_type, allow_reviews, business_description)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                values = (
                    data['company_name'], data['first_name'], data['last_name'], data['address'],
                    data['city'], data['state'], data['zip_code'], data['main_phone'],
                    data.get('mobile_phone'), data['email'], generate_password_hash(data['password']),
                    ','.join(data.getlist('skills')), data.get('other_skills'),
                    int(data['years_experience']), data['has_insurance'] == 'Yes',
                    data.get('insurance_type'), data['has_certification'] == 'Yes',
                    data.get('certification_type'), data['allow_reviews'] == 'Yes',
                    data['business_description']
                )
                cursor.execute(query, values)
                installer_id = cursor.lastrowid

                for file in files:
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        cursor.execute("INSERT INTO installer_photos (installer_id, photo_name) VALUES (%s, %s)",
                                       (installer_id, filename))

                conn.commit()
            return jsonify({"message": "Application submitted successfully"}), 201
        except Exception as e:
            logging.error(f"Application submission error: {str(e)}")
            return jsonify({"error": "An error occurred while submitting the application"}), 500


    @app.teardown_appcontext
    def close_db(error):
        if hasattr(g, 'db'):
            g.db.close()

    return app, socketio, limiter

app, socketio, limiter = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    socketio.run(app, host='0.0.0.0', port=port)