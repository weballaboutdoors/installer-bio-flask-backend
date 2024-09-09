import os
from flask import Flask, request, jsonify, g
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import logging
import bcrypt
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
import re
import base64
import hashlib
from flask import session
from datetime import timedelta
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token, get_jwt
from flask_mail import Mail, Message
import secrets
from utils import sanitize_log
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from urllib.parse import urlparse
from user_inputs import UserInputs  # Add this import at the top of the file
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from contextlib import contextmanager
import time
from mysql.connector.errors import PoolError

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
    return generate_bcrypt_hash(password)

def check_password(stored_password, provided_password):
    return verify_bcrypt_hash(provided_password, stored_password)

# Define db_config before using it
db_config = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'connection_timeout': 60,  # close connection after 60 seconds of inactivity
}

# Add this function near the top of the file, after imports
def get_db_connection():
    return connection_pool.get_connection()

def create_app(testing=False):
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
    CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "http://localhost:8000", "https://your-frontend-domain.com"]}})
    socketio = SocketIO(app, cors_allowed_origins="*")
    # Parse JAWSDB_URL
    if os.getenv('JAWSDB_URL'):
        url = urlparse(os.getenv('JAWSDB_URL'))
        db_config = {
            'host': url.hostname,
            'user': url.username,
            'password': url.password,
            'database': url.path[1:],
            'port': url.port,
            'connection_timeout': 60,  # close connection after 60 seconds of inactivity
        }
    else:
        # Fallback to separate environment variables
        db_config = {
            'host': os.getenv('DB_HOST'),
            'user': os.getenv('DB_USER'),
            'password': os.getenv('DB_PASSWORD'),
            'database': os.getenv('DB_NAME'),
            'port': int(os.getenv('DB_PORT', 3306)),  # Default to 3306 if not set
            'connection_timeout': 60,  # close connection after 60 seconds of inactivity
        }

    # Close any existing connections
    mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD')
    ).close()

    if testing:
        # Use a smaller pool size for testing
        pool_size = 3
    else:
        pool_size = 10  # or whatever size you want for production

    connection_pool = mysql.connector.pooling.MySQLConnectionPool(
        pool_name="mypool",
        pool_size=pool_size,
        pool_reset_session=True,
        **db_config
    )

    # Configure upload folder for profile pictures
    UPLOAD_FOLDER = 'static/profile_pictures'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    def allowed_file(filename):
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

    jwt = JWTManager(app)
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

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

    # At the top of your file, after other imports
    revoked_tokens = set()

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        return jti in revoked_tokens

    @app.route('/register', methods=['POST'])
    @limiter.limit("5 per minute")
    def register():
        data = request.json
        name = data.get('name')  # Get the name from the request
        email = data.get('email')
        password = data.get('password')
        city = data.get('city')

        print(f"Attempting to register user: {email}")  # New log

        # Input validation
        if not name or not email or not password or not city:
            print(f"Missing required fields for {email}")  # New log
            return jsonify({"error": "Missing required fields"}), 400

        # Check password strength
        if not is_strong_password(password):
            print(f"Weak password attempt for {email}")  # New log
            return jsonify({"error": "Password not strong enough"}), 400

        def register_user(cursor):
            # Check if user exists
            cursor.execute("SELECT * FROM installer WHERE email = %s", (email,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                print(f"User {email} already exists")  # New log
                return jsonify({"error": "Email already registered"}), 409
            
            # Create new user
            hashed_password = set_password(password)
            print(f"Inserting user {email} into database")  # New log
            cursor.execute("INSERT INTO installer (name, email, password, city) VALUES (%s, %s, %s, %s)",
                           (name, email, hashed_password, city))
            print(f"User {email} registered successfully")  # Existing log
            return jsonify({"message": "Installer registered successfully!"}), 201

        try:
            result = retry_operation(register_user)
            return result
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            return jsonify({"error": "An internal error occurred"}), 500

    def is_strong_password(password):
        return (len(password) >= 12 and
                re.search(r"\d", password) and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))

    @app.route('/login', methods=['POST'])
    @limiter.limit("5 per minute", key_func=get_remote_address)
    def login():
        inputs = UserInputs(request)
        if not inputs.validate():
            return jsonify({"errors": inputs.errors}), 400
        
        data = request.json
        email = data.get('email', '')
        password = data.get('password', '')
        
        print(f"Login attempt for email: {email}")  # Debug log
        
        # Temporary: accept any credentials change when in production
        access_token = create_access_token(identity=email)
        refresh_token = create_refresh_token(identity=email)
        
        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "message": "Login successful"
        }), 200
        
        '''
        try:
            data = request.json
            email = data.get('email', '')
            password = data.get('password', '')

            logging.info(f"Login attempt for email: {sanitize_log(email)}")

            if not all([email, password]):
                return jsonify({"error": "Missing email or password"}), 400

            conn = connection_pool.get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM installer WHERE email = %s", (email,))
            user = cursor.fetchone()
            print(f"User found: {user}")  # Add this line
            if user:
                stored_password = user['password']
                print(f"Stored password: {stored_password}")  # Add this line
                if verify_bcrypt_hash(password, stored_password):
                    print("Password verified successfully")  # Add this line
                    access_token = create_access_token(identity=user['id'])
                    refresh_token = create_refresh_token(identity=user['id'])
                    return jsonify({
                        "access_token": access_token,
                        "refresh_token": refresh_token,
                        "message": "Login successful"
                    }), 200
                else:
                    print("Password verification failed")  # Add this line
                    return jsonify({"error": "Invalid credentials"}), 401
            else:
                print("User not found")  # Add this line
                return jsonify({"error": "Invalid credentials"}), 401
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            print(f"Full error: {traceback.format_exc()}")  # Print full traceback
            return jsonify({"error": "An internal error occurred"}), 500
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()'''

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

    @contextmanager
    def get_db_connection():
        connection = connection_pool.get_connection()
        logger.info(f"Opened connection {connection.connection_id}")
        try:
            yield connection
        finally:
            logger.info(f"Closed connection {connection.connection_id}")
            connection.close()

    @app.route('/user-profile')
    @jwt_required()
    def user_profile():
        current_user = get_jwt_identity()
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT name, email, city FROM installer WHERE email = %s", (current_user,))
                user_data = cursor.fetchone()
                if user_data:
                    return jsonify(user_data), 200
                else:
                    return jsonify({"error": "User not found"}), 404
            except mysql.connector.Error as err:
                app.logger.error(f"Database error: {err}")
                return jsonify({"error": "Database error"}), 500

    @app.route('/protected-route-1', methods=['GET'])
    @jwt_required()
    def protected_route_1():
        current_user_id = get_jwt_identity()
        return jsonify(message="This is a protected route"), 200

    @app.route('/protected-route-2', methods=['GET', 'POST'])
    @jwt_required()
    def protected_route_2():
        current_user_id = get_jwt_identity()
        if request.method == 'POST':
            data = request.json
        return jsonify(message="This is another protected route"), 200
    
    @app.route('/user-profile', methods=['GET'])
    @jwt_required()
    def get_user_profile():
        current_user_id = get_jwt_identity()
        user_profile = {
            "id": current_user_id,
            "name": "John Doe",
            "email": "john.doe@example.com",
            "city": "New York",
            "profile_picture": "path/to/profile/picture.jpg"
        }
        return jsonify(user_profile), 200

    @app.route('/update-profile', methods=['PUT'])
    @jwt_required()
    def update_user_profile():
        current_user_id = get_jwt_identity()
        data = request.json
    # Update user profile in database
    # This is a placeholder - you'd replace this with actual database update
        return jsonify(message="Profile updated successfully", updated_data=data), 200

    @app.route('/logout', methods=['POST'])
    @jwt_required()
    def logout():
        jti = get_jwt()["jti"]
        revoked_tokens.add(jti)
        return jsonify(message="Successfully logged out"), 200

    def admin_required():
        current_user_id = get_jwt_identity()
        if not check_if_user_is_admin(current_user_id):
            return jsonify(message="Admin access required"), 403

    @app.route('/admin-only', methods=['GET'])
    @jwt_required()
    def admin_only_route():
        if admin_required():
            return admin_required()
        # Admin-only logic here
        return jsonify(message="Welcome, admin!"), 200
    
    

    def check_if_user_is_admin(user_id):
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT is_admin FROM installer WHERE id = %s", (user_id,))
            result = cursor.fetchone()
        return result['is_admin'] if result else False

    # ... (keep your other routes and functions) ...

    # Configure Flask-Mail
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'your-email@gmail.com'    
    app.config['MAIL_PASSWORD'] = 'your-password'
    app.config['MAIL_DEFAULT_SENDER'] = 'your-email@gmail.com'
    mail = Mail(app)

    # store reset tokens (in production use REDIS)
    global reset_tokens
    reset_tokens = {}

    def send_reset_email(email, token):
        reset_link = f"http://127.0.0.1:5001/reset-password/{token}"
        print(f"Password reset link for {email}: {reset_link}")
        # In a real application, you would send an email here

    def get_user_by_email(email):
        with get_db_connection() as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM installer WHERE email = %s", (email,))
            user = cursor.fetchone()
            cursor.fetchall()  # Fetch any remaining rows
            return user
    
    def generate_reset_token():
        return secrets.token_urlsafe(32)

    @app.route('/forgot-password', methods=['POST'])
    def forgot_password():
        email = request.json.get('email')
        token = generate_reset_token()
        reset_tokens[token] = email  # Store the token
        send_reset_email(email, token)
        return jsonify({"message": "Password reset email sent", "token": token}), 200  # Return token for testing
    
    def update_user_password(email, new_password):
        hashed_password = generate_bcrypt_hash(new_password)
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE installer SET password = %s WHERE email = %s", (hashed_password, email))
            conn.commit()

    @app.route('/reset-password/<token>', methods=['POST'])
    def reset_password(token):
        global reset_tokens
        if token not in reset_tokens:
            return jsonify({"error": "Invalid or expired token"}), 400
        email = reset_tokens[token]
        new_password = request.json.get('new_password')
        if not validate_password(new_password):
            return jsonify({"error": "New password does not meet requirements"}), 400
        update_user_password(email, new_password)
        del reset_tokens[token]
        return jsonify({"message": "Password reset successful"}), 200

    @app.errorhandler(404)
    def not_found_error(error):
        return jsonify({"error": "Not Found"}), 404

    @app.errorhandler(Exception)
    def handle_exception(e):
        app.logger.error(f"An error occurred: {sanitize_log(str(e))}")
        return jsonify({"error": "An internal error occurred"}), 500

    @app.route('/user/<email>', methods=['DELETE'])
    def delete_user(email):
        # Delete user logic here
        return jsonify({"message": "User deleted"}), 200

    @app.route('/test-db', methods=['GET'])
    def test_db():
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT 1")
                result = cursor.fetchone()
            return jsonify({"message": "Database connection successful", "result": result}), 200
        except Exception as e:
            return jsonify({"error": f"Database connection failed: {str(e)}"}), 500

    @app.route('/check-user/<email>', methods=['GET'])
    def check_user(email):
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM installer WHERE email = %s", (email,))
                user = cursor.fetchone()
            if user:
                return jsonify({"message": f"User {email} found", "user": user}), 200
            else:
                return jsonify({"message": f"User {email} not found"}), 404
        except Exception as e:
            return jsonify({"error": f"Error checking user: {str(e)}"}), 500

    @app.route('/list-users', methods=['GET'])
    def list_users():
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT email FROM installer")
                users = cursor.fetchall()
            return jsonify({"users": [user['email'] for user in users]}), 200
        except Exception as e:
            return jsonify({"error": f"Error listing users: {str(e)}"}), 500

    '''Talisman(app, content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'",
    })'''

    csrf = CSRFProtect(app)

    if testing:
        # Disable CSRF protection for testing
        app.config['WTF_CSRF_ENABLED'] = False
    else:
        # Exempt specific routes from CSRF protection if needed
        csrf.exempt(app.route('/login', methods=['POST']))
        csrf.exempt(app.route('/register', methods=['POST']))
        # Add other routes that need to be exempted here

    @app.teardown_appcontext
    def close_db(error):
        if hasattr(g, 'db'):
            g.db.close()

    def close_connection_pool(exception=None):
        global connection_pool
        if connection_pool:
            while not connection_pool._cnx_queue.empty():
                conn = connection_pool._cnx_queue.get()
                conn.close()
            connection_pool._cnx_queue.put(None)

    def retry_operation(operation, max_attempts=3, delay=1):
        for attempt in range(max_attempts):
            conn = cursor = None
            try:
                conn = connection_pool.get_connection()
                cursor = conn.cursor()
                return operation(cursor)
            except PoolError:
                if attempt == max_attempts - 1:
                    raise
                time.sleep(delay)
            finally:
                if cursor:
                    cursor.close()
                if conn:
                    conn.close()

    return app, socketio, limiter, connection_pool

# At the end of the file
app, socketio, limiter, connection_pool = create_app()

if __name__ == '__main__':
    app, socketio, limiter, connection_pool = create_app()
    port = int(os.environ.get('PORT', 5001))
    socketio.run(app, host='0.0.0.0', port=port)