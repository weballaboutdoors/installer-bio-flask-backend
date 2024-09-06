import os
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
import mysql.connector
from mysql.connector import pooling
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import logging
import scrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
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

load_dotenv()  # Load environment variables

logging.basicConfig(level=logging.INFO)

# Password validation function
def validate_password(password):
    return (len(password) >= 8 and
            re.search(r"\d", password) and
            re.search(r"[A-Z]", password) and
            re.search(r"[a-z]", password) and
            re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
# Generate scrypt hash for password
def generate_scrypt_hash(password):
    salt = os.urandom(16)
    hash = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
    return f"$scrypt$n=16384,r=8,p=1${salt.hex()}${hash.hex()}"

def verify_scrypt_hash(password, hash_string):
    try:
        algorithm, params, salt, hash = hash_string.split('$')[1:]
        assert algorithm == 'scrypt'
        n, r, p = [int(x.split('=')[1]) for x in params.split(',')]
        salt = bytes.fromhex(salt)
        hash = bytes.fromhex(hash)
        return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p) == hash
    except (ValueError, AssertionError):
        return False

def set_password(password):
    return generate_scrypt_hash(password)

def check_password(stored_password, provided_password):
    return verify_scrypt_hash(provided_password, stored_password)

def create_app():
    try:
        app = Flask(__name__)
        app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
        app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
        CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "https://your-frontend-domain.com"]}})
        socketio = SocketIO(app, cors_allowed_origins="*")

        # Create a connection pool
        db_config = {
            "host": os.getenv('DB_HOST'),
            "user": os.getenv('DB_USER'),
            "password": os.getenv('DB_PASSWORD'),
            "database": os.getenv('DB_NAME')
        }
        connection_pool = pooling.MySQLConnectionPool(pool_name="mypool", pool_size=5, **db_config)

        # Configure upload folder for profile pictures
        UPLOAD_FOLDER = 'static/profile_pictures'
        ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
        app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

        def allowed_file(filename):
            return '.' in filename and \
                   filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

        limiter = Limiter(
            get_remote_address,
            app=app,
            default_limits=["200 per day", "50 per hour"]
        )

        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

        jwt = JWTManager(app)
        app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

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
        def register():
            data = request.json
            email = data.get('email')
            name = data.get('name', 'Default Name')  # Provide a default name if not provided
            
            conn = connection_pool.get_connection()
            cursor = conn.cursor(dictionary=True)
            
            # Check if user exists
            cursor.execute("SELECT * FROM installer WHERE email = %s", (email,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                # If user exists, delete it
                cursor.execute("DELETE FROM installer WHERE email = %s", (email,))
            
            # Create new user
            hashed_password = set_password(data['password'])
            cursor.execute("INSERT INTO installer (email, name, city, password) VALUES (%s, %s, %s, %s)",
                           (email, name, data['city'], hashed_password))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            return jsonify({"message": "Installer registered successfully!"}), 201

        @app.route('/login', methods=['POST'])
        @limiter.limit("10 per minute")
        def login():
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
                    if verify_scrypt_hash(password, stored_password):
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

        @app.route('/user-profile', methods=['GET'])
        @jwt_required()
        def user_profile():
            current_user = get_jwt_identity()
            # ... rest of the function ...

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
            conn = connection_pool.get_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT is_admin FROM installer WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            cursor.close()
            conn.close()
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
            conn = connection_pool.get_connection()
            try:
                cursor = conn.cursor(dictionary=True)
                cursor.execute("SELECT * FROM installer WHERE email = %s", (email,))
                user = cursor.fetchone()
                cursor.fetchall()  # Fetch any remaining rows
                return user
            finally:
                cursor.close()
                conn.close()
        
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
            hashed_password = generate_scrypt_hash(new_password)
            conn = connection_pool.get_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE installer SET password = %s WHERE email = %s", (hashed_password, email))
            conn.commit()
            cursor.close()
            conn.close()

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

        return app, socketio, limiter, connection_pool
    except Exception as e:
        print(f"Error in create_app(): {e}")
        import traceback
        traceback.print_exc()
        return None, None, None, None  # Return a tuple of None values

app, socketio, limiter, connection_pool = create_app()

if app is not None:
    if __name__ == '__main__':
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', port=port)
else:
    print("Failed to create app")
