from flask import Blueprint, request, jsonify  # Import Flask modules for routing and JSON handling
from flask_login import login_user, logout_user, login_required  # Import Flask-Login for user management
from werkzeug.security import generate_password_hash  # Import functions for password hashing
from ..models import Installer  # Import the Installer model from the parent directory
from .. import db  # Import the database instance from the parent directory

# Create a Blueprint for authentication-related routes
auth = Blueprint('auth', __name__)

# Route for user registration
@auth.route('/register', methods=['POST'])
def register():
    data = request.get_json()  # Get the JSON data from the incoming POST request
    username = data.get('username')  # Extract the username from the JSON data
    email = data.get('email')  # Extract the email from the JSON data
    password = data.get('password')  # Extract the password from the JSON data
    
    # Check if any required fields are missing
    if not username or not email or not password:
        return jsonify({'message': 'Missing fields'}), 400  # Return a 400 error if fields are missing

    # Hash the password using SHA-256 for security
    hashed_password = generate_password_hash(password, method='sha256')
    
    # Create a new User instance with the provided data
    new_installer = Installer(username=username, email=email)
    new_installer.set_password(password)
    db.session.add(new_installer)
    db.session.commit()

    return jsonify({'message': 'Registered successfully'}), 201  # Return a success message

# Route for user login
@auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()  # Get the JSON data from the incoming POST request
    username = data.get('username')  # Extract the username from the JSON data
    password = data.get('password')  # Extract the password from the JSON data
    
    # Query the database to find a user with the given email
    installer = Installer.query.filter_by(username=username).first()
    if installer and installer.check_password(password):
        login_user(installer)
        return jsonify({'message': 'Logged in successfully'}), 200  # Return a success message if login is successful
    return jsonify({'error': 'Invalid username or password'}), 401  # Return a 401 error if credentials are invalid

# Route for user logout
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200  # Return a success message if logout is successful
