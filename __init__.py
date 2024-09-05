from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import os

# Initialize the database
db = SQLAlchemy()

def create_app():
    # Create the Flask application instance
    app = Flask(__name__)
    @app.route('/')
    def home():
        return jsonify({'message': 'Welcome to the Home'})
    # Enable CORS (Cross-Origin Resource Sharing)
    CORS(app)
    
    # Set up the app configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'allaboutdoors&windows1!'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'mysql://root:root@127.0.0.1/installers_db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize the database with the app instance
    db.init_app(app)
    
    # Import blueprints
    from .routes.auth import auth as auth_blueprint
    from .routes.installer import installer_bp as installer_blueprint  # Changed from installers to installer
    from .routes.skillsets import skillsets_bp
    
    # Register blueprints with the application instance
    app.register_blueprint(auth_blueprint, url_prefix='/auth')
    app.register_blueprint(installer_blueprint, url_prefix='/installer')  # Changed from installers to installer
    app.register_blueprint(skillsets_bp, url_prefix='/skillsets')
    
    # Initialize routes
    from .routes import init_routes
    init_routes(app)
    
    return app

# Create the app instance
app = create_app()
