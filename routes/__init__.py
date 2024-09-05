from flask import Blueprint

# Create a Blueprint for the main routes
bp = Blueprint('main', __name__)

def init_routes(app):
    # Register the main blueprint
    app.register_blueprint(bp)

    # Import route modules
    from . import auth, installer, skillsets

# Import routes to avoid circular imports
from . import auth, installer, skillsets
