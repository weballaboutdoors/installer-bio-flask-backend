from flask import Blueprint, request, jsonify  # Import necessary modules from Flask
from .. import db  # Import the database instance from the app
from ..models import Installer  # Assuming you have an Installer model

# Create a Blueprint for the installer routes
installer_bp = Blueprint('installer', __name__)

# Define a route for getting a list of installers with optional search parameters
@installer_bp.route('', methods=['GET'])
def get_installers():
    profession = request.args.get('profession')  # Get the 'profession' parameter from the request's query string
    city = request.args.get('city')  # Get the 'city' parameter from the request's query string
    
    # Base SQL query to select all installers
    query = "SELECT * FROM installer WHERE 1=1"  # Changed from installers to installer
    params = []  # List to hold parameters for the SQL query
    
    # If a profession is specified, add it to the SQL query
    if profession:
        query += " AND profession = %s"
        params.append(profession)
    
    # If a city is specified, add it to the SQL query
    if city:
        query += " AND city = %s"
        params.append(city)
    
    # Create a cursor to execute the query, with dictionary=True to get results as dictionaries
    cursor = db.cursor(dictionary=True)
    cursor.execute(query, tuple(params))  # Execute the query with the specified parameters
    installers = cursor.fetchall()  # Fetch all the results from the query
    
    # Return the list of installers as a JSON response
    return jsonify(installers)

# Define a route for searching installers by city
@installer_bp.route('/search', methods=['GET'])
def search_installers():
    city = request.args.get('city')
    if not city:
        return jsonify({'error': 'City parameter is required'}), 400

    installers = Installer.query.filter(Installer.city.ilike(f'%{city}%')).all()
    
    results = [
        {
            'id': installer.id,
            'name': installer.name,
            'city': installer.city,
            # Add other relevant fields
        } for installer in installers
    ]

    return jsonify(results)
