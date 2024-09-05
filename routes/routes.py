from flask import jsonify

def init_routes(app):
    @app.route('/')
    def index():
        return jsonify({"message": "Welcome to the API"})

    @app.route('/health')
    def health_check():
        return jsonify({"status": "healthy"})

    # Add more routes as needed
