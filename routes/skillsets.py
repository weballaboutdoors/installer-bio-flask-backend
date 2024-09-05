from flask import Blueprint, request, jsonify
from ..models import db, Person, Skillset

skillsets_bp = Blueprint('skillsets', __name__)

@skillsets_bp.route('/search', methods=['GET'])
def search_skillsets():
    query = request.args.get('q', '')
    people = Person.query.join(Skillset).filter(Skillset.name.ilike(f'%{query}%')).all()
    return jsonify([person.to_dict() for person in people])
