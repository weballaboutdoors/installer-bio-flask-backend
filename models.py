from datetime import datetime  # Import the datetime class to handle dates and times
from . import db  # Import the database object from the app module, typically an instance of SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# User Model
class User(db.Model):
    __tablename__ = 'users'  # Define the name of the table in the database

    id = db.Column(db.Integer, primary_key=True)  # Primary key column, automatically increments
    username = db.Column(db.String(100), nullable=False, unique=True)  # Username column, must be unique and not null
    email = db.Column(db.String(100), nullable=False, unique=True)  # Email column, must be unique and not null
    password = db.Column(db.String(255), nullable=False)  # Password column, must not be null
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp for when the user was created, defaults to current time

    def __repr__(self):
        return f"<User {self.username}>"  # String representation of the User object, useful for debugging

# Installer Model
class Installer(db.Model, UserMixin):
    __tablename__ = 'installer'  # Ensure this matches your table name
    
    id = db.Column(db.Integer, primary_key=True)  # Primary key column, automatically increments
    username = db.Column(db.String(64), unique=True, nullable=False)  # Username column, must be unique and not null
    email = db.Column(db.String(120), unique=True, nullable=False)  # Email column, must be unique and not null
    password_hash = db.Column(db.String(128))  # Password hash column, must not be null
    name = db.Column(db.String(100), nullable=False)  # Name column, must not be null
    city = db.Column(db.String(100), nullable=False)  # City column, must not be null
    profession = db.Column(db.String(100), nullable=False)  # Profession column, must not be null
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp for when the installer was created, defaults to current time

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<Installer {self.name}, {self.profession} in {self.city}>"  # String representation of the Installer object

# Example Additional Model: Appointment
class Appointment(db.Model):
    __tablename__ = 'appointments'  # Define the name of the table in the database

    id = db.Column(db.Integer, primary_key=True)  # Primary key column, automatically increments
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Foreign key linking to the User table, must not be null
    installer_id = db.Column(db.Integer, db.ForeignKey('installers.id'), nullable=False)  # Foreign key linking to the Installer table, must not be null
    appointment_date = db.Column(db.DateTime, nullable=False)  # Date and time of the appointment, must not be null
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp for when the appointment was created, defaults to current time

    # Relationships with the User and Installer models
    user = db.relationship('User', backref=db.backref('appointments', lazy=True))  # Relationship to the User model
    installer = db.relationship('Installer', backref=db.backref('appointments', lazy=True))  # Relationship to the Installer model

    def __repr__(self):
        return f"<Appointment {self.id}: User {self.user_id} with Installer {self.installer_id} on {self.appointment_date}>"  # String representation of the Appointment object

class Person(db.Model):
    # Define your Person model here
    id = db.Column(db.Integer, primary_key=True)
    # Add other fields as needed

class Skillset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Add other fields as needed
    
    def __repr__(self):
        return f'<Skillset {self.id}>'

class PersonSkillset(db.Model):
    # Define your PersonSkillset model here
    id = db.Column(db.Integer, primary_key=True)
    person_id = db.Column(db.Integer, db.ForeignKey('person.id'), nullable=False)
    skillset_id = db.Column(db.Integer, db.ForeignKey('skillset.id'), nullable=False)
    # Add other fields as needed