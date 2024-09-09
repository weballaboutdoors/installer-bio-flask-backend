import sys
import os
import requests
import time
import mysql.connector
from mysql.connector import pooling
from app import create_app, get_db_connection
import unittest
import uuid

# Add the current directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

class TestAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app, cls.socketio, cls.limiter, cls.connection_pool = create_app(testing=True)
        cls.client = cls.app.test_client()
        cls.app_context = cls.app.app_context()
        cls.app_context.push()

    @classmethod
    def tearDownClass(cls):
        cls.app_context.pop()
        # Instead of closing the pool, we'll close all connections in it
        while cls.connection_pool._cnx_queue.qsize() > 0:
            conn = cls.connection_pool._cnx_queue.get()
            conn.close()

    def setUp(self):
        self.connection = None
        self.cursor = None
        self.unique_email = f"testuser_{uuid.uuid4()}@example.com"

    def tearDown(self):
        if self.cursor:
            self.cursor.close()
        if self.connection:
            self.connection.close()

    def get_db_cursor(self):
        if not self.connection or not self.connection.is_connected():
            self.connection = get_db_connection()
        if not self.cursor or self.cursor.is_closed():
            self.cursor = self.connection.cursor(dictionary=True)
        return self.cursor

    def test_app_exists(self):
        self.assertIsNotNone(self.app)

    def test_registration(self):
        response = self.client.post('/register', json={
            'name': 'Test User',
            'email': self.unique_email,
            'password': 'StrongPassword123!',
            'city': 'Test City'
        })
        self.assertEqual(response.status_code, 201)
        # Add more assertions as needed

    def test_login(self):
        # First, register a user
        self.client.post('/register', json={
            'name': 'Test User',
            'email': self.unique_email,
            'password': 'StrongPassword123!',
            'city': 'Test City'
        })
        
        # Then, try to log in
        response = self.client.post('/login', json={
            "email": self.unique_email,
            "password": "StrongPassword123!"
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn("access_token", response.json)
        self.assertIn("refresh_token", response.json)

    def test_invalid_login(self):
        # Test login with incorrect credentials
        pass

    def test_password_reset(self):
        # Test password reset functionality
        pass

    def test_token_expiration(self):
        # Test if authentication tokens expire correctly
        pass

if __name__ == '__main__':
    unittest.main()