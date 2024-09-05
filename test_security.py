import unittest
import json
import time
import logging  # Add this import
from utils import sanitize_log  # Make sure this import is correct
from app import app  # Add this import

class TestSecurity(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_sanitize_log(self):
        sensitive_data = "password=secret123&token=abc123&email=user@example.com"
        sanitized = sanitize_log(sensitive_data)
        print(f"Original: {sensitive_data}")
        print(f"Sanitized: {sanitized}")
        expected = "password=*****&token=*****&email=*****@*****"
        self.assertEqual(sanitized, expected)

    def test_error_handling(self):
        response = self.app.get('/non_existent_route')
        self.assertEqual(response.status_code, 404)
        data = json.loads(response.data)
        self.assertIn("error", data)
        self.assertNotIn("Werkzeug", data["error"])

    def test_login_error(self):
        response = self.app.post('/login', json={
            'email': 'nonexistent@example.com',
            'password': 'wrongpassword'
        })
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertIn("error", data)
        self.assertEqual(data["error"], "Invalid credentials")

    def test_password_not_exposed(self):
        email = 'test@example.com'
        # First, ensure the user doesn't exist
        delete_response = self.app.delete(f'/user/{email}')
        print(f"Delete response: {delete_response.status_code}, {delete_response.data}")
        
        time.sleep(0.1)  # Add a small delay
        
        response = self.app.post('/register', json={
            'name': 'Test User',
            'email': email,
            'password': 'TestPassword123!',
            'city': 'Test City'
        })
        print(f"Register response: {response.status_code}, {response.data}")
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertNotIn("TestPassword123!", str(data))

    def test_debug_mode_off(self):
        self.assertFalse(app.debug)

    def test_sensitive_data_not_in_logs(self):
        with self.assertLogs(level='INFO') as log:
            logging.info(sanitize_log("User login: email=user@example.com, password=secret123"))
        self.assertNotIn("user@example.com", log.output[0])
        self.assertNotIn("secret123", log.output[0])

    def test_sanitize_log_multiple_patterns(self):
        sensitive_data = "User login: email=user@example.com, password=secret123, token=abc123"
        sanitized = sanitize_log(sensitive_data)
        print(f"Multiple patterns - Original: {sensitive_data}")
        print(f"Multiple patterns - Sanitized: {sanitized}")
        expected = "User login: email=*****@*****, password=*****, token=*****"
        self.assertEqual(sanitized, expected)

if __name__ == '__main__':
    unittest.main()
