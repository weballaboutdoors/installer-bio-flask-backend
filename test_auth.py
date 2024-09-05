import sys
import os
import requests
import time
import mysql.connector
from mysql.connector import pooling

# Add the current directory to the Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(current_dir)

from app import app, connection_pool

BASE_URL = "http://127.0.0.1:5002"  # Changed port to 5002

reset_tokens = {}

def clean_database():
    conn = connection_pool.get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM installer WHERE email = 'test@example.com'")
        conn.commit()
    finally:
        cursor.close()
        conn.close()

def mock_send_reset_email(email, token):
    reset_tokens[email] = token
    print(f"Mock reset link for {email}: http://yourdomain.com/reset-password/{token}")

# Replace the real send_reset_email with the mock version
app.send_reset_email = mock_send_reset_email

def test_register():
    data = {
        "username": "testuser",
        "email": "test@example.com",
        "password": "TestPassword123!",
        "city": "Test City"
    }
    response = requests.post(f"{BASE_URL}/register", json=data)
    print("\nRegister Test:")
    print(f"URL: {response.url}")
    print(f"Request data: {data}")
    print(f"Response status code: {response.status_code}")
    print(f"Response text: {response.text}")
    assert response.status_code == 201
    return data['email'], data['password']

def test_login(email, password):
    data = {
        "email": email,
        "password": password
    }
    response = requests.post(f"{BASE_URL}/login", json=data)
    print("\nLogin Test:")
    print(f"URL: {response.url}")
    print(f"Request data: {data}")
    print(f"Response status code: {response.status_code}")
    print(f"Response text: {response.text}")
    assert response.status_code == 200
    return response.json().get('access_token'), response.json().get('refresh_token')

def test_protected_route(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f"{BASE_URL}/protected", headers=headers)
    print("\nProtected Route Test:")
    print(f"URL: {response.url}")
    print(f"Response status code: {response.status_code}")
    print(f"Response text: {response.text}")
    assert response.status_code == 200

def test_user_profile(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f"{BASE_URL}/user-profile", headers=headers)
    print("\nUser Profile Test:")
    print(f"Response status code: {response.status_code}")
    print(f"Response text: {response.text}")
    assert response.status_code == 200

def test_token_refresh(refresh_token):
    headers = {'Authorization': f'Bearer {refresh_token}'}
    response = requests.post(f"{BASE_URL}/refresh", headers=headers)
    print("\nToken Refresh Test:")
    print(f"Response status code: {response.status_code}")
    print(f"Response text: {response.text}")
    assert response.status_code == 200

def test_logout(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.post(f"{BASE_URL}/logout", headers=headers)
    print("\nLogout Test:")
    print(f"Response status code: {response.status_code}")
    print(f"Response text: {response.text}")
    assert response.status_code == 200

def test_forgot_password():
    email = 'test@example.com'
    response = requests.post(f"{BASE_URL}/forgot-password", json={'email': email})
    print("\nForgot Password Test:")
    print(f"Response status code: {response.status_code}")
    print(f"Response text: {response.text}")
    assert response.status_code == 200
    response_data = response.json()
    assert 'token' in response_data, "Reset token not generated"
    return response_data['token']

def get_reset_token():
    return list(reset_tokens.keys())[0] if reset_tokens else None

def test_reset_password():
    email = 'test@example.com'
    token = test_forgot_password()
    assert token is not None, "No reset token found"

    new_password = 'NewTestPassword123!'
    response = requests.post(f"{BASE_URL}/reset-password/{token}", json={'new_password': new_password})
    print("\nReset Password Test:")
    print(f"Response status code: {response.status_code}")
    print(f"Response text: {response.text}")
    assert response.status_code == 200

    # Try logging in with the new password
    login_response = requests.post(f"{BASE_URL}/login", json={'email': email, 'password': new_password})
    assert login_response.status_code == 200

if __name__ == '__main__':
    # Clean the database before running tests
    clean_database()
    
    # Start the Flask app in a separate thread
    import threading
    server_thread = threading.Thread(target=app.run, kwargs={"debug": False, "port": 5002})
    server_thread.start()
    
    # Wait for the server to start
    time.sleep(2)
    
    try:
        # Run your tests
        email, password = test_register()
        access_token, refresh_token = test_login(email, password)
        
        if access_token and refresh_token:
            test_protected_route(access_token)
            test_user_profile(access_token)
            test_token_refresh(refresh_token)
            test_logout(access_token)
        
        test_forgot_password()
        time.sleep(1)  # Add a small delay to ensure the token is generated
        test_reset_password()
    except KeyboardInterrupt:
        print("\nTests interrupted by user.")
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
    finally:
        print("Tests completed.")
        # Optionally, you can add code here to shut down the Flask app