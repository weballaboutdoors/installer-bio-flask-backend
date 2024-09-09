import random
import string

def generate_name():
    first_names = ['John', 'Jane', 'Alice', 'Bob', 'Charlie', 'Diana', 'Ethan', 'Fiona', 'George', 'Hannah']
    last_names = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez']
    return f"{random.choice(first_names)} {random.choice(last_names)}"

def generate_email(name):
    domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'example.com']
    username = name.lower().replace(' ', '.') + ''.join(random.choices(string.digits, k=3))
    return f"{username}@{random.choice(domains)}"

def generate_password():
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=12))

def generate_test_data(num_entries):
    test_data = []
    for _ in range(num_entries):
        name = generate_name()
        email = generate_email(name)
        password = generate_password()
        test_data.append({'name': name, 'email': email, 'password': password})
    return test_data

if __name__ == "__main__":
    num_entries = 10  # Change this to generate more or fewer entries
    test_data = generate_test_data(num_entries)
    for entry in test_data:
        print(f"Name: {entry['name']}")
        print(f"Email: {entry['email']}")
        print(f"Password: {entry['password']}")
        print()
