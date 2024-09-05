import os  # Import the os module to access environment variables and interact with the operating system

class Config:
    # Retrieve the SECRET_KEY from the environment variables if available, or use a default value
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'allaboutdoors&windows1!'

    # Retrieve the MySQL database host from the environment variables, or use '127.0.0.1' as the default (localhost)
    MYSQL_HOST = os.environ.get('MYSQL_HOST') or '127.0.0.1'

    # Retrieve the MySQL username from the environment variables, or use 'root' as the default
    MYSQL_USER = os.environ.get('MYSQL_USER') or 'root'

    # Retrieve the MySQL password from the environment variables, or use 'root' as the default
    MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD') or 'root'

    # Retrieve the MySQL database name from the environment variables, or use 'installers_db' as the default
    MYSQL_DB = os.environ.get('MYSQL_DB') or 'installers_db'

    # Updated database URI using pymysql
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:root@127.0.0.1/installers_db'
