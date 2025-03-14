import os
import secrets
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Generate a secure secret key
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(16)
    
    # Configure SQLAlchemy
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'food_donation.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Ensure the database directory is writable
    if not os.environ.get('DATABASE_URL') and not os.path.exists(basedir):
        os.makedirs(basedir)

    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_TYPE = 'filesystem'
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Theme settings
    DEFAULT_THEME = 'system'  # Options: light, dark, system
    
    # Debug and development settings
    DEBUG = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
