import os
from datetime import timedelta

class Config:
    SECRET_KEY = 'your-secure-secret-key'  # Change this!
    SQLALCHEMY_DATABASE_URI = 'sqlite:///food_donation.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERMANENT_SESSION_LIFETIME = timedelta(days=1)
    SESSION_TYPE = 'filesystem'
