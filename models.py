from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Define relationships
    donations = db.relationship('FoodDonation', backref='donor', lazy=True)
    requests_made = db.relationship('FoodRequest', backref='requester', lazy=True,
                                  foreign_keys='FoodRequest.requester_id')

class FoodDonation(db.Model):
    __tablename__ = 'food_donations'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    food_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    expiry_date = db.Column(db.Date, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='available')
    
    # Define relationship
    requests = db.relationship('FoodRequest', backref='donation', lazy=True, 
                             cascade="all, delete-orphan")

class FoodRequest(db.Model):
    __tablename__ = 'food_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('food_donations.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, collected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)