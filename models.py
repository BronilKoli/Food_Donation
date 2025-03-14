from flask_sqlalchemy import SQLAlchemy
from datetime import datetime


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # donor, organization, volunteer, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    theme_preference = db.Column(db.String(20), default='system')  # light, dark, system

    # Define relationships
    donations = db.relationship('Donation', backref='donor', lazy=True)
    requests_made = db.relationship('DonationRequest', backref='requester', lazy=True,
                                    foreign_keys='DonationRequest.requester_id')
    volunteers = db.relationship('Volunteer', backref='assigned_agent', lazy=True,
                                  foreign_keys='Volunteer.assigned_agent_id')


class Donation(db.Model):
    __tablename__ = 'donations'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    item_name = db.Column(db.String(100), nullable=False)
    donation_type = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='available')
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), default='food')

    # Define relationship
    requests = db.relationship('DonationRequest', backref='donation', lazy=True,
                               cascade="all, delete-orphan")


class DonationRequest(db.Model):
    __tablename__ = 'donation_requests'

    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('donations.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    volunteer_id = db.Column(db.Integer, db.ForeignKey('volunteers.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, approved, collected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Volunteer(db.Model):
    __tablename__ = 'volunteers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contact = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    assigned_agent_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)  # Assigned to a specific NGO
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    donation_requests = db.relationship('DonationRequest', backref='volunteer', lazy=True)
