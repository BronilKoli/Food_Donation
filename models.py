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
    theme_preference = db.Column(db.String(20), default='system')
    contact_number = db.Column(db.String(20))
    address = db.Column(db.String(200))

    # Relationships
    donations = db.relationship('FoodDonation', backref='donor', lazy=True)
    requests_made = db.relationship('FoodRequest', backref='requester', lazy=True,
                                  foreign_keys='FoodRequest.requester_id')
    volunteer_profile = db.relationship('Volunteer', backref='user', lazy=True,
                                      uselist=False)

class FoodDonation(db.Model):
    __tablename__ = 'food_donations'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    food_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.String(50), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='available')  # available, reserved, collected
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), default='food')
    storage_instructions = db.Column(db.Text)
    allergen_info = db.Column(db.String(200))

    # Relationships
    requests = db.relationship('FoodRequest', backref='donation', lazy=True,
                             cascade="all, delete-orphan")
    receipt = db.relationship('DonationReceipt', backref='donation', lazy=True,
                            uselist=False)

class FoodRequest(db.Model):
    __tablename__ = 'food_requests'

    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('food_donations.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    volunteer_id = db.Column(db.Integer, db.ForeignKey('volunteers.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, approved, collected, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    pickup_time = db.Column(db.DateTime)
    delivery_status = db.Column(db.String(20))  # picked_up, in_transit, delivered
    delivery_notes = db.Column(db.Text)

class Volunteer(db.Model):
    __tablename__ = 'volunteers'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    status = db.Column(db.String(20), default='active')  # active, inactive, busy
    assigned_task = db.Column(db.String(100))
    availability = db.Column(db.String(200))
    vehicle_type = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime)

    # Relationships
    assigned_requests = db.relationship('FoodRequest', backref='volunteer', lazy=True)
    organization = db.relationship('User', foreign_keys=[organization_id], backref='assigned_volunteers')

class DonationReceipt(db.Model):
    __tablename__ = 'donation_receipts'

    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('food_donations.id'), nullable=False, unique=True)
    receipt_date = db.Column(db.DateTime, default=datetime.utcnow)
    receipt_number = db.Column(db.String(50), unique=True)
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    collection_signature = db.Column(db.String(255))
    notes = db.Column(db.Text)

    # Relationship with admin who generated the receipt
    admin = db.relationship('User', foreign_keys=[generated_by])
