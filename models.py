from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(db.Model, UserMixin):
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
    is_active = db.Column(db.Boolean, default=True)

    # Fix relationships to prevent conflicts
    donations = db.relationship('FoodDonation', 
                              backref='donor', 
                              lazy=True,
                              foreign_keys='FoodDonation.user_id')
    
    requests_made = db.relationship('FoodRequest', 
                                  backref='requester', 
                                  lazy=True,
                                  foreign_keys='FoodRequest.requester_id')
    
    # Relationships for volunteers and organizations
    volunteer_profile = db.relationship('Volunteer',
                                       backref='user',
                                       lazy=True,
                                       uselist=False,
                                       foreign_keys='Volunteer.user_id')
    
    managed_volunteers = db.relationship('Volunteer',
                                       backref='organization',
                                       lazy=True,
                                       foreign_keys='Volunteer.organization_id')
    
    # Fix the receipts relationship
    receipts_generated = db.relationship('DonationReceipt',
                                       backref='generated_by_user',
                                       lazy=True,
                                       foreign_keys='DonationReceipt.generated_by')

    def __repr__(self):
        return f'<User {self.name}, {self.role}>'

class FoodDonation(db.Model):
    __tablename__ = 'food_donations'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    food_name = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    unit = db.Column(db.String(20), nullable=False, default='items')
    location = db.Column(db.String(200), nullable=True)  # Make nullable for backward compatibility
    pickup_address = db.Column(db.Text, nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='available')  # available, reserved, collected
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), default='perishable')
    storage_instructions = db.Column(db.Text, nullable=True)
    allergen_info = db.Column(db.String(200), nullable=True)

    # Fix relationships
    requests = db.relationship('FoodRequest', 
                             backref='donation', 
                             lazy=True,
                             cascade="all, delete-orphan")
    
    receipts = db.relationship('DonationReceipt',
                             backref='donation',
                             lazy=True,
                             cascade="all, delete-orphan")

    # Convenience properties
    @property
    def donor_name(self):
        return self.donor.name if self.donor else "Unknown"

    @property
    def date(self):
        return self.created_at.strftime('%Y-%m-%d') if self.created_at else ""

    @property
    def amount(self):
        return f"{self.quantity} {self.unit}"
    
    def __repr__(self):
        return f'<FoodDonation {self.food_name}, {self.status}>'

class FoodRequest(db.Model):
    __tablename__ = 'food_requests'

    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('food_donations.id'), nullable=False)
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    volunteer_id = db.Column(db.Integer, db.ForeignKey('volunteers.id'), nullable=True)
    status = db.Column(db.String(20), default='pending')  # pending, approved, denied, completed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    pickup_time = db.Column(db.DateTime, nullable=True)
    delivery_status = db.Column(db.String(20), nullable=True)  # picked_up, in_transit, delivered
    delivery_notes = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<FoodRequest {self.id}, status: {self.status}>'

    # Convenience properties
    @property
    def organization_name(self):
        return self.requester.name if self.requester else "Unknown"

class Volunteer(db.Model):
    __tablename__ = 'volunteers'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    status = db.Column(db.String(20), default='active')  # active, inactive, busy
    assigned_task = db.Column(db.String(100), nullable=True)
    availability = db.Column(db.String(200), nullable=True)
    vehicle_type = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_active = db.Column(db.DateTime, nullable=True)
    contact = db.Column(db.String(20), nullable=True)
    address = db.Column(db.Text, nullable=True)
    preferred_area = db.Column(db.String(100), nullable=True)
    max_distance = db.Column(db.Integer, nullable=True)
    languages = db.Column(db.String(200), nullable=True)
    emergency_contact = db.Column(db.String(100), nullable=True)
    
    # Fix relationship to prevent conflicts
    assigned_requests = db.relationship('FoodRequest', 
                                      backref='volunteer', 
                                      lazy=True)
    
    def __repr__(self):
        return f'<Volunteer {self.id}, status: {self.status}>'

class DonationReceipt(db.Model):
    __tablename__ = 'donation_receipts'

    id = db.Column(db.Integer, primary_key=True)
    donation_id = db.Column(db.Integer, db.ForeignKey('food_donations.id'), nullable=False)
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receipt_number = db.Column(db.String(50), unique=True, nullable=False)
    receipt_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Receipt {self.receipt_number}>'
