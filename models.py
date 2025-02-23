from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # "Donor" or "Receiver"
    name = db.Column(db.String(100), nullable=False)

class FoodDonation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food_name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(50), default='Available')  # Available, Collected

    user = db.relationship('User', backref='donations')
