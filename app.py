from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, FoodDonation
from config import Config
from functools import wraps
import logging
from datetime import datetime

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
logging.basicConfig(level=logging.DEBUG)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You must be logged in.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        role = request.form.get('role')

        if not email or not password or not name or not role:
            flash("All fields are required!", "danger")
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists.', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        user = User(email=email, password=hashed_password, role=role, name=name)

        db.session.add(user)
        db.session.commit()
        flash('Account created!', 'success')

        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['user_name'] = user.name
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))

        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('manage_donations.html')

@app.route('/donate_food', methods=['GET', 'POST'])
@login_required
def donate_food():
    if request.method == 'POST':
        food_name = request.form.get('food_name')
        quantity = request.form.get('quantity')
        location = request.form.get('location')
        expiry_date = request.form.get('expiry_date')

        donation = FoodDonation(
            user_id=session['user_id'],
            food_name=food_name,
            quantity=quantity,
            location=location,
            expiry_date=datetime.strptime(expiry_date, '%Y-%m-%d').date()
        )

        db.session.add(donation)
        db.session.commit()
        flash("Food donation submitted!", "success")

        return redirect(url_for('dashboard'))

    return render_template('donate_food.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
