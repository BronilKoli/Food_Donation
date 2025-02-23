from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, FoodDonation
from config import Config
from functools import wraps
import logging
from datetime import datetime
from sqlalchemy.exc import IntegrityError
from sqlalchemy import desc

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
        try:
            email = request.form.get('email').lower().strip()
            password = request.form.get('password')
            name = request.form.get('name').strip()
            role = request.form.get('role')

            if not all([email, password, name, role]):
                flash("All fields are required!", "danger")
                return redirect(url_for('signup'))

            if User.query.filter_by(email=email).first():
                flash('Email already exists.', 'danger')
                return redirect(url_for('signup'))

            user = User(
                email=email,
                password=generate_password_hash(password, method='pbkdf2:sha256'),
                role=role,
                name=name
            )

            db.session.add(user)
            db.session.commit()
            logger.info(f"New user registered: {email}")
            flash('Account created successfully!', 'success')
            return redirect(url_for('login'))

        except IntegrityError:
            db.session.rollback()
            logger.error(f"Database integrity error during signup for email: {email}")
            flash('An error occurred during registration.', 'danger')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error during signup: {str(e)}")
            flash('An unexpected error occurred.', 'danger')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        try:
            email = request.form.get('email', '').lower().strip()
            password = request.form.get('password', '')

            logger.debug(f"Login attempt for email: {email}")

            if not email or not password:
                flash('Please provide both email and password.', 'danger')
                return render_template('login.html')

            user = User.query.filter_by(email=email).first()
            
            if user and check_password_hash(user.password, password):
                session.clear()
                session['user_id'] = user.id
                session['role'] = user.role
                session['user_name'] = user.name
                session.permanent = True
                
                logger.info(f"User logged in successfully: {email}")
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            
            logger.warning(f"Failed login attempt for email: {email}")
            flash('Invalid email or password.', 'danger')

        except Exception as e:
            logger.error(f"Error during login: {str(e)}")
            flash('An error occurred during login.', 'danger')

    return render_template('login.html')

@app.route('/')
@login_required
def dashboard():
    try:
        user_donations = []  # Initialize with empty list instead of None
        
        if session['role'] == 'donor':
            user_donations = FoodDonation.query.filter_by(
                user_id=session['user_id']
            ).order_by(desc(FoodDonation.created_at)).all() or []
        elif session['role'] == 'recipient':
            user_donations = FoodDonation.query.filter_by(
                status='available'
            ).order_by(FoodDonation.expiry_date).all() or []

        return render_template('manage_donations.html', donations=user_donations)

    except Exception as e:
        logger.error(f"Error in dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard.', 'danger')
        return redirect(url_for('login'))

@app.route('/donate_food', methods=['GET', 'POST'])
@login_required
def donate_food():
    if request.method == 'POST':
        try:
            food_name = request.form.get('food_name').strip()
            quantity = request.form.get('quantity').strip()
            location = request.form.get('location').strip()
            expiry_date = request.form.get('expiry_date')

            if not all([food_name, quantity, location, expiry_date]):
                flash("All fields are required!", "danger")
                return redirect(url_for('donate_food'))

            donation = FoodDonation(
                user_id=session['user_id'],
                food_name=food_name,
                quantity=quantity,
                location=location,
                expiry_date=datetime.strptime(expiry_date, '%Y-%m-%d').date()
            )

            db.session.add(donation)
            db.session.commit()
            logger.info(f"New food donation added by user {session['user_id']}")
            flash("Food donation submitted successfully!", "success")
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error in food donation: {str(e)}")
            flash('An error occurred while submitting the donation.', 'danger')

    return render_template('donate_food.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/debug-session')
def debug_session():
    if app.debug:
        return {
            'session': dict(session),
            'user_id_in_session': 'user_id' in session,
            'current_user': session.get('user_id')
        }
    return "Debug endpoint disabled in production"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
