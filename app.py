from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
import logging
from models import db, User, FoodDonation, FoodRequest
from config import Config
import os

# Set up logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize database
db.init_app(app)

# Create database tables
def init_db():
    with app.app_context():
        try:
            # Drop all tables first to ensure clean state
            db.drop_all()
            logger.info("Dropped all existing tables")
            
            # Create all tables
            db.create_all()
            logger.info("Created all database tables successfully!")
            
            # Create test users if needed
            if app.config['DEBUG']:
                test_donor = User(
                    email='donor@test.com',
                    password=generate_password_hash('password'),
                    name='Test Donor',
                    role='donor'
                )
                test_recipient = User(
                    email='recipient@test.com',
                    password=generate_password_hash('password'),
                    name='Test Recipient',
                    role='recipient'
                )
                db.session.add(test_donor)
                db.session.add(test_recipient)
                db.session.commit()
                logger.info("Created test users")
                
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            raise e

# Initialize database when app starts
init_db()

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Role-based access decorator
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') != role:
                flash(f'Only {role}s can access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    try:
        logger.info("Accessing signup route")
        
        if 'user_id' in session:
            logger.info("User already logged in, redirecting to dashboard")
            return redirect(url_for('dashboard'))
            
        if request.method == 'POST':
            try:
                # Extract and validate form data
                email = request.form.get('email', '').lower().strip()
                password = request.form.get('password', '')
                name = request.form.get('name', '').strip()
                role = request.form.get('role', '')

                # Validate required fields
                if not all([email, password, name, role]):
                    flash("All fields are required!", "danger")
                    return render_template('signup.html')

                # Email format validation (basic)
                if '@' not in email or '.' not in email:
                    flash("Please enter a valid email address.", "danger")
                    return render_template('signup.html')

                # Password length validation
                if len(password) < 6:
                    flash("Password must be at least 6 characters long.", "danger")
                    return render_template('signup.html')

                # Check if email already exists
                existing_user = User.query.filter_by(email=email).first()
                if existing_user:
                    flash('Email already exists.', 'danger')
                    return render_template('signup.html')

                # Validate role
                if role not in ['donor', 'recipient']:
                    flash('Invalid role selected.', 'danger')
                    return render_template('signup.html')

                # Create new user
                new_user = User(
                    email=email,
                    password=generate_password_hash(password),
                    name=name,
                    role=role
                )

                db.session.add(new_user)
                db.session.commit()
                
                logger.info(f"New {role} registered: {email}")
                flash('Account created successfully! Please login.', 'success')
                return redirect(url_for('login'))

            except Exception as e:
                db.session.rollback()
                logger.error(f"Error during signup: {str(e)}")
                flash('An error occurred during registration. Please try again.', 'danger')

        # GET request - show the signup form
        logger.info("Rendering signup template")
        return render_template('signup.html')
    except Exception as e:
        logger.error(f"Error in signup route: {str(e)}")
        return f"Error: {str(e)}", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        # Clear any existing session first
        session.clear()
        
        logger.info("Accessing login route")

        if request.method == 'POST':
            email = request.form.get('email', '').lower().strip()
            password = request.form.get('password', '')

            if not email or not password:
                flash('Please provide both email and password.', 'danger')
                return render_template('login.html')

            user = User.query.filter_by(email=email).first()
            
            if user and check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['role'] = user.role
                session['user_name'] = user.name
                
                logger.info(f"User logged in successfully: {email}")
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            
            flash('Invalid email or password.', 'danger')
            return render_template('login.html')

        # GET request
        return render_template('login.html')

    except Exception as e:
        logger.error(f"Error in login route: {str(e)}")
        flash('An error occurred. Please try again.', 'danger')
        return render_template('login.html')

@app.route('/')
@login_required
def dashboard():
    try:
        if session['role'] == 'donor':
            donations = FoodDonation.query.filter_by(user_id=session['user_id'])
            stats = {
                'total_donations': donations.count(),
                'active_donations': donations.filter_by(status='available').count(),
                'people_helped': FoodRequest.query.join(FoodDonation).filter(
                    FoodDonation.user_id == session['user_id'],
                    FoodRequest.status == 'collected'
                ).count()
            }
            recent_donations = donations.order_by(
                desc(FoodDonation.created_at)
            ).limit(6).all()
            
            return render_template('donor_dashboard.html',
                                 stats=stats,
                                 recent_donations=recent_donations)
        else:
            available_donations = FoodDonation.query.filter_by(
                status='available'
            ).order_by(FoodDonation.expiry_date).all()
            my_requests = FoodRequest.query.filter_by(
                requester_id=session['user_id']
            ).order_by(desc(FoodRequest.created_at)).limit(5).all()
            
            return render_template('receiver_dashboard.html',
                                 available_donations=available_donations,
                                 my_requests=my_requests)
            
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard.', 'danger')
        return redirect(url_for('login'))

@app.route('/donate', methods=['GET', 'POST'])
@login_required
@role_required('donor')
def donate_food():
    if request.method == 'POST':
        try:
            donation = FoodDonation(
                food_name=request.form['food_name'],
                quantity=request.form['quantity'],
                location=request.form['location'],
                expiry_date=datetime.strptime(request.form['expiry_date'], '%Y-%m-%d'),
                user_id=session['user_id']
            )
            db.session.add(donation)
            db.session.commit()
            flash('Food donation added successfully!', 'success')
            return redirect(url_for('manage_donations'))
        except Exception as e:
            logger.error(f"Donation error: {str(e)}")
            flash('Error adding donation.', 'danger')
            
    return render_template('donate_food.html')

@app.route('/manage-donations')
@login_required
@role_required('donor')
def manage_donations():
    donations = FoodDonation.query.filter_by(
        user_id=session['user_id']
    ).order_by(desc(FoodDonation.created_at)).all()
    return render_template('manage_donations.html', donations=donations)

@app.route('/browse-donations')
@login_required
@role_required('recipient')
def browse_donations():
    donations = FoodDonation.query.filter_by(
        status='available'
    ).order_by(FoodDonation.expiry_date).all()
    return render_template('browse_donations.html', donations=donations)

@app.route('/my-requests')
@login_required
@role_required('recipient')
def my_requests():
    requests = FoodRequest.query.filter_by(
        requester_id=session['user_id']
    ).order_by(desc(FoodRequest.created_at)).all()
    return render_template('my_requests.html', requests=requests)

@app.route('/request-food/<int:donation_id>', methods=['POST'])
@login_required
@role_required('recipient')
def request_food(donation_id):
    try:
        donation = FoodDonation.query.get_or_404(donation_id)
        if donation.status != 'available':
            flash('This donation is no longer available.', 'danger')
            return redirect(url_for('browse_donations'))
            
        existing_request = FoodRequest.query.filter_by(
            donation_id=donation_id,
            requester_id=session['user_id']
        ).first()
        
        if existing_request:
            flash('You have already requested this donation.', 'warning')
            return redirect(url_for('browse_donations'))
            
        request = FoodRequest(
            donation_id=donation_id,
            requester_id=session['user_id']
        )
        db.session.add(request)
        db.session.commit()
        flash('Request submitted successfully!', 'success')
        
    except Exception as e:
        logger.error(f"Food request error: {str(e)}")
        flash('Error submitting request.', 'danger')
        
    return redirect(url_for('my_requests'))

@app.route('/update-request/<int:request_id>/<string:status>')
@login_required
@role_required('donor')
def update_request(request_id, status):
    try:
        food_request = FoodRequest.query.get_or_404(request_id)
        # Verify the donor owns the donation
        if food_request.donation.user_id != session['user_id']:
            flash('Unauthorized action.', 'danger')
            return redirect(url_for('manage_donations'))
            
        food_request.status = status
        if status == 'collected':
            food_request.donation.status = 'collected'
            
        db.session.commit()
        flash('Request updated successfully!', 'success')
        
    except Exception as e:
        logger.error(f"Update request error: {str(e)}")
        flash('Error updating request.', 'danger')
        
    return redirect(url_for('manage_donations'))

@app.route('/edit-donation/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('donor')
def edit_donation(id):
    donation = FoodDonation.query.get_or_404(id)
    
    
    if donation.user_id != session['user_id']:
        flash('You can only edit your own donations.', 'danger')
        return redirect(url_for('manage_donations'))
        
    if request.method == 'POST':
        try:
            donation.food_name = request.form['food_name']
            donation.quantity = request.form['quantity']
            donation.location = request.form['location']
            donation.expiry_date = datetime.strptime(request.form['expiry_date'], '%Y-%m-%d')
            db.session.commit()
            flash('Donation updated successfully!', 'success')
            return redirect(url_for('manage_donations'))
        except Exception as e:
            logger.error(f"Error in edit_donation: {str(e)}")
            flash('Error updating donation. Please try again.', 'danger')
            
    return render_template('edit_donation.html', donation=donation)

@app.route('/delete-donation/<int:id>')
@login_required
def delete_donation(id):
    if session['role'] != 'donor':
        return redirect(url_for('dashboard'))
        
    try:
        donation = FoodDonation.query.get_or_404(id)
        if donation.user_id != session['user_id']:
            flash('You can only delete your own donations.', 'danger')
            return redirect(url_for('manage_donations'))
            
        db.session.delete(donation)
        db.session.commit()
        flash('Donation deleted successfully!', 'success')
        
    except Exception as e:
        logger.error(f"Error in delete_donation: {str(e)}")
        flash('Error deleting donation. Please try again.', 'danger')
        
    return redirect(url_for('manage_donations'))

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
    try:
        # Initialize database
        init_db()
        logger.info("Database initialized successfully!")
        
        # Run the application
        app.run(debug=True)
    except Exception as e:
        logger.error(f"Application failed to start: {str(e)}")
