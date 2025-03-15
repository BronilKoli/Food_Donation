from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
from functools import wraps
from sqlalchemy import desc
import logging
from models import db, User, FoodDonation, FoodRequest, Volunteer, DonationReceipt
from forms import (LoginForm, SignupForm, DonationForm, UserPreferencesForm, 
                  DonationRequestForm, VolunteerForm)
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

# Disable CSRF protection for development
app.config['WTF_CSRF_ENABLED'] = False

# Initialize database
db.init_app(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except:
        return None

# Create database tables
def init_db():
    with app.app_context():
        try:
            # Check if database directory is writable
            db_path = app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            db_dir = os.path.dirname(db_path)
            
            if db_dir and not os.access(db_dir, os.W_OK):
                logger.error(f"Database directory {db_dir} is not writable")
                raise PermissionError(f"Database directory {db_dir} is not writable")
            
            # Check if database file exists and is writable
            if os.path.exists(db_path) and not os.access(db_path, os.W_OK):
                logger.error(f"Database file {db_path} is not writable")
                raise PermissionError(f"Database file {db_path} is not writable")
            
            # Check tables
            inspect = db.inspect(db.engine)
            tables_exist = inspect.get_table_names()
            
            if not tables_exist:
                logger.info("Creating database tables...")
                db.create_all()
                logger.info("Database tables created successfully!")
                
                # Create admin user only when tables are created fresh
                logger.info("Creating admin user...")
                admin = User(
                    email='admin@example.com',
                    password=generate_password_hash('admin123'),
                    name='Admin',
                    role='admin'
                )
                db.session.add(admin)
                db.session.commit()
                logger.info("Admin user created successfully!")
            else:
                logger.info("Database tables already exist")
                
                # Check if admin user exists
                admin_exists = User.query.filter_by(email='admin@example.com').first()
                if not admin_exists:
                    logger.info("Creating admin user...")
                    admin = User(
                        email='admin@example.com',
                        password=generate_password_hash('admin123'),
                        name='Admin',
                        role='admin'
                    )
                    db.session.add(admin)
                    db.session.commit()
                    logger.info("Admin user created successfully!")
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database initialization error: {str(e)}")
            raise e

# Initialize database when app starts
with app.app_context():
    init_db()  # This line is fine, but remove any DB operations outside functions

# Fix the inject_permissions context processor to use current_user instead of session
@app.context_processor
def inject_permissions():
    """Inject permissions into all templates"""
    if current_user.is_authenticated:
        return {'permissions': get_user_permissions(current_user.role)}
    return {'permissions': []}

# Fix the inject_theme context processor to use current_user
@app.context_processor
def inject_theme():
    theme = 'system'  # Default
    if current_user.is_authenticated:
        theme = current_user.theme_preference
    return {'theme_preference': theme}

# Update role_required decorator to handle multiple roles
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Allow lists of acceptable roles
            acceptable_roles = [role] if isinstance(role, str) else role
            
            if current_user.role not in acceptable_roles:
                flash('You do not have permission to access this page.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_user_permissions(role):
    """Define permissions for each role"""
    permissions = {
        'admin': ['manage_users', 'manage_donations', 'manage_volunteers', 
                 'generate_receipts', 'approve_requests'],
        'donor': ['create_donation', 'view_donations', 'update_donation'],
        'organization': ['request_donation', 'manage_volunteers', 'view_donations'],
        'volunteer': ['update_status', 'view_assignments', 'view_donations']
    }
    return permissions.get(role, [])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = SignupForm()
    if form.validate_on_submit():
        try:
            # Check if email exists
            if User.query.filter_by(email=form.email.data.lower()).first():
                flash('Email already registered', 'danger')
                return render_template('signup.html', form=form)

            # Create user
            user = User(
                email=form.email.data.lower(),
                password=generate_password_hash(form.password.data),
                name=form.name.data,
                role=form.role.data
            )
            
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error during registration. Please try again.', 'danger')
            
    return render_template('signup.html', form=form)

# Fix the login route (around line 199)
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):  # Changed password_hash to password
            login_user(user, remember=form.remember_me.data)
            session['role'] = user.role  # Store role in session
            session['user_id'] = user.id  # Store user_id in session
            
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('dashboard')
                
            return redirect(next_page)
        else:
            flash('Invalid email or password', 'danger')
            
    return render_template('login.html', form=form)

# Add the missing forgot_password route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Password recovery functionality"""
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # In a real application, you would:
            # 1. Generate a secure token
            # 2. Store it in the database with an expiry
            # 3. Send an email with a reset link
            
            flash('If your email exists in our system, you will receive password reset instructions.', 'info')
        else:
            # Don't reveal if email exists or not (security best practice)
            flash('If your email exists in our system, you will receive password reset instructions.', 'info')
            
        return redirect(url_for('login'))
        
    return render_template('forgot_password.html')

# Update the index route
@app.route('/')
def index():
    """Landing page route"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Update dashboard route to include all stats
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
            
        context = {
            'user': current_user,
            'role': current_user.role
        }
        
        if current_user.role == 'donor':
            donations = FoodDonation.query.filter_by(user_id=current_user.id)
            context.update({
                'stats': {
                    'total_donations': donations.count(),
                    'active_donations': donations.filter_by(status='available').count(),
                    'people_helped': FoodRequest.query.join(FoodDonation).filter(
                        FoodDonation.user_id == current_user.id,
                        FoodRequest.status == 'collected'
                    ).count()
                },
                'recent_donations': donations.order_by(desc(FoodDonation.created_at)).limit(6).all()
            })
            return render_template('donor_dashboard.html', **context)
            
        elif current_user.role == 'organization':
            requests = FoodRequest.query.filter_by(requester_id=current_user.id)
            context.update({
                'organization': current_user,
                'stats': {
                    'pending_requests': requests.filter_by(status='pending').count(),
                    'received_donations': requests.filter_by(status='completed').count(),
                    'active_volunteers': Volunteer.query.filter_by(
                        organization_id=current_user.id,
                        status='active'
                    ).count()
                },
                'recent_requests': requests.order_by(desc(FoodRequest.created_at)).limit(5).all(),
                'available_donations': FoodDonation.query.filter_by(status='available')
                    .order_by(FoodDonation.expiry_date).all()
            })
            return render_template('organization_dashboard.html', **context)
        
        elif current_user.role == 'volunteer':
            volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
            context.update({
                'volunteer': volunteer,
                'current_tasks': FoodRequest.query.filter_by(
                    volunteer_id=volunteer.id if volunteer else None,
                    status='approved'
                ).all(),
                'completed_tasks': FoodRequest.query.filter_by(
                    volunteer_id=volunteer.id if volunteer else None,
                    status='collected'
                ).order_by(desc(FoodRequest.created_at)).all()
            })
            return render_template('volunteer_dashboard.html', **context)
                                 
        elif current_user.role == 'admin':
            context.update({
                'stats': {
                    'total_users': User.query.count(),
                    'active_donations': FoodDonation.query.filter_by(status='available').count(),
                    'total_organizations': User.query.filter_by(role='organization').count(),
                    'active_volunteers': Volunteer.query.filter_by(status='active').count()
                },
                'recent_activities': get_recent_activities()
            })
            return render_template('admin_dashboard.html', **context)
            
        else:
            flash('Invalid user role', 'danger')
            return redirect(url_for('logout'))
            
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard.', 'danger')
        return redirect(url_for('login'))

# Add helper function for admin dashboard
def get_recent_activities():
    """Get recent system activities for admin dashboard"""
    activities = []
    
    # Recent donations
    donations = FoodDonation.query.order_by(desc(FoodDonation.created_at)).limit(5)
    for donation in donations:
        activities.append({
            'action': 'New Donation',
            'user': donation.donor.name,
            'date': donation.created_at,
            'id': donation.id
        })
    
    # Recent requests
    requests = FoodRequest.query.order_by(desc(FoodRequest.created_at)).limit(5)
    for request in requests:
        activities.append({
            'action': 'New Request',
            'user': request.requester.name,
            'date': request.created_at,
            'id': request.id
        })
    
    # Sort by date
    activities.sort(key=lambda x: x['date'], reverse=True)
    return activities[:5]

# Update donate_food route to match create_donations.html
@app.route('/donate', methods=['GET', 'POST'])
@login_required
@role_required('donor')
def donate_food():
    form = DonationForm()
    
    if request.method == 'POST':
        if not form.validate():
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f"{field}: {error}", 'danger')
        
        if form.validate_on_submit():
            try:
                donation = FoodDonation(
                    food_name=form.food_name.data,
                    quantity=form.quantity.data,
                    unit=form.unit.data,
                    location=form.pickup_address.data,
                    pickup_address=form.pickup_address.data,
                    expiry_date=form.expiry_date.data,
                    description=form.description.data,
                    category=form.category.data,
                    user_id=current_user.id,
                    storage_instructions=form.storage_instructions.data,
                    status='available'
                )
                db.session.add(donation)
                db.session.commit()
                flash('Donation added successfully!', 'success')
                return redirect(url_for('manage_donations'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Donation error: {str(e)}")
                flash(f'Error adding donation: {str(e)}', 'danger')
            
    return render_template('create_donations.html', form=form)

@app.route('/manage-donations')
@login_required
@role_required('donor')
def manage_donations():
    donations = FoodDonation.query.filter_by(
        user_id=current_user.id  # Use current_user.id instead of session['user_id']
    ).order_by(desc(FoodDonation.created_at)).all()
    return render_template('manage_donations.html', donations=donations)

@app.route('/browse-donations')
@login_required
@role_required(['organization', 'volunteer'])
def browse_donations():
    donations = FoodDonation.query.filter_by(
        status='available'
    ).order_by(FoodDonation.expiry_date).all()
    return render_template('browse_donations.html', donations=donations)

@app.route('/my-requests')
@login_required
@role_required('organization')
def my_requests():
    requests = FoodRequest.query.filter_by(
        requester_id=current_user.id  # Use current_user.id instead of session['user_id']
    ).order_by(desc(FoodRequest.created_at)).all()
    return render_template('my_requests.html', requests=requests)

@app.route('/request-food/<int:donation_id>', methods=['POST'])
@login_required
@role_required(['organization', 'volunteer'])
def request_food(donation_id):
    try:
        donation = FoodDonation.query.get_or_404(donation_id)
        if donation.status != 'available':
            flash('This donation is no longer available.', 'danger')
            return redirect(url_for('browse_donations'))
            
        existing_request = FoodRequest.query.filter_by(
            donation_id=donation_id,
            requester_id=current_user.id  # Changed from session['user_id'] to current_user.id
        ).first()
        
        if existing_request:
            flash('You have already requested this donation.', 'warning')
            return redirect(url_for('browse_donations'))
            
        request = FoodRequest(
            donation_id=donation_id,
            requester_id=current_user.id  # Changed from session['user_id'] to current_user.id
        )
        db.session.add(request)
        db.session.commit()
        flash('Request submitted successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Food request error: {str(e)}")
        flash('Error submitting request.', 'danger')
        
    return redirect(url_for('my_requests'))

# Update the update_request route
@app.route('/update-request/<int:request_id>/<string:status>')
@login_required
@role_required(['admin', 'donor'])
def update_request(request_id, status):
    try:
        food_request = FoodRequest.query.get_or_404(request_id)
        
        # Verify authorization using current_user instead of session
        if current_user.role == 'donor' and food_request.donation.user_id != current_user.id:
            flash('Unauthorized action.', 'danger')
            return redirect(url_for('manage_donations'))
            
        if status not in ['approved', 'denied', 'collected']:
            flash('Invalid status.', 'danger')
            return redirect(url_for('manage_donations'))
            
        food_request.status = status
        if status == 'approved':
            food_request.donation.status = 'reserved'
        elif status == 'collected':
            food_request.donation.status = 'collected'
        elif status == 'denied':
            food_request.donation.status = 'available'
            
        db.session.commit()
        
        status_messages = {
            'approved': 'Request approved successfully!',
            'denied': 'Request denied successfully!',
            'collected': 'Donation marked as collected!'
        }
        flash(status_messages.get(status, 'Request updated successfully!'), 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update request error: {str(e)}")
        flash('Error updating request.', 'danger')
        
    return redirect(url_for('manage_donations'))

# Update the settings route 
@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings page for managing preferences"""
    try:
        # Use current_user instead of session
        user = current_user
        form = UserPreferencesForm(obj=user)

        if request.method == 'POST' and form.validate_on_submit():
            form.populate_obj(user)
            db.session.commit()
            flash('Settings updated successfully!', 'success')
            return redirect(url_for('settings'))

        return render_template('settings.html', form=form)

    except Exception as e:
        logger.error(f"Settings error: {str(e)}")
        flash('Error updating settings.', 'danger')
        return redirect(url_for('dashboard'))

# Add missing view_request route
@app.route('/view-request/<int:id>')
@login_required
def view_request(id):
    try:
        request = FoodRequest.query.get_or_404(id)
        
        # Check permissions
        if current_user.role == 'donor' and request.donation.user_id != current_user.id:
            flash('You do not have permission to view this request.', 'danger')
            return redirect(url_for('dashboard'))
            
        if current_user.role == 'organization' and request.requester_id != current_user.id:
            flash('You do not have permission to view this request.', 'danger')
            return redirect(url_for('dashboard'))
            
        return render_template('request_details.html', request=request)
        
    except Exception as e:
        logger.error(f"Request details error: {str(e)}")
        flash('Error loading request details.', 'danger')
        return redirect(url_for('dashboard'))

# Add missing volunteer registration route
@app.route('/register-volunteer', methods=['GET', 'POST'])
@login_required
def register_volunteer():
    """Register as a volunteer"""
    if current_user.role != 'volunteer':
        flash('You must have a volunteer account to register as a volunteer.', 'danger')
        return redirect(url_for('dashboard'))
        
    existing_volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
    if existing_volunteer:
        flash('You are already registered as a volunteer.', 'info')
        return redirect(url_for('dashboard'))
        
    form = VolunteerForm()
    
    if form.validate_on_submit():
        try:
            volunteer = Volunteer(
                user_id=current_user.id,
                availability=form.availability.data,
                vehicle_type=form.vehicle_type.data if form.has_vehicle.data else None,
                status='active'
            )
            db.session.add(volunteer)
            db.session.commit()
            flash('Thank you for registering as a volunteer!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Volunteer registration error: {str(e)}")
            flash('Error during registration. Please try again.', 'danger')
            
    return render_template('register_volunteer.html', form=form)

# Fix the missing donation-requests route
@app.route('/donation-requests/<int:donation_id>')
@login_required
@role_required('donor')
def donation_requests(donation_id):
    """View requests for a specific donation"""
    try:
        donation = FoodDonation.query.get_or_404(donation_id)
        
        # Check if the current user is the owner of the donation
        if donation.user_id != current_user.id:
            flash('You can only view requests for your own donations.', 'danger')
            return redirect(url_for('manage_donations'))
            
        requests = FoodRequest.query.filter_by(donation_id=donation_id).all()
        
        return render_template('donation_requests.html', donation=donation, requests=requests)
        
    except Exception as e:
        logger.error(f"Error viewing donation requests: {str(e)}")
        flash('Error loading donation requests.', 'danger')
        return redirect(url_for('manage_donations'))

@app.route('/edit-donation/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('donor')
def edit_donation(id):
    donation = FoodDonation.query.get_or_404(id)
    
    # Use current_user.id instead of session['user_id']
    if donation.user_id != current_user.id:
        flash('You can only edit your own donations.', 'danger')
        return redirect(url_for('manage_donations'))
    
    form = DonationForm(obj=donation)
    
    if request.method == 'POST' and form.validate_on_submit():
        try:
            form.populate_obj(donation)
            db.session.commit()
            flash('Donation updated successfully!', 'success')
            return redirect(url_for('manage_donations'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error in edit_donation: {str(e)}")
            flash('Error updating donation. Please try again.', 'danger')
            
    return render_template('edit_donation.html', donation=donation, form=form)

@app.route('/delete-donation/<int:id>')
@login_required
@role_required('donor')
def delete_donation(id):
    """Delete a donation if it's not already requested"""
    try:
        donation = FoodDonation.query.get_or_404(id)
        
        # Security check
        if donation.user_id != current_user.id:
            flash('You can only delete your own donations.', 'danger')
            return redirect(url_for('manage_donations'))
        
        # Check if there are approved requests
        if donation.status != 'available' and FoodRequest.query.filter_by(donation_id=id, status='approved').count() > 0:
            flash('Cannot delete donation that has already been approved for collection.', 'danger')
            return redirect(url_for('manage_donations'))
            
        # Delete donation and all associated requests
        db.session.delete(donation)
        db.session.commit()
        flash('Donation deleted successfully.', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting donation: {str(e)}")
        flash('Error deleting donation.', 'danger')
        
    return redirect(url_for('manage_donations'))

@app.route('/set-theme', methods=['POST'])
@login_required
def set_theme():
    try:
        theme = request.json.get('theme')
        if theme in ['light', 'dark', 'system']:
            user = User.query.get(current_user.id)
            user.theme_preference = theme
            session['theme'] = theme
            db.session.commit()
            return jsonify({'success': True})
        return jsonify({'success': False, 'error': 'Invalid theme'}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error setting theme: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Add new routes for volunteer management
@app.route('/assign-volunteer/<int:volunteer_id>/<int:request_id>')
@login_required
@role_required(['admin', 'organization'])
def assign_volunteer(volunteer_id, request_id):
    try:
        volunteer = Volunteer.query.get_or_404(volunteer_id)
        request = FoodRequest.query.get_or_404(request_id)
        
        if current_user.role == 'organization' and volunteer.assigned_agent_id != current_user.id:
            flash('You can only assign volunteers assigned to your organization.', 'danger')
            return redirect(url_for('dashboard'))
            
        request.volunteer_id = volunteer.id
        db.session.commit()
        flash('Volunteer assigned successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error assigning volunteer: {str(e)}")
        flash('Error assigning volunteer.', 'danger')
        
    return redirect(url_for('dashboard'))

@app.route('/assign-volunteer/<int:volunteer_id>', methods=['POST'])
@login_required
@role_required(['admin', 'organization'])
def assign_volunteer_to_org(volunteer_id):
    try:
        volunteer = Volunteer.query.get_or_404(volunteer_id)
        
        # For organization users, they can only assign volunteers to themselves
        if current_user.role == 'organization':
            volunteer.assigned_agent_id = current_user.id
            flash('Volunteer assigned to your organization successfully!', 'success')
        # For admin users, they can assign to any organization
        else:
            organization_id = request.form.get('organization_id')
            if not organization_id:
                flash('Please select an organization to assign the volunteer.', 'danger')
                return redirect(url_for('manage_volunteers'))
                
            volunteer.assigned_agent_id = organization_id
            flash('Volunteer assigned to organization successfully!', 'success')
        
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error assigning volunteer: {str(e)}")
        flash('Error assigning volunteer.', 'danger')
        
    return redirect(url_for('manage_volunteers'))

# Add admin routes
@app.route('/admin')  # Keep only this route for admin dashboard
@login_required
@role_required('admin')
def admin_dashboard():
    """Admin dashboard with system overview and management options"""
    try:
        # Get system statistics
        stats = {
            'total_donations': FoodDonation.query.count(),
            'active_donations': FoodDonation.query.filter_by(status='available').count(),
            'total_requests': FoodRequest.query.count(),
            'pending_requests': FoodRequest.query.filter_by(status='pending').count(),
            'total_users': User.query.count(),
            'total_volunteers': Volunteer.query.count()
        }
        
        # Get recent activity
        recent_donations = FoodDonation.query.order_by(desc(FoodDonation.created_at)).limit(5).all()
        recent_requests = FoodRequest.query.order_by(desc(FoodRequest.created_at)).limit(5).all()
        
        # Get user counts by role
        role_counts = db.session.query(
            User.role, 
            db.func.count(User.id)
        ).group_by(User.role).all()
        
        return render_template(
            'admin_dashboard.html',
            stats=stats,
            recent_donations=recent_donations,
            recent_requests=recent_requests,
            role_counts=dict(role_counts)
        )
        
    except Exception as e:
        logger.error(f"Error in admin dashboard: {str(e)}")
        flash('Error loading admin dashboard', 'danger')
        return redirect(url_for('dashboard'))

# Add volunteer management routes
@app.route('/manage-volunteers', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'organization'])
def manage_volunteers():
    """Manage volunteer assignments and view volunteer details"""
    try:
        if request.method == 'POST':
            volunteer_id = request.form.get('volunteer_id')
            action = request.form.get('action')
            
            volunteer = Volunteer.query.get_or_404(volunteer_id)
            
            if action == 'assign':
                if current_user.role == 'organization':
                    if volunteer.assigned_agent_id:
                        flash('Volunteer already assigned', 'danger')
                        return redirect(url_for('manage_volunteers'))
                    volunteer.assigned_agent_id = current_user.id
                else:  # admin
                    org_id = request.form.get('organization_id')
                    if not org_id:
                        flash('Please select an organization', 'danger')
                        return redirect(url_for('manage_volunteers'))
                    volunteer.assigned_agent_id = org_id
                flash('Volunteer assigned successfully!', 'success')
                
            elif action == 'unassign':
                if current_user.role == 'organization' and volunteer.assigned_agent_id != current_user.id:
                    flash('Unauthorized action', 'danger')
                else:
                    volunteer.assigned_agent_id = None
                    flash('Volunteer unassigned successfully!', 'success')
                    
            db.session.commit()
            
        # Get volunteers based on role
        if current_user.role == 'admin':
            volunteers = Volunteer.query.all()
            organizations = User.query.filter_by(role='organization').all()
        else:
            volunteers = Volunteer.query.filter_by(assigned_agent_id=current_user.id).all()
            organizations = None
            
        return render_template('manage_volunteers.html', 
                             volunteers=volunteers,
                             organizations=organizations)
                             
    except Exception as e:
        logger.error(f"Error in manage_volunteers: {str(e)}")
        db.session.rollback()
        flash('An error occurred while managing volunteers', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/handle-request/<int:request_id>', methods=['POST'])
@login_required
@role_required(['admin', 'donor'])
def handle_request(request_id):
    """Handle donation requests (approve/deny/complete)"""
    try:
        request = FoodRequest.query.get_or_404(request_id)
        action = request.form.get('action')
        
        # Verify authorization
        if current_user.role == 'donor' and request.donation.user_id != current_user.id:
            flash('Unauthorized action', 'danger')
            return redirect(url_for('manage_donations'))
            
        if action == 'approve':
            request.status = 'approved'
            request.donation.status = 'reserved'
            
            # Notify organization
            flash('Request approved successfully!', 'success')
            
        elif action == 'deny':
            request.status = 'denied'
            request.donation.status = 'available'
            flash('Request denied successfully!', 'success')
            
        elif action == 'complete':
            request.status = 'completed'
            request.donation.status = 'collected'
            flash('Donation marked as collected!', 'success')
            
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error handling request: {str(e)}")
        flash('Error processing request', 'danger')
        
    return redirect(url_for('manage_donations'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management"""
    try:
        user = User.query.get(current_user.id)
        
        if request.method == 'POST':
            user.name = request.form.get('name', user.name)
            if request.form.get('new_password'):
                if check_password_hash(user.password, request.form.get('current_password', '')):  # Changed password_hash to password
                    user.password = generate_password_hash(request.form.get('new_password'))
                    flash('Password updated successfully!', 'success')
                else:
                    flash('Current password is incorrect.', 'danger')
                    return redirect(url_for('profile'))
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))

        return render_template('profile.html', user=user)

    except Exception as e:
        logger.error(f"Profile error: {str(e)}")
        flash('Error updating profile.', 'danger')
        return redirect(url_for('dashboard'))

# Add receipt generation route
@app.route('/generate-receipt/<int:donation_id>')
@login_required
@role_required('admin')
def generate_receipt(donation_id):
    try:
        donation = FoodDonation.query.get_or_404(donation_id)
        request = FoodRequest.query.filter_by(
            donation_id=donation_id,
            status='completed'
        ).first()
        
        if not request:
            flash('Receipt can only be generated for completed donations', 'warning')
            return redirect(url_for('admin_dashboard'))
            
        receipt = DonationReceipt(
            donation_id=donation_id,
            generated_by=current_user.id,
            receipt_number=f"RCP-{donation.id}-{request.id}"
        )
        db.session.add(receipt)
        db.session.commit()
        
        return render_template('receipt_generation.html', receipt=receipt)
        
    except Exception as e:
        logger.error(f"Receipt generation error: {str(e)}")
        flash('Error generating receipt', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/update-delivery-status/<int:request_id>', methods=['POST'])
@login_required
@role_required('volunteer')
def update_delivery_status(request_id):
    """Update donation delivery status by volunteer"""
    try:
        donation_request = FoodRequest.query.get_or_404(request_id)
        volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
        
        if donation_request.volunteer_id != volunteer.id:
            flash('Unauthorized action', 'danger')
            return redirect(url_for('dashboard'))
            
        status = request.form.get('status')
        notes = request.form.get('notes')
        
        if status in ['picked_up', 'in_transit', 'delivered']:
            donation_request.delivery_status = status
            donation_request.delivery_notes = notes
            
            if status == 'delivered':
                donation_request.status = 'completed'
                donation_request.donation.status = 'collected'
                
            db.session.commit()
            flash('Delivery status updated successfully', 'success')
        else:
            flash('Invalid status', 'danger')
            
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        logger.error(f"Status update error: {str(e)}")
        flash('Error updating status', 'danger')
        return redirect(url_for('dashboard'))

# Add error handler routes
@app.errorhandler(404)
def not_found_error(error):
    error_info = {
        'code': 404,
        'message': 'Page Not Found',
        'description': 'The page you are looking for might have been removed, had its name changed, or is temporarily unavailable.'
    }
    return render_template('error_page.html', error=error_info), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    error_info = {
        'code': 500,
        'message': 'Internal Server Error',
        'description': 'The server encountered an internal error and was unable to complete your request.'
    }
    return render_template('error_page.html', error=error_info), 500

# Update receipt generation route
@app.route('/receipts')
@login_required
@role_required('admin')
def view_receipts():
    receipts = DonationReceipt.query.order_by(desc(DonationReceipt.receipt_date)).all()
    donors = User.query.filter_by(role='donor').all()
    return render_template('reciept_generation.html', receipts=receipts, donors=donors)

@app.route('/task-details/<int:id>')
@login_required
@role_required('volunteer')
def task_details(id):
    """View detailed information about an assigned task"""
    try:
        task = FoodRequest.query.get_or_404(id)
        volunteer = Volunteer.query.filter_by(user_id=current_user.id).first()
        
        if not volunteer or task.volunteer_id != volunteer.id:
            flash('You do not have permission to view this task.', 'danger')
            return redirect(url_for('dashboard'))
            
        return render_template('task_details.html', task=task)
        
    except Exception as e:
        logger.error(f"Task details error: {str(e)}")
        flash('Error loading task details.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/request-details/<int:id>')
@login_required
def request_details(id):
    """View detailed information about a donation request"""
    try:
        request = FoodRequest.query.get_or_404(id)
        
        # Check permissions
        if current_user.role == 'donor' and request.donation.user_id != current_user.id:
            flash('You do not have permission to view this request.', 'danger')
            return redirect(url_for('dashboard'))
            
        if current_user.role == 'organization' and request.requester_id != current_user.id:
            flash('You do not have permission to view this request.', 'danger')
            return redirect(url_for('dashboard'))
            
        return render_template('request_details.html', request=request)
        
    except Exception as e:
        logger.error(f"Request details error: {str(e)}")
        flash('Error loading request details.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/activity-details/<int:id>')
@login_required
@role_required('admin')
def activity_details(id):
    """View detailed activity information for admins"""
    try:
        # Handle both donation and request activities
        donation = FoodDonation.query.get(id)
        if donation:
            return render_template('activity_details.html', 
                                  activity_type='donation',
                                  activity=donation)
        
        request = FoodRequest.query.get(id)
        if request:
            return render_template('activity_details.html', 
                                  activity_type='request',
                                  activity=request)
                                  
        flash('Activity not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
        
    except Exception as e:
        logger.error(f"Activity details error: {str(e)}")
        flash('Error loading activity details.', 'danger')
        return redirect(url_for('admin_dashboard'))

@app.route('/manage-users')
@login_required
@role_required('admin')
def manage_users():
    """Admin user management page"""
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/manage-organizations')
@login_required
@role_required('admin')
def manage_organizations():
    """Admin organization management page"""
    organizations = User.query.filter_by(role='organization').all()
    return render_template('manage_organizations.html', organizations=organizations)

@app.route('/view-donations')
@login_required
def view_donations():
    """View available donations"""
    donations = FoodDonation.query.filter_by(status='available').all()
    return render_template('view_donations.html', donations=donations)

@app.route('/donate-food', methods=['GET', 'POST'])
@login_required
@role_required('donor')
def donate_food_redirect():
    """Alternative route name for /donate"""
    # Redirect to the original donate function with all parameters preserved
    return redirect(url_for('donate_food'))

if __name__ == '__main__':
    try:
        # Initialize database
        init_db()
        logger.info("Database initialized successfully!")
        
        # Run the application
        app.run(debug=True)
    except Exception as e:
        logger.error(f"Application failed to start: {str(e)}")
