from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
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
            else:
                logger.info("Database tables already exist")
                
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
            raise e

# Initialize database when app starts
with app.app_context():
    init_db()

# Context processor to add theme preference to all templates
@app.context_processor
def inject_theme():
    theme = 'system'  # Default
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user:
            theme = user.theme_preference
    return {'theme_preference': theme}

# Login decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Update role_required decorator to handle multiple roles
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') not in (roles if isinstance(roles, list) else [roles]):
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

@app.context_processor
def inject_permissions():
    """Inject permissions into all templates"""
    if 'role' in session:
        return {'permissions': get_user_permissions(session['role'])}
    return {'permissions': []}

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    try:
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
            
        form = SignupForm(csrf_enabled=False)
        
        if request.method == 'POST':
            logger.info(f"Signup form data: {form.data}")
            
            if form.validate_on_submit():
                email = form.email.data.lower().strip()
                
                # Check if email already exists
                if User.query.filter_by(email=email).first():
                    flash('Email already registered. Please login.', 'danger')
                    return render_template('signup.html', form=form)
                    
                # Create user
                new_user = User(
                    email=email,
                    password=generate_password_hash(form.password.data),
                    name=form.name.data.strip(),
                    role=form.role.data
                )
                db.session.add(new_user)
                db.session.flush()  # Get user ID without full commit
                
                # Create volunteer profile if needed
                if form.role.data == 'volunteer':
                    volunteer = Volunteer(
                        name=form.name.data.strip(),
                        contact=request.form.get('contact'),
                        address=request.form.get('address'),
                        user_id=new_user.id
                    )
                    db.session.add(volunteer)
                    
                db.session.commit()
                logger.info(f"User created: {email}, ID: {new_user.id}")
                flash('Account created successfully!', 'success')
                return redirect(url_for('login'))
            else:
                logger.warning(f"Form validation errors: {form.errors}")
                for field, errors in form.errors.items():
                    for error in errors:
                        flash(f"{field}: {error}", 'danger')

        return render_template('signup.html', form=form)

    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        db.session.rollback()
        flash(f'Error during signup: {str(e)}', 'danger')
        return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        session.clear()
        form = LoginForm(csrf_enabled=False)
        
        if request.method == 'POST' and form.validate_on_submit():
            email = form.email.data.lower().strip()
            user = User.query.filter_by(email=email).first()
            
            if user and check_password_hash(user.password, form.password.data):
                session['user_id'] = user.id
                session['role'] = user.role
                session['user_name'] = user.name
                session['theme'] = user.theme_preference
                
                logger.info(f"User logged in successfully: {email}")
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                logger.warning(f"Failed login attempt for email: {email}")
                flash('Invalid email or password.', 'danger')
            
        return render_template('login.html', form=form)

    except Exception as e:
        logger.error(f"Error in login route: {str(e)}")
        flash('An error occurred. Please try again.', 'danger')
        return render_template('login.html', form=form)

# Update dashboard route to use correct template names
@app.route('/')
@login_required
def dashboard():
    try:
        role = session['role']
        user = User.query.get(session['user_id'])
        
        context = {
            'user': user,
            'role': role
        }
        
        if role == 'donor':
            donations = FoodDonation.query.filter_by(user_id=session['user_id'])
            context.update({
                'stats': {
                    'total_donations': donations.count(),
                    'active_donations': donations.filter_by(status='available').count(),
                    'people_helped': FoodRequest.query.join(FoodDonation).filter(
                        FoodDonation.user_id == session['user_id'],
                        FoodRequest.status == 'collected'
                    ).count()
                },
                'recent_donations': donations.order_by(desc(FoodDonation.created_at)).limit(6).all()
            })
            return render_template('donor_dashboard.html', **context)
            
        elif role == 'organization':
            available_donations = FoodDonation.query.filter_by(status='available').order_by(FoodDonation.expiry_date).all()
            my_requests = FoodRequest.query.filter_by(requester_id=session['user_id']).order_by(desc(FoodRequest.created_at)).limit(5).all()
            assigned_volunteers = Volunteer.query.filter_by(organization_id=session['user_id']).all()
            
            context.update({
                'available_donations': available_donations,
                'my_requests': my_requests,
                'volunteers': assigned_volunteers
            })
            
            return render_template('organization_dashboard.html', **context)
        
        elif role == 'volunteer':
            volunteer = Volunteer.query.filter_by(user_id=session['user_id']).first()
            assigned_requests = FoodRequest.query.filter_by(volunteer_id=volunteer.id if volunteer else None).all()
            
            context.update({
                'volunteer': volunteer,
                'assigned_requests': assigned_requests
            })
            
            return render_template('volunteer_dashboard.html', **context)
                                 
        elif role == 'admin':
            stats = {
                'total_donations': FoodDonation.query.count(),
                'pending_requests': FoodRequest.query.filter_by(status='pending').count(),
                'total_volunteers': Volunteer.query.count(),
                'total_users': User.query.count()
            }
            pending_requests = FoodRequest.query.filter_by(status='pending').all()
            volunteers = Volunteer.query.all()
            
            context.update({
                'stats': stats,
                'pending_requests': pending_requests,
                'volunteers': volunteers
            })
            
            return render_template('admin_dashboard.html', **context)
            
        else:
            flash('Invalid user role', 'danger')
            return redirect(url_for('logout'))
            
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard.', 'danger')
        return redirect(url_for('login'))

@app.route('/donate', methods=['GET', 'POST'])
@login_required
@role_required('donor')
def donate_food():
    form = DonationForm()
    
    if request.method == 'POST' and form.validate_on_submit():
        try:
            donation = FoodDonation(
                item_name=form.item_name.data,
                donation_type=form.donation_type.data,
                quantity=form.quantity.data,
                location=form.location.data,
                expiry_date=form.expiry_date.data,
                description=form.description.data,
                category=form.category.data,
                user_id=session['user_id'],
                status='available'
            )
            db.session.add(donation)
            db.session.commit()
            flash('Donation added successfully!', 'success')
            return redirect(url_for('manage_donations'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Donation error: {str(e)}")
            flash('Error adding donation.', 'danger')
            
    return render_template('donate_food.html', form=form)

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
@role_required(['organization', 'volunteer'])
def browse_donations():
    donations = FoodDonation.query.filter_by(
        status='available'
    ).order_by(FoodDonation.expiry_date).all()
    return render_template('browse_donations.html', donations=donations)

@app.route('/my-requests')
@login_required
@role_required('organization')  # Fix role name: 'recipient' -> 'organization'
def my_requests():
    requests = FoodRequest.query.filter_by(
        requester_id=session['user_id']
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
        db.session.rollback()
        logger.error(f"Food request error: {str(e)}")
        flash('Error submitting request.', 'danger')
        
    return redirect(url_for('my_requests'))

@app.route('/update-request/<int:request_id>/<string:status>')
@login_required
@role_required(['admin', 'donor'])
def update_request(request_id, status):
    try:
        food_request = FoodRequest.query.get_or_404(request_id)
        
        # Verify authorization
        if session['role'] == 'donor' and food_request.donation.user_id != session['user_id']:
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

@app.route('/edit-donation/<int:id>', methods=['GET', 'POST'])
@login_required
@role_required('donor')
def edit_donation(id):
    donation = FoodDonation.query.get_or_404(id)
    
    if donation.user_id != session['user_id']:
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
    try:
        donation = FoodDonation.query.get_or_404(id)
        if donation.user_id != session['user_id']:
            flash('You can only delete your own donations.', 'danger')
            return redirect(url_for('manage_donations'))
            
        db.session.delete(donation)
        db.session.commit()
        flash('Donation deleted successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in delete_donation: {str(e)}")
        flash('Error deleting donation. Please try again.', 'danger')
        
    return redirect(url_for('manage_donations'))

@app.route('/set-theme', methods=['POST'])
@login_required
def set_theme():
    try:
        theme = request.json.get('theme')
        if theme in ['light', 'dark', 'system']:
            user = User.query.get(session['user_id'])
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
def logout():
    session.clear()
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
        
        if session['role'] == 'organization' and volunteer.assigned_agent_id != session['user_id']:
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
        if session['role'] == 'organization':
            volunteer.assigned_agent_id = session['user_id']
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
                if session['role'] == 'organization':
                    if volunteer.assigned_agent_id:
                        flash('Volunteer already assigned', 'danger')
                        return redirect(url_for('manage_volunteers'))
                    volunteer.assigned_agent_id = session['user_id']
                else:  # admin
                    org_id = request.form.get('organization_id')
                    if not org_id:
                        flash('Please select an organization', 'danger')
                        return redirect(url_for('manage_volunteers'))
                    volunteer.assigned_agent_id = org_id
                flash('Volunteer assigned successfully!', 'success')
                
            elif action == 'unassign':
                if session['role'] == 'organization' and volunteer.assigned_agent_id != session['user_id']:
                    flash('Unauthorized action', 'danger')
                else:
                    volunteer.assigned_agent_id = None
                    flash('Volunteer unassigned successfully!', 'success')
                    
            db.session.commit()
            
        # Get volunteers based on role
        if session['role'] == 'admin':
            volunteers = Volunteer.query.all()
            organizations = User.query.filter_by(role='organization').all()
        else:
            volunteers = Volunteer.query.filter_by(assigned_agent_id=session['user_id']).all()
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
        if session['role'] == 'donor' and request.donation.user_id != session['user_id']:
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

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings page for managing preferences"""
    try:
        user = User.query.get(session['user_id'])
        form = UserPreferencesForm(obj=user)

        if request.method == 'POST' and form.validate_on_submit():
            form.populate_obj(user)
            db.session.commit()
            session['theme'] = user.theme_preference
            flash('Settings updated successfully!', 'success')
            return redirect(url_for('settings'))

        return render_template('settings.html', form=form)

    except Exception as e:
        logger.error(f"Settings error: {str(e)}")
        flash('Error updating settings.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management"""
    try:
        user = User.query.get(session['user_id'])
        
        if request.method == 'POST':
            user.name = request.form.get('name', user.name)
            if request.form.get('new_password'):
                if check_password_hash(user.password, request.form.get('current_password', '')):
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
            generated_by=session['user_id'],
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
        volunteer = Volunteer.query.filter_by(user_id=session['user_id']).first()
        
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

if __name__ == '__main__':
    try:
        # Initialize database
        init_db()
        logger.info("Database initialized successfully!")
        
        # Run the application
        app.run(debug=True)
    except Exception as e:
        logger.error(f"Application failed to start: {str(e)}")
