from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, PasswordField, DateField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Optional
from datetime import date

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')

class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message='Password must be at least 6 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    name = StringField('Full Name', validators=[DataRequired()])
    role = SelectField('Role', choices=[
        ('', 'Select Role'),
        ('donor', 'Donor'),
        ('organization', 'Organization'),
        ('volunteer', 'Volunteer')
    ], validators=[DataRequired()])
    contact = StringField('Contact Number')
    address = TextAreaField('Address')

    def validate_contact(self, field):
        if self.role.data == 'volunteer' and not field.data:
            raise ValidationError('Contact number is required for volunteers')

    def validate_address(self, field):
        if self.role.data == 'volunteer' and not field.data:
            raise ValidationError('Address is required for volunteers')

class DonationForm(FlaskForm):
    item_name = StringField('Item Name', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('food', 'Food'),
        ('meals', 'Prepared Meals'),
        ('groceries', 'Groceries'),
        ('household', 'Household Items'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    quantity = StringField('Quantity', validators=[DataRequired()])
    location = StringField('Pickup Location', validators=[DataRequired()])
    expiry_date = DateField('Expiry/Best Before Date', validators=[Optional()])
    description = TextAreaField('Description', validators=[Optional()])
    condition = SelectField('Condition', choices=[
        ('new', 'New'),
        ('good', 'Good'),
        ('fair', 'Fair')
    ], validators=[DataRequired()])
    pickup_time = StringField('Preferred Pickup Time', validators=[Optional()])

    def validate_expiry_date(self, field):
        if field.data and field.data < date.today():
            raise ValidationError('Expiry date cannot be in the past')

class DonationRequestForm(FlaskForm):
    message = TextAreaField('Message for Donor', validators=[Optional()])
    pickup_time = StringField('Preferred Pickup Time', validators=[Optional()])
    volunteer_needed = BooleanField('Request Volunteer Help')
    special_instructions = TextAreaField('Special Instructions', validators=[Optional()])

class VolunteerForm(FlaskForm):
    contact = StringField('Contact Number', validators=[DataRequired()])
    address = TextAreaField('Address', validators=[DataRequired()])
    availability = SelectField('Availability', choices=[
        ('weekdays', 'Weekdays'),
        ('weekends', 'Weekends'),
        ('both', 'Both')
    ], validators=[DataRequired()])
    has_vehicle = BooleanField('Has Vehicle')
    preferred_area = StringField('Preferred Area', validators=[Optional()])
    max_distance = StringField('Maximum Travel Distance (km)', validators=[Optional()])

class UserPreferencesForm(FlaskForm):
    theme_preference = SelectField('Theme Preference', choices=[
        ('system', 'System Preference'),
        ('light', 'Light Theme'),
        ('dark', 'Dark Theme')
    ])
    name = StringField('Full Name')
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password', validators=[
        Optional(),  # Only validate if field is provided
        Length(min=6, message='Password must be at least 6 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        Optional(),  # Only validate if field is provided
        EqualTo('new_password', message='Passwords must match')
    ])
    notification_preferences = SelectField('Notification Preferences', choices=[
        ('email', 'Email Only'),
        ('both', 'Email and In-App'),
        ('none', 'None')
    ])
    default_location = StringField('Default Location')

    def validate_current_password(self, field):
        if self.new_password.data and not field.data:
            raise ValidationError('Current password is required to change password')