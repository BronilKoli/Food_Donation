from flask_wtf import FlaskForm
from wtforms import (StringField, SelectField, TextAreaField, PasswordField, 
                    DateField, BooleanField, IntegerField, FileField)
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
        ('donor', 'Donor'),
        ('organization', 'Organization'),
        ('volunteer', 'Volunteer')
    ], validators=[DataRequired()])

class DonationForm(FlaskForm):
    food_name = StringField('Food Name', validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('perishable', 'Perishable Food'),
        ('non_perishable', 'Non-Perishable Food'),
        ('prepared_meals', 'Prepared Meals'),
        ('groceries', 'Groceries'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired()])
    unit = SelectField('Unit', choices=[
        ('kgs', 'Kilograms'),
        ('items', 'Items'),
        ('boxes', 'Boxes'),
        ('meals', 'Meals')
    ], validators=[DataRequired()])
    expiry_date = DateField('Expiry Date', validators=[Optional()])
    pickup_address = TextAreaField('Pickup Address', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[Optional()])
    storage_instructions = TextAreaField('Storage Instructions', validators=[Optional()])
    allergen_info = StringField('Allergen Information', validators=[Optional()])
    
    def validate_expiry_date(self, field):
        if field.data and field.data < date.today():
            raise ValidationError('Expiry date cannot be in the past')

class DonationRequestForm(FlaskForm):
    quantity_requested = IntegerField('Quantity Requested', validators=[DataRequired()])
    purpose = TextAreaField('Purpose of Request', validators=[DataRequired()])
    pickup_time = StringField('Preferred Pickup Time', validators=[DataRequired()])
    volunteer_needed = BooleanField('Need Volunteer for Pickup')
    special_instructions = TextAreaField('Special Instructions')
    contact_person = StringField('Contact Person', validators=[DataRequired()])
    contact_number = StringField('Contact Number', validators=[DataRequired()])

class VolunteerForm(FlaskForm):
    contact = StringField('Contact Number', validators=[DataRequired()])
    address = TextAreaField('Address', validators=[DataRequired()])
    availability = SelectField('Availability', choices=[
        ('weekdays', 'Weekdays'),
        ('weekends', 'Weekends'),
        ('both', 'Both')
    ], validators=[DataRequired()])
    has_vehicle = BooleanField('Has Vehicle')
    vehicle_type = SelectField('Vehicle Type', choices=[
        ('', 'Select Vehicle Type'),
        ('bike', 'Bike'),
        ('car', 'Car'),
        ('van', 'Van')
    ])
    preferred_area = StringField('Preferred Area', validators=[Optional()])
    max_distance = IntegerField('Maximum Travel Distance (km)', validators=[Optional()])
    languages = StringField('Languages Spoken')
    emergency_contact = StringField('Emergency Contact')

class UserPreferencesForm(FlaskForm):
    theme_preference = SelectField('Theme Preference', choices=[
        ('system', 'System Preference'),
        ('light', 'Light Theme'),
        ('dark', 'Dark Theme')
    ])
    name = StringField('Full Name')
    email = StringField('Email', validators=[Optional(), Email()])
    contact = StringField('Contact Number')
    address = TextAreaField('Address')
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password', validators=[
        Optional(),
        Length(min=6, message='Password must be at least 6 characters')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        Optional(),
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