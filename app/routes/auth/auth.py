import hashlib
import re
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_user, logout_user, current_user
from app.models.models import User
from app.routes.routes import app_name
from app import db

auth = Blueprint('auth', __name__)

# Email regex pattern for basic validation
email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate email format using regex
        if not re.match(email_regex, email):
            flash('Invalid email format. Please check the email address.', 'danger')
            return render_template('auth/login.html')

        # Query the database for the user by email
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email address not found. Please check and try again.', 'danger')
            return render_template('auth/login.html')

        
        if hashlib.sha256(password.encode()).hexdigest() == user.password:  # Check if passwords match
            login_user(user)  # Log in the user

            # Redirect to the dashboard based on the role
            if current_user.role_id == 1:
                return redirect(url_for('admin.admin_dashboard'))
            elif current_user.role_id == 2:
                return redirect(url_for('lecturer.dashboard'))
            else:
                return redirect(url_for('routes.index'))
        else:
            flash('Invalid password. Please try again.', 'danger')

    return render_template('auth/login.html')


# Route for logging out
@auth.route('/logout')
def logout():
    logout_user()  # Log out the current user
    # Redirect to home page or login page
    return redirect(url_for('routes.index'))