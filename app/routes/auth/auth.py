import hashlib
import re
from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_user, logout_user, current_user
from itsdangerous import URLSafeTimedSerializer
from app.routes.routes import app_name
from app.models.models import User
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

def generate_reset_token(email):
    """Generate a secure token for password reset."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=current_app.config['SECURITY_PASSWORD_SALT'])

@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Get the email from the form
        email = request.form.get('email')

        # Validate the email format using regex
        if not re.match(email_regex, email):
            flash('Invalid email format. Please check the email address.', 'danger')
            return render_template('auth/forgot_password.html')

        # Check if the email exists in the User table
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email address not found. Please check and try again.', 'danger')
            return render_template('auth/forgot_password.html')

        # from app.utilities.email import send_email

        # Generate reset token and send the password reset email
        token = generate_reset_token(user.email)
        reset_url = url_for('auth.reset_password', token=token, _external=True)

        subject = "Password Reset Request"
        body = f"Hello {user.first_name} {user.last_name},\n\n" \
                f"We received a request to reset the password for your account.\n\n" \
                f"To reset your password, simply click the link below:\n\n" \
                f"{reset_url}\n\n" \
                f"Please note, the link will expire in 5 minutes for your security.\n\n" \
                f"If you did not request a password reset, you can safely ignore this email.\n\n" \
                f"Need help? Feel free to contact our support team.\n\n" \
                f"Best regards,\nThe {app_name()} Team"

        # Send the reset email using send_email function
        # send_email(subject, body, user.email)

        flash('Password reset link has been sent to your email.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/forgot_password.html')

# Define the 'reset_password' route
@auth.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset the user's password using a secure token."""
    try:
        email = confirm_reset_token(token)
    except Exception as e:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.forgot_password'))

    user = User.query.filter_by(email=email).first()

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Both password fields are required.', 'warning')
        elif new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
        elif user:
            user.password = new_password  # Replace with hashed password in production
            db.session.commit()
            flash('Your password has been updated!', 'success')
            return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', token=token)


def confirm_reset_token(token):
    """Confirm the password reset token and get the email."""
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=300)  # 1 hour expiration
        return email
    except Exception as e:
        raise ValueError("Token is invalid or expired")