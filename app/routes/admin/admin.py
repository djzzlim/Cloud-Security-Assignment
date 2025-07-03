from flask import Blueprint, render_template, current_app, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from datetime import datetime, timedelta
import logging
import uuid
import hashlib
import os
from werkzeug.utils import secure_filename
import boto3
from config import *
from app import db

admin = Blueprint('admin', __name__)

def hash_password(password):
    """Hash password using SHA-256 (in production, use bcrypt or similar)"""
    return hashlib.sha256(password.encode()).hexdigest()

def log_activity(user_id, action):
    """
    Log an activity with current timestamp
    
    Args:
        user_id (str): User ID who performed the action (None for system actions)
        action (str): Description of the action performed
    """
    try:
        db.session.execute(text("""
            INSERT INTO ActivityLog (UserID, Action, Timestamp)
            VALUES (:user_id, :action, :timestamp)
        """), {
            'user_id': user_id,
            'action': action,
            'timestamp': datetime.now()
        })
        
        db.session.commit()
        current_app.logger.info(f"Activity logged: {action}")
        
    except Exception as e:
        current_app.logger.error(f"Error logging activity: {e}")
        db.session.rollback()

def get_roles():
    """Fetch all roles from database using SQLAlchemy"""
    try:
        result = db.session.execute(text("SELECT RoleID, RoleName FROM Role ORDER BY RoleName"))
        roles = []
        for row in result:
            roles.append({'id': row.RoleID, 'name': row.RoleName})
        return roles
    except Exception as e:
        current_app.logger.error(f"Error fetching roles: {e}")
        return []

def get_faculties():
    """Fetch all faculties from database using SQLAlchemy"""
    try:
        result = db.session.execute(text("SELECT FacultyID, FacultyName FROM Faculty ORDER BY FacultyName"))
        faculties = []
        for row in result:
            faculties.append({'id': row.FacultyID, 'name': row.FacultyName})
        return faculties
    except Exception as e:
        current_app.logger.error(f"Error fetching faculties: {e}")
        return []

def create_faculty(faculty_name):
    """Create a new faculty in the database using SQLAlchemy with proper activity logging"""
    try:
        # Check if faculty already exists
        result = db.session.execute(text("SELECT COUNT(*) as count FROM Faculty WHERE FacultyName = :name"), 
                                  {'name': faculty_name})
        if result.fetchone().count > 0:
            return False, "Faculty already exists"
        
        # Insert faculty
        db.session.execute(text("INSERT INTO Faculty (FacultyName) VALUES (:name)"), 
                          {'name': faculty_name})
        
        # Log the activity with current timestamp
        log_activity(None, f"New faculty created: {faculty_name}")
        
        return True, "Faculty created successfully"
        
    except Exception as e:
        current_app.logger.error(f"Error creating faculty: {e}")
        db.session.rollback()
        return False, f"Error creating faculty: {str(e)}"

def get_all_users():
    """Fetch all users with their roles and expert information using SQLAlchemy"""
    try:
        query = text("""
            SELECT 
                u.UserID,
                u.FullName,
                u.Email,
                r.RoleName,
                f.FacultyName,
                e.Position,
                e.Phone,
                e.OfficeLocation
            FROM User u
            LEFT JOIN Role r ON u.RoleID = r.RoleID
            LEFT JOIN Expert e ON u.UserID = e.UserID
            LEFT JOIN Faculty f ON e.FacultyID = f.FacultyID
            ORDER BY u.FullName
        """)
        
        result = db.session.execute(query)
        users = []
        for row in result:
            users.append({
                'id': row.UserID,
                'full_name': row.FullName,
                'email': row.Email,
                'role': row.RoleName or 'Unknown',
                'faculty': row.FacultyName or 'N/A',
                'position': row.Position or 'N/A',
                'phone': row.Phone or 'N/A',
                'office_location': row.OfficeLocation or 'N/A'
            })
        
        return users
        
    except Exception as e:
        current_app.logger.error(f"Error fetching users: {e}")
        return []

def delete_user(user_id):
    """Delete a user from the database using SQLAlchemy with proper activity logging"""
    try:
        # Get user name for logging
        result = db.session.execute(text("SELECT FullName FROM User WHERE UserID = :user_id"), 
                                  {'user_id': user_id})
        user_row = result.fetchone()
        if not user_row:
            return False, "User not found"
        
        user_name = user_row.FullName
        
        # Delete user (cascade will handle Expert and other related records)
        result = db.session.execute(text("DELETE FROM User WHERE UserID = :user_id"), 
                                   {'user_id': user_id})
        
        if result.rowcount == 0:
            return False, "User not found"
        
        # Log the activity with current timestamp
        log_activity(None, f"User deleted: {user_name}")
        
        return True, f"User '{user_name}' deleted successfully"
        
    except Exception as e:
        current_app.logger.error(f"Error deleting user: {e}")
        db.session.rollback()
        return False, f"Error deleting user: {str(e)}"

def create_user(user_data):
    """Create a new user in the database using SQLAlchemy with proper activity logging"""
    try:
        # Generate UUID for user
        user_id = str(uuid.uuid4())
        
        # Hash the password
        password_hash = hash_password(user_data['password'])
        
        # Insert user
        db.session.execute(text("""
            INSERT INTO User (UserID, FullName, PasswordHash, Email, RoleID)
            VALUES (:user_id, :full_name, :password_hash, :email, :role_id)
        """), {
            'user_id': user_id,
            'full_name': user_data['full_name'],
            'password_hash': password_hash,
            'email': user_data['email'],
            'role_id': user_data['role_id']
        })
        
        # If user is an Expert, create Expert profile
        if user_data['role_id'] == 2:  # Expert role
            expert_id = str(uuid.uuid4())
            db.session.execute(text("""
                INSERT INTO Expert (
                    ExpertID, UserID, FacultyID, FullName, Title, Position,
                    Email, Phone, PhotoURL, OfficeLocation,
                    Biography, EducationBackground, WorkingExperience
                ) VALUES (:expert_id, :user_id, :faculty_id, :full_name, :title, :position,
                         :email, :phone, :photo_url, :office_location,
                         :biography, :education_background, :working_experience)
            """), {
                'expert_id': expert_id,
                'user_id': user_id,
                'faculty_id': user_data.get('faculty_id'),
                'full_name': user_data['full_name'],
                'title': user_data.get('title', ''),
                'position': user_data.get('position', ''),
                'email': user_data['email'],
                'phone': user_data.get('phone', ''),
                'photo_url': user_data.get('photo_url'),
                'office_location': user_data.get('office_location', ''),
                'biography': user_data.get('biography', ''),
                'education_background': user_data.get('education_background', ''),
                'working_experience': user_data.get('working_experience', '')
            })
        
        # Log the activity with current timestamp
        log_activity(user_id, f"New user account created: {user_data['full_name']}")
        
        return True, "User created successfully"
        
    except Exception as e:
        current_app.logger.error(f"Error creating user: {e}")
        db.session.rollback()
        # Check for duplicate email
        if "Duplicate entry" in str(e) and "email" in str(e).lower():
            return False, "Email address already exists"
        return False, f"Error creating user: {str(e)}"

def get_dashboard_stats():
    """Fetch dashboard statistics from database using SQLAlchemy"""
    try:
        stats = {}
        
        # Total Users
        result = db.session.execute(text("SELECT COUNT(*) as count FROM User"))
        stats['total_users'] = result.fetchone().count
        
        # Faculty Members (Users with Expert role)
        result = db.session.execute(text("""
            SELECT COUNT(*) as count
            FROM User u 
            INNER JOIN Role r ON u.RoleID = r.RoleID 
            WHERE r.RoleName = 'Expert'
        """))
        stats['faculty_members'] = result.fetchone().count
        
        # Recent Activities (last 7 days)
        result = db.session.execute(text("""
            SELECT COUNT(*) as count
            FROM ActivityLog 
            WHERE Timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        """))
        stats['pending_approvals'] = result.fetchone().count
        
        # Research Areas (approximation based on publications)
        result = db.session.execute(text("SELECT COUNT(DISTINCT Venue) as count FROM Publication"))
        stats['research_areas'] = result.fetchone().count
        
        return stats
        
    except Exception as e:
        current_app.logger.error(f"Error fetching dashboard stats: {e}")
        return None

def get_recent_activities():
    """Fetch recent activities from database using SQLAlchemy with proper time handling"""
    try:
        # Get recent activities with user information
        query = text("""
            SELECT 
                al.Action,
                al.Timestamp,
                u.FullName,
                r.RoleName,
                u.UserID,
                al.LogID
            FROM ActivityLog al
            LEFT JOIN User u ON al.UserID = u.UserID
            LEFT JOIN Role r ON u.RoleID = r.RoleID
            ORDER BY al.Timestamp DESC
            LIMIT 10
        """)
        
        result = db.session.execute(query)
        activities = []
        
        for row in result:
            # Get current time for comparison
            current_time = datetime.now()
            activity_time = row.Timestamp
            
            # Calculate time difference more accurately
            if activity_time:
                time_diff = current_time - activity_time
                total_seconds = int(time_diff.total_seconds())
                
                # Format time ago based on time difference
                if time_diff.days > 365:
                    years = time_diff.days // 365
                    time_ago = f"{years} year{'s' if years > 1 else ''} ago"
                elif time_diff.days > 30:
                    months = time_diff.days // 30
                    time_ago = f"{months} month{'s' if months > 1 else ''} ago"
                elif time_diff.days > 7:
                    weeks = time_diff.days // 7
                    time_ago = f"{weeks} week{'s' if weeks > 1 else ''} ago"
                elif time_diff.days > 0:
                    time_ago = f"{time_diff.days} day{'s' if time_diff.days > 1 else ''} ago"
                elif total_seconds > 3600:
                    hours = total_seconds // 3600
                    time_ago = f"{hours} hour{'s' if hours > 1 else ''} ago"
                elif total_seconds > 60:
                    minutes = total_seconds // 60
                    time_ago = f"{minutes} minute{'s' if minutes > 1 else ''} ago"
                elif total_seconds > 0:
                    time_ago = f"{total_seconds} second{'s' if total_seconds > 1 else ''} ago"
                else:
                    time_ago = "Just now"
            else:
                time_ago = "Unknown time"
                activity_time = current_time
            
            # Determine status based on action type
            action_lower = row.Action.lower()
            if any(word in action_lower for word in ['created', 'added', 'registered', 'new']):
                status = {'class': 'bg-success', 'text': 'Created'}
            elif any(word in action_lower for word in ['updated', 'modified', 'edited', 'changed']):
                status = {'class': 'bg-info', 'text': 'Updated'}
            elif any(word in action_lower for word in ['deleted', 'removed', 'archived']):
                status = {'class': 'bg-danger', 'text': 'Deleted'}
            elif any(word in action_lower for word in ['login', 'logged in', 'signed in']):
                status = {'class': 'bg-primary', 'text': 'Login'}
            elif any(word in action_lower for word in ['logout', 'logged out', 'signed out']):
                status = {'class': 'bg-secondary', 'text': 'Logout'}
            else:
                status = {'class': 'bg-secondary', 'text': 'Activity'}
            
            activities.append({
                'action': row.Action,
                'timestamp': activity_time,
                'user_name': row.FullName or 'System',
                'role': row.RoleName or 'System',
                'time_ago': time_ago,
                'status': status,
                'formatted_date': activity_time.strftime('%Y-%m-%d %H:%M:%S') if activity_time else 'N/A'
            })
        
        return activities
        
    except Exception as e:
        current_app.logger.error(f"Error fetching recent activities: {e}")
        return []

def get_faculties_with_expert_count():
    """Fetch all faculties with their expert count using SQLAlchemy"""
    try:
        query = text("""
            SELECT 
                f.FacultyID,
                f.FacultyName,
                COUNT(e.ExpertID) as expert_count
            FROM Faculty f
            LEFT JOIN Expert e ON f.FacultyID = e.FacultyID
            GROUP BY f.FacultyID, f.FacultyName
            ORDER BY f.FacultyName
        """)
        
        result = db.session.execute(query)
        faculties = []
        for row in result:
            faculties.append({
                'id': row.FacultyID,
                'name': row.FacultyName,
                'expert_count': row.expert_count
            })
        
        return faculties
        
    except Exception as e:
        current_app.logger.error(f"Error fetching faculties with expert count: {e}")
        return []

def delete_faculty(faculty_id):
    """Delete a faculty from the database using SQLAlchemy with proper activity logging"""
    try:
        # First check if faculty has any experts
        result = db.session.execute(text("""
            SELECT COUNT(*) as count 
            FROM Expert 
            WHERE FacultyID = :faculty_id
        """), {'faculty_id': faculty_id})
        
        expert_count = result.fetchone().count
        if expert_count > 0:
            return False, f"Cannot delete faculty. It has {expert_count} expert(s) assigned to it. Please reassign or remove the experts first."
        
        # Get faculty name for logging
        result = db.session.execute(text("SELECT FacultyName FROM Faculty WHERE FacultyID = :faculty_id"), 
                                  {'faculty_id': faculty_id})
        faculty_row = result.fetchone()
        if not faculty_row:
            return False, "Faculty not found"
        
        faculty_name = faculty_row.FacultyName
        
        # Delete faculty
        result = db.session.execute(text("DELETE FROM Faculty WHERE FacultyID = :faculty_id"), 
                                   {'faculty_id': faculty_id})
        
        if result.rowcount == 0:
            return False, "Faculty not found"
        
        # Log the activity with current timestamp
        log_activity(None, f"Faculty deleted: {faculty_name}")
        
        return True, f"Faculty '{faculty_name}' deleted successfully"
        
    except Exception as e:
        current_app.logger.error(f"Error deleting faculty: {e}")
        db.session.rollback()
        return False, f"Error deleting faculty: {str(e)}"

def validate_image_file(file):
    """Validate uploaded image file"""
    allowed_types = ['image/jpeg', 'image/png', 'image/jpg']
    max_size = 2 * 1024 * 1024  # 2MB

    if file.content_type.lower() not in allowed_types:
        return False, "Only JPG and PNG images are allowed."

    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    if size > max_size:
        return False, "Image must be under 2MB."

    return True, "Valid"

# Route Handlers

@admin.route('/manage-faculties')
def manage_faculties():
    """Manage faculties page"""
    faculties = get_faculties_with_expert_count()
    return render_template('admin/manage_faculty.html', faculties=faculties)

@admin.route('/delete-faculty/<int:faculty_id>', methods=['POST'])
def delete_faculty_route(faculty_id):
    """Delete faculty endpoint"""
    success, message = delete_faculty(faculty_id)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'error')
    
    return redirect(url_for('admin.manage_faculties'))

@admin.route('/')
def admin_dashboard():
    """Admin dashboard with real database data"""
    try:
        # Get dashboard statistics
        stats = get_dashboard_stats()
        recent_activities = get_recent_activities()
        
        if stats is None:
            # If database connection fails, show error
            return render_template('admin/dashboard.html', 
                                 database_error="Unable to connect to MySQL database. Please check your connection settings.")
        
        return render_template('admin/dashboard.html',
                             total_users=stats['total_users'],
                             faculty_members=stats['faculty_members'],
                             pending_approvals=stats['pending_approvals'],
                             research_areas=stats['research_areas'],
                             recent_activities=recent_activities)
    
    except Exception as e:
        current_app.logger.error(f"Dashboard error: {e}")
        return render_template('admin/dashboard.html', 
                             database_error=f"Dashboard error: {str(e)}")

@admin.route('/add-user', methods=['GET', 'POST'])
def add_user():
    """Add new user page"""
    if request.method == 'POST':
        # Get form data
        user_data = {
            'full_name': request.form.get('full_name', '').strip(),
            'email': request.form.get('email', '').strip(),
            'password': request.form.get('password', ''),
            'role_id': int(request.form.get('role_id', 1)),
            'faculty_id': request.form.get('faculty_id'),
            'title': request.form.get('title', '').strip(),
            'position': request.form.get('position', '').strip(),
            'phone': request.form.get('phone', '').strip(),
            'office_location': request.form.get('office_location', '').strip(),
            'biography': request.form.get('biography', '').strip(),
            'education_background': request.form.get('education_background', '').strip(),
            'working_experience': request.form.get('working_experience', '').strip(),
            'photo_url': None  
        }

        # Convert empty faculty_id to None
        if user_data['faculty_id'] == '':
            user_data['faculty_id'] = None
        else:
            user_data['faculty_id'] = int(user_data['faculty_id'])

        # Handle file upload to S3
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename:
                # Validate the uploaded image file
                is_valid, message = validate_image_file(file)
                if is_valid:
                    try:
                        # Generate unique filename
                        filename = secure_filename(file.filename)
                        ext = filename.rsplit('.', 1)[-1].lower()
                        unique_filename = f"{uuid.uuid4().hex}.{ext}"
                        s3_key = f"expert-photos/{unique_filename}"

                        current_app.logger.info(f"Starting S3 upload for file: {filename}")
                        
                        # Reset file pointer to beginning
                        file.seek(0)
                        
                        # Initialize S3 client
                        s3 = boto3.client(
                            "s3",
                            aws_access_key_id=current_app.config['S3_ACCESS_KEY'],
                            aws_secret_access_key=current_app.config['S3_SECRET_KEY'],
                            region_name=current_app.config['S3_REGION']
                        )

                        # Upload file to S3 with proper content type
                        s3.upload_fileobj(
                            file,
                            current_app.config['S3_BUCKET_NAME'],
                            s3_key
                        )

                        # Generate the public S3 URL
                        photo_url = f"https://{current_app.config['S3_BUCKET_NAME']}.s3.{current_app.config['S3_REGION']}.amazonaws.com/{s3_key}"
                        user_data['photo_url'] = photo_url
                        
                        # Log successful upload for debugging
                        current_app.logger.info(f"Photo uploaded successfully to S3: {photo_url}")
                        current_app.logger.info(f"Photo URL will be saved to database: {photo_url}")
                        
                    except Exception as e:
                        current_app.logger.error(f"S3 upload error: {str(e)}")
                        flash(f"Error uploading photo to S3: {str(e)}", 'error')
                        return redirect(request.url)
                else:
                    flash(message, 'error')
                    return redirect(request.url)
            else:
                current_app.logger.info("No file selected for upload")

        # Basic validation
        if not user_data['full_name']:
            flash('Full name is required', 'error')
        elif not user_data['email']:
            flash('Email is required', 'error')
        elif not user_data['password']:
            flash('Password is required', 'error')
        else:
            # Log the photo URL being passed to create_user for debugging
            if user_data.get('photo_url'):
                current_app.logger.info(f"Creating user with photo_url: {user_data['photo_url']}")
            else:
                current_app.logger.info("Creating user without photo")
            
            success, message = create_user(user_data)
            if success:
                flash(message, 'success')
                # Log successful user creation
                current_app.logger.info(f"User created successfully: {user_data['full_name']}")
                return redirect(url_for('admin.admin_dashboard'))
            else:
                current_app.logger.error(f"User creation failed: {message}")
                flash(message, 'error')

    # Get roles and faculties for form
    roles = get_roles()
    faculties = get_faculties()

    return render_template('admin/add_user.html', roles=roles, faculties=faculties)

@admin.route('/add_faculty', methods=['GET', 'POST'])
def add_faculty():
    """Add new faculty page"""
    if request.method == 'POST':
        faculty_name = request.form.get('faculty_name', '').strip()
        
        if not faculty_name:
            flash('Faculty name is required', 'error')
        else:
            success, message = create_faculty(faculty_name)
            if success:
                flash(message, 'success')
                return redirect(url_for('admin.admin_dashboard'))
            else:
                flash(message, 'error')
    
    return render_template('admin/add_faculty.html')

@admin.route('/manage-users')
def manage_users():
    """Manage users page"""
    users = get_all_users()
    return render_template('admin/manage_users.html', users=users)

@admin.route('/delete-user/<user_id>', methods=['POST'])
def delete_user_route(user_id):
    """Delete user endpoint"""
    success, message = delete_user(user_id)
    if success:
        flash(message, 'success')
    else:
        flash(message, 'error')
    
    return redirect(url_for('admin.manage_users'))

@admin.route('/test-db')
def test_database_connection():
    """Test database connection endpoint"""
    try:
        result = db.session.execute(text("SELECT COUNT(*) as count FROM User"))
        user_count = result.fetchone().count
        return f"Database connection successful! Found {user_count} users in the database."
    except Exception as e:
        return f"Database connection failed: {e}"