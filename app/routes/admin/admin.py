from flask import Blueprint, render_template, current_app, request, redirect, url_for, flash
import pyodbc
from datetime import datetime, timedelta
import logging
import uuid
import hashlib

admin = Blueprint('admin', __name__)

def get_db_connection():
    """Create and return database connection"""
    try:
        # Update these connection parameters according to your SQL Server setup
        connection_string = (
            "DRIVER={ODBC Driver 17 for SQL Server};"
            "SERVER=localhost;"  # or your server name/IP
            "DATABASE=ExpertDB;"
             "UID=sa;"
             "PWD=Pa$$w0rd;"
        )
        
        conn = pyodbc.connect(connection_string)
        return conn
    except Exception as e:
        current_app.logger.error(f"Database connection error: {e}")
def hash_password(password):
    """Hash password using SHA-256 (in production, use bcrypt or similar)"""
    return hashlib.sha256(password.encode()).hexdigest()

def get_roles():
    """Fetch all roles from database"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT RoleID, RoleName FROM Role ORDER BY RoleName")
        roles = []
        for row in cursor.fetchall():
            roles.append({'id': row.RoleID, 'name': row.RoleName})
        
        cursor.close()
        conn.close()
        return roles
    except Exception as e:
        current_app.logger.error(f"Error fetching roles: {e}")
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        return []

def get_faculties():
    """Fetch all faculties from database"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT FacultyID, FacultyName FROM Faculty ORDER BY FacultyName")
        faculties = []
        for row in cursor.fetchall():
            faculties.append({'id': row.FacultyID, 'name': row.FacultyName})
        
        cursor.close()
        conn.close()
        return faculties
    except Exception as e:
        current_app.logger.error(f"Error fetching faculties: {e}")
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        return []

def create_user(user_data):
    """Create a new user in the database"""
    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed"
    
    try:
        cursor = conn.cursor()
        
        # Generate UUID for user
        user_id = str(uuid.uuid4())
        
        # Hash the password
        password_hash = hash_password(user_data['password'])
        
        # Insert user
        cursor.execute("""
            INSERT INTO [User] (UserID, FullName, PasswordHash, Email, RoleID)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, user_data['full_name'], password_hash, user_data['email'], user_data['role_id']))
        
        # If user is an Expert, create Expert profile
        if user_data['role_id'] == 2:  # Expert role
            expert_id = str(uuid.uuid4())
            cursor.execute("""
                INSERT INTO Expert (
                    ExpertID, UserID, FacultyID, FullName, Title, Position,
                    Email, Phone, PhotoURL, OfficeLocation,
                    Biography, EducationBackground, WorkingExperience
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                expert_id, user_id, user_data.get('faculty_id'),
                user_data['full_name'], user_data.get('title', ''),
                user_data.get('position', ''), user_data['email'],
                user_data.get('phone', ''), user_data.get('photo_url', ''),
                user_data.get('office_location', ''), user_data.get('biography', ''),
                user_data.get('education_background', ''), user_data.get('working_experience', '')
            ))
        
        # Log the activity
        cursor.execute("""
            INSERT INTO ActivityLog (UserID, Action)
            VALUES (?, ?)
        """, (user_id, f"New user account created: {user_data['full_name']}"))
        
        conn.commit()
        cursor.close()
        conn.close()
        return True, "User created successfully"
        
    except pyodbc.IntegrityError as e:
        cursor.close()
        conn.close()
        if "UNIQUE KEY constraint" in str(e) or "duplicate key" in str(e):
            return False, "Email address already exists"
        return False, f"Database constraint error: {str(e)}"
    except Exception as e:
        current_app.logger.error(f"Error creating user: {e}")
        cursor.close()
        conn.close()
        return False, f"Error creating user: {str(e)}"

def get_dashboard_stats():
    """Fetch dashboard statistics from database"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        stats = {}
        
        # Total Users
        cursor.execute("SELECT COUNT(*) FROM [User]")
        stats['total_users'] = cursor.fetchone()[0]
        
        # Faculty Members (Users with Expert role)
        cursor.execute("""
            SELECT COUNT(*) 
            FROM [User] u 
            INNER JOIN Role r ON u.RoleID = r.RoleID 
            WHERE r.RoleName = 'Expert'
        """)
        stats['faculty_members'] = cursor.fetchone()[0]
        
        # Recent Activities (last 7 days)
        cursor.execute("""
            SELECT COUNT(*) 
            FROM ActivityLog 
            WHERE Timestamp >= DATEADD(day, -7, GETDATE())
        """)
        stats['pending_approvals'] = cursor.fetchone()[0]
        
        # Research Areas (approximation based on publications)
        cursor.execute("SELECT COUNT(DISTINCT Venue) FROM Publication")
        stats['research_areas'] = cursor.fetchone()[0]
        
        cursor.close()
        conn.close()
        return stats
        
    except Exception as e:
        current_app.logger.error(f"Error fetching dashboard stats: {e}")
        cursor.close()
        conn.close()
        return None

def get_recent_activities():
    """Fetch recent activities from database"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        
        # Get recent activities with user information
        query = """
            SELECT TOP 10
                al.Action,
                al.Timestamp,
                u.FullName,
                r.RoleName,
                u.UserID
            FROM ActivityLog al
            INNER JOIN [User] u ON al.UserID = u.UserID
            LEFT JOIN Role r ON u.RoleID = r.RoleID
            ORDER BY al.Timestamp DESC
        """
        
        cursor.execute(query)
        activities = []
        
        for row in cursor.fetchall():
            # Calculate time ago
            time_diff = datetime.now() - row.Timestamp
            if time_diff.days > 0:
                time_ago = f"{time_diff.days} day{'s' if time_diff.days > 1 else ''} ago"
            elif time_diff.seconds > 3600:
                hours = time_diff.seconds // 3600
                time_ago = f"{hours} hour{'s' if hours > 1 else ''} ago"
            elif time_diff.seconds > 60:
                minutes = time_diff.seconds // 60
                time_ago = f"{minutes} minute{'s' if minutes > 1 else ''} ago"
            else:
                time_ago = "Just now"
            
            # Determine status based on action type
            action_lower = row.Action.lower()
            if 'created' in action_lower or 'added' in action_lower:
                status = {'class': 'bg-success', 'text': 'Completed'}
            elif 'updated' in action_lower or 'modified' in action_lower:
                status = {'class': 'bg-info', 'text': 'Updated'}
            elif 'deleted' in action_lower or 'removed' in action_lower:
                status = {'class': 'bg-danger', 'text': 'Removed'}
            else:
                status = {'class': 'bg-secondary', 'text': 'Activity'}
            
            activities.append({
                'action': row.Action,
                'timestamp': row.Timestamp,
                'user_name': row.FullName,
                'role': row.RoleName or 'Unknown',
                'time_ago': time_ago,
                'status': status
            })
        
        cursor.close()
        conn.close()
        return activities
        
    except Exception as e:
        current_app.logger.error(f"Error fetching recent activities: {e}")
        cursor.close()
        conn.close()
        return None

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
                                 database_error="Unable to connect to ExpertDB database. Please check your connection settings.")
        
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
            'photo_url': request.form.get('photo_url', '').strip()
        }
        
        # Convert empty faculty_id to None
        if user_data['faculty_id'] == '':
            user_data['faculty_id'] = None
        else:
            user_data['faculty_id'] = int(user_data['faculty_id'])
        
        # Basic validation
        if not user_data['full_name']:
            flash('Full name is required', 'error')
        elif not user_data['email']:
            flash('Email is required', 'error')
        elif not user_data['password']:
            flash('Password is required', 'error')
        else:
            # Create user
            success, message = create_user(user_data)
            if success:
                flash(message, 'success')
                return redirect(url_for('admin.admin_dashboard'))
            else:
                flash(message, 'error')
    
    # Get roles and faculties for form
    roles = get_roles()
    faculties = get_faculties()
    
    return render_template('admin/add_user.html', roles=roles, faculties=faculties)

@admin.route('/test-db')
def test_database_connection():
    """Test database connection endpoint"""
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM [User]")
            user_count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            return f"Database connection successful! Found {user_count} users in the database."
        except Exception as e:
            return f"Database connection established but query failed: {e}"
    else:
        return "Database connection failed. Please check your connection settings."