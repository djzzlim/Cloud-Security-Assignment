from flask import Blueprint, render_template, abort, current_app, redirect, url_for, request
from flask_login import login_required, current_user
from app.models.models import Expert, Faculty  # Import your models
from functools import wraps

def app_name():
    app_name = "Directory of Expertise"
    # with current_app.app_context():
    #     setting = Settings.query.filter_by(setting_key='school_name').first()
    #     if setting and setting.setting_value:
    #         app_name = setting.setting_value
    return app_name

def role_required(*roles):
    """Decorator to restrict access to users with specific role IDs."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role_id not in roles:
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

routes = Blueprint('routes', __name__)

@routes.route('/', methods=['GET', 'POST'])
def index():
    # Get search parameters
    search_query = request.args.get('search', '').strip()
    faculty_filter = request.args.get('faculty', '')
    
    # Start with base query
    query = Expert.query.join(Faculty, Expert.faculty_id == Faculty.id, isouter=True)
    
    # Apply search filter if provided
    if search_query:
        query = query.filter(
            Expert.full_name.ilike(f'%{search_query}%') |
            Expert.title.ilike(f'%{search_query}%') |
            Expert.position.ilike(f'%{search_query}%') |
            Expert.biography.ilike(f'%{search_query}%')
        )
    
    # Apply faculty filter if provided
    if faculty_filter and faculty_filter != 'all':
        query = query.filter(Faculty.faculty_name == faculty_filter)
    
    # Execute query and get results
    experts = query.all()
    
    # Get all faculties for dropdown
    faculties = Faculty.query.all()
    
    # Prepare expert data for template
    expert_data = []
    for expert in experts:
        expert_data.append({
            'id': expert.id,
            'name': expert.full_name,
            'title': expert.title or 'N/A',
            'position': expert.position or 'N/A',
            'faculty': expert.faculty.faculty_name if expert.faculty else 'N/A',
            'email': expert.email,
            'phone': expert.phone,
            'photo_url': expert.photo_url,
            'office_location': expert.office_location,
            'biography': expert.biography
        })
    
    return render_template("index.html", 
                         app_name=app_name(), 
                         experts=expert_data,
                         faculties=faculties,
                         current_search=search_query,
                         current_faculty=faculty_filter)

@routes.route('/expert/<expert_id>')
def expert_profile(expert_id):
    """View individual expert profile"""
    expert = Expert.query.get_or_404(expert_id)
    
    # Get expert's publications
    publications = []
    for relation in expert.publication_relations:
        publications.append(relation.publication)
    
    expert_data = {
        'id': expert.id,
        'name': expert.full_name,
        'title': expert.title,
        'position': expert.position,
        'faculty': expert.faculty.faculty_name if expert.faculty else 'N/A',
        'email': expert.email,
        'phone': expert.phone,
        'photo_url': expert.photo_url,
        'office_location': expert.office_location,
        'biography': expert.biography,
        'education_background': expert.education_background,
        'working_experience': expert.working_experience,
        'publications': publications
    }
    
    return render_template("expert_profile.html", 
                         app_name=app_name(), 
                         expert=expert_data)

@routes.route('/dashboard')
@login_required
def dashboard():
    if current_user.role_id == 1:  # Admin (changed from string to int)
        return redirect(url_for('admin.admin_dashboard'))
    elif current_user.role_id == 2:  # Lecturer (changed from string to int)
        return redirect(url_for('lecturer.dashboard'))
    else:
        return redirect(url_for('routes.index'))