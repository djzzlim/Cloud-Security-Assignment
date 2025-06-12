from flask import Blueprint, render_template, abort, current_app, redirect, url_for
from flask_login import login_required, current_user
# from app.models.models import Settings
from functools import wraps

def app_name():
    app_name = "Directory of Expertise"
    # with current_app.app_context():
    #     setting = Settings.query.filter_by(setting_key='school_name').first()
    #     if setting and setting.setting_value:
    #         app_name = setting.setting_value
    # return app_name

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
    return render_template("index.html", app_name=app_name())

@routes.route('/dashboard')
@login_required 
def dashboard():
    if current_user.role_id == '1':  # Admin
        return redirect(url_for('admin.dashboard'))
    elif current_user.role_id == '2':  # Lecturer
        return redirect(url_for('lecturer.dashboard'))
    else:
        return redirect(url_for('routes.index'))
