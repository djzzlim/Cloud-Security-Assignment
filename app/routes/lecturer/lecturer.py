from flask import Blueprint, render_template

lecturer = Blueprint('lecturer', __name__)

@lecturer.route('/')
def admin_dashboard():
    return render_template('lecturer/profile.html')