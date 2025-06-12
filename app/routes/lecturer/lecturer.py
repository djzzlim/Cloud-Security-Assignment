from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_required, current_user
import os
import uuid
import re
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from app import db
from app.models.models import User, Expert, Faculty, Publication, ExpertPublicationRelation, ActivityLog

lecturer = Blueprint('lecturer', __name__, url_prefix='/lecturer')

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads/profiles'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def clean_text_formatting(text):
    """Clean and format text for consistent display"""
    if not text:
        return text
    
    # Remove excessive whitespace and normalize line breaks
    text = re.sub(r'\s+', ' ', text)  # Replace multiple spaces with single space
    text = re.sub(r'\s*•\s*', ' • ', text)  # Normalize bullet point spacing
    text = text.strip()
    
    return text

def log_activity(action):
    """Log user activity"""
    try:
        activity = ActivityLog(
            user_id=current_user.id,
            action=action
        )
        db.session.add(activity)
        db.session.commit()
    except Exception as e:
        print(f"Error logging activity: {str(e)}")

def parse_bullet_points(text):
    """Parse text into bullet points list"""
    if not text:
        return []
    
    # Split by bullet points and clean up
    lines = text.split('•')
    bullet_points = []
    
    for line in lines:
        cleaned_line = line.strip()
        if cleaned_line:
            bullet_points.append(cleaned_line)
    
    return bullet_points


@lecturer.route('/')
@lecturer.route('/dashboard')
@login_required
def dashboard():
    """Lecturer dashboard - redirect to edit profile for now"""
    return redirect(url_for('lecturer.edit_profile'))

@lecturer.route('/edit-profile')
@login_required
def edit_profile():
    """Display the edit profile form"""
    try:
        # Get the expert profile for the current user
        expert = Expert.query.filter_by(user_id=current_user.id).first()
        
        if not expert:
            # Create a new expert profile if it doesn't exist
            expert = Expert(
                user_id=current_user.id,
                full_name=current_user.full_name,
                email=current_user.email
            )
            db.session.add(expert)
            db.session.commit()
        
        # Get faculty information
        faculty = None
        if expert.faculty_id:
            faculty = Faculty.query.get(expert.faculty_id)
        
        # Get publications for this expert
        publications = []
        pub_relations = ExpertPublicationRelation.query.filter_by(expert_id=expert.id).all()
        for relation in pub_relations:
            publication = Publication.query.get(relation.publication_id)
            if publication:
                publications.append({
                    'title': publication.title,
                    'year': publication.year,
                    'venue': publication.venue
                })
        
        # Prepare user data for template
        user_data = {
            'full_name': expert.full_name or '',
            'title': expert.title or '',
            'position': expert.position or '',
            'faculty_id': str(expert.faculty_id) if expert.faculty_id else '',
            'faculty_name': faculty.faculty_name if faculty else '',
            'email': expert.email or current_user.email,
            'phone': expert.phone or '',
            'photo_url': expert.photo_url or '',
            'office_location': expert.office_location or '',
            'biography': expert.biography or '',
            'education_background': expert.education_background or '',
            'working_experience': expert.working_experience or '',
            'publications': publications
        }
        
        return render_template('lecturer/edit-profile.html', user_data=user_data)
        
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'error')
        return redirect(url_for('routes.index'))

@lecturer.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    """Handle profile update form submission"""
    try:
        # Get or create expert profile
        expert = Expert.query.filter_by(user_id=current_user.id).first()
        if not expert:
            expert = Expert(user_id=current_user.id)
            db.session.add(expert)
        
        # Update basic information with cleaned formatting
        expert.full_name = request.form.get('full_name', '').strip()
        expert.title = request.form.get('title', '').strip()
        expert.position = request.form.get('position', '').strip()
        expert.email = request.form.get('email', '').strip()
        expert.phone = request.form.get('phone', '').strip()
        expert.office_location = request.form.get('office_location', '').strip()
        
        # Clean text formatting for multi-line fields
        expert.biography = clean_text_formatting(request.form.get('biography', ''))
        expert.education_background = clean_text_formatting(request.form.get('education_background', ''))
        expert.working_experience = clean_text_formatting(request.form.get('working_experience', ''))
        
        # Update faculty
        faculty_id = request.form.get('faculty_id')
        if faculty_id and faculty_id.isdigit():
            expert.faculty_id = int(faculty_id)
        else:
            expert.faculty_id = None
        
        # Handle file upload
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Generate unique filename
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
                
                # Create directory if it doesn't exist
                os.makedirs(UPLOAD_FOLDER, exist_ok=True)
                
                file.save(file_path)
                expert.photo_url = f"uploads/profiles/{unique_filename}"
        
        # Handle publications
        pub_titles = request.form.getlist('pub_titles[]')
        pub_years = request.form.getlist('pub_years[]')
        pub_venues = request.form.getlist('pub_venues[]')
        
        # Remove existing publication relations
        ExpertPublicationRelation.query.filter_by(expert_id=expert.id).delete()
        
        # Add new publications
        for i, title in enumerate(pub_titles):
            if title.strip():
                year = pub_years[i] if i < len(pub_years) else ''
                venue = pub_venues[i] if i < len(pub_venues) else ''
                
                # Check if publication already exists
                publication = Publication.query.filter_by(title=title.strip(), year=year).first()
                if not publication:
                    publication = Publication(
                        title=title.strip(),
                        year=year.strip() if year else '',
                        venue=venue.strip()
                    )
                    db.session.add(publication)
                    db.session.flush()  # Get the ID
                
                # Create relation
                relation = ExpertPublicationRelation(
                    expert_id=expert.id,
                    publication_id=publication.id
                )

                print(f"Checking publication: '{title}' ({year}) -> Existing: {publication is not None}")
                db.session.add(relation)
               
        # Save changes
        db.session.commit()
        
        # Log activity
        log_activity(f"Updated profile for {expert.full_name}")
        
        flash('Profile updated successfully!', 'success')
        return jsonify({'status': 'success', 'message': 'Profile updated successfully!'})
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating profile: {str(e)}', 'error')
        return jsonify({'status': 'error', 'message': f'Error updating profile: {str(e)}'}), 500

@lecturer.route('/profile')
@login_required
def view_profile():
    """View profile page"""
    try:
        expert = Expert.query.filter_by(user_id=current_user.id).first()
        if not expert:
            return redirect(url_for('lecturer.edit_profile'))
        
        # Get faculty information
        faculty = None
        if expert.faculty_id:
            faculty = Faculty.query.get(expert.faculty_id)
        
        # Get publications
        publications = []
        pub_relations = ExpertPublicationRelation.query.filter_by(expert_id=expert.id).all()
        for relation in pub_relations:
            publication = Publication.query.get(relation.publication_id)
            if publication:
                publications.append(publication)
        
        # Parse bullet points for display (except biography)
        education_points = parse_bullet_points(expert.education_background) if expert.education_background else []
        experience_points = parse_bullet_points(expert.working_experience) if expert.working_experience else []
        
        return render_template('lecturer/profile.html', 
                             expert=expert, 
                             faculty=faculty, 
                             publications=publications,
                             education_points=education_points,
                             experience_points=experience_points)
        
    except Exception as e:
        flash(f'Error loading profile: {str(e)}', 'error')
        return redirect(url_for('lecturer.edit_profile'))

@lecturer.route('/research')
@login_required
def research():
    """Research management page"""
    return render_template('lecturer/research.html')

@lecturer.route('/publications')
@login_required
def publications():
    """Publications management page"""
    try:
        expert = Expert.query.filter_by(user_id=current_user.id).first()
        publications = []
        
        if expert:
            pub_relations = ExpertPublicationRelation.query.filter_by(expert_id=expert.id).all()
            for relation in pub_relations:
                publication = Publication.query.get(relation.publication_id)
                if publication:
                    publications.append(publication)
        
        return render_template('lecturer/publications.html', publications=publications)
        
    except Exception as e:
        flash(f'Error loading publications: {str(e)}', 'error')
        return render_template('lecturer/publications.html', publications=[])

# API routes for AJAX requests
@lecturer.route('/api/faculties')
def get_faculties():
    """Get list of faculties for dropdown"""
    try:
        faculties = Faculty.query.all()
        faculty_list = []
        for faculty in faculties:
            faculty_list.append({
                'id': faculty.id,
                'name': faculty.faculty_name
            })
        return jsonify(faculty_list)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@lecturer.route('/api/upload-photo', methods=['POST'])
@login_required
def upload_photo():
    """Handle photo upload via AJAX"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
            
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            file.save(file_path)
            
            # Update expert photo URL in database
            expert = Expert.query.filter_by(user_id=current_user.id).first()
            if expert:
                expert.photo_url = f"uploads/profiles/{unique_filename}"
                db.session.commit()
                
                log_activity("Updated profile photo")
            
            photo_url = f"/static/uploads/profiles/{unique_filename}"
            return jsonify({'success': True, 'photo_url': photo_url})
        
        return jsonify({'error': 'Invalid file type'}), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@lecturer.route('/api/profile-data')
@login_required
def get_profile_data():
    """Get current user's profile data as JSON"""
    try:
        expert = Expert.query.filter_by(user_id=current_user.id).first()
        if not expert:
            return jsonify({'error': 'Profile not found'}), 404
        
        # Get faculty information
        faculty = None
        if expert.faculty_id:
            faculty = Faculty.query.get(expert.faculty_id)
        
        # Get publications
        publications = []
        pub_relations = ExpertPublicationRelation.query.filter_by(expert_id=expert.id).all()
        for relation in pub_relations:
            publication = Publication.query.get(relation.publication_id)
            if publication:
                publications.append({
                    'title': publication.title,
                    'year': publication.year,
                    'venue': publication.venue
                })
        
        profile_data = {
            'full_name': expert.full_name or '',
            'title': expert.title or '',
            'position': expert.position or '',
            'faculty_id': expert.faculty_id,
            'faculty_name': faculty.faculty_name if faculty else '',
            'email': expert.email or '',
            'phone': expert.phone or '',
            'photo_url': expert.photo_url or '',
            'office_location': expert.office_location or '',
            'biography': expert.biography or '',
            'education_background': expert.education_background or '',
            'working_experience': expert.working_experience or '',
            'publications': publications
        }
        
        return jsonify(profile_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500