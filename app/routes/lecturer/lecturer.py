from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_required, current_user
import os
import uuid
import re
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash
from app import db
from app.models.models import User, Expert, Faculty, Publication, ExpertPublicationRelation, ActivityLog
from config import *

lecturer = Blueprint('lecturer', __name__, url_prefix='/lecturer')

# Configure upload settings
UPLOAD_FOLDER = 'static/uploads/profiles'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 2 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image_file(file):
    """Validate uploaded image file"""
    if not file or file.filename == '':
        return False, "No file selected"
    
    if not allowed_file(file.filename):
        return False, "Invalid file type. Please upload PNG, JPG, JPEG, or GIF files only."
    
    # Check file size (Flask doesn't automatically limit this)
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)  # Reset file pointer
    
    if file_size > MAX_FILE_SIZE:
        return False, "File size too large. Maximum size is 2MB."
    
    return True, "Valid file"

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
    return redirect(url_for('lecturer.view_profile'))

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
            db.session.flush()  # Get the ID immediately
        
        # Update basic information
        expert.full_name = request.form.get('full_name', '').strip()
        expert.title = request.form.get('title', '').strip()
        expert.position = request.form.get('position', '').strip()
        expert.email = request.form.get('email', '').strip()
        expert.phone = request.form.get('phone', '').strip()
        expert.office_location = request.form.get('office_location', '').strip()
        expert.biography = request.form.get('biography', '').strip()
        expert.education_background = request.form.get('education_background', '').strip()
        expert.working_experience = request.form.get('working_experience', '').strip()
        
        # Update faculty
        faculty_id = request.form.get('faculty_id')
        if faculty_id and faculty_id.isdigit():
            expert.faculty_id = int(faculty_id)
        else:
            expert.faculty_id = None
        
        # Handle file upload - FIXED VERSION
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            print(f"File received: {file.filename}")  # Debug print
            print(f"File size: {file.content_length if hasattr(file, 'content_length') else 'unknown'}")
            
            # Check if a file was actually selected
            if file and file.filename and file.filename != '':
                # Validate file
                is_valid, message = validate_image_file(file)
                print(f"File validation: {is_valid}, {message}")
                
                if is_valid:
                    try:
                        # Create unique filename
                        filename = secure_filename(file.filename)
                        file_extension = filename.rsplit('.', 1)[1].lower()
                        unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
                        
                        # Ensure upload directory exists
                        full_upload_path = os.path.abspath(UPLOAD_FOLDER)
                        os.makedirs(full_upload_path, exist_ok=True)
                        print(f"Upload directory: {full_upload_path}")
                        
                        # Create full file path
                        file_path = os.path.join(full_upload_path, unique_filename)
                        print(f"Full file path: {file_path}")
                        
                        # Reset file pointer to beginning
                        file.seek(0)
                        
                        # Save file
                        file.save(file_path)
                        print(f"File saved to: {file_path}")
                        
                        # Verify file was saved and get actual size
                        if os.path.exists(file_path):
                            file_size = os.path.getsize(file_path)
                            print(f"File saved successfully. Size: {file_size} bytes")
                            
                            # Update database with relative path (for web access)
                            relative_path = f"uploads/profiles/{unique_filename}"
                            expert.photo_url = relative_path
                            print(f"Database photo_url set to: {expert.photo_url}")
                            
                            # Force database flush to ensure the change is registered
                            db.session.flush()
                            print(f"After flush, expert.photo_url = {expert.photo_url}")
                            
                            flash("Profile photo uploaded successfully!", "success")
                        else:
                            print("ERROR: File was not saved properly")
                            flash("Error: Failed to save profile photo", "error")
                            
                    except Exception as file_error:
                        print(f"File upload error: {str(file_error)}")
                        import traceback
                        traceback.print_exc()
                        flash(f"Error uploading photo: {str(file_error)}", "error")
                else:
                    print(f"File validation failed: {message}")
                    flash(message, "error")
            else:
                print("No file selected or empty filename")
        else:
            print("No 'profile_photo' key in request.files")
        
        # Handle publications (existing code)
        pub_titles = request.form.getlist('pub_titles[]')
        pub_years = request.form.getlist('pub_years[]')
        pub_venues = request.form.getlist('pub_venues[]')
        
        # Remove existing publication relations
        if expert.id:
            ExpertPublicationRelation.query.filter_by(expert_id=expert.id).delete()
        
        # Add new publications
        for i, title in enumerate(pub_titles):
            if title.strip():
                year = pub_years[i] if i < len(pub_years) else ''
                venue = pub_venues[i] if i < len(pub_venues) else ''
                
                # Check if publication already exists
                publication = Publication.query.filter_by(title=title.strip()).first()
                if not publication:
                    publication = Publication(
                        title=title.strip(),
                        year=year.strip() if year else '',
                        venue=venue.strip()
                    )
                    db.session.add(publication)
                    db.session.flush()
                
                # Create relation
                relation = ExpertPublicationRelation(
                    expert_id=expert.id,
                    publication_id=publication.id
                )
                db.session.add(relation)
        
        # Final commit with error handling
        try:
            db.session.commit()
            print("Database commit successful")
            
            # Verify the photo_url was actually saved
            updated_expert = Expert.query.filter_by(user_id=current_user.id).first()
            print(f"After commit, photo_url in database: {updated_expert.photo_url}")
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('lecturer.view_profile'))
            
        except Exception as commit_error:
            db.session.rollback()
            print(f"Database commit error: {str(commit_error)}")
            flash(f'Error saving to database: {str(commit_error)}', 'error')
            return redirect(url_for('lecturer.edit_profile'))
        
    except Exception as e:
        db.session.rollback()
        print(f"General error in update_profile: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'Error updating profile: {str(e)}', 'error')
        return redirect(url_for('lecturer.edit_profile'))

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
        
        return render_template('lecturer/view-profile.html', 
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
        
        # Validate file
        is_valid, message = validate_image_file(file)
        if not is_valid:
            return jsonify({'error': message}), 400
        
        # Process file
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
        
        # Create directory and save file
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        file.save(file_path)
        
        # Verify file was saved
        if not os.path.exists(file_path):
            return jsonify({'error': 'Failed to save file'}), 500
        
        # Update expert photo URL in database
        expert = Expert.query.filter_by(user_id=current_user.id).first()
        if not expert:
            expert = Expert(user_id=current_user.id)
            db.session.add(expert)
            db.session.flush()
        
        expert.photo_url = f"uploads/profiles/{unique_filename}"
        db.session.commit()
        
        # Return success with photo URL
        photo_url = url_for('static', filename=f"uploads/profiles/{unique_filename}")
        return jsonify({
            'success': True, 
            'photo_url': photo_url,
            'message': 'Photo uploaded successfully'
        })
        
    except Exception as e:
        print(f"AJAX upload error: {str(e)}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

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