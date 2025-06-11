from app import db
from flask_login import UserMixin
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from sqlalchemy.sql import func
import uuid

# Role model
class Role(db.Model):
    __tablename__ = 'Role'
    id = db.Column('RoleID', db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    role_name = db.Column('RoleName', db.String, nullable=False)

    # Relationships
    users = relationship('User', back_populates='role')

# User model
class User(UserMixin, db.Model):
    __tablename__ = 'User'
    
    id = db.Column('UserID', db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    full_name = db.Column('FullName', db.String, nullable=False)
    password_hash = db.Column('PasswordHash', db.String, nullable=True)
    email = db.Column('Email', db.String, nullable=False, unique=True)
    role_id = db.Column('RoleID', db.String, ForeignKey('Role.RoleID', ondelete='SET NULL'))

    # Relationships
    role = relationship('Role', back_populates='users')
    activity_logs = relationship('ActivityLog', back_populates='user')

    def get_id(self):
        return self.id

# Faculty model
class Faculty(db.Model):
    __tablename__ = 'Faculty'
    
    id = db.Column('FacultyID', db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    faculty_name = db.Column('FacultyName', db.String, nullable=False)

    # Relationships
    experts = relationship('Expert', back_populates='faculty')

# Expert model
class Expert(db.Model):
    __tablename__ = 'Expert'
    
    id = db.Column('ExpertID', db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    faculty_id = db.Column('FacultyID', db.String, ForeignKey('Faculty.FacultyID', ondelete='SET NULL'))
    full_name = db.Column('FullName', db.String, nullable=False)
    title = db.Column('Title', db.String)
    email = db.Column('Email', db.String)
    phone = db.Column('Phone', db.String)
    photo_url = db.Column('PhotoURL', db.String)
    office_location = db.Column('OfficeLocation', db.String)
    biography = db.Column('Biography', db.Text)
    education_background = db.Column('EducationBackground', db.Text)
    working_experience = db.Column('WorkingExperience', db.Text)
    
    # Relationships
    faculty = relationship('Faculty', back_populates='experts')
    entities = relationship('Entity', back_populates='expert')

# Publication model
class Publication(db.Model):
    __tablename__ = 'Publication'
    
    id = db.Column('PublicationID', db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column('Title', db.String, nullable=False)
    year = db.Column('Year', db.String, nullable=False)
    
    # Relationships
    entities = relationship('Entity', back_populates='publication')

# Entity model (junction table for Expert-Publication many-to-many relationship)
class Entity(db.Model):
    __tablename__ = 'Entity'
    
    id = db.Column('RelationID', db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    expert_id = db.Column('ExpertID', db.String, ForeignKey('Expert.ExpertID', ondelete='CASCADE'))
    publication_id = db.Column('PublicationID', db.String, ForeignKey('Publication.PublicationID', ondelete='CASCADE'))
    
    # Relationships
    expert = relationship('Expert', back_populates='entities')
    publication = relationship('Publication', back_populates='entities')

# ActivityLog model
class ActivityLog(db.Model):
    __tablename__ = 'ActivityLog'
    
    id = db.Column('LogID', db.String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column('UserID', db.String, ForeignKey('User.UserID', ondelete='CASCADE'))
    action = db.Column('Action', db.String, nullable=False)
    timestamp = db.Column('Timestamp', db.DateTime, server_default=func.now())

    # Relationships
    user = relationship('User', back_populates='activity_logs')