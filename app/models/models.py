from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text
from sqlalchemy.dialects.mssql import NVARCHAR
from sqlalchemy.sql import func
from flask_login import UserMixin
from sqlalchemy.orm import relationship
from app import db
import uuid

def generate_uuid():
    return str(uuid.uuid4())

class Role(db.Model):
    __tablename__ = 'Role'
    id = Column('RoleID', Integer, primary_key=True, autoincrement=True)
    role_name = Column('RoleName', NVARCHAR(100), nullable=False)
    users = relationship('User', back_populates='role')

class User(UserMixin, db.Model):
    __tablename__ = 'User'
    id = Column('UserID', NVARCHAR(50), primary_key=True, default=generate_uuid)
    full_name = Column('FullName', NVARCHAR(200), nullable=False)
    password_hash = Column('PasswordHash', NVARCHAR(255))
    email = Column('Email', NVARCHAR(200), nullable=False, unique=True)
    role_id = Column('RoleID', Integer, ForeignKey('Role.RoleID', ondelete='SET NULL'))

    role = relationship('Role', back_populates='users')
    expert_profile = relationship('Expert', back_populates='user', uselist=False)
    activity_logs = relationship('ActivityLog', back_populates='user')

    def get_id(self):
        return str(self.id)

class Faculty(db.Model):
    __tablename__ = 'Faculty'
    id = Column('FacultyID', Integer, primary_key=True, autoincrement=True)
    faculty_name = Column('FacultyName', NVARCHAR(200), nullable=False)
    experts = relationship('Expert', back_populates='faculty')

class Expert(db.Model):
    __tablename__ = 'Expert'
    id = Column('ExpertID', NVARCHAR(36), primary_key=True, default=generate_uuid)
    user_id = Column('UserID', NVARCHAR(50), ForeignKey('User.UserID', ondelete='CASCADE'), unique=True)
    faculty_id = Column('FacultyID', Integer, ForeignKey('Faculty.FacultyID', ondelete='SET NULL'))

    full_name = Column('FullName', NVARCHAR(200), nullable=False)
    title = Column('Title', NVARCHAR(100))
    position = Column('Position', NVARCHAR(100))
    email = Column('Email', NVARCHAR(200))
    phone = Column('Phone', NVARCHAR(50))
    photo_url = Column('PhotoURL', NVARCHAR(300))
    office_location = Column('OfficeLocation', NVARCHAR(200))
    biography = Column('Biography', Text)
    education_background = Column('EducationBackground', Text)
    working_experience = Column('WorkingExperience', Text)

    user = relationship('User', back_populates='expert_profile')
    faculty = relationship('Faculty', back_populates='experts')
    publication_relations = relationship('ExpertPublicationRelation', back_populates='expert')

class Publication(db.Model):
    __tablename__ = 'Publication'
    id = Column('PublicationID', Integer, primary_key=True, autoincrement=True)
    title = Column('Title', NVARCHAR(300), nullable=False)
    year = Column('Year', NVARCHAR(4), nullable=False)
    publication_relations = relationship('ExpertPublicationRelation', back_populates='publication')

class ExpertPublicationRelation(db.Model):
    __tablename__ = 'ExpertPublicationRelation'
    id = Column('RelationID', Integer, primary_key=True, autoincrement=True)
    expert_id = Column('ExpertID', NVARCHAR(36), ForeignKey('Expert.ExpertID', ondelete='CASCADE'))
    publication_id = Column('PublicationID', Integer, ForeignKey('Publication.PublicationID', ondelete='CASCADE'))

    expert = relationship('Expert', back_populates='publication_relations')
    publication = relationship('Publication', back_populates='publication_relations')

class ActivityLog(db.Model):
    __tablename__ = 'ActivityLog'
    id = Column('LogID', Integer, primary_key=True, autoincrement=True)
    user_id = Column('UserID', NVARCHAR(50), ForeignKey('User.UserID', ondelete='CASCADE'))
    action = Column('Action', NVARCHAR(255), nullable=False)
    timestamp = Column('Timestamp', DateTime, server_default=func.now())

    user = relationship('User', back_populates='activity_logs')