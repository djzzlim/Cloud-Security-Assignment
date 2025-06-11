from flask import Blueprint

# Initialize Blueprint
admin = Blueprint('admin', __name__)

from .admin import *