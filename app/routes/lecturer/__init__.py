from flask import Blueprint

# Initialize Blueprint
lecturer = Blueprint('lecturer', __name__)

from .lecturer import *