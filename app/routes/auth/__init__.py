from flask import Blueprint

# Initialize Blueprint
auth = Blueprint('auth', __name__)

from .auth import *