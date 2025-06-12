from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from config import Config
from flask_login import LoginManager
import os

db = SQLAlchemy()
login_manager = LoginManager()
DB_NAME = "db.sqlite3"


def create_app():
    app = Flask(__name__, static_url_path='/static', static_folder='static')
    app.config.from_object(Config)


    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static')

    db.init_app(app)

    from .routes.routes import routes
    from .routes.auth import auth
    from .routes.admin import admin
    from .routes.lecturer import lecturer

    app.register_blueprint(routes, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')
    app.register_blueprint(admin, url_prefix='/admin')
    app.register_blueprint(lecturer, url_prefix='/lecturer')

    with app.app_context():
        db.create_all()

    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    return app

@login_manager.user_loader
def load_user(user_id):
    from .models.models import User
    return User.query.get(user_id)