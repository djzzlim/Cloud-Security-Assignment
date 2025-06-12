import os

class Config:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = (
        'mssql+pyodbc://sa:Pa$$w0rd@localhost:1433/ExpertDB'
        '?driver=ODBC+Driver+17+for+SQL+Server&trustServerCertificate=yes'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.urandom(24)
    SECURITY_PASSWORD_SALT = 'secret-salt'
    