# import os

# class Config:
#     BASE_DIR = os.path.abspath(os.path.dirname(__file__))
#     SQLALCHEMY_DATABASE_URI = (
#         'mssql+pyodbc://sa:Pa$$w0rd@localhost:1433/ExpertDB'
#         '?driver=ODBC+Driver+17+for+SQL+Server&trustServerCertificate=yes'
#     )
#     SQLALCHEMY_TRACK_MODIFICATIONS = False
#     SECRET_KEY = os.urandom(24)
#     SECURITY_PASSWORD_SALT = 'secret-salt'
import os

class Config:
    # Base directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # SQL Server database
    SQLALCHEMY_DATABASE_URI = (
        'mssql+pyodbc://sa:Pa$$w0rd@localhost:1433/ExpertDB'
        '?driver=ODBC+Driver+17+for+SQL+Server&trustServerCertificate=yes'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask security
    SECRET_KEY = os.urandom(24)
    SECURITY_PASSWORD_SALT = 'secret-salt'

    # AWS S3 configuration
    S3_BUCKET_NAME = 'expert-directory-photos'  # Your bucket name
    S3_REGION = 'us-east-1'  # AWS Academy sandbox region

    # It's best to store keys in environment variables for security
    S3_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')        # Leave blank if using sandbox's CLI/Boto3 context
    S3_SECRET_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')    # Leave blank if using sandbox's CLI/Boto3 context

    # Optional: pre-format public URL prefix
    S3_PUBLIC_URL_PREFIX = f'https://{S3_BUCKET_NAME}.s3.amazonaws.com/'
