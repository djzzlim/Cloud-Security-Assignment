import os

class Config:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    SQLALCHEMY_DATABASE_URI = (
        'mysql+pymysql://admin:myapp123@my-app-database.cif4ogai21kj.us-east-1.rds.amazonaws.com:3306/myapp'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ✅ Fixed secret key for stable sessions
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key')  # Change this in prod
    SECURITY_PASSWORD_SALT = 'secret-salt'

    # ✅ Session config for Flask-Login + ALB
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_HTTPONLY = True

    # AWS S3 configuration
    S3_BUCKET_NAME = 'my-app-bucket-kjshjh'
    S3_REGION = 'us-east-1'
    S3_ACCESS_KEY = 'AKIA5RTSP5UBGRMVD6MW'
    S3_SECRET_KEY = '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'

    S3_PUBLIC_URL_PREFIX = f'https://{S3_BUCKET_NAME}.s3.amazonaws.com/'
