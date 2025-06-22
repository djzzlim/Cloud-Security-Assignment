import os

class Config:
    # Base directory
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

    # SQL Server database
    SQLALCHEMY_DATABASE_URI = (
        'mysql+pymysql://admin:myapp123@main-database.cif4ogai21kj.us-east-1.rds.amazonaws.com:3306/myapp'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask security
    SECRET_KEY = os.urandom(24)
    SECURITY_PASSWORD_SALT = 'secret-salt'

    # AWS S3 configuration
    S3_BUCKET_NAME = 'my-app-bucket-dtslle88'  # Your bucket name
    S3_REGION = 'us-east-1'  # AWS Academy sandbox region

    # It's best to store keys in environment variables for security
    S3_ACCESS_KEY = 'AKIA5RTSP5UBGRMVD6MW'
    S3_SECRET_KEY = '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'

    # Optional: pre-format public URL prefix
    S3_PUBLIC_URL_PREFIX = f'https://{S3_BUCKET_NAME}.s3.amazonaws.com/'