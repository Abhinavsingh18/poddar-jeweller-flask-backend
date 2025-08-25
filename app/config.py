# app/config.py
import os
from dotenv import load_dotenv

# Path to the .env file in the root directory (parent of 'app')
basedir = os.path.abspath(os.path.dirname(__file__))
dotenv_path = os.path.join(basedir, '..', '.env')
load_dotenv(dotenv_path)

class Config:
    """Base configuration."""
    # Load SECRET_KEY from .env, with a fallback (though .env should always provide it)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'default-fallback-secret-key-SHOULD-BE-IN-DOTENV'
    
    # Load MONGO_URI from .env
    MONGO_URI = os.environ.get('MONGO_URI')

    # You can add other global configurations here if needed
    # For example:
    # SQLALCHEMY_TRACK_MODIFICATIONS = False 

class DevelopmentConfig(Config):
    DEBUG = True
    # You could override MONGO_URI for a local dev DB if needed, but usually .env handles environments

class ProductionConfig(Config):
    DEBUG = False
    # In production, you'd want to ensure critical configs like SECRET_KEY and MONGO_URI
    # are definitely set via environment variables (which .env simulates for dev)
    if not Config.SECRET_KEY or Config.SECRET_KEY == 'default-fallback-secret-key-SHOULD-BE-IN-DOTENV':
        # This check is more for a conceptual understanding.
        # In a real CI/CD pipeline, you'd have stricter checks or rely on platform-provided env vars.
        print("WARNING: Production environment is using a default or missing SECRET_KEY. This is insecure.")
    if not Config.MONGO_URI:
        print("WARNING: Production environment is missing MONGO_URI.")


# Dictionary to access config by name, used in app/__init__.py
config_by_name = dict(
    development=DevelopmentConfig,
    production=ProductionConfig,
    default=DevelopmentConfig # Set 'default' to DevelopmentConfig for convenience
)
