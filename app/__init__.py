# # from flask import Flask
# # from flask_pymongo import PyMongo
# # from flask_cors import CORS
# # from .config import config_by_name # Import the config dictionary from app.config
# # import os # <--- ADD THIS LINE
# # mongo = PyMongo() # Initialize PyMongo, will be configured in create_app
# #
# # def create_app(config_name='default'):
# #     """
# #     Application factory function.
# #     """
# #     app = Flask(__name__)
# #
# #     # --- Load Configuration ---
# #     # This should correctly load MONGO_URI and SECRET_KEY from config_by_name
# #     app.config.from_object(config_by_name[config_name])
# #
# #     # --- Initialize extensions ---
# #     mongo.init_app(app) # Configure PyMongo with app config
# #
# #     # Optional: Setup basic logging if not in debug mode
# #     if not app.debug and not app.testing:
# #         import logging
# #         from logging.handlers import RotatingFileHandler
# #         # Example: Log to a file
# #         # Ensure 'logs' directory exists or choose a different path
# #         if not os.path.exists('logs'):
# #             os.mkdir('logs')
# #         file_handler = RotatingFileHandler('logs/poddar_backend.log', maxBytes=10240, backupCount=10)
# #         file_handler.setFormatter(logging.Formatter(
# #             '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
# #         ))
# #         file_handler.setLevel(logging.INFO)
# #         app.logger.addHandler(file_handler)
# #         app.logger.setLevel(logging.INFO)
# #         app.logger.info('Poddar Jeweller Backend startup')
# #
# #     # Enable CORS - allow requests from any origin to /api/* routes
# #     CORS(app, resources={r"/api/*": {"origins": "*"}})
# #
# #     # --- Register blueprints (routes) ---
# #     from .routes import main_bp # Import your blueprint from app.routes
# #     app.register_blueprint(main_bp, url_prefix='/api') # All routes in main_bp will be prefixed with /api
# #
# #     # --- Simple root route for health check or welcome message ---
# #     @app.route('/')
# #     def hello():
# #         # Check if MongoDB is connected as a basic health check
# #         try:
# #             # mongo.cx is the MongoClient instance. server_info() pings the server.
# #             mongo.cx.server_info()
# #             db_status = "MongoDB connection successful."
# #         except Exception as e:
# #             db_status = f"MongoDB connection error: {e}"
# #             app.logger.error(f"Health check MongoDB connection error: {e}")
# #         return f"Flask Backend for Poddar Jewellers is running! {db_status}"
# #
# #     return app
#
#
#
#
#
#
# # app/__init__.py
#
# from flask import Flask
# from flask_pymongo import PyMongo
# from flask_cors import CORS
# from .config import config_by_name
# import os
#
# mongo = PyMongo()
#
# def create_app(config_name='default'):
#     """
#     Application factory function.
#     """
#     app = Flask(__name__)
#
#     # --- Load Configuration ---
#     app.config.from_object(config_by_name[config_name])
#
#     # --- Initialize extensions ---
#     mongo.init_app(app)
#
#     # --- THIS IS THE CRITICAL LINE THAT WAS MISSING ---
#     # This makes the database object available to your routes via 'current_app.db'
#     app.db = mongo.db
#     # --- END OF CRITICAL LINE ---
#
#     # Optional: Setup basic logging if not in debug mode
#     if not app.debug and not app.testing:
#         import logging
#         from logging.handlers import RotatingFileHandler
#         if not os.path.exists('logs'):
#             os.mkdir('logs')
#         file_handler = RotatingFileHandler('logs/poddar_backend.log', maxBytes=10240, backupCount=10)
#         file_handler.setFormatter(logging.Formatter(
#             '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
#         ))
#         file_handler.setLevel(logging.INFO)
#         app.logger.addHandler(file_handler)
#         app.logger.setLevel(logging.INFO)
#         app.logger.info('Poddar Jeweller Backend startup')
#
#     # Enable CORS
#     CORS(app, resources={r"/api/*": {"origins": "*"}})
#
#     # --- Register blueprints (routes) ---
#     from .routes import main_bp
#     app.register_blueprint(main_bp, url_prefix='/api')
#
#     # --- Simple root route for health check ---
#     @app.route('/')
#     def hello():
#         try:
#             mongo.cx.server_info()
#             db_status = "MongoDB connection successful."
#         except Exception as e:
#             db_status = f"MongoDB connection error: {e}"
#             app.logger.error(f"Health check MongoDB connection error: {e}")
#         return f"Flask Backend for Poddar Jewellers is running! {db_status}"
#
#     return app




# app/__init__.py

from flask import Flask
from flask_pymongo import PyMongo
from flask_cors import CORS
from .config import config_by_name
import os
import logging # <-- Import logging

# --- (1) ADD NEW IMPORTS FOR FIREBASE ---
import firebase_admin
from firebase_admin import credentials
# ----------------------------------------

mongo = PyMongo()

def create_app(config_name='default'):
    """
    Application factory function.
    """
    app = Flask(__name__)

    # --- Load Configuration ---
    app.config.from_object(config_by_name[config_name])

    # --- Initialize extensions ---
    mongo.init_app(app)

    # --- THIS IS THE CRITICAL LINE THAT WAS MISSING ---
    # This makes the database object available to your routes via 'current_app.db'
    app.db = mongo.db
    # --- END OF CRITICAL LINE ---

    # --- (2) INITIALIZE THE FIREBASE ADMIN SDK ---
    # This should be done only once when the app is created.
    try:
        # IMPORTANT: Make sure 'firebase-service-account.json' is in your root backend folder
        # (poddar_jeweller_flask_backend/), NOT inside the 'app' folder.
        cred = credentials.Certificate("firebase-service-account.json")
        firebase_admin.initialize_app(cred)
        # Use app.logger which is configured below
        # print("✅ Firebase Admin SDK was initialized successfully.")
    except FileNotFoundError:
        # Using print because logger might not be configured yet if startup fails here
        print("❌ CRITICAL: 'firebase-service-account.json' not found. Firebase features will fail.")
    except Exception as e:
        print(f"❌ CRITICAL: Failed to initialize Firebase Admin SDK: {e}")
    # --------------------------------------------------

    # Optional: Setup basic logging if not in debug mode
    if not app.debug and not app.testing:
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = logging.FileHandler('logs/poddar_backend.log')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Poddar Jeweller Backend startup')

    # Log Firebase status after logger is configured
    if firebase_admin._apps:
        app.logger.info("✅ Firebase Admin SDK was initialized successfully.")
    else:
        app.logger.error("❌ Firebase Admin SDK failed to initialize. Check logs above.")


    # Enable CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # --- Register blueprints (routes) ---
    from .routes import main_bp
    app.register_blueprint(main_bp, url_prefix='/api')

    # --- Simple root route for health check ---
    @app.route('/')
    def hello():
        try:
            mongo.cx.server_info()
            db_status = "MongoDB connection successful."
        except Exception as e:
            db_status = f"MongoDB connection error: {e}"
            app.logger.error(f"Health check MongoDB connection error: {e}")
        return f"Flask Backend for Poddar Jewellers is running! {db_status}"

    return app

