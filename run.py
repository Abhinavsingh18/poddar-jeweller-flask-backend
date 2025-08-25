import os
from app import create_app # Import the app factory function from app/__init__.py

# Determine which configuration to use from FLASK_ENV or default to 'development'
# This ensures that create_app(config_name) in __init__.py gets the correct environment.
config_name = os.getenv('FLASK_ENV') or 'development'
app = create_app(config_name) # <--- 'app' IS CREATED HERE

if __name__ == '__main__':
    # Get PORT from .env or default to 5000
    port = int(os.environ.get('PORT', 5000))

    # Debug mode will be set based on the loaded configuration (e.g., DevelopmentConfig.DEBUG)
    # The host='0.0.0.0' makes the server accessible externally (e.g., from your Flutter app if on same network)
    app.run(host='0.0.0.0', port=port)

