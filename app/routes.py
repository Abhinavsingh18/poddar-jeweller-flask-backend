# app/routes.py

from flask import Blueprint, jsonify, request, current_app
# from . import mongo # Import the mongo instance from app/__init__.py
from bson import ObjectId
from bson.errors import InvalidId
from werkzeug.security import check_password_hash # For login
import jwt # For login (PyJWT library)
import datetime # For login token expiration and lastUpdated timestamp
from functools import wraps # Needed for the token_required decorator

def to_iso_z(dt):
    """Converts a datetime object to ISO 8601 format with a 'Z' for UTC."""
    if isinstance(dt, datetime.datetime):
        return dt.isoformat() + "Z"
    return None # Or return the original value, or an empty string, based on preference

# --- Main Blueprint ---
# This blueprint will be registered with a /api prefix in your app/__init__.py
main_bp = Blueprint('main', __name__)

# --- Token Required Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Check for token in 'Authorization: Bearer <token>' header first
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
        # Fallback to 'x-access-token' if Bearer token not found
        elif 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            current_app.logger.warning("Authentication token is missing for a protected route.")
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Decode the token using the application's SECRET_KEY
            secret_key = current_app.config.get('SECRET_KEY')
            if not secret_key or secret_key == 'default-fallback-secret-key-SHOULD-BE-IN-DOTENV': # Ensure this default matches your actual default if used
                current_app.logger.error("CRITICAL SECURITY: Attempt to use token_required decorator without a valid SECRET_KEY configured.")
                return jsonify({'message': 'Server security configuration error.'}), 500

            decoded_payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            # Example: Fetch user from DB based on token data to ensure user exists
            # admin_user = mongo.db.admins.find_one({"_id": ObjectId(decoded_payload.get("user_id"))})
            # if not admin_user:
            #     current_app.logger.warning(f"Token valid, but user ID {decoded_payload.get('user_id')} not found in database.")
            #     return jsonify({'message': 'Token is invalid, user not found!'}), 401
            # return f(admin_user, *args, **kwargs) # Pass the user object

        except jwt.ExpiredSignatureError:
            current_app.logger.warning("Authentication token has expired.")
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError as e: # Catch specific invalid token errors
            current_app.logger.warning(f"Authentication token is invalid: {e}")
            return jsonify({'message': f'Token is invalid: {e}'}), 401
        except Exception as e: # Catch any other errors during token decoding
            current_app.logger.error(f"An unexpected error occurred during token validation: {e}", exc_info=True)
            return jsonify({'message': 'Token validation failed due to a server error.'}), 500

        # Pass the decoded payload to the wrapped function.
        return f(decoded_payload, *args, **kwargs)
    return decorated


# --- Product Routes ---
@main_bp.route('/products', methods=['GET'])
def get_products():
    try:
        products_collection = mongo.db.products
        products_cursor = products_collection.find({})
        products_list = []
        for product in products_cursor:
            product['_id'] = str(product['_id']) # Convert ObjectId to string for JSON
            products_list.append(product)
        current_app.logger.info("Successfully fetched all products.")
        return jsonify(products_list), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching products: {e}", exc_info=True)
        return jsonify({"message": "Error fetching products from database", "error": str(e)}), 500

@main_bp.route('/products/<string:product_id>', methods=['GET'])
def get_product(product_id):
    try:
        products_collection = mongo.db.products
        try:
            db_product_id = ObjectId(product_id)
        except InvalidId:
            current_app.logger.warning(f"Attempt to fetch product with invalid ID format: {product_id}")
            return jsonify({"message": "Invalid product ID format"}), 400

        product = products_collection.find_one({'_id': db_product_id})
        if product:
            product['_id'] = str(product['_id'])
            current_app.logger.info(f"Successfully fetched product with ID: {product_id}")
            return jsonify(product), 200
        else:
            current_app.logger.info(f"Product with ID: {product_id} not found.")
            return jsonify({"message": "Product not found"}), 404
    except Exception as e:
        current_app.logger.error(f"Error fetching product {product_id}: {e}", exc_info=True)
        return jsonify({"message": f"Error fetching product {product_id}", "error": str(e)}), 500


# app/routes.py
# ... (imports and other routes) ...

@main_bp.route('/products', methods=['POST'])
@token_required
def admin_add_product(decoded_token_data):
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Product add attempt by admin: {admin_username} to /products")
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "Request body must be JSON"}), 400

        # UPDATED required_fields
        required_fields = ["name", "price", "mainCategory", "subCategory", "weight", "makingCharges"]
        # Karat is now conditionally required based on mainCategory, handle this logic

        for field in required_fields:
            if field not in data or data[field] is None:
                # Special check for Karat if mainCategory is Gold
                if field == "karat" and data.get("mainCategory") == "Gold":
                     return jsonify({"message": f"Missing or null required field: {field} for Gold product"}), 400
                elif field != "karat": # For other required fields
                    return jsonify({"message": f"Missing or null required field: {field}"}), 400


        # Basic Validations
        if not isinstance(data["name"], str) or not data["name"].strip():
            return jsonify({"message": "Product name must be a non-empty string"}), 400
        if not isinstance(data.get("mainCategory"), str) or not data.get("mainCategory").strip(): # NEW
            return jsonify({"message": "Main category must be a non-empty string"}), 400
        if not isinstance(data.get("subCategory"), str) or not data.get("subCategory").strip():   # NEW
            return jsonify({"message": "Sub-category must be a non-empty string"}), 400

        try:
            price = float(data["price"])
            making_charges = float(data["makingCharges"])
            weight = float(data["weight"])
            if price < 0 or making_charges < 0 or weight <= 0:
                 return jsonify({"message": "Price & making charges must be non-negative, weight must be positive"}), 400
        except (ValueError, TypeError):
            return jsonify({"message": "Price, weight, and makingCharges must be valid numbers"}), 400

        karat_value = data.get("karat")
        if data.get("mainCategory") == "Gold":
            if not karat_value or not isinstance(karat_value, str) or not karat_value.strip():
                return jsonify({"message": "Karat is required and must be a non-empty string for Gold products"}), 400
        else: # For Silver or other main categories, Karat might be optional or null
            karat_value = None


        new_product = {
            "name": data["name"].strip(),
            "price": price,
            "mainCategory": data["mainCategory"].strip(), # NEW
            "subCategory": data["subCategory"].strip(),   # NEW
            "description": str(data.get("description", "")).strip(),
            "imageUrl": data.get("imageUrl"),
            "weight": weight,
            "karat": karat_value, # Use validated/processed karat_value
            "makingCharges": making_charges,
            "addedBy": admin_username,
            "addedDate": datetime.datetime.utcnow(),
            "lastUpdatedDate": datetime.datetime.utcnow(),
            "lastUpdatedBy": admin_username
        }

        result = mongo.db.products.insert_one(new_product)
        inserted_product = mongo.db.products.find_one({"_id": result.inserted_id})
        if inserted_product:
            inserted_product['_id'] = str(inserted_product['_id'])
            if 'addedDate' in inserted_product: # no need to check type, will be datetime from DB
                inserted_product['addedDate'] = to_iso_z(inserted_product['addedDate'])
            if 'lastUpdatedDate' in inserted_product:
                inserted_product['lastUpdatedDate'] = to_iso_z(inserted_product['lastUpdatedDate'])
            current_app.logger.info(f"Admin {admin_username} successfully added product: {inserted_product['name']} (ID: {inserted_product['_id']})")
            return jsonify({"message": "Product added successfully", "product": inserted_product}), 201
        else:
            current_app.logger.error(f"Admin {admin_username} added product but failed to retrieve it. ID: {result.inserted_id}")
            return jsonify({"message": "Product added but failed to retrieve confirmation."}), 207

    except Exception as e:
        current_app.logger.error(f"Error adding product by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred", "error": str(e)}), 500


@main_bp.route('/products/<string:mongo_id>', methods=['PUT'])
@token_required
def admin_update_product(decoded_token_data, mongo_id):
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Product update: ID {mongo_id} by admin: {admin_username}")
    try:
        try:
            db_id = ObjectId(mongo_id)
        except InvalidId:
            return jsonify({"message": "Invalid product MongoDB ID format"}), 400

        data = request.get_json()
        if not data:
            return jsonify({"message": "Request body must be JSON and non-empty"}), 400

        update_fields = {}
        allowed_fields_types = {
            "name": str, "price": float, "description": str,
            "mainCategory": str, "subCategory": str, # NEW
            "imageUrl": str, "weight": float, "karat": str, "makingCharges": float
        }

        # Handle Karat specifically based on mainCategory
        new_main_category = data.get("mainCategory")
        current_product_for_main_cat_check = None # To check current mainCategory if not updating mainCategory

        if "karat" in data:
            karat_value = data.get("karat")
            # If mainCategory is being updated to Gold, or is already Gold and not being changed
            if new_main_category == "Gold":
                if not karat_value or not isinstance(karat_value, str) or not karat_value.strip():
                    return jsonify({"message": "Karat is required and must be non-empty for Gold products"}), 400
                update_fields["karat"] = karat_value.strip()
            elif new_main_category == "Silver": # Or any other non-gold category
                 update_fields["karat"] = None # Explicitly set Karat to null if metal changes from Gold
            else: # mainCategory is not in payload, check existing product's mainCategory
                if not current_product_for_main_cat_check:
                    current_product_for_main_cat_check = mongo.db.products.find_one({"_id": db_id})
                if current_product_for_main_cat_check and current_product_for_main_cat_check.get("mainCategory") == "Gold":
                    if not karat_value or not isinstance(karat_value, str) or not karat_value.strip():
                         return jsonify({"message": "Karat is required and must be non-empty for Gold products"}), 400
                    update_fields["karat"] = karat_value.strip()
                else: # Existing is not Gold, and mainCategory not changed to Gold
                    update_fields["karat"] = None # Set to null if current is not Gold

        # If mainCategory itself is being updated to non-Gold, ensure Karat is nulled
        if new_main_category and new_main_category != "Gold" and "karat" not in update_fields : # "karat" not in update_fields means it wasn't explicitly set to None above
            update_fields["karat"] = None


        for field, field_type in allowed_fields_types.items():
            if field == "karat": continue # Handled above

            if field in data:
                value = data[field]
                if field == "name" and (not isinstance(value, str) or not value.strip()):
                    return jsonify({"message": "Product name must be a non-empty string"}), 400
                if field in ["mainCategory", "subCategory"] and (not isinstance(value, str) or not value.strip()): # NEW
                    return jsonify({"message": f"{field.capitalize()} must be a non-empty string"}), 400
                if field in ["price", "makingCharges"] and isinstance(value, (int, float)) and value < 0:
                    return jsonify({"message": f"{field.capitalize()} must be non-negative"}), 400
                if field == "weight" and isinstance(value, (int, float)) and value <= 0:
                    return jsonify({"message": "Weight must be positive"}), 400

                if field_type == float:
                    try: update_fields[field] = float(value)
                    except (ValueError, TypeError): return jsonify({"message": f"{field.capitalize()} must be a valid number"}), 400
                elif field_type == str:
                    update_fields[field] = str(value).strip() if field in ["name", "description", "mainCategory", "subCategory"] else str(value)
                # No 'int' type in your allowed_fields_types for now

        if not update_fields:
            return jsonify({"message": "No valid update fields provided or no changes detected"}), 400

        update_fields["lastUpdatedDate"] = datetime.datetime.utcnow()
        update_fields["lastUpdatedBy"] = admin_username

        result = mongo.db.products.update_one({"_id": db_id}, {"$set": update_fields})

        if result.matched_count == 0:
            return jsonify({"message": "Product not found"}), 404

        updated_product_doc = mongo.db.products.find_one({"_id": db_id})
        if not updated_product_doc:
            return jsonify({"message": "Error retrieving product after update"}), 500

        updated_product_doc['_id'] = str(updated_product_doc['_id'])
        if 'addedDate' in updated_product_doc:
            updated_product_doc['addedDate'] = to_iso_z(updated_product_doc['addedDate'])
        if 'lastUpdatedDate' in updated_product_doc:
            updated_product_doc['lastUpdatedDate'] = to_iso_z(updated_product_doc['lastUpdatedDate'])

        current_app.logger.info(f"Admin {admin_username} product update for {mongo_id}: modified_count={result.modified_count}")
        return jsonify({"message": "Product updated successfully", "product": updated_product_doc}), 200

    except Exception as e:
        current_app.logger.error(f"Error updating product {mongo_id} by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred", "error": str(e)}), 500

# ... (rest of your routes.py)

@main_bp.route('/products/<string:mongo_id>', methods=['DELETE'])
@token_required
def admin_delete_product(decoded_token_data, mongo_id):
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Product delete attempt for MongoDB ID {mongo_id} by admin: {admin_username}")

    try:
        try:
            db_id = ObjectId(mongo_id)
        except InvalidId:
            current_app.logger.warning(f"Admin {admin_username} product delete attempt with invalid MongoDB ID format: {mongo_id}")
            return jsonify({"message": "Invalid product MongoDB ID format"}), 400

        # Optional: Check if the product is referenced elsewhere before deleting (e.g., in orders)
        # This is a more advanced check and depends on your application's data integrity rules.
        # For now, we'll proceed with a direct delete.

        result = mongo.db.products.delete_one({"_id": db_id})

        if result.deleted_count == 0:
            current_app.logger.warning(f"Admin {admin_username} failed to delete non-existent product MongoDB ID: {mongo_id}")
            return jsonify({"message": "Product not found"}), 404
        else:
            current_app.logger.info(f"Admin {admin_username} successfully deleted product MongoDB ID: {mongo_id}")
            return jsonify({"message": "Product deleted successfully"}), 200 # Standard success
            # Alternatively, you could return 204 No Content:
            # return "", 204

    except Exception as e:
        current_app.logger.error(f"Error deleting product MongoDB ID {mongo_id} by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred while deleting the product", "error": str(e)}), 500

# MAKE SURE THIS NEW CODE IS PLACED *AFTER* admin_update_product
# AND *BEFORE* YOUR # --- Admin Login Route --- SECTION (if it comes next)
# OR ANY OTHER ROUTE DEFINITIONS.
# --- Bank Details Routes ---
@main_bp.route('/settings/bank-details', methods=['GET'])
# @token_required # Decided to make GET public, but admin required for PUT.
def get_bank_details(): # removed decoded_token_data as it's public
    current_app.logger.info(f"Attempting to fetch bank details (public endpoint).")
    try:
        settings_collection = mongo.db.app_settings
        bank_details_filter = {"config_type": "bank_details"}
        bank_details_doc = settings_collection.find_one(bank_details_filter)

        if bank_details_doc:
            bank_details_doc['_id'] = str(bank_details_doc['_id'])
            bank_details_doc['lastUpdated'] = to_iso_z(bank_details_doc.get('lastUpdated'))
            bank_details_doc['createdAt'] = to_iso_z(bank_details_doc.get('createdAt'))
            # Exclude fields like 'lastUpdatedBy', 'createdBy' from public GET response if desired
            # for key_to_remove in ['lastUpdatedBy', 'createdBy']:
            #     bank_details_doc.pop(key_to_remove, None)
            current_app.logger.info(f"Successfully fetched bank details.")
            return jsonify(bank_details_doc), 200
        else:
            current_app.logger.info(f"No bank details found in the database.")
            # Return a default structure indicating details are not set
            return jsonify({
                "config_type": "bank_details",
                "accountHolderName": None,
                "accountNumber": None,
                "ifscCode": None,
                "bankName": None,
                "branchName": None,
                "qrCodeImageUrl": None,
                "contactWhatsAppNumber": None,
                "lastUpdated": None,
                "createdAt": None,
                "message": "Bank details not configured yet."
            }), 200 # Return 200 with message, not 404, as it's a config state
    except Exception as e:
        current_app.logger.error(f"Error fetching bank details: {e}", exc_info=True)
        return jsonify({"message": "Error fetching bank details from database", "error": str(e)}), 500

@main_bp.route('/settings/bank-details', methods=['PUT'])
@token_required
def update_bank_details(decoded_token_data):
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Admin {admin_username} attempting to update/create bank details.")
    try:
        data = request.get_json()
        if not data:
            current_app.logger.warning(f"Admin {admin_username} attempt to update bank details with no JSON data.")
            return jsonify({"message": "Request body must be JSON"}), 400

        settings_collection = mongo.db.app_settings
        bank_details_filter = {"config_type": "bank_details"}

        payload_to_save = {}
        # Define fields and whether they are strictly required (must be non-empty string)
        # For optional fields, allow None or empty string to clear them.
        field_definitions = {
            "accountHolderName": {"required": True, "type": str},
            "accountNumber": {"required": True, "type": str},
            "ifscCode": {"required": True, "type": str},
            "bankName": {"required": True, "type": str},
            "branchName": {"required": True, "type": str}, # Changed to True based on previous context
            "qrCodeImageUrl": {"required": False, "type": str}, # Can be null or empty string
            "contactWhatsAppNumber": {"required": False, "type": str} # Can be null or empty string
        }

        for field, props in field_definitions.items():
            value = data.get(field)
            if props["required"]:
                if value is None or (props["type"] == str and not str(value).strip()):
                    msg = f"Missing or empty required field: {field}"
                    current_app.logger.warning(f"Admin {admin_username} bank details update: {msg}")
                    return jsonify({"message": msg}), 400
                payload_to_save[field] = str(value).strip() if props["type"] == str else value
            elif field in data: # Optional field, but present in request
                if value is None:
                    payload_to_save[field] = None # Explicitly set to null if provided as null
                elif props["type"] == str:
                    payload_to_save[field] = str(value).strip() # Strip if string, even if optional
                else: # For future non-string optional fields
                    payload_to_save[field] = value
            # If an optional field is not in data, it's not included in payload_to_save,
            # so it won't be $set to null unintentionally unless explicitly provided as null.

        if not payload_to_save:
            current_app.logger.info(f"Admin {admin_username} bank details update: No valid fields provided for update.")
            # Fetch current state to return if no actual changes
            current_details = settings_collection.find_one(bank_details_filter)
            if current_details:
                current_details['_id'] = str(current_details['_id'])
                current_details['lastUpdated'] = to_iso_z(current_details.get('lastUpdated'))
                current_details['createdAt'] = to_iso_z(current_details.get('createdAt'))
                return jsonify({"message": "No valid fields provided for update.", "bankDetails": current_details}), 200
            else: # No details exist and no fields provided
                return jsonify({"message": "No bank details exist and no fields provided to create them."}), 400


        payload_to_save["lastUpdatedBy"] = admin_username
        payload_to_save["lastUpdated"] = datetime.datetime.utcnow()

        # Using update_one with upsert=True will create if not exists, update if exists
        result = settings_collection.update_one(
            bank_details_filter,
            {
                "$set": payload_to_save,
                "$setOnInsert": { # These fields are only set when a new document is created
                    "config_type": "bank_details",
                    "createdAt": datetime.datetime.utcnow(),
                    "createdBy": admin_username
                }
            },
            upsert=True
        )

        # Fetch the document after operation to return the complete, current state
        updated_bank_details_doc = settings_collection.find_one(bank_details_filter)
        if not updated_bank_details_doc:
            current_app.logger.critical(f"Admin {admin_username} bank details upsert operation status unclear: Document not found after upsert.")
            return jsonify({"message": "Bank details operation status unclear, please verify."}), 500

        updated_bank_details_doc['_id'] = str(updated_bank_details_doc['_id'])
        updated_bank_details_doc['lastUpdated'] = to_iso_z(updated_bank_details_doc.get('lastUpdated'))
        updated_bank_details_doc['createdAt'] = to_iso_z(updated_bank_details_doc.get('createdAt'))

        if result.upserted_id is not None:
            current_app.logger.info(f"Admin {admin_username} successfully created new bank details. MongoDB ID: {result.upserted_id}")
            return jsonify({"message": "Bank details created successfully", "bankDetails": updated_bank_details_doc}), 201
        elif result.modified_count > 0:
            current_app.logger.info(f"Admin {admin_username} successfully updated existing bank details.")
            return jsonify({"message": "Bank details updated successfully", "bankDetails": updated_bank_details_doc}), 200
        elif result.matched_count > 0: # Matched but no modification (data was the same)
            current_app.logger.info(f"Admin {admin_username} bank details update: No changes made (data might be same as existing).")
            return jsonify({"message": "Bank details found but no changes were made", "bankDetails": updated_bank_details_doc}), 200
        else:
             # This case should ideally not be reached if upsert=True and logic is correct.
             # It implies no match, no modification, and no upsert ID, which is strange.
             current_app.logger.error(f"Admin {admin_username} bank details update logic error: No match, no modification, no upsert ID, but document found post-op. This is unexpected.")
             return jsonify({"message": "Error processing bank details update. State is inconsistent."}), 500

    except Exception as e:
        current_app.logger.error(f"Error updating bank details by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred while updating bank details", "error": str(e)}), 500

# app/routes.py
# ... (all your existing imports and code up to the end of Bank Details or Coin routes) ...

# --- Making Charges Setting Routes ---
@main_bp.route('/settings/making-charges', methods=['GET'])
def get_making_charges_percentage():
    current_app.logger.info("Attempting to fetch making charges percentage.")
    try:
        settings_collection = mongo.db.app_settings
        making_charges_doc = settings_collection.find_one({"config_type": "making_charges"})

        if making_charges_doc:
            response_data = {
                "percentage": making_charges_doc.get("percentage"),
                "lastUpdated": to_iso_z(making_charges_doc.get("lastUpdated"))
            }
            current_app.logger.info(f"Successfully fetched making charges: {response_data.get('percentage')}%")
            return jsonify(response_data), 200
        else:
            current_app.logger.warning("Making charges configuration not found. Returning default or error.")
            # Decide: return a default, or an error if it MUST exist.
            # For calculator, a default might be okay, but admin needs to set it.
            return jsonify({"message": "Making charges not configured.", "percentage": 10.0, "lastUpdated": None}), 200 # Default 10%
    except Exception as e:
        current_app.logger.error(f"Error fetching making charges percentage: {e}", exc_info=True)
        return jsonify({"message": "Error fetching making charges", "error": str(e)}), 500

@main_bp.route('/admin/settings/making-charges', methods=['PUT'])
@token_required
def admin_update_making_charges_percentage(decoded_token_data):
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Admin {admin_username} attempting to update making charges percentage.")
    try:
        data = request.get_json()
        if not data or 'percentage' not in data:
            current_app.logger.warning(f"Admin {admin_username} making charges update: Missing 'percentage' in JSON data.")
            return jsonify({"message": "Request body must be JSON and include 'percentage'"}), 400

        try:
            new_percentage = float(data['percentage'])
            if not (0 <= new_percentage <= 100): # Assuming percentage is between 0 and 100
                current_app.logger.warning(f"Admin {admin_username} making charges update: Invalid percentage value {new_percentage}.")
                return jsonify({"message": "Percentage must be a valid number between 0 and 100."}), 400
        except ValueError:
            current_app.logger.warning(f"Admin {admin_username} making charges update: Percentage not a valid number.")
            return jsonify({"message": "Percentage must be a valid number."}), 400

        settings_collection = mongo.db.app_settings
        config_filter = {"config_type": "making_charges"}

        update_payload = {
            "percentage": new_percentage,
            "lastUpdated": datetime.datetime.utcnow(),
            "lastUpdatedBy": admin_username
        }

        result = settings_collection.update_one(
            config_filter,
            {
                "$set": update_payload,
                "$setOnInsert": { # If it doesn't exist for some reason, create it
                    "config_type": "making_charges",
                    "createdBy": admin_username # If you track creation
                }
            },
            upsert=True # Create the document if it doesn't exist
        )

        # Fetch the updated document to confirm
        updated_doc = settings_collection.find_one(config_filter)
        if not updated_doc:
             current_app.logger.error(f"Admin {admin_username} making charges update: Failed to retrieve document after upsert.")
             return jsonify({"message": "Error confirming update."}), 500


        response_data = {
            "percentage": updated_doc.get("percentage"),
            "lastUpdated": to_iso_z(updated_doc.get("lastUpdated"))
        }

        if result.upserted_id:
            current_app.logger.info(f"Admin {admin_username} successfully created making charges setting: {new_percentage}%.")
            return jsonify({"message": "Making charges setting created successfully.", "data": response_data}), 201
        elif result.modified_count > 0:
            current_app.logger.info(f"Admin {admin_username} successfully updated making charges percentage to {new_percentage}%.")
            return jsonify({"message": "Making charges percentage updated successfully.", "data": response_data}), 200
        elif result.matched_count > 0 : # Matched but no change
             current_app.logger.info(f"Admin {admin_username} making charges update: No change to percentage value ({new_percentage}%).")
             return jsonify({"message": "Making charges percentage was not changed.", "data": response_data}), 200
        else:
            # Should not happen with upsert=True if find_one worked
            current_app.logger.error(f"Admin {admin_username} making charges update: Unexpected result from update_one.")
            return jsonify({"message": "An unexpected error occurred during update."}), 500

    except Exception as e:
        current_app.logger.error(f"Error updating making charges by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred", "error": str(e)}), 500

# --- (Your existing Admin Login Route, Metal Purity Rate Routes, Coin Price Routes, etc., follow here) ---
# @main_bp.route('/admin/login', methods=['POST'])
# def admin_login():
# ... and so on
# app/routes.py
# ... (all your existing imports and code) ...

# --- Slider Images Routes ---

@main_bp.route('/slider-images', methods=['GET'])
def get_slider_images():
    """
    Fetches all active slider images.
    Publicly accessible.
    """
    try:
        slider_images_collection = mongo.db.slider_images
        # Optionally sort by upload date if you add an 'order' field or by 'uploadedAt'
        images_cursor = slider_images_collection.find({}).sort("uploadedAt", -1) # Sort by newest first
        images_list = []
        for img_doc in images_cursor:
            img_doc['_id'] = str(img_doc['_id'])
            if 'uploadedAt' in img_doc and isinstance(img_doc['uploadedAt'], datetime.datetime):
                img_doc['uploadedAt'] = to_iso_z(img_doc['uploadedAt'])
            images_list.append(img_doc)
        current_app.logger.info(f"Successfully fetched {len(images_list)} slider images.")
        return jsonify(images_list), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching slider images: {e}", exc_info=True)
        return jsonify({"message": "Error fetching slider images", "error": str(e)}), 500

@main_bp.route('/admin/slider-images', methods=['POST'])
@token_required
def admin_add_slider_image(decoded_token_data):
    """
    Adds a new slider image URL.
    Expects JSON: {"imageUrl": "http://..."}
    """
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Admin {admin_username} attempting to add slider image.")
    try:
        data = request.get_json()
        if not data or not data.get('imageUrl'):
            current_app.logger.warning(f"Admin {admin_username} slider image add: Missing 'imageUrl'.")
            return jsonify({"message": "imageUrl is required"}), 400

        image_url = data.get('imageUrl')
        # Basic validation for URL (you might want a more robust one)
        if not image_url.startswith(('http://', 'https://')):
            current_app.logger.warning(f"Admin {admin_username} slider image add: Invalid URL format for '{image_url}'.")
            return jsonify({"message": "Invalid imageUrl format"}), 400

        slider_images_collection = mongo.db.slider_images

        # Optional: Check for duplicates if necessary, though multiple uses of same URL might be fine.
        # existing_image = slider_images_collection.find_one({"imageUrl": image_url})
        # if existing_image:
        #     return jsonify({"message": "This image URL already exists in the slider."}), 409

        new_slider_image = {
            "imageUrl": image_url,
            "uploadedAt": datetime.datetime.utcnow(),
            "uploadedBy": admin_username,
            # You could add an 'order' field here if you want manual sorting
        }
        result = slider_images_collection.insert_one(new_slider_image)

        # Fetch the inserted document to return it with its ID
        inserted_doc = slider_images_collection.find_one({"_id": result.inserted_id})
        if inserted_doc:
            inserted_doc['_id'] = str(inserted_doc['_id'])
            if 'uploadedAt' in inserted_doc and isinstance(inserted_doc['uploadedAt'], datetime.datetime):
                inserted_doc['uploadedAt'] = to_iso_z(inserted_doc['uploadedAt'])
            current_app.logger.info(f"Admin {admin_username} successfully added slider image: {image_url}")
            return jsonify({"message": "Slider image added successfully", "sliderImage": inserted_doc}), 201
        else:
            current_app.logger.error(f"Admin {admin_username} added slider image but failed to retrieve it. URL: {image_url}")
            return jsonify({"message": "Slider image added but failed to retrieve confirmation."}), 207

    except Exception as e:
        current_app.logger.error(f"Error adding slider image by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred", "error": str(e)}), 500

@main_bp.route('/admin/slider-images/<string:image_id>', methods=['DELETE'])
@token_required
def admin_delete_slider_image(decoded_token_data, image_id):
    """
    Deletes a slider image by its MongoDB ObjectId.
    """
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Admin {admin_username} attempting to delete slider image ID: {image_id}")
    try:
        try:
            db_id = ObjectId(image_id)
        except InvalidId:
            current_app.logger.warning(f"Admin {admin_username} slider image delete: Invalid ID format {image_id}.")
            return jsonify({"message": "Invalid slider image ID format"}), 400

        slider_images_collection = mongo.db.slider_images
        result = slider_images_collection.delete_one({"_id": db_id})

        if result.deleted_count == 0:
            current_app.logger.warning(f"Admin {admin_username} slider image delete: Image ID {image_id} not found.")
            return jsonify({"message": "Slider image not found"}), 404
        else:
            current_app.logger.info(f"Admin {admin_username} successfully deleted slider image ID: {image_id}")
            # Note: This doesn't delete the image from Cloudinary itself, only the reference from the database.
            # Actual Cloudinary deletion would require their API and is more complex.
            return jsonify({"message": "Slider image deleted successfully"}), 200 # Or 204 No Content

    except Exception as e:
        current_app.logger.error(f"Error deleting slider image ID {image_id} by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred", "error": str(e)}), 500
# app/routes.py
# Paste this in the same place you put the new routes before

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +++ CORRECTED: CONTACT INFO & SOCIAL LINKS ROUTES +++++++++++
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

@main_bp.route('/contact-info', methods=['GET'])
def get_contact_info():
    """
    Fetches the main contact info document.
    This is public so the app can get the numbers.
    """
    current_app.logger.info("Fetching public contact information.")
    try:
        # --- FIX: Use current_app.db instead of mongo.db ---
        settings_collection = current_app.db.app_settings
        contact_doc = settings_collection.find_one({"config_type": "contact_info"})

        if contact_doc:
            response_data = {
                "phone_number": contact_doc.get("phone_number"),
                "whatsapp_number": contact_doc.get("whatsapp_number"),
                "whatsapp_text": contact_doc.get("whatsapp_text"),
                "instagram_url": contact_doc.get("instagram_url"),
                "lastUpdated": to_iso_z(contact_doc.get("lastUpdated"))
            }
            return jsonify(response_data), 200
        else:
            current_app.logger.warning("Contact info not found in database.")
            return jsonify({"message": "Contact info has not been configured yet."}), 404

    except Exception as e:
        current_app.logger.error(f"Error fetching contact info: {e}", exc_info=True)
        return jsonify({"message": "Error fetching contact info", "error": str(e)}), 500

@main_bp.route('/admin/contact-info', methods=['PUT'])
@token_required
def admin_update_contact_info(decoded_token_data):
    """
    Admin endpoint to create or update the contact info.
    Protected by token authentication.
    """
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Admin {admin_username} attempting to update contact info.")
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "Request body must be JSON"}), 400

        # --- FIX: Use current_app.db instead of mongo.db ---
        settings_collection = current_app.db.app_settings
        config_filter = {"config_type": "contact_info"}

        update_payload = {}
        fields_to_update = ["phone_number", "whatsapp_number", "whatsapp_text", "instagram_url"]
        for field in fields_to_update:
            if field in data and isinstance(data[field], str):
                update_payload[field] = data[field].strip()

        if not update_payload:
            return jsonify({"message": "No valid fields provided for update"}), 400

        update_payload["lastUpdated"] = datetime.datetime.utcnow()
        update_payload["lastUpdatedBy"] = admin_username

        result = settings_collection.update_one(
            config_filter,
            {
                "$set": update_payload,
                "$setOnInsert": { "config_type": "contact_info", "createdAt": datetime.datetime.utcnow() }
            },
            upsert=True
        )

        updated_doc = settings_collection.find_one(config_filter)
        updated_doc['_id'] = str(updated_doc['_id'])
        updated_doc['lastUpdated'] = to_iso_z(updated_doc.get('lastUpdated'))

        message = "Contact info updated successfully."
        if result.upserted_id:
            message = "Contact info created successfully."

        current_app.logger.info(f"Admin {admin_username}: {message}")
        return jsonify({"message": message, "contactInfo": updated_doc}), 200

    except Exception as e:
        current_app.logger.error(f"Error updating contact info by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred", "error": str(e)}), 500

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +++ END: CORRECTED ROUTES +++++++++++++++++++++++++++++++++++
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# --- (Your existing Admin Login Route, Product Routes, etc., should follow or precede) ---
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +++ NEW: HOME SCREEN VIDEO ROUTES +++++++++++++++++++++++++++
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

@main_bp.route('/home-video-details', methods=['GET'])
def get_home_video_details():
    """
    Fetches the currently active home screen video details.
    Publicly accessible.
    """
    current_app.logger.info("Attempting to fetch home screen video details.")
    try:
        settings_collection = mongo.db.app_settings
        # Assuming a single document stores this config, identified by 'config_type'
        video_config_doc = settings_collection.find_one({"config_type": "home_video"})

        if video_config_doc and video_config_doc.get("videoUrl"):
            # Ensure videoUrl is not empty or just whitespace
            video_url = video_config_doc.get("videoUrl")
            if isinstance(video_url, str) and video_url.strip():
                response_data = {
                    "title": video_config_doc.get("title"), # Can be None or empty
                    "videoUrl": video_url.strip(),
                    "lastUpdated": to_iso_z(video_config_doc.get("lastUpdated"))
                }
                current_app.logger.info(f"Successfully fetched home video details: Title '{response_data.get('title')}'")
                return jsonify(response_data), 200
            else:
                current_app.logger.info("Home video configuration found, but videoUrl is empty or invalid.")
                return jsonify({"message": "Home video URL is not properly configured."}), 404
        else:
            current_app.logger.info("No active home video configuration found or videoUrl is missing.")
            return jsonify({"message": "No home video is currently configured."}), 404
    except Exception as e:
        current_app.logger.error(f"Error fetching home video details: {e}", exc_info=True)
        return jsonify({"message": "Error fetching home video details", "error": str(e)}), 500

@main_bp.route('/admin/home-video', methods=['POST'])
@token_required
def admin_set_or_update_home_video(decoded_token_data): # Renamed for clarity (create/update)
    """
    Sets or updates the home screen video details.
    Uses upsert: creates the config if it doesn't exist, updates it if it does.
    Expects JSON: {"title": "Optional Video Title", "videoUrl": "https://..."}
    """
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Admin {admin_username} attempting to set/update home screen video.")
    try:
        data = request.get_json()
        if not data:
            current_app.logger.warning(f"Admin {admin_username} home video set/update: No JSON data.")
            return jsonify({"message": "Request body must be JSON"}), 400

        video_url_from_req = data.get('videoUrl')
        title_from_req = data.get('title', "") # Title is optional, defaults to empty string

        if not video_url_from_req: # video_url is essential
            current_app.logger.warning(f"Admin {admin_username} home video set/update: Missing 'videoUrl'.")
            return jsonify({"message": "videoUrl is required"}), 400

        if not isinstance(video_url_from_req, str) or not video_url_from_req.strip().startswith(('http://', 'https://')):
            current_app.logger.warning(f"Admin {admin_username} home video set/update: Invalid URL format for '{video_url_from_req}'.")
            return jsonify({"message": "Invalid videoUrl format. Must be a valid HTTP/HTTPS URL."}), 400

        if not isinstance(title_from_req, str):
             current_app.logger.warning(f"Admin {admin_username} home video set/update: Invalid title format.")
             return jsonify({"message": "Title must be a string."}), 400

        settings_collection = mongo.db.app_settings
        config_filter = {"config_type": "home_video"}

        update_payload = {
            "title": title_from_req.strip(),
            "videoUrl": video_url_from_req.strip(),
            "lastUpdated": datetime.datetime.utcnow(),
            "lastUpdatedBy": admin_username
        }

        result = settings_collection.update_one(
            config_filter,
            {
                "$set": update_payload,
                "$setOnInsert": {
                    "config_type": "home_video",
                    "createdAt": datetime.datetime.utcnow(),
                    "createdBy": admin_username
                }
            },
            upsert=True
        )

        updated_config_doc = settings_collection.find_one(config_filter)
        if not updated_config_doc:
            current_app.logger.error(f"Admin {admin_username} home video set/update: Failed to retrieve document after upsert for video URL '{video_url_from_req}'.")
            return jsonify({"message": "Error confirming home video update."}), 500

        updated_config_doc['_id'] = str(updated_config_doc['_id'])
        updated_config_doc['lastUpdated'] = to_iso_z(updated_config_doc.get('lastUpdated'))
        if 'createdAt' in updated_config_doc: # Only present if newly created
            updated_config_doc['createdAt'] = to_iso_z(updated_config_doc.get('createdAt'))

        if result.upserted_id:
            current_app.logger.info(f"Admin {admin_username} successfully set new home video: URL '{video_url_from_req}'.")
            return jsonify({"message": "Home video set successfully.", "videoDetails": updated_config_doc}), 201
        elif result.modified_count > 0:
            current_app.logger.info(f"Admin {admin_username} successfully updated home video to URL '{video_url_from_req}'.")
            return jsonify({"message": "Home video updated successfully.", "videoDetails": updated_config_doc}), 200
        elif result.matched_count > 0 :
            current_app.logger.info(f"Admin {admin_username} home video set/update: No change to video details (URL '{video_url_from_req}').")
            return jsonify({"message": "Home video details were not changed.", "videoDetails": updated_config_doc}), 200
        else:
            current_app.logger.error(f"Admin {admin_username} home video set/update: Unexpected database result for URL '{video_url_from_req}'.")
            return jsonify({"message": "An unexpected error occurred during home video update."}), 500

    except Exception as e:
        current_app.logger.error(f"Error setting/updating home video by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred", "error": str(e)}), 500

@main_bp.route('/admin/home-video', methods=['DELETE'])
@token_required
def admin_clear_home_video(decoded_token_data):
    """
    Clears the home screen video configuration by setting videoUrl and title to None.
    """
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Admin {admin_username} attempting to clear home screen video.")
    try:
        settings_collection = mongo.db.app_settings
        config_filter = {"config_type": "home_video"}

        update_payload = {
            "title": None,
            "videoUrl": None, # Set to null to indicate no video
            "lastUpdated": datetime.datetime.utcnow(),
            "lastUpdatedBy": admin_username
        }
        result = settings_collection.update_one(
            config_filter,
            {"$set": update_payload}
            # No $setOnInsert here as we only update if it exists; if not, it's already "cleared"
        )

        if result.matched_count > 0:
            if result.modified_count > 0:
                current_app.logger.info(f"Admin {admin_username} successfully cleared home video URL and title.")
                # Fetch and return the cleared state
                cleared_doc = settings_collection.find_one(config_filter)
                if cleared_doc:
                    cleared_doc['_id'] = str(cleared_doc['_id'])
                    cleared_doc['lastUpdated'] = to_iso_z(cleared_doc.get('lastUpdated'))
                    if 'createdAt' in cleared_doc: cleared_doc['createdAt'] = to_iso_z(cleared_doc.get('createdAt'))
                    return jsonify({"message": "Home video cleared successfully.", "videoDetails": cleared_doc}), 200
                else: # Should not happen if matched_count > 0
                    return jsonify({"message": "Home video cleared, but error fetching confirmation."}), 200

            else: # Matched but not modified (already cleared)
                current_app.logger.info(f"Admin {admin_username} clear home video: Video was already cleared or not set with a URL.")
                return jsonify({"message": "Home video was already cleared or had no URL set."}), 200
        else: # No document with config_type: "home_video" found
            current_app.logger.info(f"Admin {admin_username} clear home video: No configuration document found to clear.")
            return jsonify({"message": "No home video configuration was set to clear."}), 200 # It's effectively cleared

    except Exception as e:
        current_app.logger.error(f"Error clearing home video by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred while clearing home video", "error": str(e)}), 500

# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# +++ END: HOME SCREEN VIDEO ROUTES +++++++++++++++++++++++++++
# +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++



# --- Admin Login Route ---
@main_bp.route('/admin/login', methods=['POST'])
def admin_login():
    try:
        data = request.get_json()
        if not data:
            current_app.logger.warning("Admin login attempt with no JSON data in request body.")
            return jsonify({"message": "Request body must be JSON"}), 400

        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            current_app.logger.warning(f"Admin login attempt with missing username or password. Username provided: '{username}'")
            return jsonify({"message": "Username and password are required"}), 400

        admin_user = mongo.db.admins.find_one({"username": username})

        if not admin_user:
            current_app.logger.warning(f"Admin login attempt for non-existent user: {username}")
            return jsonify({"message": "Invalid username or password"}), 401 # Changed from 404 to 401 for security

        if check_password_hash(str(admin_user.get('password')), password): # Ensure admin_user['password'] is a string
            secret_key_from_config = current_app.config.get('SECRET_KEY')

            if current_app.debug:
                 key_preview = str(secret_key_from_config)[:5] if secret_key_from_config else "None"
                 current_app.logger.debug(f"Admin Login - SECRET_KEY for JWT (first 5 chars): {key_preview}...")
                 current_app.logger.debug(f"Admin Login - SECRET_KEY type: {type(secret_key_from_config)}")

            if not secret_key_from_config or secret_key_from_config == 'default-fallback-secret-key-SHOULD-BE-IN-DOTENV':
                current_app.logger.error("CRITICAL SECURITY RISK (Admin Login): SECRET_KEY is not configured properly or is using the insecure default fallback!")
                return jsonify({"message": "Server configuration error: Security key is missing or is the default fallback."}), 500

            if not isinstance(secret_key_from_config, (str, bytes)):
                current_app.logger.error(f"CRITICAL (Admin Login): SECRET_KEY is not a string or bytes. Type: {type(secret_key_from_config)}")
                return jsonify({"message": "Server configuration error: Security key type invalid."}), 500

            token_payload = {
                'user_id': str(admin_user.get('_id')),
                'username': admin_user.get('username'),
                'role': 'admin', # Assuming admin users have a 'role' field or it's implied
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=current_app.config.get('JWT_EXPIRATION_HOURS', 24)) # Default 24h
            }

            try:
                current_app.logger.info(f"Admin Login: Attempting to encode JWT with payload: {token_payload}")
                token = jwt.encode(token_payload, secret_key_from_config, algorithm="HS256")
                current_app.logger.info(f"Admin user '{username}' logged in successfully. Token generated.")
                return jsonify({"message": "Login successful", "token": token}), 200
            except Exception as e:
                current_app.logger.error(f"Error during JWT encoding (Admin Login - jwt.encode call): {e}", exc_info=True)
                return jsonify({"message": "Could not generate authentication token due to an encoding error."}), 500
        else:
            current_app.logger.warning(f"Failed login attempt for admin user: {username}. Password check failed.")
            return jsonify({"message": "Invalid username or password"}), 401

    except Exception as e:
        current_app.logger.error(f"An unexpected error occurred during admin login: {e}", exc_info=True)
        return jsonify({"message": "An internal server error occurred during login process"}), 500

# --- Purity Rate Routes (Gold Rates - for general purities like 22KT, 24KT) ---
# app/routes.py
# ... (other imports and code remain the same) ...

# --- Helper Functions (to_iso_z, token_required) remain the same ---

# ... (Product Routes, Bank Details Routes, Admin Login Route remain the same) ...


# --- Metal Purity Rate Routes (Handles Gold and Silver) ---
# Renamed from /gold-rates to /metal-rates
@main_bp.route('/metal-rates', methods=['GET'])
def get_metal_rates(): # Renamed from get_purity_rates
    try:
        rates_collection = mongo.db.purity_rates
        rates_cursor = rates_collection.find({}) # Fetches all rates (gold and silver)
        rates_list = []
        for rate in rates_cursor:
            rate['_id'] = str(rate['_id'])
            # Ensure 'metalType' is present, default to 'GOLD' for older entries if necessary
            if 'metalType' not in rate:
                rate['metalType'] = 'GOLD' # Or handle as unknown, or fetch based on rateId pattern

            if 'lastUpdated' in rate and isinstance(rate['lastUpdated'], datetime.datetime):
                rate['lastUpdated'] = to_iso_z(rate['lastUpdated']) # Use the helper
            rates_list.append(rate)
        current_app.logger.info("Successfully fetched all metal rates.")
        return jsonify(rates_list), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching metal rates: {e}", exc_info=True)
        return jsonify({"message": "Error fetching metal rates from database", "error": str(e)}), 500

# Renamed from /gold-rates/update to /metal-rates/update
@main_bp.route('/metal-rates/update', methods=['POST'])
@token_required
def update_metal_rate(decoded_token_data): # Renamed from update_purity_rate
    """
    Updates the price of a specific metal purity rate (gold or silver).
    Requires admin authentication (JWT token).
    Expects JSON body: {"rateId": "22KT", "newPrice": 6500.00}
                     or {"rateId": "SILVER_1G", "newPrice": 75.00}
    The 'rateId' should be a unique identifier for the purity (e.g., "22KT", "SILVER_1G").
    """
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Metal rate update attempt by admin: {admin_username}")

    try:
        data = request.get_json()
        if not data:
            current_app.logger.warning(f"Update metal rate (by {admin_username}): attempt with no JSON data.")
            return jsonify({"message": "Request body must be JSON"}), 400

        rate_identifier = data.get('rateId')
        new_price_str = data.get('newPrice')

        if not rate_identifier or new_price_str is None:
            current_app.logger.warning(
                f"Update metal rate (by {admin_username}): missing rateId ('{rate_identifier}') or newPrice ('{new_price_str}')."
            )
            return jsonify({"message": "rateId and newPrice are required"}), 400

        try:
            new_price_numeric = float(str(new_price_str))
            if new_price_numeric < 0:
                 current_app.logger.warning(
                    f"Update metal rate (by {admin_username}) for '{rate_identifier}': invalid newPrice '{new_price_str}' (negative value)."
                )
                 return jsonify({"message": "newPrice cannot be negative"}), 400
        except ValueError:
            current_app.logger.warning(
                f"Update metal rate (by {admin_username}) for '{rate_identifier}': invalid newPrice format '{new_price_str}'."
            )
            return jsonify({"message": "newPrice must be a valid number"}), 400

        rates_collection = mongo.db.purity_rates

        # Find the document and update its price and lastUpdated timestamp
        result = rates_collection.update_one(
            {'rateId': rate_identifier},
            {'$set': {
                'price': new_price_numeric,
                'lastUpdated': datetime.datetime.utcnow(),
                # 'lastUpdatedBy': admin_username # Optionally track who updated
                }
            }
        )

        if result.matched_count == 0:
            current_app.logger.warning(
                f"Update attempt (by {admin_username}) for non-existent metal rateId: {rate_identifier}"
            )
            # You might consider if adding a new rate via this endpoint is desired (upsert=True)
            # For now, it requires the rate to exist.
            return jsonify({"message": f"Metal rate with ID '{rate_identifier}' not found. Cannot update."}), 404

        # Fetch the updated document to return it
        updated_rate_doc = rates_collection.find_one({'rateId': rate_identifier})
        if not updated_rate_doc:
            current_app.logger.error(f"Metal rate '{rate_identifier}' was updated by {admin_username}, but could not retrieve the updated record post-update.")
            # This should ideally not happen if matched_count > 0.
            return jsonify({"message": f"Rate '{rate_identifier}' updated, but error retrieving confirmation."}), 500


        updated_rate_doc['_id'] = str(updated_rate_doc['_id'])
        if 'lastUpdated' in updated_rate_doc and isinstance(updated_rate_doc['lastUpdated'], datetime.datetime):
            updated_rate_doc['lastUpdated'] = to_iso_z(updated_rate_doc['lastUpdated'])
        if 'metalType' not in updated_rate_doc : # Ensure metalType is in response
             updated_rate_doc['metalType'] = 'GOLD' # Default or determine based on rateId

        if result.modified_count > 0:
            current_app.logger.info(
                f"Metal rate '{rate_identifier}' updated successfully to {new_price_numeric} by admin {admin_username}"
            )
            return jsonify({"message": f"Metal rate '{rate_identifier}' updated successfully.", "updatedRate": updated_rate_doc}), 200
        else: # matched_count > 0 but modified_count == 0 (price was likely the same)
            current_app.logger.info(
                f"Metal rate '{rate_identifier}' was not modified by {admin_username} (price likely unchanged)."
            )
            return jsonify({"message": f"Metal rate '{rate_identifier}' price was not changed.", "currentRate": updated_rate_doc}), 200

    except Exception as e:
        rate_id_for_log = data.get('rateId', 'unknown') if 'data' in locals() and isinstance(data, dict) else 'unknown'
        admin_user_for_log = admin_username if 'admin_username' in locals() else 'unknown'
        current_app.logger.error(
            f"Error updating metal rate for '{rate_id_for_log}' by admin {admin_user_for_log}: {e}",
            exc_info=True
        )
        return jsonify({"message": "An internal server error occurred while updating metal rate"}), 500


# ... (Coin Price Routes and Admin Coin Management routes remain the same) ...

# --- Coin Price Routes ---
@main_bp.route('/coin-rates', methods=['GET'])
def get_coin_rates():
    """
    Fetches all coin prices from the 'coin_prices' collection.
    """
    try:
        coin_prices_collection = mongo.db.coin_prices
        coin_prices_cursor = coin_prices_collection.find({})
        coin_prices_list = []
        for coin_price_doc in coin_prices_cursor:
            coin_price_doc['_id'] = str(coin_price_doc['_id'])
            if 'lastUpdated' in coin_price_doc and isinstance(coin_price_doc['lastUpdated'], datetime.datetime):
                coin_price_doc['lastUpdated'] = coin_price_doc['lastUpdated'].isoformat() + "Z"
            coin_prices_list.append(coin_price_doc)

        current_app.logger.info(f"Successfully fetched {len(coin_prices_list)} coin prices.")
        return jsonify(coin_prices_list), 200
    except Exception as e:
        current_app.logger.error(f"Error fetching coin prices: {e}", exc_info=True)
        return jsonify({"message": "Error fetching coin prices from database", "error": str(e)}), 500

# --- Admin Coin Price Management ---

@main_bp.route('/admin/coins', methods=['GET'])
@token_required
def admin_get_all_coins(decoded_token_data):
    """ Admin endpoint to fetch all coin prices for management. """
    try:
        coin_prices_collection = mongo.db.coin_prices
        coin_prices_cursor = coin_prices_collection.find({})
        coin_prices_list = []
        for coin_price_doc in coin_prices_cursor:
            coin_price_doc['_id'] = str(coin_price_doc['_id'])
            if 'lastUpdated' in coin_price_doc and isinstance(coin_price_doc['lastUpdated'], datetime.datetime):
                coin_price_doc['lastUpdated'] = coin_price_doc['lastUpdated'].isoformat() + "Z"
            coin_prices_list.append(coin_price_doc)
        current_app.logger.info(f"Admin {decoded_token_data.get('username')} fetched all coin prices.")
        return jsonify(coin_prices_list), 200
    except Exception as e:
        current_app.logger.error(f"Error admin fetching coin prices: {e}", exc_info=True)
        return jsonify({"message": "Error fetching coin prices", "error": str(e)}), 500

@main_bp.route('/admin/coins/add', methods=['POST'])
@token_required
def admin_add_coin(decoded_token_data):
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Coin add attempt by admin: {admin_username}")
    try:
        data = request.get_json()
        if not data:
            return jsonify({"message": "Request body must be JSON"}), 400

        required_fields = ["coinId", "metal", "displayName", "price", "weightGrams"]
        for field in required_fields:
            if field not in data or data[field] is None: # Ensure field exists and is not None
                return jsonify({"message": f"Missing or null required field: {field}"}), 400

        if not isinstance(data["coinId"], str) or not data["coinId"].strip():
            return jsonify({"message": "coinId must be a non-empty string"}), 400
        if not isinstance(data["metal"], str) or data["metal"].upper() not in ["GOLD", "SILVER"]:
            return jsonify({"message": "metal must be 'GOLD' or 'SILVER'"}), 400
        if not isinstance(data["displayName"], str) or not data["displayName"].strip():
            return jsonify({"message": "displayName must be a non-empty string"}), 400

        try:
            price = float(data["price"])
            weight_grams = float(data["weightGrams"])
            if price < 0 or weight_grams <= 0:
                 return jsonify({"message": "Price must be non-negative and weight must be positive"}), 400
        except (ValueError, TypeError):
            return jsonify({"message": "Price and weightGrams must be valid numbers"}), 400


        new_coin = {
            "coinId": data["coinId"].strip(),
            "metal": data["metal"].upper(),
            "displayName": data["displayName"].strip(),
            "price": price,
            "weightGrams": weight_grams,
            "lastUpdated": datetime.datetime.utcnow()
        }

        if mongo.db.coin_prices.find_one({"coinId": new_coin["coinId"]}):
            current_app.logger.warning(f"Admin {admin_username} attempted to add duplicate coinId: {new_coin['coinId']}")
            return jsonify({"message": f"Coin with coinId '{new_coin['coinId']}' already exists."}), 409

        result = mongo.db.coin_prices.insert_one(new_coin)
        new_coin['_id'] = str(result.inserted_id)
        new_coin['lastUpdated'] = new_coin['lastUpdated'].isoformat() + "Z"

        current_app.logger.info(f"Admin {admin_username} successfully added coin: {new_coin['coinId']}")
        return jsonify({"message": "Coin added successfully", "coin": new_coin}), 201

    except Exception as e:
        current_app.logger.error(f"Error adding coin by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "Error adding coin", "error": str(e)}), 500


@main_bp.route('/admin/coins/update/<string:mongo_id>', methods=['PUT'])
@token_required
def admin_update_coin(decoded_token_data, mongo_id):
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Coin update attempt for ID {mongo_id} by admin: {admin_username}")
    try:
        try:
            db_id = ObjectId(mongo_id)
        except InvalidId:
            return jsonify({"message": "Invalid coin MongoDB ID format"}), 400

        data = request.get_json()
        if not data:
            return jsonify({"message": "Request body must be JSON and non-empty"}), 400

        update_fields = {}
        # Allow updating coinId, but ensure it doesn't clash with another existing coinId
        if "coinId" in data:
            if not isinstance(data["coinId"], str) or not data["coinId"].strip():
                 return jsonify({"message": "coinId must be a non-empty string"}), 400
            existing_coin_with_new_id = mongo.db.coin_prices.find_one({"coinId": data["coinId"].strip(), "_id": {"$ne": db_id}})
            if existing_coin_with_new_id:
                return jsonify({"message": f"Another coin with coinId '{data['coinId']}' already exists."}), 409
            update_fields["coinId"] = data["coinId"].strip()

        if "metal" in data:
            if not isinstance(data["metal"], str) or data["metal"].upper() not in ["GOLD", "SILVER"]:
                 return jsonify({"message": "Metal must be 'GOLD' or 'SILVER'"}), 400
            update_fields["metal"] = data["metal"].upper()
        if "displayName" in data:
            if not isinstance(data["displayName"], str) or not data["displayName"].strip():
                 return jsonify({"message": "displayName must be a non-empty string"}), 400
            update_fields["displayName"] = data["displayName"].strip()
        if "price" in data:
            try:
                price = float(data["price"])
                if price < 0:
                    return jsonify({"message": "Price must be non-negative"}), 400
                update_fields["price"] = price
            except (ValueError, TypeError):
                return jsonify({"message": "Price must be a valid number"}), 400
        if "weightGrams" in data:
            try:
                weight = float(data["weightGrams"])
                if weight <= 0:
                     return jsonify({"message": "Weight must be positive"}), 400
                update_fields["weightGrams"] = weight
            except (ValueError, TypeError):
                 return jsonify({"message": "weightGrams must be a valid number"}), 400

        if not update_fields:
            return jsonify({"message": "No valid update fields provided"}), 400

        update_fields["lastUpdated"] = datetime.datetime.utcnow()

        result = mongo.db.coin_prices.update_one(
            {"_id": db_id},
            {"$set": update_fields}
        )

        if result.matched_count == 0:
            current_app.logger.warning(f"Admin {admin_username} failed to update non-existent coin MongoDB ID: {mongo_id}")
            return jsonify({"message": "Coin not found"}), 404

        updated_coin = mongo.db.coin_prices.find_one({"_id": db_id})
        updated_coin['_id'] = str(updated_coin['_id']) # Should already be a string if fetched by _id from update
        if 'lastUpdated' in updated_coin and isinstance(updated_coin['lastUpdated'], datetime.datetime):
            updated_coin['lastUpdated'] = updated_coin['lastUpdated'].isoformat() + "Z"

        current_app.logger.info(f"Admin {admin_username} successfully updated coin MongoDB ID: {mongo_id}")
        return jsonify({"message": "Coin updated successfully", "coin": updated_coin}), 200

    except Exception as e:
        current_app.logger.error(f"Error updating coin MongoDB ID {mongo_id} by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "Error updating coin", "error": str(e)}), 500


@main_bp.route('/admin/coins/delete/<string:mongo_id>', methods=['DELETE'])
@token_required
def admin_delete_coin(decoded_token_data, mongo_id):
    admin_username = decoded_token_data.get('username', 'Unknown Admin')
    current_app.logger.info(f"Coin delete attempt for MongoDB ID {mongo_id} by admin: {admin_username}")
    try:
        try:
            db_id = ObjectId(mongo_id)
        except InvalidId:
            return jsonify({"message": "Invalid coin MongoDB ID format"}), 400

        result = mongo.db.coin_prices.delete_one({"_id": db_id})

        if result.deleted_count == 0:
            current_app.logger.warning(f"Admin {admin_username} failed to delete non-existent coin MongoDB ID: {mongo_id}")
            return jsonify({"message": "Coin not found"}), 404

        current_app.logger.info(f"Admin {admin_username} successfully deleted coin MongoDB ID: {mongo_id}")
        return jsonify({"message": "Coin deleted successfully"}), 200 # 204 No Content is also an option

    except Exception as e:
        current_app.logger.error(f"Error deleting coin MongoDB ID {mongo_id} by admin {admin_username}: {e}", exc_info=True)
        return jsonify({"message": "Error deleting coin", "error": str(e)}), 500

