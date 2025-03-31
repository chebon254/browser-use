from authlib.integrations.flask_client import OAuth
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import os
import json
import uuid
import pymysql
import bcrypt
import secrets
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask_mail import Mail, Message
from linkedin_agent import run_automation
from werkzeug.utils import secure_filename
from functools import wraps
import re
import jwt
import requests
import time

# Load environment variables
load_dotenv()

app = Flask(__name__)
oauth = OAuth(app)

app.secret_key = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(16))

# Configure mail
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
mail = Mail(app)

# Google OAuth configuration
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs'
)

# Configure AWS S3 (if using)
use_s3 = os.getenv('USE_S3', 'False').lower() in ('true', '1', 't')
if use_s3:
    import boto3
    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
        region_name=os.getenv('AWS_REGION')
    )
    S3_BUCKET = os.getenv('S3_BUCKET')

# Ensure upload directories exist
UPLOAD_FOLDER = os.path.join('static', 'uploads')
PROFILE_IMAGES_FOLDER = os.path.join('static', 'profile_images')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROFILE_IMAGES_FOLDER, exist_ok=True)
os.makedirs('logs/linkedin_automation', exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROFILE_IMAGES_FOLDER'] = PROFILE_IMAGES_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max upload

# Database connection
def get_db_connection():
    return pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', ''),
        db=os.getenv('DB_NAME', 'linkedin_automation'),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Upload to S3 helper
def upload_file_to_s3(file_path, s3_path):
    if use_s3:
        try:
            s3_client.upload_file(file_path, S3_BUCKET, s3_path)
            return f"https://{S3_BUCKET}.s3.amazonaws.com/{s3_path}"
        except Exception as e:
            print(f"S3 upload error: {str(e)}")
            return None
    return file_path

# Validation helpers
def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def validate_password(password):
    # At least 8 characters, 1 uppercase, 1 lowercase, 1 number
    if len(password) < 8:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    return True

# Routes
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        # Handle automation request
        selected_prompt_id = request.form.get('selected_prompt')
        custom_prompt = request.form.get('custom_prompt')
        
        # Determine which prompt to use
        prompt = None
        if selected_prompt_id:
            # Get the selected prompt from database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT prompt_text FROM saved_prompts WHERE id = %s", (selected_prompt_id,))
            prompt_data = cursor.fetchone()
            conn.close()
            
            if prompt_data:
                prompt = prompt_data['prompt_text']
        elif custom_prompt:
            prompt = custom_prompt
            
        if not prompt:
            flash('Please select or enter a prompt', 'error')
            return redirect(url_for('dashboard'))
            
        # Handle image upload
        uploaded_image = None
        if 'linkedin_image' in request.files:
            image_file = request.files['linkedin_image']
            if image_file.filename != '':
                # Generate a unique filename to prevent overwriting
                file_ext = os.path.splitext(image_file.filename)[1]
                unique_filename = f"{uuid.uuid4().hex}{file_ext}"
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                image_file.save(image_path)
                
                # Upload to S3 if configured
                if use_s3:
                    s3_path = f"uploads/{unique_filename}"
                    s3_url = upload_file_to_s3(image_path, s3_path)
                    if s3_url:
                        uploaded_image = s3_url
                    else:
                        uploaded_image = image_path
                else:
                    uploaded_image = image_path
                
        try:
            # Log the automation in the database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO automation_history (user_id, prompt_text, image_path, status) VALUES (%s, %s, %s, %s)",
                (session['user_id'], prompt, uploaded_image, 'running')
            )
            automation_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Run the automation
            result = run_automation(prompt, uploaded_image)
            
            # Update the automation status in the database
            conn = get_db_connection()
            cursor = conn.cursor()
            status = 'success' if result['success'] else 'error'
            result_message = result['final_result']
            cursor.execute(
                "UPDATE automation_history SET status = %s, result_message = %s, completed_at = NOW() WHERE id = %s",
                (status, result_message, automation_id)
            )
            conn.commit()
            conn.close()
            
            # Check if the automation was successful
            if result['success']:
                flash('Automation completed successfully!', 'success')
            else:
                error_message = "Automation did not complete successfully."
                if result['errors'] and len(result['errors']) > 0:
                    error_message = f"Error during automation: {result['errors'][0]}"
                flash(error_message, 'error')
            
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error running automation: {str(e)}', 'error')
            return redirect(url_for('dashboard'))
    
    # Get user's saved prompts and sample prompts
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Get user info
    cursor.execute("SELECT full_name, email, profile_image FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    
    # Get sample prompts
    cursor.execute("SELECT id, prompt_text FROM saved_prompts WHERE is_sample = TRUE")
    sample_prompts = cursor.fetchall()
    
    # Get user's saved prompts
    cursor.execute("SELECT id, prompt_text FROM saved_prompts WHERE user_id = %s AND is_sample = FALSE", (session['user_id'],))
    user_prompts = cursor.fetchall()
    
    # Get recent automation history
    cursor.execute(
        "SELECT * FROM automation_history WHERE user_id = %s ORDER BY started_at DESC LIMIT 5", 
        (session['user_id'],)
    )
    history = cursor.fetchall()
    
    conn.close()
    
    return render_template('index.html', 
                          user=user,
                          sample_prompts=sample_prompts, 
                          user_prompts=user_prompts,
                          history=history)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Please provide both email and password', 'error')
            return render_template('login.html')
        
        # Validate email format
        if not validate_email(email):
            flash('Invalid email format', 'error')
            return render_template('login.html')
            
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and user['auth_type'] == 'email':
            # For email users, verify password
            if bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                session['user_id'] = user['id']
                session['full_name'] = user['full_name']
                session['auth_type'] = user['auth_type']
                flash(f'Welcome back, {user["full_name"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password', 'error')
        else:
            flash('Invalid email or password', 'error')
            
        return render_template('login.html')
        
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not full_name or not email or not password or not confirm_password:
            flash('All fields are required', 'error')
            return render_template('register.html')
            
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
            
        if not validate_email(email):
            flash('Invalid email format', 'error')
            return render_template('register.html')
            
        if not validate_password(password):
            flash('Password must be at least 8 characters with at least one uppercase letter, one lowercase letter, and one number', 'error')
            return render_template('register.html')
            
        # Check if email already exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            conn.close()
            flash('Email already registered', 'error')
            return render_template('register.html')
            
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create the user
        try:
            cursor.execute(
                "INSERT INTO users (full_name, email, password_hash, auth_type) VALUES (%s, %s, %s, %s)",
                (full_name, email, hashed_password, 'email')
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            # Log the user in
            session['user_id'] = user_id
            session['full_name'] = full_name
            session['auth_type'] = 'email'
            
            flash(f'Welcome, {full_name}! Your account has been created.', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            conn.close()
            flash(f'Error creating account: {str(e)}', 'error')
            return render_template('register.html')
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update profile info
        updates_made = False
        
        # Update name if provided
        if full_name:
            cursor.execute("UPDATE users SET full_name = %s WHERE id = %s", (full_name, session['user_id']))
            session['full_name'] = full_name
            updates_made = True
        
        # Update password if provided (only for email users)
        if session['auth_type'] == 'email' and current_password and new_password and confirm_password:
            # Get current password hash
            cursor.execute("SELECT password_hash FROM users WHERE id = %s", (session['user_id'],))
            user = cursor.fetchone()
            
            if not user or not bcrypt.checkpw(current_password.encode('utf-8'), user['password_hash'].encode('utf-8')):
                conn.close()
                flash('Current password is incorrect', 'error')
                return redirect(url_for('profile'))
                
            if new_password != confirm_password:
                conn.close()
                flash('New passwords do not match', 'error')
                return redirect(url_for('profile'))
                
            if not validate_password(new_password):
                conn.close()
                flash('New password must be at least 8 characters with at least one uppercase letter, one lowercase letter, and one number', 'error')
                return redirect(url_for('profile'))
                
            # Hash and update the new password
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_password, session['user_id']))
            updates_made = True
        
        # Handle profile image upload
        if 'profile_image' in request.files:
            profile_image = request.files['profile_image']
            if profile_image.filename != '':
                # Validate file size
                if len(profile_image.read()) > 5 * 1024 * 1024:  # 5MB
                    conn.close()
                    flash('Profile image must be less than 5MB', 'error')
                    return redirect(url_for('profile'))
                
                # Reset file pointer after reading for size check
                profile_image.seek(0)
                
                # Check file type
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
                file_ext = os.path.splitext(profile_image.filename)[1].lower().lstrip('.')
                if file_ext not in allowed_extensions:
                    conn.close()
                    flash('Invalid file type. Please upload a PNG, JPG, JPEG, or GIF file.', 'error')
                    return redirect(url_for('profile'))
                
                # Generate a unique filename
                unique_filename = f"{session['user_id']}_{uuid.uuid4().hex}.{file_ext}"
                image_path = os.path.join(app.config['PROFILE_IMAGES_FOLDER'], unique_filename)
                profile_image.save(image_path)
                
                # Upload to S3 if configured
                if use_s3:
                    s3_path = f"profile_images/{unique_filename}"
                    s3_url = upload_file_to_s3(image_path, s3_path)
                    if s3_url:
                        cursor.execute("UPDATE users SET profile_image = %s WHERE id = %s", (s3_url, session['user_id']))
                    else:
                        cursor.execute("UPDATE users SET profile_image = %s WHERE id = %s", 
                                      (f"/static/profile_images/{unique_filename}", session['user_id']))
                else:
                    cursor.execute("UPDATE users SET profile_image = %s WHERE id = %s", 
                                  (f"/static/profile_images/{unique_filename}", session['user_id']))
                
                updates_made = True
        
        if updates_made:
            conn.commit()
            flash('Profile updated successfully', 'success')
        
        conn.close()
        return redirect(url_for('profile'))
    
    # Get user profile info
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT full_name, email, profile_image, auth_type FROM users WHERE id = %s", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()
    
    return render_template('profile.html', user=user)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email or not validate_email(email):
            flash('Please enter a valid email address', 'error')
            return render_template('forgot_password.html')
            
        # Check if email exists and user is email-based
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, auth_type FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if not user:
            # Don't reveal if email exists or not for security
            flash('If your email is registered, you will receive password reset instructions', 'info')
            conn.close()
            return render_template('forgot_password.html')
            
        if user['auth_type'] != 'email':
            flash('This account uses social login and cannot reset password this way', 'error')
            conn.close()
            return render_template('forgot_password.html')
            
        # Generate token
        token = secrets.token_urlsafe(32)
        expiry = datetime.now() + timedelta(hours=1)
        
        # Save token to database
        cursor.execute(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (%s, %s, %s)",
            (user['id'], token, expiry)
        )
        conn.commit()
        conn.close()
        
        # Send email
        reset_url = url_for('reset_password', token=token, _external=True)
        try:
            msg = Message('Password Reset Request', recipients=[email])
            msg.body = f'''To reset your password, visit the following link:
{reset_url}

This link will expire in 1 hour.

If you did not make this request, please ignore this email.
'''
            mail.send(msg)
            flash('Password reset instructions have been sent to your email', 'info')
        except Exception as e:
            flash(f'Error sending email: {str(e)}. Please try again later.', 'error')
            
        return render_template('forgot_password.html')
        
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Verify token
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id, expires_at, used FROM password_reset_tokens WHERE token = %s",
        (token,)
    )
    token_data = cursor.fetchone()
    
    # Check if token is valid
    if not token_data or token_data['used'] or token_data['expires_at'] < datetime.now():
        conn.close()
        flash('Invalid or expired password reset link', 'error')
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate passwords
        if not password or not confirm_password:
            flash('Both fields are required', 'error')
            return render_template('reset_password.html', token=token)
            
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
            
        if not validate_password(password):
            flash('Password must be at least 8 characters with at least one uppercase letter, one lowercase letter, and one number', 'error')
            return render_template('reset_password.html', token=token)
            
        # Update password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (hashed_password, token_data['user_id'])
        )
        
        # Mark token as used
        cursor.execute(
            "UPDATE password_reset_tokens SET used = TRUE WHERE token = %s",
            (token,)
        )
        
        conn.commit()
        conn.close()
        
        flash('Your password has been reset successfully. You can now log in with your new password.', 'success')
        return redirect(url_for('login'))
        
    conn.close()
    return render_template('reset_password.html', token=token)

@app.route('/save-prompt', methods=['POST'])
@login_required
def save_prompt():
    prompt_text = request.form.get('prompt_text')
    
    if not prompt_text:
        flash('Prompt text is required', 'error')
        return redirect(url_for('dashboard'))
        
    # Save the prompt to the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO saved_prompts (user_id, prompt_text, is_sample) VALUES (%s, %s, %s)",
        (session['user_id'], prompt_text, False)
    )
    conn.commit()
    conn.close()
    
    flash('Prompt saved successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete-prompt/<int:prompt_id>', methods=['POST'])
@login_required
def delete_prompt(prompt_id):
    # Delete the prompt from the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "DELETE FROM saved_prompts WHERE id = %s AND user_id = %s AND is_sample = FALSE",
        (prompt_id, session['user_id'])
    )
    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    if deleted:
        flash('Prompt deleted successfully', 'success')
    else:
        flash('Error deleting prompt', 'error')
        
    return redirect(url_for('dashboard'))

@app.route('/update-prompt/<int:prompt_id>', methods=['POST'])
@login_required
def update_prompt(prompt_id):
    prompt_text = request.form.get('prompt_text')
    
    if not prompt_text:
        flash('Prompt text is required', 'error')
        return redirect(url_for('dashboard'))
        
    # Update the prompt in the database
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE saved_prompts SET prompt_text = %s WHERE id = %s AND user_id = %s AND is_sample = FALSE",
        (prompt_text, prompt_id, session['user_id'])
    )
    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()
    
    if updated:
        flash('Prompt updated successfully', 'success')
    else:
        flash('Error updating prompt', 'error')
        
    return redirect(url_for('dashboard'))

# Replace the existing Google OAuth route with this
@app.route('/auth/google')
def google_auth():
    redirect_uri = url_for('google_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def google_callback():
    try:
        token = google.authorize_access_token()
        resp = google.get('userinfo')
        user_info = resp.json()
        
        # Get user details from Google response
        email = user_info['email']
        name = user_info['name']
        google_id = user_info['id']
        
        # Check if user exists
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user:
            # User exists, check if it's a Google login
            if user['auth_type'] == 'google':
                # Update the Google ID if needed
                if user['auth_provider_id'] != google_id:
                    cursor.execute(
                        "UPDATE users SET auth_provider_id = %s WHERE id = %s",
                        (google_id, user['id'])
                    )
                    conn.commit()
                
                # Log the user in
                session['user_id'] = user['id']
                session['full_name'] = user['full_name']
                session['auth_type'] = 'google'
                conn.close()
                flash(f'Welcome back, {user["full_name"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # User exists but with a different auth type
                conn.close()
                flash(f'An account with this email already exists. Please log in with {user["auth_type"].capitalize()}.', 'error')
                return redirect(url_for('login'))
        else:
            # Create new user
            cursor.execute(
                "INSERT INTO users (full_name, email, auth_type, auth_provider_id) VALUES (%s, %s, %s, %s)",
                (name, email, 'google', google_id)
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            # Log the user in
            session['user_id'] = user_id
            session['full_name'] = name
            session['auth_type'] = 'google'
            
            flash(f'Welcome, {name}! Your account has been created.', 'success')
            return redirect(url_for('dashboard'))
            
    except Exception as e:
        print(f"Google OAuth error: {str(e)}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('login'))

# Add the Apple OAuth configuration to app.py
@app.route('/auth/apple')
def apple_auth():
    # Generate a random state string to prevent CSRF
    state = secrets.token_urlsafe(32)
    session['apple_auth_state'] = state
    
    # Configure the Apple Sign In request
    apple_auth_url = "https://appleid.apple.com/auth/authorize"
    
    # Parameters for the authorization request
    params = {
        'response_type': 'code',
        'client_id': os.getenv('APPLE_CLIENT_ID'),
        'redirect_uri': url_for('apple_callback', _external=True),
        'state': state,
        'scope': 'name email',
        'response_mode': 'form_post'
    }
    
    # Build the URL with query parameters
    auth_url = f"{apple_auth_url}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
    
    return redirect(auth_url)

@app.route('/auth/apple/callback', methods=['POST'])
def apple_callback():
    try:
        # Verify state to prevent CSRF attacks
        if 'state' not in request.form or request.form.get('state') != session.pop('apple_auth_state', None):
            flash('Invalid state parameter. Authentication failed.', 'error')
            return redirect(url_for('login'))
        
        # Get the authorization code from Apple
        code = request.form.get('code')
        if not code:
            flash('Authentication failed. No authorization code received.', 'error')
            return redirect(url_for('login'))
        
        # Exchange the code for tokens
        client_id = os.getenv('APPLE_CLIENT_ID')
        client_secret = generate_apple_client_secret()  # Function to generate the client secret
        
        token_request_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': url_for('apple_callback', _external=True)
        }
        
        token_response = requests.post('https://appleid.apple.com/auth/token', data=token_request_data)
        token_data = token_response.json()
        
        if 'error' in token_data:
            flash(f"Authentication failed: {token_data.get('error_description', token_data['error'])}", 'error')
            return redirect(url_for('login'))
        
        # Get the ID token and decode it to get user information
        id_token = token_data.get('id_token')
        user_info = jwt.decode(id_token, '', options={"verify_signature": False})
        
        # Extract user information
        apple_id = user_info.get('sub')
        email = user_info.get('email')
        
        # The name might be included in the initial sign-in request but not in subsequent requests
        # Check if user data is in the form
        user_data = {}
        if request.form.get('user'):
            try:
                user_data = json.loads(request.form.get('user'))
            except:
                pass
        
        # Get the name from user_data or use email as a fallback
        name = None
        if user_data and 'name' in user_data:
            name_data = user_data['name']
            first_name = name_data.get('firstName', '')
            last_name = name_data.get('lastName', '')
            name = f"{first_name} {last_name}".strip()
        
        if not name:
            # Use email prefix as name if no name is provided
            name = email.split('@')[0] if email else "Apple User"
        
        if not email:
            flash('Authentication failed. Email information is required.', 'error')
            return redirect(url_for('login'))
        
        # Check if user exists in database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        if user:
            # User exists, check if it's an Apple login
            if user['auth_type'] == 'apple':
                # Update the Apple ID if needed
                if user['auth_provider_id'] != apple_id:
                    cursor.execute(
                        "UPDATE users SET auth_provider_id = %s WHERE id = %s",
                        (apple_id, user['id'])
                    )
                    conn.commit()
                
                # Log the user in
                session['user_id'] = user['id']
                session['full_name'] = user['full_name']
                session['auth_type'] = 'apple'
                conn.close()
                flash(f'Welcome back, {user["full_name"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                # User exists but with a different auth type
                conn.close()
                flash(f'An account with this email already exists. Please log in with {user["auth_type"].capitalize()}.', 'error')
                return redirect(url_for('login'))
        else:
            # Create new user
            cursor.execute(
                "INSERT INTO users (full_name, email, auth_type, auth_provider_id) VALUES (%s, %s, %s, %s)",
                (name, email, 'apple', apple_id)
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            
            # Log the user in
            session['user_id'] = user_id
            session['full_name'] = name
            session['auth_type'] = 'apple'
            
            flash(f'Welcome, {name}! Your account has been created.', 'success')
            return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"Apple OAuth error: {str(e)}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('login'))

# Function to generate the client secret for Apple Sign In
def generate_apple_client_secret():
    # Apple requires a JWT token signed with the private key as client secret
    # This implementation needs your Apple private key in a .p8 file
    
    private_key_path = os.getenv('APPLE_PRIVATE_KEY_PATH')
    team_id = os.getenv('APPLE_TEAM_ID')
    client_id = os.getenv('APPLE_CLIENT_ID')
    key_id = os.getenv('APPLE_KEY_ID')
    
    # Read the private key
    with open(private_key_path, 'r') as f:
        private_key = f.read()
    
    # Create JWT headers
    headers = {
        'kid': key_id
    }
    
    # Create JWT payload
    now = int(time.time())
    payload = {
        'iss': team_id,
        'iat': now,
        'exp': now + 3600,  # Valid for 1 hour
        'aud': 'https://appleid.apple.com',
        'sub': client_id
    }
    
    # Create the JWT
    client_secret = jwt.encode(
        payload,
        private_key,
        algorithm='ES256',
        headers=headers
    )
    
    return client_secret

@app.route('/auth/callback', methods=['POST'])
def oauth_callback():
    provider = request.form.get('provider')
    email = request.form.get('email')
    name = request.form.get('name')
    provider_id = request.form.get('provider_id', uuid.uuid4().hex)
    
    if not provider or not email or not name:
        flash('Authentication failed', 'error')
        return redirect(url_for('login'))
        
    # Check if user exists
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    
    if user:
        # User exists, check if it's a social login
        if user['auth_type'] == provider.lower():
            # User already has this social login, just log them in
            session['user_id'] = user['id']
            session['full_name'] = user['full_name']
            session['auth_type'] = user['auth_type']
            conn.close()
            flash(f'Welcome back, {user["full_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # User exists but with a different auth type
            conn.close()
            flash(f'An account with this email already exists. Please log in with {user["auth_type"].capitalize()}.', 'error')
            return redirect(url_for('login'))
    else:
        # Create new user
        cursor.execute(
            "INSERT INTO users (full_name, email, auth_type, auth_provider_id) VALUES (%s, %s, %s, %s)",
            (name, email, provider.lower(), provider_id)
        )
        conn.commit()
        user_id = cursor.lastrowid
        conn.close()
        
        # Log the user in
        session['user_id'] = user_id
        session['full_name'] = name
        session['auth_type'] = provider.lower()
        
        flash(f'Welcome, {name}! Your account has been created.', 'success')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    # Check if ANTHROPIC_API_KEY is set
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("Warning: ANTHROPIC_API_KEY is not set in .env file")
    
    app.run(debug=True)