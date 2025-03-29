# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import json
from linkedin_agent import run_automation
from dotenv import load_dotenv
import uuid

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default-secret-key")

# Ensure upload directories exist
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('logs/linkedin_automation', exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Get the prompt from the form
        prompt = request.form.get('prompt')
        
        if not prompt:
            flash('Please enter a prompt', 'error')
            return redirect(url_for('index'))
            
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
                uploaded_image = image_path
                
        try:
            # Run the automation with the image if available
            result = run_automation(prompt, uploaded_image)
            
            # Check if the automation was actually successful
            if result['success']:
                flash('Automation completed successfully!', 'success')
            else:
                error_message = "Automation did not complete successfully."
                if result['errors'] and len(result['errors']) > 0:
                    error_message = f"Error during automation: {result['errors'][0]}"
                flash(error_message, 'error')
            
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error running automation: {str(e)}', 'error')
            return redirect(url_for('index'))
    
    # Default sample prompts
    sample_prompts = [
        "Go to https://www.linkedin.com/feed/ and comment on posts after reading them, and insert a comment based on their paragraph content, ignore links and hash tag eg #school. After posting a comment, to find more posts scrolling down, comment on 10 posts. My account email: contact@chebonkelvin.com password: @?Kelvin11468 on linkedin user interface"
    ]
    
    return render_template('index.html', sample_prompts=sample_prompts)

if __name__ == '__main__':
    # Check if ANTHROPIC_API_KEY is set
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("Warning: ANTHROPIC_API_KEY is not set in .env file")
    
    app.run(debug=True)