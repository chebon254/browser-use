# LinkedIn Automation Tool - Setup Instructions

This document provides instructions for setting up the LinkedIn Automation Tool with user authentication and database integration.

## Prerequisites

1. Python 3.8+
2. MySQL Server
3. Anthropic API key (for Claude)
4. SMTP server access (for password reset emails)
5. AWS credentials (optional, for S3 storage)

## Setup Steps

### 1. Create a Virtual Environment

```bash
# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

### 2. Install Required Packages

```bash
pip install flask pymysql bcrypt python-dotenv flask-mail boto3 langchain-anthropic
pip install browser-use
```

### 3. Database Setup

1. Create a MySQL database using the provided schema:
   ```bash
   mysql -u root -p < database_schema.sql
   ```
   
   or import the database schema through a MySQL client using the SQL in `database_schema.sql`.

### 4. Configure Environment Variables

Create a `.env` file in the project root with the following variables:

```
# Flask settings
FLASK_SECRET_KEY=your_random_secure_secret_key

# Database settings
DB_HOST=localhost
DB_USER=your_db_username
DB_PASSWORD=your_db_password
DB_NAME=linkedin_automation

# Anthropic API settings
ANTHROPIC_API_KEY=your_anthropic_api_key

# Browser settings
BROWSER_TYPE=chromium  # or firefox, webkit

# Email settings (for password reset)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
MAIL_DEFAULT_SENDER=your_email@gmail.com

# AWS settings (optional, for S3)
USE_S3=False
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1
S3_BUCKET=your-bucket-name
```

### 5. Create Static Directories

Ensure the following directories exist in your project structure:

```bash
mkdir -p static/uploads
mkdir -p static/profile_images
mkdir -p static/images
mkdir -p logs/linkedin_automation
```

### 6. Add SVG icons for social login

Copy the provided SVG files to the static/images directory:
- Copy `google.svg` to `static/images/google.svg`
- Copy `apple.svg` to `static/images/apple.svg`

### 7. Run the Application

```bash
python app.py
```

Visit http://127.0.0.1:5000/ in your browser to access the application.

## AWS Setup (Optional)

If you want to use AWS for file storage:

1. Create an S3 bucket in your AWS account
2. Create an IAM user with programmatic access
3. Attach the AmazonS3FullAccess policy to the user
4. Generate access keys and add them to your .env file
5. Set USE_S3=True in the .env file

## MySQL Database on AWS

If setting up MySQL on AWS:

1. Create an RDS MySQL instance
2. Configure security groups to allow connections from your application
3. Update the DB_HOST in your .env file to point to the RDS endpoint
4. Ensure the database credentials in .env match your RDS instance

## Default LinkedIn Interface Image

To use a default LinkedIn interface image as a reference, place a screenshot of the LinkedIn interface at:
```
static/uploads/linkedin_interface.png
```

## Development Notes

- For local development, you may want to set `debug=True` in `app.py`
- Make sure to secure your .env file and never commit it to version control
- In a production environment, use a proper WSGI server like Gunicorn or uWSGI