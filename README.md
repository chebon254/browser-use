# LinkedIn Automation Tool

A web application that uses Browser Use and Anthropic AI to automate LinkedIn interactions based on natural language prompts.

## Features

- Simple web interface for entering automation prompts
- Run browser automations with a single click
- View detailed results including screenshots
- Sample prompts for common LinkedIn tasks

## Prerequisites

- Python 3.11 or higher
- Anthropic API key (Claude model)
- Modern web browser

## Installation

### Local Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/linkedin-automation.git
   cd linkedin-automation
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install Playwright browsers:
   ```bash
   playwright install
   ```

5. Create a `.env` file:
   ```bash
   cp .env.example .env
   ```

6. Edit the `.env` file and add your Anthropic API key and a secret key for Flask:
   ```
   ANTHROPIC_API_KEY=your_anthropic_key_here
   FLASK_SECRET_KEY=random_secret_key_here
   ```

7. Run the application:
   ```bash
   python app.py
   ```

8. Open your browser and navigate to `http://127.0.0.1:5000`

### Server Deployment

#### Option 1: Deploy on a VPS (e.g., DigitalOcean, AWS EC2, etc.)

1. SSH into your server:
   ```bash
   ssh user@your-server-ip
   ```

2. Install required packages:
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-venv nginx
   ```

3. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/linkedin-automation.git
   cd linkedin-automation
   ```

4. Follow steps 2-6 from the Local Setup section.

5. Install and set up Gunicorn:
   ```bash
   pip install gunicorn
   ```

6. Create a systemd service file:
   ```bash
   sudo nano /etc/systemd/system/linkedin-automation.service
   ```

7. Add the following content (adjust paths and user as needed):
   ```
   [Unit]
   Description=LinkedIn Automation Tool
   After=network.target

   [Service]
   User=your_username
   WorkingDirectory=/path/to/linkedin-automation
   Environment="PATH=/path/to/linkedin-automation/venv/bin"
   ExecStart=/path/to/linkedin-automation/venv/bin/gunicorn -w 1 -b 127.0.0.1:8000 app:app
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

8. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable linkedin-automation
   sudo systemctl start linkedin-automation
   ```

9. Configure Nginx as a reverse proxy:
   ```bash
   sudo nano /etc/nginx/sites-available/linkedin-automation
   ```

10. Add the following configuration:
    ```
    server {
        listen 80;
        server_name your-domain.com;

        location / {
            proxy_pass http://127.0.0.1:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
    ```

11. Enable the site and restart Nginx:
    ```bash
    sudo ln -s /etc/nginx/sites-available/linkedin-automation /etc/nginx/sites-enabled/
    sudo systemctl restart nginx
    ```

12. (Optional) Set up HTTPS with Certbot:
    ```bash
    sudo apt install certbot python3-certbot-nginx
    sudo certbot --nginx -d your-domain.com
    ```

#### Option 2: Deploy with Docker

1. Create a Dockerfile in your project directory:
   ```bash
   nano Dockerfile
   ```

2. Add the following content:
   ```Dockerfile
   FROM python:3.11-slim

   WORKDIR /app

   # Install system dependencies
   RUN apt-get update && apt-get install -y \
       wget \
       gnupg \
       && rm -rf /var/lib/apt/lists/*

   # Install Playwright dependencies
   RUN pip install playwright && python -m playwright install --with-deps chromium

   # Install Python dependencies
   COPY requirements.txt .
   RUN pip install -r requirements.txt

   # Copy application code
   COPY . .

   # Create logs directory
   RUN mkdir -p logs/linkedin_automation

   # Run the application
   CMD ["python", "app.py"]
   ```

3. Create a docker-compose.yml file:
   ```bash
   nano docker-compose.yml
   ```

4. Add the following content:
   ```yaml
   version: '3'
   services:
     linkedin-automation:
       build: .
       ports:
         - "5000:5000"
       environment:
         - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
         - FLASK_SECRET_KEY=${FLASK_SECRET_KEY}
       volumes:
         - ./logs:/app/logs
       restart: unless-stopped
   ```

5. Build and run with Docker Compose:
   ```bash
   docker-compose up -d
   ```

## Usage

1. Open the application in your web browser
2. Enter a prompt describing what you want to do on LinkedIn
3. Click "Run Automation" to start the process
4. View the results including screenshots and actions performed

## Important Notes

- The application will use your browser's existing LinkedIn session if you're logged in
- Be mindful of LinkedIn's usage policies to avoid account restrictions
- This tool is for educational purposes; use responsibly and ethically

## Anthropic API and Pricing

Anthropic's Claude AI models (used in this application) are not free. Here's what you need to know:

- You need an Anthropic API key to use this application
- Claude offers [free trial credits](https://www.anthropic.com/api) for new users (typically $5-$10)
- API costs are based on input and output tokens (similar to OpenAI's pricing model)
- Claude 3 Sonnet costs approximately:
  - Input: $3.00 per million tokens
  - Output: $15.00 per million tokens
- For testing and low-volume use, the initial credits should be sufficient
- For production use, you will need to provide payment information to Anthropic

For detailed and current pricing information, visit [Anthropic's pricing page](https://www.anthropic.com/api/pricing).

## Troubleshooting

- **Browser doesn't open**: Make sure Playwright is installed correctly with `playwright install`
- **Authentication errors**: Check your Anthropic API key in the .env file
- **Automation fails**: LinkedIn's UI can change, affecting automation reliability