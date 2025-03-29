# automation/linkedin_agent.py
import os
import asyncio
import base64
from browser_use import Agent, Browser, BrowserConfig
from langchain_anthropic import ChatAnthropic
from dotenv import load_dotenv
import time
import traceback

load_dotenv()

async def run_linkedin_automation(prompt, uploaded_image_path=None):
    """
    Run a LinkedIn automation task using Browser Use and Anthropic
    
    Args:
        prompt (str): The instruction for the agent, e.g., 
                     "Go to https://www.linkedin.com/mynetwork/ and connect with people"
        uploaded_image_path (str, optional): Path to the uploaded screenshot of LinkedIn UI
    
    Returns:
        dict: Results of the automation including final output and any errors
    """
    browser = None
    try:
        print("Initializing browser for LinkedIn automation...")
        
        # Initialize the browser with minimal configuration
        browser = Browser()
        
        # Initialize the Anthropic model
        model = ChatAnthropic(
            model="claude-3-5-sonnet-latest",
            temperature=0.0,
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY")
        )
        
        # If an image was uploaded, modify the prompt to include reference to it
        enhanced_prompt = prompt
        if uploaded_image_path and os.path.exists(uploaded_image_path):
            try:
                print(f"Processing uploaded image: {uploaded_image_path}")
                
                # For demonstration, we'll just reference the image in the path
                # In a production system, you might want to use the actual image data
                interface_image_path = os.path.abspath(uploaded_image_path)
                
                # Add reference to the image in the prompt instead of trying to pass it directly
                image_reference = f"""
                Note: I've seen the LinkedIn interface from the screenshot you uploaded at {interface_image_path}.
                I'll use my knowledge of LinkedIn's interface to navigate and perform the actions you requested.
                Pay special attention to the structure of posts, the comment sections, and interactive elements.
                """
                enhanced_prompt = image_reference + "\n\n" + prompt
                print("Added LinkedIn UI image reference to prompt")
                
            except Exception as e:
                print(f"Warning: Failed to process uploaded image: {str(e)}")
                traceback.print_exc()
        else:
            # Check if we should use the default interface image
            default_image_path = os.path.join('static', 'uploads', 'linkedin_interface.png')
            if os.path.exists(default_image_path):
                interface_image_path = os.path.abspath(default_image_path)
                image_reference = f"""
                Note: I'll use the standard LinkedIn interface screenshot at {interface_image_path} as a reference.
                I'll use my knowledge of LinkedIn's interface to navigate and perform the actions you requested.
                """
                enhanced_prompt = image_reference + "\n\n" + prompt
                print("Added default LinkedIn UI image reference to prompt")
        
        # Create the Browser Use agent with enhanced prompt
        print("Creating Browser Use agent...")
        agent = Agent(
            task=enhanced_prompt,
            llm=model,
            browser=browser,
            save_conversation_path="logs/linkedin_automation"
        )
        
        # Configure the agent to use a specific browser with explicit playwright options
        browser_type = os.getenv("BROWSER_TYPE", "chromium")  # Default to chromium if not specified
        agent.browser_kwargs = {
            "browser_type": browser_type,
            "headless": False
        }
        
        # Only add executable_path if Opera is specified and the path exists
        if browser_type == "webkit" and os.path.exists("/usr/bin/opera"):
            agent.launch_kwargs = {
                "executable_path": "/usr/bin/opera"
            }
        
        # Run the agent with a timeout
        print(f"Running automation with prompt: {enhanced_prompt[:100]}...")
        try:
            history = await asyncio.wait_for(agent.run(), timeout=600)  # 10 minute timeout
            print("Automation completed successfully")
            
            # Extract the results and information
            result = {
                "final_result": history.final_result(),
                "success": history.is_done(),
                "errors": history.errors(),
                "visited_urls": history.urls(),
                "screenshots": history.screenshots(),
                "action_names": history.action_names()
            }
            
            return result
        except asyncio.TimeoutError:
            return {
                "success": False,
                "errors": ["Automation timed out after 10 minutes"],
                "final_result": "The automation process took too long and was terminated."
            }
    
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"Error in LinkedIn automation: {str(e)}")
        print(error_traceback)
        return {
            "success": False,
            "errors": [str(e), error_traceback],
            "final_result": f"Error occurred: {str(e)}"
        }
    finally:
        # Ensure browser is closed properly
        if browser:
            try:
                await browser.close()
                print("Browser closed successfully")
            except Exception as close_error:
                print(f"Error closing browser: {str(close_error)}")

def run_automation(prompt, uploaded_image_path=None):
    """
    Wrapper function to run the async LinkedIn automation
    
    Args:
        prompt (str): The instruction for the agent
        uploaded_image_path (str, optional): Path to the uploaded screenshot of LinkedIn UI
    
    Returns:
        dict: Results of the automation
    """
    try:
        print(f"Starting LinkedIn automation with prompt: {prompt[:100]}...")
        if uploaded_image_path:
            print(f"Using uploaded image: {uploaded_image_path}")
        
        # Verify that the Anthropic API key is set
        if not os.getenv("ANTHROPIC_API_KEY"):
            return {
                "success": False,
                "errors": ["Anthropic API key is not set. Please check your .env file."],
                "final_result": "Configuration error: Anthropic API key is missing."
            }
        
        # Run the automation in an async context
        return asyncio.run(run_linkedin_automation(prompt, uploaded_image_path))
    except Exception as e:
        error_traceback = traceback.format_exc()
        print(f"Error in run_automation wrapper: {str(e)}")
        print(error_traceback)
        return {
            "success": False,
            "errors": [str(e), error_traceback],
            "final_result": f"Error occurred in automation wrapper: {str(e)}"
        }