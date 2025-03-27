// static/js/automation.js

document.addEventListener('DOMContentLoaded', function() {
    // Elements
    const form = document.getElementById('automationForm');
    const runButton = document.getElementById('runButton');
    const stopButton = document.getElementById('stopButton');
    const promptTextarea = document.getElementById('prompt');
    
    // State
    let automationRunning = false;
    
    // Fill prompt from sample
    window.fillPrompt = function(element) {
        promptTextarea.value = element.innerText;
        // Scroll to the form
        promptTextarea.scrollIntoView({ behavior: 'smooth' });
        // Focus the textarea
        promptTextarea.focus();
    };
    
    // Start automation
    form.addEventListener('submit', function(e) {
        if (!automationRunning) {
            automationRunning = true;
            runButton.classList.add('loading');
            runButton.querySelector('.btn-text').innerText = 'Running Automation...';
            runButton.style.display = 'none';
            stopButton.style.display = 'block';
        }
    });
    
    // Stop automation
    stopButton.addEventListener('click', function() {
        // In a real implementation, this would need to communicate 
        // with the backend to stop the automation process
        
        // For now, we'll just simulate stopping by changing the UI
        automationRunning = false;
        stopButton.style.display = 'none';
        runButton.style.display = 'block';
        runButton.classList.remove('loading');
        runButton.querySelector('.btn-text').innerText = 'Run Automation';
        
        // Flash a message that automation was stopped
        showFlashMessage('Automation stopped by user', 'warning');
    });
    
    // Helper function to show flash messages
    function showFlashMessage(message, type = 'info') {
        const flashContainer = document.createElement('div');
        flashContainer.className = `alert alert-${type}`;
        flashContainer.textContent = message;
        
        // Insert at the top of the card
        const card = document.querySelector('.card');
        card.insertBefore(flashContainer, card.firstChild);
        
        // Remove the flash message after 3 seconds
        setTimeout(() => {
            flashContainer.remove();
        }, 3000);
    }
    
    // Image preview functionality
    const imageInput = document.getElementById('linkedin_image');
    const previewContainer = document.getElementById('image-preview');
    
    if (imageInput) {
        imageInput.addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                // Show filename
                const small = this.nextElementSibling;
                small.textContent = `Selected file: ${file.name}`;
                
                // Create image preview
                previewContainer.innerHTML = '';
                previewContainer.style.display = 'block';
                
                const img = document.createElement('img');
                img.src = URL.createObjectURL(file);
                img.onload = function() {
                    URL.revokeObjectURL(this.src);
                };
                
                previewContainer.appendChild(img);
            } else {
                // Reset preview
                previewContainer.style.display = 'none';
                previewContainer.innerHTML = '';
            }
        });
    }
});