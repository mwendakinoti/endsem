// ai-assistant.js
const GEMINI_API_KEY = 'AIzaSyAiNQbie0EljXvXTLR4WmZ4YpkkraFP6uk'; 
const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent';

function initChatbot() {
    const chatInput = document.getElementById('chat-input');
    const chatSubmit = document.getElementById('chat-submit');
    const chatMessages = document.getElementById('chat-messages');

    chatSubmit.addEventListener('click', sendMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    function sendMessage() {
        const message = chatInput.value.trim();
        if (message) {
            addMessage('user', message);
            chatInput.value = '';
            fetchGeminiResponse(message);
        }
    }

    function addMessage(sender, text) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', `${sender}-message`);
        messageElement.textContent = text;
        chatMessages.appendChild(messageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    async function fetchGeminiResponse(prompt) {
        try {
            const requestBody = {
                contents: [{
                    parts: [{
                        text: prompt
                    }]
                }]
            };
            console.log('Request body:', JSON.stringify(requestBody, null, 2));
    
            const response = await fetch(`${GEMINI_API_URL}?key=${GEMINI_API_KEY}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody)
            });
    
            console.log('Response status:', response.status);
            const responseText = await response.text();
            console.log('Response body:', responseText);
    
            if (!response.ok) {
                throw new Error(`API request failed with status ${response.status}: ${responseText}`);
            }
    
            const data = JSON.parse(responseText);
            const botResponse = data.candidates[0].content.parts[0].text;
            addMessage('bot', botResponse);
        } catch (error) {
            console.error('Error details:', error);
            addMessage('bot', `Sorry, I encountered an error: ${error.message}`);
        }
    }

    // Add a welcome message
    addMessage('bot', 'Hello! I\'m your AI assistant for Twerandus Sacco. How can I help you today?');
}

// Initialize the chatbot when the page loads
document.addEventListener('DOMContentLoaded', initChatbot);