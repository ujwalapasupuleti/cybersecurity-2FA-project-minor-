from flask import Flask, render_template, request, redirect, url_for, session
import pyotp
import qrcode
import base64
from io import BytesIO
import os
import json # <-- Import JSON library for file persistence

# --- FLASK SETUP ---
app = Flask(__name__)
# IMPORTANT: This secret key is used to secure sessions (cookies). 
# You MUST change this to a strong, random value for any real application.
app.secret_key = 'your_strong_secret_key_here_for_sessions' 

# --- DATA PERSISTENCE SETUP ---
DATA_FILE = 'users.json'
USERS = {} # Global dictionary to hold user data in memory

def load_users():
    """Loads user data from the JSON file into the USERS dictionary."""
    global USERS
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                USERS = json.load(f)
            print(f"Data loaded from {DATA_FILE}. Total users: {len(USERS)}")
        except json.JSONDecodeError:
            print(f"Warning: Could not decode JSON from {DATA_FILE}. Starting with empty user list.")
            USERS = {}
    else:
        print(f"Starting new application. {DATA_FILE} not found.")

def save_users():
    """Saves the current state of the USERS dictionary to the JSON file."""
    global USERS
    with open(DATA_FILE, 'w') as f:
        json.dump(USERS, f, indent=4)
    print(f"Data saved to {DATA_FILE}.")

# --- ROUTES ---

@app.route('/')
def index():
    """Initial login/registration page."""
    # Check if the user is already authenticated with a session cookie
    if 'username' in session and USERS.get(session['username'], {}).get('2fa_enabled'):
        # If logged in and 2FA is enabled, show the success page
        return redirect(url_for('success'))
    
    # Otherwise, show the login template
    return render_template('login.html')

@app.route('/register', methods=['POST'])
def register():
    """Handles new user registration and sets up the 2FA secret."""
    username = request.form['username']
    
    if username in USERS:
        # Simple error handling for existing user
        return render_template('login.html', error="User already exists. Please log in.")

    # 1. Generate the shared secret key (the core of 2FA)
    secret = pyotp.random_base32()
    
    # Store user data with 2FA initially disabled
    USERS[username] = {'secret': secret, '2fa_enabled': False}
    
    # Save the updated user data to the file immediately
    save_users() 
    
    # Redirect to the 2FA setup page to show the QR code
    return redirect(url_for('setup_2fa', username=username))

@app.route('/setup_2fa/<username>')
def setup_2fa(username, error=None):
    """Generates the QR code for the user to scan with their authenticator app."""
    user_data = USERS.get(username)
    
    # Security check: User must exist and 2FA must not already be enabled
    if not user_data or user_data['2fa_enabled']:
        return redirect(url_for('index'))

    secret = user_data['secret']
    
    # 2. Create the Provisioning URI
    # This URI is a standard format understood by authenticator apps
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="CyberSecProject"
    )

    # 3. Generate QR Code image and encode it as Base64 for display in HTML
    img_buffer = BytesIO()
    qr_img = qrcode.make(totp_uri)
    qr_img.save(img_buffer, format="PNG")
    qr_base64 = base64.b64encode(img_buffer.getvalue()).decode('utf-8')
    
    # Render the setup page with the Base64 QR code data and any error message
    return render_template('setup_2fa.html', 
                           username=username, 
                           qr_code_data=qr_base64,
                           error=error)

@app.route('/verify_setup', methods=['POST'])
def verify_setup():
    """Verifies the first 2FA code to confirm the user successfully scanned the QR code."""
    username = request.form['username']
    otp_code = request.form['otp_code']
    user_data = USERS.get(username)

    if not user_data:
        return redirect(url_for('index'))

    # 4. Verification Step (using the stored secret)
    secret = user_data['secret']
    totp = pyotp.TOTP(secret)
    
    # The verify method checks the current time step and adjacent steps (for clock drift)
    if totp.verify(otp_code):
        # Setup successful, enable 2FA for this user
        USERS[username]['2fa_enabled'] = True
        session['username'] = username # Log the user in
        
        # Save the change in 2FA status to the file immediately
        save_users() 
        
        return redirect(url_for('success'))
    else:
        # Failure: We call the setup_2fa function directly to pass the error message
        error_msg = "Invalid code. Please re-scan the QR code or check your app's clock and try again."
        return setup_2fa(username, error=error_msg)

@app.route('/login', methods=['POST'])
def login():
    """Handles the final login attempt, requiring the 2FA code."""
    username = request.form['username']
    otp_code = request.form['otp_code']
    
    # NOTE: In a real app, you would first verify the password associated with 'username' here!
    
    user_data = USERS.get(username)

    if not user_data:
        return render_template('login.html', error="User not registered.")

    # Require 2FA if it's enabled
    if not user_data['2fa_enabled']:
        return redirect(url_for('setup_2fa', username=username))

    # 5. Final Verification during Login
    secret = user_data['secret']
    totp = pyotp.TOTP(secret)

    if totp.verify(otp_code):
        session['username'] = username # Login successful
        return redirect(url_for('success'))
    else:
        return render_template('login.html', error="Invalid 2FA code.")

@app.route('/success')
def success():
    """The landing page after successful 2FA authentication."""
    if 'username' in session:
        return render_template('success.html', username=session['username'])
    # Redirect if no session exists (not logged in)
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Clears the session and logs the user out."""
    session.pop('username', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    # Load data from file before starting the server
    load_users() 
    
    # Running the Flask app.
    # We use 'use_reloader=False' to fix the continuous restarting issue you observed.
    print("--- SERVER STARTING ---")
    print("Access the application at http://127.0.0.1:5000/")
    app.run(debug=True, use_reloader=False)
