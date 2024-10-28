from flask import Flask, redirect, url_for, session, request
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from google.auth.transport import requests
import os

app = Flask(__name__)
app.secret_key = 'YOUR_SECRET_KEY'
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Only for testing without HTTPS

# Configure OAuth 2.0
GOOGLE_CLIENT_ID = ""
client_secrets_file = ""
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"]

# Initialize OAuth 2.0 flow
flow = Flow.from_client_secrets_file(client_secrets_file, scopes=SCOPES)
flow.redirect_uri = "http://127.0.0.1:8000/api/google/callback"

@app.route('/')
def index():
    if session.get('logged_in', False):
        return redirect('/profile')
    return "Welcome! <a href='/login'>Login with Google</a>"

@app.route('/login')
def login():
    # Generate authorization URL and redirect user
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/api/google/callback')
def callback():
    # Retrieve state and authorization response
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    request_session = requests.Request()
    
    # Verify and get user information
    id_info = id_token.verify_oauth2_token(
        credentials._id_token, request_session, GOOGLE_CLIENT_ID
    )
    session['user_info'] = id_info
    session['logged_in'] = True
    # Extract user info
    return redirect('/profile')

@app.route('/profile')
def profile():
    if session.get('logged_in', False):
        id_info = session.get('user_info')
        user_info = {
            "name": id_info.get("name"),
            "email": id_info.get("email"),
            "picture": id_info.get("picture")
        }
        
        # Display user information
        return f"""
        <h1>Welcome, {user_info['name']}!</h1>
        <p>Email: {user_info['email']}</p>
        <img src="{user_info['picture']}" alt="User's profile picture">
        <a href='/logout'>Logout</a>
        """
    
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True, port=8000)
