import time
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps

app = Flask(__name__)

# Secret key for session management (change this in production!)
app.secret_key = 'your_secret_key'

# A simple function to check the status of a website
def check_website_status(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return "Up", response.status_code
        else:
            return "Down", response.status_code
    except requests.RequestException as e:
        return "Down", str(e)

# Dummy user data for login
USER_CREDENTIALS = {
    'username': 'admin',
    'password': 'password123'
}

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if the username and password are correct
        if username == USER_CREDENTIALS['username'] and password == USER_CREDENTIALS['password']:
            session['username'] = username  # Store username in session
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Homepage route (protected by login_required)
@app.route('/')
@login_required
def index():
    websites = [
        {"name": "Google", "url": "https://www.google.com"},
        {"name": "StackOverflow", "url": "https://stackoverflow.com"},
        {"name": "GitHub", "url": "https://github.com"},
    ]
    
    statuses = []
    for site in websites:
        status, code_or_error = check_website_status(site['url'])
        statuses.append({
            'name': site['name'],
            'url': site['url'],
            'status': status,
            'code_or_error': code_or_error
        })

    return render_template('index.html', statuses=statuses)

if __name__ == '__main__':
    app.run(debug=True)
