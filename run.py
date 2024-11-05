from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'votre_clé_secrète'

# SQLite database file
DATABASE = 'WipiLog.db'

# Function to get a database connection
def get_db():
    conn = sqlite3.connect(DATABASE)
    return conn

# Function to initialize the database and insert a default user
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Create the users table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL UNIQUE,
                            password TEXT NOT NULL
                          )''')
        
        # Insert a default user if the table is empty
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        if user_count == 0:
            default_username = 'admin'
            default_password = 'adminpassword'
            
            # Hash the default password
            hashed_password = generate_password_hash(default_password, method='pbkdf2:sha256')

            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                           (default_username, hashed_password))
            db.commit()
            print("Default user 'admin' created with password 'adminpassword'.")

# Route to register a new user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password before storing
        hashed_password = generate_password_hash(password, method='sha256')

        # Check if the user already exists
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user:
            flash('Username already taken, try another one.', 'danger')
        else:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
            db.commit()
            flash('User successfully created!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

# Route to log in
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check user credentials
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):  # user[2] is the hashed password
            session['user_id'] = user[0]  # Store user ID in the session
            flash('Successfully logged in!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to dashboard
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

# Route to the dashboard (accessible only after login)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template('index.html')

# Route to log out
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Start the app
if __name__ == '__main__':
    init_db()  # Initialize the database with the default user
    app.run(debug=True)
