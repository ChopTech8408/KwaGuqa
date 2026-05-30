import os
import bcrypt
import sqlite3
from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__,
            template_folder=os.path.abspath('../frontend/templates'),
            static_folder=os.path.abspath('../frontend/static'))

DB_PATH = os.path.abspath('../frontend/database.db')

def hash_password(plain_text_password):
    #Convert the string password into bytes
    password_bytes = plain_text_password.encode('utf-8')

    #Generate a salt and hash the password
    #gensalt() generates a random salt, and hashpw() hashes the password with the salt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)

    #Return the hash decoded back to a string for storage
    return hashed_password.decode('utf-8')

def verify_password(plain_text_password, stored_hash):
    """Compares a plain text password with a stored hash."""
    return bcrypt.checkpw(plain_text_password.encode('utf-8'), stored_hash.encode('utf-8'))

@app.route('/')
def home():
    # Renders your index.html from frontend/templates/
    return render_template('index.html')


@app.route('/register', methods=['POST'])
def register():
    """Handles user sign-up, hashes password, and saves to SQLite."""
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not username or not email or not password:
        return "All fields are required!", 400

    # 1. Secure the password
    hashed_password = hash_password(password)
    
    # 2. Insert into database
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO users (username, password, email) 
            VALUES (?, ?, ?)
        """, (username, hashed_password, email))
        conn.commit()
        return "Registration successful! You can now log in."
    except sqlite3.IntegrityError:
        # Fires if username or email breaks the UNIQUE constraint
        return "Error: Username or Email already exists!", 400
    finally:
        conn.close()


@app.route('/login', methods=['POST'])
def login():
    """Handles user authentication by verifying the bcrypt hash."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Fetch user data based on username
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        stored_hash = user[0]
        # Verify if the submitted password matches the hashed password in DB
        if verify_password(password, stored_hash):
            return f"Welcome back, {username}! Login successful."
        
    return "Invalid username or password!", 401


if __name__ == '__main__':
    # Runs the server locally at http://127.0.0.1:5000
    app.run(debug=True)