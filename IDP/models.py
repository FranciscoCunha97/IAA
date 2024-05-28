import sqlite3
import time
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = 'database.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS user (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        phone TEXT UNIQUE,
        pin TEXT,
        citizen_card TEXT UNIQUE
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS oauth2_client (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        client_id TEXT UNIQUE NOT NULL,
        client_secret TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        criticality_level TEXT NOT NULL DEFAULT 'low',
        FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS oauth2_authorization_code (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        client_id TEXT NOT NULL,
        code TEXT UNIQUE NOT NULL,
        redirect_uri TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY(client_id) REFERENCES oauth2_client(client_id) ON DELETE CASCADE
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS oauth2_token (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        client_id TEXT NOT NULL,
        access_token TEXT UNIQUE NOT NULL,
        refresh_token TEXT UNIQUE,
        expires_at INTEGER NOT NULL,
        revoked INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES user(id) ON DELETE CASCADE,
        FOREIGN KEY(client_id) REFERENCES oauth2_client(client_id) ON DELETE CASCADE
    )
    ''')

    conn.commit()
    conn.close()

def add_user(username, email, password):
    conn = get_db()
    cursor = conn.cursor()
    hashed_password = generate_password_hash(password)
    cursor.execute('INSERT INTO user (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_password))
    conn.commit()
    conn.close()

def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE email = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_username(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM user WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def add_oauth2_client(user_id, client_id, client_secret, redirect_uri, criticality_level):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO oauth2_client (user_id, client_id, client_secret, redirect_uri, criticality_level) 
    VALUES (?, ?, ?, ?, ?)''', (user_id, client_id, client_secret, redirect_uri, criticality_level))
    conn.commit()
    conn.close()

def get_oauth2_client(client_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM oauth2_client WHERE client_id = ?', (client_id,))
    client = cursor.fetchone()
    conn.close()
    return client

def add_oauth2_authorization_code(user_id, client_id, code, redirect_uri, expires_at):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO oauth2_authorization_code (user_id, client_id, code, redirect_uri, expires_at) 
    VALUES (?, ?, ?, ?, ?)''', (user_id, client_id, code, redirect_uri, expires_at))
    conn.commit()
    conn.close()

def get_oauth2_authorization_code(code):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM oauth2_authorization_code WHERE code = ?', (code,))
    authorization_code = cursor.fetchone()
    conn.close()
    return authorization_code

def add_oauth2_token(user_id, client_id, access_token, refresh_token, expires_at):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO oauth2_token (user_id, client_id, access_token, refresh_token, expires_at) 
    VALUES (?, ?, ?, ?, ?)''', (user_id, client_id, access_token, refresh_token, expires_at))
    conn.commit()
    conn.close()

def get_oauth2_token(access_token):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM oauth2_token WHERE access_token = ?', (access_token,))
    token = cursor.fetchone()
    conn.close()
    return token

def introspect_token(access_token):
    token = get_oauth2_token(access_token)
    if token and token['expires_at'] > int(time.time()) and token['revoked'] == 0:
        return {
            'active': True,
            'user_id': token['user_id'],
            'client_id': token['client_id'],
            'expires_at': token['expires_at']
        }
    return {'active': False}

def revoke_token(access_token):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE oauth2_token SET revoked = 1 WHERE access_token = ?', (access_token,))
    conn.commit()
    conn.close()
