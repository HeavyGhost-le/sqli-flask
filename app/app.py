from flask import Flask, request, render_template_string, session, redirect, g
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = 'super_secret_key_123'
FLAG = "flag{sql1_m4st3r_xyz789}"

# Initialize database connection
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(':memory:', check_same_thread=False)
        g.db.row_factory = sqlite3.Row
        init_db(g.db)
    return g.db

# Initialize database tables and data
def init_db(conn):
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            description TEXT,
            price REAL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE flags (
            id INTEGER PRIMARY KEY,
            flag TEXT
        )
    ''')
    
    # Insert initial data
    cursor.execute("INSERT INTO users VALUES (1, 'admin', ?, 1)", 
                  (hashlib.sha256('SuperSecureAdminPass123!'.encode()).hexdigest(),))
    cursor.execute("INSERT INTO users VALUES (2, 'guest', ?, 0)", 
                  (hashlib.sha256('guest_password'.encode()).hexdigest(),))
    cursor.execute("INSERT INTO products VALUES (1, 'Apple', 'Fresh red apple', 1.99)")
    cursor.execute("INSERT INTO products VALUES (2, 'Banana', 'Yellow banana', 0.99)")
    cursor.execute(f"INSERT INTO flags VALUES (1, '{FLAG}')")
    
    conn.commit()

@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# Home page
@app.route('/')
def index():
    return render_template_string('''
        <html>
        <head>
            <title>Product Search</title>
            <style>
                body { font-family: 'Courier New', monospace; background-color: #1e1e1e; color: #fff; margin: 0; padding: 20px; }
                .container { max-width: 800px; margin: 0 auto; padding: 20px; background-color: #2e2e2e; border-radius: 8px; }
                h1 { color: #0f0; }
                .search-box { margin: 20px 0; }
                input, button { padding: 10px; margin: 5px 0; border-radius: 4px; }
                input { width: 100%; background-color: #333; color: #fff; border: 1px solid #444; }
                button { background-color: #0f0; color: #000; border: none; cursor: pointer; }
                button:hover { background-color: #0c0; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { border: 1px solid #444; padding: 8px; text-align: left; }
                th { background-color: #444; }
                .error { color: #f00; }
                .message { color: #0f0; }
                a { color: #0f0; text-decoration: none; }
                a:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Product Search</h1>
                {% if 'username' in session %}
                    <p>Welcome, {{ session['username'] }}! <a href="/logout">Logout</a></p>
                    {% if session.get('is_admin') %}
                        <p><a href="/admin">Admin Panel</a></p>
                    {% endif %}
                {% else %}
                    <p><a href="/login">Login</a> or <a href="/register">Register</a></p>
                {% endif %}
                
                <div class="search-box">
                    <form action="/search" method="GET">
                        <input type="text" name="query" placeholder="Search products..." required>
                        <button type="submit">Search</button>
                    </form>
                </div>
                
                {% if error %}
                    <p class="error">{{ error }}</p>
                {% endif %}
            </div>
        </body>
        </html>
    ''', error=request.args.get('error'))

# Search function with SQL injection vulnerability
@app.route('/search')
def search():
    query = request.args.get('query', '')
    
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%' OR description LIKE '%{query}%'")
        results = cursor.fetchall()
        
        return render_template_string('''
            <html>
            <head>
                <title>Search Results</title>
                <style>
                    body { font-family: 'Courier New', monospace; background-color: #1e1e1e; color: #fff; }
                    .container { max-width: 800px; margin: 0 auto; padding: 20px; background-color: #2e2e2e; border-radius: 8px; }
                    h2 { color: #0f0; }
                    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                    th, td { border: 1px solid #444; padding: 8px; text-align: left; }
                    th { background-color: #444; }
                    a { color: #0f0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Search Results for "{{ query }}"</h2>
                    {% if results %}
                        <table>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Description</th>
                                <th>Price</th>
                            </tr>
                            {% for product in results %}
                                <tr>
                                    <td>{{ product[0] }}</td>
                                    <td>{{ product[1] }}</td>
                                    <td>{{ product[2] }}</td>
                                    <td>${{ "%.2f"|format(product[3]) }}</td>
                                </tr>
                            {% endfor %}
                        </table>
                    {% else %}
                        <p>No products found.</p>
                    {% endif %}
                    <p><a href="/">Back to search</a></p>
                </div>
            </body>
            </html>
        ''', query=query, results=results)
    
    except Exception as e:
        return redirect(f'/?error={str(e)}')

# Registration system
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            return redirect('/register?error=Username+and+password+required')
        
        if len(password) < 8:
            return redirect('/register?error=Password+must+be+at+least+8+characters')
        
        try:
            db = get_db()
            cursor = db.cursor()
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                          (username, hashed_password))
            db.commit()
            return redirect('/login?message=Registration+successful!+Please+login.')
        except sqlite3.IntegrityError:
            return redirect('/register?error=Username+already+exists')
    
    return render_template_string('''
        <html>
        <head>
            <title>Register</title>
            <style>
                body { font-family: 'Courier New', monospace; background-color: #1e1e1e; color: #fff; }
                .container { max-width: 400px; margin: 0 auto; padding: 20px; background-color: #2e2e2e; border-radius: 8px; }
                h1 { color: #0f0; }
                input { width: 100%; padding: 10px; margin: 5px 0; background-color: #333; color: #fff; border: 1px solid #444; border-radius: 4px; }
                button { background-color: #0f0; color: #000; border: none; padding: 10px; border-radius: 4px; cursor: pointer; }
                button:hover { background-color: #0c0; }
                .error { color: #f00; }
                a { color: #0f0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Register</h1>
                {% if error %}
                    <p class="error">{{ error }}</p>
                {% endif %}
                <form method="POST">
                    <div>
                        <label>Username:</label>
                        <input type="text" name="username" required>
                    </div>
                    <div>
                        <label>Password (min 8 chars):</label>
                        <input type="password" name="password" required minlength="8">
                    </div>
                    <button type="submit">Register</button>
                </form>
                <p>Already have an account? <a href="/login">Login</a></p>
            </div>
        </body>
        </html>
    ''', error=request.args.get('error'))

# Login system
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        
        if user:
            session['username'] = username
            session['is_admin'] = bool(user['is_admin'])
            if user['is_admin']:
                return redirect('/admin')
            return redirect('/')
        else:
            return redirect('/login?error=Invalid+credentials')
    
    return render_template_string('''
        <html>
        <head>
            <title>Login</title>
            <style>
                body { font-family: 'Courier New', monospace; background-color: #1e1e1e; color: #fff; }
                .container { max-width: 400px; margin: 0 auto; padding: 20px; background-color: #2e2e2e; border-radius: 8px; }
                h1 { color: #0f0; }
                input { width: 100%; padding: 10px; margin: 5px 0; background-color: #333; color: #fff; border: 1px solid #444; border-radius: 4px; }
                button { background-color: #0f0; color: #000; border: none; padding: 10px; border-radius: 4px; cursor: pointer; }
                button:hover { background-color: #0c0; }
                .error { color: #f00; }
                .message { color: #0f0; }
                a { color: #0f0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Login</h1>
                {% if error %}
                    <p class="error">{{ error }}</p>
                {% endif %}
                {% if message %}
                    <p class="message">{{ message }}</p>
                {% endif %}
                <form method="POST">
                    <div>
                        <label>Username:</label>
                        <input type="text" name="username" required>
                    </div>
                    <div>
                        <label>Password:</label>
                        <input type="password" name="password" required>
                    </div>
                    <button type="submit">Login</button>
                </form>
                <p>Don't have an account? <a href="/register">Register</a></p>
            </div>
        </body>
        </html>
    ''', error=request.args.get('error'), message=request.args.get('message'))

# Admin panel
@app.route('/admin')
def admin():
    if 'username' not in session or not session.get('is_admin'):
        return "Access denied", 403
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM flags")
    flag = cursor.fetchone()
    
    return f'''
        <html>
        <head>
            <title>Admin Panel</title>
            <style>
                body { font-family: 'Courier New', monospace; background-color: #1e1e1e; color: #fff; }
                .container { max-width: 800px; margin: 0 auto; padding: 20px; background-color: #2e2e2e; border-radius: 8px; }
                h1 { color: #0f0; }
                .flag { font-size: 1.5em; color: #ff0; background-color: #333; padding: 10px; border-radius: 4px; }
                a { color: #0f0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Admin Panel</h1>
                <p>Welcome, admin!</p>
                <div class="flag">Flag: {flag['flag']}</div>
                <p><a href="/">Back to search</a></p>
            </div>
        </body>
        </html>
    '''

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
