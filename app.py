from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a random secret key

# Initialize database
def init_db():
    conn = sqlite3.connect('gmlist.db')
    cursor = conn.cursor()
    
    # Check if users table exists and get its schema
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Add is_admin column if it doesn't exist
    if 'is_admin' not in columns:
        cursor.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')
    
    # Checklists table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS checklists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Tasks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checklist_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            is_completed INTEGER DEFAULT 0,
            priority TEXT DEFAULT 'medium',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (checklist_id) REFERENCES checklists (id) ON DELETE CASCADE
        )
    ''')
    
    # Create default admin user
    cursor.execute('SELECT * FROM users WHERE email = ?', ('admin@gmlist.com',))
    if not cursor.fetchone():
        admin_password = generate_password_hash('admin123')
        cursor.execute('INSERT INTO users (name, email, password, is_admin) VALUES (?, ?, ?, ?)',
                      ('Admin User', 'admin@gmlist.com', admin_password, 1))
    
    conn.commit()
    conn.close()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = sqlite3.connect('gmlist.db')
        cursor = conn.cursor()
        cursor.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        
        if not user or not user[0]:
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('gmlist.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, name, password, is_admin FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            session['user_id'] = user[0]
            session['user_name'] = user[1]
            session['is_admin'] = user[3]
            flash(f'Welcome back, {user[1]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password!', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect('gmlist.db')
        cursor = conn.cursor()
        
        try:
            hashed_password = generate_password_hash(password)
            cursor.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
                         (name, email, hashed_password))
            conn.commit()
            flash('Account created successfully! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists!', 'error')
        finally:
            conn.close()
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('gmlist.db')
    cursor = conn.cursor()
    
    # Get user's checklists with task counts
    cursor.execute('''
        SELECT c.id, c.title, c.description, c.created_at, c.updated_at,
               COUNT(t.id) as total_tasks,
               COUNT(CASE WHEN t.is_completed = 1 THEN 1 END) as completed_tasks
        FROM checklists c
        LEFT JOIN tasks t ON c.id = t.checklist_id
        WHERE c.user_id = ?
        GROUP BY c.id, c.title, c.description, c.created_at, c.updated_at
        ORDER BY c.updated_at DESC
    ''', (session['user_id'],))
    
    checklists = cursor.fetchall()
    conn.close()
    
    return render_template('dashboard.html', checklists=checklists)

@app.route('/checklist/<int:checklist_id>')
@login_required
def view_checklist(checklist_id):
    conn = sqlite3.connect('gmlist.db')
    cursor = conn.cursor()
    
    # Get checklist details
    cursor.execute('SELECT * FROM checklists WHERE id = ? AND user_id = ?', 
                  (checklist_id, session['user_id']))
    checklist = cursor.fetchone()
    
    if not checklist:
        flash('Checklist not found!', 'error')
        return redirect(url_for('dashboard'))
    
    # Get tasks
    cursor.execute('''
        SELECT id, title, description, is_completed, priority, created_at, completed_at
        FROM tasks WHERE checklist_id = ?
        ORDER BY is_completed ASC, created_at ASC
    ''', (checklist_id,))
    
    tasks = cursor.fetchall()
    conn.close()
    
    return render_template('checklist.html', checklist=checklist, tasks=tasks)

@app.route('/create_checklist', methods=['GET', 'POST'])
@login_required
def create_checklist():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        
        conn = sqlite3.connect('gmlist.db')
        cursor = conn.cursor()
        cursor.execute('INSERT INTO checklists (user_id, title, description) VALUES (?, ?, ?)',
                      (session['user_id'], title, description))
        checklist_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        flash('Checklist created successfully!', 'success')
        return redirect(url_for('view_checklist', checklist_id=checklist_id))
    
    return render_template('create_checklist.html')

@app.route('/edit_checklist/<int:checklist_id>', methods=['GET', 'POST'])
@login_required
def edit_checklist(checklist_id):
    conn = sqlite3.connect('gmlist.db')
    cursor = conn.cursor()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        
        cursor.execute('''
            UPDATE checklists SET title = ?, description = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE id = ? AND user_id = ?
        ''', (title, description, checklist_id, session['user_id']))
        
        if cursor.rowcount:
            conn.commit()
            flash('Checklist updated successfully!', 'success')
        else:
            flash('Checklist not found!', 'error')
        
        conn.close()
        return redirect(url_for('view_checklist', checklist_id=checklist_id))
    
    # Get checklist for editing
    cursor.execute('SELECT * FROM checklists WHERE id = ? AND user_id = ?', 
                  (checklist_id, session['user_id']))
    checklist = cursor.fetchone()
    conn.close()
    
    if not checklist:
        flash('Checklist not found!', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_checklist.html', checklist=checklist)

@app.route('/delete_checklist/<int:checklist_id>', methods=['POST'])
@login_required
def delete_checklist(checklist_id):
    conn = sqlite3.connect('gmlist.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM checklists WHERE id = ? AND user_id = ?', 
                  (checklist_id, session['user_id']))
    
    if cursor.rowcount:
        flash('Checklist deleted successfully!', 'success')
    else:
        flash('Checklist not found!', 'error')
    
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/add_task/<int:checklist_id>', methods=['POST'])
@login_required
def add_task(checklist_id):
    title = request.form['title']
    description = request.form.get('description', '')
    priority = request.form.get('priority', 'medium')
    
    conn = sqlite3.connect('gmlist.db')
    cursor = conn.cursor()
    
    # Verify checklist belongs to user
    cursor.execute('SELECT id FROM checklists WHERE id = ? AND user_id = ?', 
                  (checklist_id, session['user_id']))
    if not cursor.fetchone():
        flash('Checklist not found!', 'error')
        return redirect(url_for('dashboard'))
    
    cursor.execute('INSERT INTO tasks (checklist_id, title, description, priority) VALUES (?, ?, ?, ?)',
                  (checklist_id, title, description, priority))
    
    # Update checklist timestamp
    cursor.execute('UPDATE checklists SET updated_at = CURRENT_TIMESTAMP WHERE id = ?', (checklist_id,))
    
    conn.commit()
    conn.close()
    
    flash('Task added successfully!', 'success')
    return redirect(url_for('view_checklist', checklist_id=checklist_id))

@app.route('/toggle_task/<int:task_id>', methods=['POST'])
@login_required
def toggle_task(task_id):
    conn = sqlite3.connect('gmlist.db')
    cursor = conn.cursor()
    
    # Get task and verify ownership
    cursor.execute('''
        SELECT t.id, t.is_completed, t.checklist_id
        FROM tasks t
        JOIN checklists c ON t.checklist_id = c.id
        WHERE t.id = ? AND c.user_id = ?
    ''', (task_id, session['user_id']))
    
    task = cursor.fetchone()
    if not task:
        return jsonify({'success': False, 'message': 'Task not found'})
    
    new_status = 1 if not task[1] else 0
    completed_at = datetime.now() if new_status else None
    
    cursor.execute('UPDATE tasks SET is_completed = ?, completed_at = ? WHERE id = ?',
                  (new_status, completed_at, task_id))
    
    # Update checklist timestamp
    cursor.execute('UPDATE checklists SET updated_at = CURRENT_TIMESTAMP WHERE id = ?', (task[2],))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'completed': bool(new_status)})

@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    conn = sqlite3.connect('gmlist.db')
    cursor = conn.cursor()
    
    # Get task and verify ownership
    cursor.execute('''
        SELECT t.checklist_id
        FROM tasks t
        JOIN checklists c ON t.checklist_id = c.id
        WHERE t.id = ? AND c.user_id = ?
    ''', (task_id, session['user_id']))
    
    task = cursor.fetchone()
    if not task:
        flash('Task not found!', 'error')
        return redirect(url_for('dashboard'))
    
    checklist_id = task[0]
    cursor.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    
    # Update checklist timestamp
    cursor.execute('UPDATE checklists SET updated_at = CURRENT_TIMESTAMP WHERE id = ?', (checklist_id,))
    
    conn.commit()
    conn.close()
    
    flash('Task deleted successfully!', 'success')
    return redirect(url_for('view_checklist', checklist_id=checklist_id))


if __name__ == '__main__':
    init_db()
    app.run(debug=True)