from flask import Flask, render_template, request, session, redirect, url_for, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3,json, random, os
# from datetime import datetime

app = Flask(__name__)
app.secret_key = 'Project'
DATABASE = 'quiz.db'

# Database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Initialize database
def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS quiz_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                subject TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                score INTEGER NOT NULL,
                total_questions INTEGER NOT NULL,
                percentage REAL NOT NULL,
                completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        db.commit()

# Load questions from JSON
def load_questions():
    with open('questions.json', 'r') as f:
        return json.load(f)

# Helper function to execute queries
def query_db(query, args=(), one=False, commit=False):
    cur = get_db().execute(query, args)
    if commit:
        get_db().commit()
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if user exists
        if query_db('SELECT id FROM users WHERE username = ?', [username], one=True):
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        
        if query_db('SELECT id FROM users WHERE email = ?', [email], one=True):
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        
        # Hash password and create user
        hashed_password = generate_password_hash(password)
        query_db('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                [username, email, hashed_password], commit=True)
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('home'))
        
        flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get user's quiz history
    history = query_db('''
        SELECT subject, difficulty, score, total_questions, percentage, completed_at 
        FROM quiz_history 
        WHERE user_id = ? 
        ORDER BY completed_at DESC 
        LIMIT 5
    ''', [session['user_id']])
    
    return render_template('home.html', username=session['username'], history=history)

@app.route('/start_quiz', methods=['POST'])
def start_quiz():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    subject = request.form.get('subject')
    difficulty = request.form.get('difficulty')
    
    all_questions = load_questions()
    
    # Filter questions by subject and difficulty
    filtered_questions = [q for q in all_questions 
                         if q['subject'] == subject and q['difficulty'] == difficulty]
    
    # Randomly select 10 questions
    selected_questions = random.sample(filtered_questions, 
                                      min(10, len(filtered_questions)))
    
    # Store in session
    session['questions'] = selected_questions
    session['current_question'] = 0
    session['score'] = 0
    session['subject'] = subject
    session['difficulty'] = difficulty
    
    return redirect(url_for('quiz'))


@app.route('/quiz', methods=['GET', 'POST'])
def quiz():
    if 'questions' not in session or 'user_id' not in session:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        # Check answer
        user_answer = request.form.get('answer')
        current_q = session['current_question']
        correct_answer = session['questions'][current_q]['answer']
        
        if user_answer == correct_answer:
            session['score'] += 1
        
        session['current_question'] += 1
        
        # Check if quiz is finished
        if session['current_question'] >= len(session['questions']):
            return redirect(url_for('results'))
    
    current_q = session['current_question']
    question_data = session['questions'][current_q]
    total_questions = len(session['questions'])
    
    return render_template('quiz.html', 
                         question=question_data,
                         question_num=current_q + 1,
                         total=total_questions)

@app.route('/results')
def results():
    if 'score' not in session or 'user_id' not in session:
        return redirect(url_for('home'))
    
    score = session['score']
    total = len(session['questions'])
    percentage = (score / total) * 100
    subject = session['subject']
    difficulty = session['difficulty']
    user_id = session['user_id']
    
    # Save quiz result to database
    query_db('''
        INSERT INTO quiz_history (user_id, subject, difficulty, score, total_questions, percentage)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', [user_id, subject, difficulty, score, total, percentage], commit=True)
    
    # Clear quiz session data
    session.pop('questions', None)
    session.pop('current_question', None)
    session.pop('score', None)
    session.pop('subject', None)
    session.pop('difficulty', None)
    
    return render_template('results.html', 
                         score=score, 
                         total=total,
                         percentage=percentage,
                         subject=subject,
                         difficulty=difficulty)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get all quiz history for the user
    history = query_db('''
        SELECT subject, difficulty, score, total_questions, percentage, completed_at 
        FROM quiz_history 
        WHERE user_id = ? 
        ORDER BY completed_at DESC
    ''', [session['user_id']])
    
    # Calculate statistics
    total_quizzes = len(history)
    if total_quizzes > 0:
        avg_score = sum([h['percentage'] for h in history]) / total_quizzes
    else:
        avg_score = 0
    
    return render_template('profile.html', 
                         username=session['username'],
                         history=history,
                         total_quizzes=total_quizzes,
                         avg_score=avg_score)
init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000)) 
    app.run(host="0.0.0.0", port=port)
