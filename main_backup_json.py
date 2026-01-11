from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime
import json
import os
from functools import wraps
from dotenv import load_dotenv
import bcrypt
import re
from html import escape
import logging
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()

# Configure secret key and environment settings
app.secret_key = os.getenv('SECRET_KEY', 'default-key-change-this')
app.config['ENV'] = os.getenv('FLASK_ENV', 'production')
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', False)

# ===== LOGGING CONFIGURATION =====
LOGS_DIR = 'logs'
os.makedirs(LOGS_DIR, exist_ok=True)

# Configure logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create formatters
detailed_formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# File handler for all logs
file_handler = RotatingFileHandler(
    os.path.join(LOGS_DIR, 'app.log'),
    maxBytes=10485760,  # 10MB
    backupCount=5
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(detailed_formatter)

# File handler for errors only
error_handler = RotatingFileHandler(
    os.path.join(LOGS_DIR, 'error.log'),
    maxBytes=10485760,  # 10MB
    backupCount=5
)
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(detailed_formatter)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(detailed_formatter)

logger.addHandler(file_handler)
logger.addHandler(error_handler)
logger.addHandler(console_handler)

DATA_DIR = 'data'
TICKETS_FILE = os.path.join(DATA_DIR, 'tickets.json')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Initialize data files if they don't exist
def init_data_files():
    if not os.path.exists(USERS_FILE):
        users = {
            "admin": {"password_hash": hash_password("admin123"), "role": "admin"},
            "company1": {"password_hash": hash_password("company123"), "role": "company", "company_name": "Company 1"},
            "company2": {"password_hash": hash_password("company456"), "role": "company", "company_name": "Company 2"},
            "company3": {"password_hash": hash_password("company789"), "role": "company", "company_name": "Company 3"}
        }
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    
    if not os.path.exists(TICKETS_FILE):
        with open(TICKETS_FILE, 'w') as f:
            json.dump([], f, indent=2)

# Password hashing functions
def hash_password(password):
    """Hash a password using bcrypt."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password, salt).decode('utf-8')

def verify_password(password, password_hash):
    """Verify a password against its hash."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(password_hash, str):
        password_hash = password_hash.encode('utf-8')
    return bcrypt.checkpw(password, password_hash)

# ===== INPUT VALIDATION FUNCTIONS =====
def validate_username(username):
    """Validate username format and length."""
    if not username or not isinstance(username, str):
        return False, 'Username must be a string'
    username = username.strip()
    if len(username) < 3 or len(username) > 50:
        return False, 'Username must be 3-50 characters'
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, 'Username can only contain letters, numbers, and underscores'
    return True, username

def validate_password(password):
    """Validate password strength."""
    if not password or not isinstance(password, str):
        return False, 'Password must be a string'
    if len(password) < 6 or len(password) > 256:
        return False, 'Password must be 6-256 characters'
    return True, password

def validate_company_name(name):
    """Validate company name."""
    if not name or not isinstance(name, str):
        return False, 'Company name must be a string'
    name = name.strip()
    if len(name) < 2 or len(name) > 100:
        return False, 'Company name must be 2-100 characters'
    if not re.match(r'^[a-zA-Z0-9\s\-_&.,]+$', name):
        return False, 'Company name contains invalid characters'
    return True, name

def validate_priority(priority):
    """Validate ticket priority."""
    valid_priorities = ['Low', 'Medium', 'High']
    if priority not in valid_priorities:
        return False, f'Priority must be one of: {", ".join(valid_priorities)}'
    return True, priority

def validate_text(text, min_length=5, max_length=5000, field_name='Text'):
    """Validate text field (problem, solution, etc)."""
    if not text or not isinstance(text, str):
        return False, f'{field_name} must be a string'
    text = text.strip()
    if len(text) < min_length or len(text) > max_length:
        return False, f'{field_name} must be {min_length}-{max_length} characters'
    return True, text

def validate_designation(designation):
    """Validate job designation."""
    if not designation or not isinstance(designation, str):
        return False, 'Designation must be a string'
    designation = designation.strip()
    if len(designation) < 2 or len(designation) > 50:
        return False, 'Designation must be 2-50 characters'
    if not re.match(r'^[a-zA-Z0-9\s\-_/&.]+$', designation):
        return False, 'Designation contains invalid characters'
    return True, designation

def sanitize_text(text):
    """Sanitize text to prevent XSS by HTML escaping."""
    if not isinstance(text, str):
        return text
    return escape(text.strip())

# ===== GLOBAL ERROR HANDLERS =====
@app.errorhandler(400)
def bad_request(error):
    """Handle 400 Bad Request errors."""
    logger.warning(f'Bad request: {request.path} - {str(error)}')
    return jsonify({'error': 'Bad request. Invalid input.'}), 400

@app.errorhandler(401)
def unauthorized(error):
    """Handle 401 Unauthorized errors."""
    logger.warning(f'Unauthorized access attempt: {request.path} - User: {session.get("username", "anonymous")}')
    return jsonify({'error': 'Unauthorized. Please log in.'}), 401

@app.errorhandler(403)
def forbidden(error):
    """Handle 403 Forbidden errors."""
    logger.warning(f'Forbidden access: {request.path} - User: {session.get("username", "anonymous")}')
    return jsonify({'error': 'Forbidden. You do not have access.'}), 403

@app.errorhandler(404)
def not_found(error):
    """Handle 404 Not Found errors."""
    logger.warning(f'Resource not found: {request.path}')
    return jsonify({'error': 'Resource not found.'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 Internal Server errors."""
    logger.error(f'Internal server error: {request.path} - {str(error)}', exc_info=True)
    return jsonify({'error': 'Internal server error. Please try again later.'}), 500

@app.errorhandler(Exception)
def handle_exception(error):
    """Catch all unhandled exceptions."""
    logger.error(f'Unhandled exception: {str(error)}', exc_info=True)
    return jsonify({'error': 'An unexpected error occurred.'}), 500

init_data_files()

def load_tickets():
    with open(TICKETS_FILE, 'r') as f:
        return json.load(f)

def save_tickets(tickets):
    with open(TICKETS_FILE, 'w') as f:
        json.dump(tickets, f, indent=2)

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    if 'username' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('company_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '')
            role = data.get('role', '').strip()
            
            # Validate inputs
            is_valid, msg = validate_username(username)
            if not is_valid:
                logger.warning(f'Login attempt with invalid username: {username}')
                return jsonify({'success': False, 'message': msg}), 400
            
            is_valid, msg = validate_password(password)
            if not is_valid:
                logger.warning(f'Login attempt with invalid password format from IP: {request.remote_addr}')
                return jsonify({'success': False, 'message': msg}), 400
            
            if role not in ['admin', 'company']:
                logger.warning(f'Login attempt with invalid role: {role}')
                return jsonify({'success': False, 'message': 'Invalid role'}), 400
            
            users = load_users()
            
            # Check if user exists, role matches, and password is correct
            if username in users and users[username]['role'] == role:
                password_hash = users[username].get('password_hash') or users[username].get('password')
                # Try to verify password (handles both hashed and unhashed for migration)
                try:
                    if verify_password(password, password_hash):
                        session['username'] = username
                        session['role'] = role
                        if role == 'company':
                            session['company_name'] = users[username].get('company_name', username)
                        logger.info(f'Successful login: {username} ({role})')
                        return jsonify({'success': True, 'redirect': url_for('admin_dashboard' if role == 'admin' else 'company_dashboard')})
                except Exception as e:
                    logger.error(f'Password verification error for user {username}: {str(e)}', exc_info=True)
                    pass
            
            logger.warning(f'Failed login attempt for user: {username} from IP: {request.remote_addr}')
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        except Exception as e:
            logger.error(f'Login endpoint error: {str(e)}', exc_info=True)
            return jsonify({'success': False, 'message': 'An error occurred during login'}), 500
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/company-dashboard')
@login_required
def company_dashboard():
    if session.get('role') != 'company':
        return redirect(url_for('login'))
    return render_template('client_dashboard.html', username=session['username'], company_name=session.get('company_name', session['username']))

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html', username=session['username'])

# API Endpoints
@app.route('/api/tickets', methods=['GET'])
@login_required
def get_tickets():
    tickets = load_tickets()
    username = session['username']
    role = session['role']
    
    if role == 'company':
        tickets = [t for t in tickets if t.get('company') == username or t.get('client') == username]
    
    return jsonify(tickets)

@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket(ticket_id):
    tickets = load_tickets()
    for ticket in tickets:
        if ticket['id'] == ticket_id:
            return jsonify(ticket)
    return jsonify({'error': 'Ticket not found'}), 404

@app.route('/api/tickets', methods=['POST'])
@login_required
def create_ticket():
    try:
        data = request.get_json() or {}
        
        # Validate inputs
        is_valid, problem = validate_text(data.get('problem'), 5, 5000, 'Problem description')
        if not is_valid:
            logger.warning(f'Ticket creation failed - invalid problem from user {session["username"]}: {problem}')
            return jsonify({'error': problem}), 400
        
        priority = data.get('priority', 'Medium')
        is_valid, msg = validate_priority(priority)
        if not is_valid:
            logger.warning(f'Ticket creation failed - invalid priority from user {session["username"]}: {msg}')
            return jsonify({'error': msg}), 400
        
        is_valid, raised_by = validate_text(data.get('raised_by'), 2, 100, 'Raised by name')
        if not is_valid:
            logger.warning(f'Ticket creation failed - invalid raised_by from user {session["username"]}: {raised_by}')
            return jsonify({'error': raised_by}), 400
        
        is_valid, designation = validate_designation(data.get('designation'))
        if not is_valid:
            logger.warning(f'Ticket creation failed - invalid designation from user {session["username"]}: {designation}')
            return jsonify({'error': designation}), 400
        
        # Sanitize text fields to prevent XSS
        problem = sanitize_text(problem)
        raised_by = sanitize_text(raised_by)
        designation = sanitize_text(designation)
        
        tickets = load_tickets()
        
        ticket_id = max([t['id'] for t in tickets], default=0) + 1
        
        new_ticket = {
            'id': ticket_id,
            'company': session['username'],
            'company_name': session.get('company_name', session['username']),
            'problem': problem,
            'priority': priority,
            'raised_by': raised_by,
            'designation': designation,
            'attachments': data.get('attachments', []),
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'solution': None,
            'solution_date': None
        }
        
        tickets.append(new_ticket)
        save_tickets(tickets)
        
        logger.info(f'Ticket created: ID={ticket_id} by {session["username"]} with priority {priority}')
        return jsonify({'success': True, 'ticket_id': ticket_id}), 201
    except Exception as e:
        logger.error(f'Ticket creation error for user {session.get("username")}: {str(e)}', exc_info=True)
        return jsonify({'error': 'Failed to create ticket. Please try again.'}), 500

@app.route('/api/tickets/<int:ticket_id>/solution', methods=['POST'])
@login_required
def add_solution(ticket_id):
    if session.get('role') != 'admin':
        logger.warning(f'Unauthorized solution update attempt by {session.get("username")} for ticket {ticket_id}')
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json() or {}
        
        # Validate solution
        is_valid, solution = validate_text(data.get('solution'), 5, 5000, 'Solution')
        if not is_valid:
            logger.warning(f'Invalid solution from admin {session["username"]} for ticket {ticket_id}: {solution}')
            return jsonify({'error': solution}), 400
        
        # Sanitize solution text
        solution = sanitize_text(solution)
        
        tickets = load_tickets()
        
        for ticket in tickets:
            if ticket['id'] == ticket_id:
                ticket['solution'] = solution
                ticket['status'] = 'resolved'
                ticket['solution_date'] = datetime.now().isoformat()
                save_tickets(tickets)
                logger.info(f'Ticket {ticket_id} resolved by admin {session["username"]}')
                return jsonify({'success': True})
        
        logger.warning(f'Solution update attempted for non-existent ticket {ticket_id} by {session["username"]}')
        return jsonify({'error': 'Ticket not found'}), 404
    except Exception as e:
        logger.error(f'Solution update error for ticket {ticket_id}: {str(e)}', exc_info=True)
        return jsonify({'error': 'Failed to update solution. Please try again.'}), 500

@app.route('/api/received-tickets', methods=['GET'])
@login_required
def get_received_tickets():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    tickets = load_tickets()
    pending_tickets = [t for t in tickets if t['status'] == 'pending']
    return jsonify(pending_tickets)

@app.route('/api/resolved-tickets', methods=['GET'])
@login_required
def get_resolved_tickets():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    tickets = load_tickets()
    resolved_tickets = [t for t in tickets if t['status'] == 'resolved']
    return jsonify(resolved_tickets)


@app.route('/api/companies', methods=['GET'])
@login_required
def get_companies():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    users = load_users()
    companies = []
    for uname, info in users.items():
        if info.get('role') == 'company':
            companies.append({'username': uname, 'company_name': info.get('company_name', uname)})
    return jsonify(companies)


@app.route('/api/companies', methods=['POST'])
@login_required
def add_company():
    if session.get('role') != 'admin':
        logger.warning(f'Unauthorized company creation attempt by {session.get("username")}')
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        data = request.get_json() or {}
        company_name = (data.get('company_name') or '').strip()
        password = data.get('password', '')

        # Validate inputs
        is_valid, msg = validate_company_name(company_name)
        if not is_valid:
            logger.warning(f'Invalid company name from admin {session["username"]}: {msg}')
            return jsonify({'error': msg}), 400
        
        is_valid, msg = validate_password(password)
        if not is_valid:
            logger.warning(f'Invalid password for company {company_name} from admin {session["username"]}')
            return jsonify({'error': msg}), 400

        # generate username slug from company name
        base = ''.join(c.lower() if c.isalnum() else '_' for c in company_name).strip('_')
        if not base:
            base = 'company'

        users = load_users()
        username = base
        i = 1
        while username in users:
            i += 1
            username = f"{base}{i}"

        # Hash password before storing
        users[username] = {'password_hash': hash_password(password), 'role': 'company', 'company_name': company_name}
        save_users(users)
        
        logger.info(f'New company created: {username} ({company_name}) by admin {session["username"]}')
        return jsonify({'success': True, 'username': username}), 201
    except Exception as e:
        logger.error(f'Company creation error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Failed to create company. Please try again.'}), 500


@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    try:
        data = request.get_json() or {}
        message = (data.get('message') or '').strip()
        ticket_id = data.get('ticket_id')

        # Validate message
        is_valid, msg = validate_text(message, 1, 5000, 'Message')
        if not is_valid:
            logger.warning(f'Invalid chat message from {session["username"]}: {msg}')
            return jsonify({'error': msg}), 400
        
        # Sanitize message
        message = sanitize_text(message)

        # If GEMINI_API_KEY is present, proxy the request to Google Gemini API.
        api_key = os.getenv('GEMINI_API_KEY')
        if api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=api_key)

                system_prompt = (
                    "You are a highly experienced technical support engineer helping developers and support staff. "
                    "Provide concise, actionable troubleshooting steps, prioritize reproducible diagnostics, and ask focused clarifying questions when needed. "
                    "Do NOT modify ticket data — only suggest solutions and next steps for the support agent."
                )

                # Use the fixed Gemini model 'gemini-2.5-flash' for generation.
                try:
                    model_name = 'gemini-2.5-flash'
                    full_message = system_prompt + "\n\nUser question: " + message
                    model = genai.GenerativeModel(model_name)
                    response = model.generate_content(full_message)
                    text = None
                    if hasattr(response, 'text') and response.text:
                        text = response.text
                    else:
                        try:
                            cand = getattr(response, 'candidates', None)
                            if cand and len(cand) > 0:
                                text = getattr(cand[0], 'content', None) or getattr(cand[0], 'text', None)
                        except Exception:
                            text = None

                    if text:
                        assistant_text = text.strip()
                        logger.info(f'Chat request processed for {session["username"]}')
                        return jsonify({'reply': assistant_text})
                    else:
                        logger.error('No text returned from Gemini model')
                        return jsonify({'error': 'No text returned from Gemini model.'}), 500
                except Exception as e:
                    logger.error(f'Gemini API error: {str(e)}', exc_info=True)
                    return jsonify({'error': 'Gemini request failed. Using fallback response.'}), 500
            except Exception as e:
                logger.error(f'Gemini configuration error: {str(e)}', exc_info=True)
                return jsonify({'error': 'Gemini service unavailable.'}), 500

        # Fallback simple rule-based assistant when no API key configured
        def fallback_reply(msg):
            txt = msg.lower()
            if 'password' in txt or 'login' in txt:
                return 'Check if the company account exists and reset the password from the admin panel. If multiple failed attempts, advise the user to clear browser cache and try again.'
            if 'slow' in txt or 'performance' in txt:
                return 'Ask the user for browser, approximate time, and any console/network errors. Suggest trying a different browser and collecting screenshots.'
            if 'error' in txt or 'traceback' in txt:
                return 'Request the full traceback and reproduction steps. If available, ask for exact error text and timestamps.'
            if 'how to' in txt or 'how do i' in txt:
                return 'Provide step-by-step instructions for the requested task and include examples where helpful.'
            return 'Can you provide more details (browser, steps to reproduce, screenshots)?'

        logger.info(f'Fallback chat response for {session["username"]}')
        return jsonify({'reply': fallback_reply(message)})
    except Exception as e:
        logger.error(f'Chat endpoint error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Chat service error. Please try again.'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
