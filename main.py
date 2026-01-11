from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import json
import os
from functools import wraps
from dotenv import load_dotenv
import bcrypt
import re
from html import escape
import logging
from logging.handlers import RotatingFileHandler
import jwt

app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()

# Configure secret key and environment settings
app.secret_key = os.getenv('SECRET_KEY', 'default-key-change-this')
app.config['ENV'] = os.getenv('FLASK_ENV', 'production')
app.config['DEBUG'] = os.getenv('FLASK_DEBUG', False)

# ===== DATABASE CONFIGURATION =====
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///tickets.db')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ===== RATE LIMITING CONFIGURATION =====
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # Use in-memory storage for development; use Redis for production
)

# ===== JWT CONFIGURATION =====
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', app.secret_key or 'fallback-jwt-secret-key')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24
JWT_REFRESH_EXPIRATION_DAYS = 7

# ===== DATABASE MODELS =====
class User(db.Model):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False)  # 'admin' or 'company'
    company_name = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'username': self.username,
            'role': self.role,
            'company_name': self.company_name
        }

class Ticket(db.Model):
    __tablename__ = 'tickets'
    
    id = Column(Integer, primary_key=True)
    company = Column(String(50), nullable=False, index=True)
    company_name = Column(String(100), nullable=False)
    problem = Column(Text, nullable=False)
    priority = Column(String(20), nullable=False, default='Medium')
    raised_by = Column(String(100), nullable=False)
    designation = Column(String(50), nullable=False)
    attachments = Column(Text, default='[]')  # JSON string
    status = Column(String(20), nullable=False, default='pending', index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    solution = Column(Text, nullable=True)
    solution_date = Column(DateTime, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'company': self.company,
            'company_name': self.company_name,
            'problem': self.problem,
            'priority': self.priority,
            'raised_by': self.raised_by,
            'designation': self.designation,
            'attachments': json.loads(self.attachments) if self.attachments else [],
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'solution': self.solution,
            'solution_date': self.solution_date.isoformat() if self.solution_date else None
        }

class LoginAttempt(db.Model):
    """Track failed login attempts for abuse detection."""
    __tablename__ = 'login_attempts'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    success = Column(Boolean, nullable=False, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    def is_blocked(self):
        """Check if this IP/username combination should be blocked."""
        # Block after 5 failed attempts in 15 minutes
        fifteen_mins_ago = datetime.utcnow() - timedelta(minutes=15)
        recent_failures = LoginAttempt.query.filter(
            LoginAttempt.username == self.username,
            LoginAttempt.ip_address == self.ip_address,
            LoginAttempt.success == False,
            LoginAttempt.timestamp > fifteen_mins_ago
        ).count()
        return recent_failures >= 5

class TokenBlacklist(db.Model):
    """Track revoked JWT tokens."""
    __tablename__ = 'token_blacklist'
    
    id = Column(Integer, primary_key=True)
    jti = Column(String(255), unique=True, nullable=False, index=True)  # JWT ID
    username = Column(String(50), nullable=False, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

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

# ===== MIGRATION FUNCTION =====
def migrate_from_json():
    """Migrate data from JSON files to SQLite database."""
    try:
        # Check if users exist in DB
        if User.query.count() > 0:
            logger.info('Database already has users, skipping migration')
            return
        
        # Migrate users from JSON
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                users_data = json.load(f)
            
            for username, user_info in users_data.items():
                user = User(
                    username=username,
                    password_hash=user_info.get('password_hash') or user_info.get('password'),
                    role=user_info.get('role'),
                    company_name=user_info.get('company_name')
                )
                db.session.add(user)
            
            db.session.commit()
            logger.info(f'Migrated {len(users_data)} users to database')
        
        # Migrate tickets from JSON
        if os.path.exists(TICKETS_FILE):
            with open(TICKETS_FILE, 'r') as f:
                tickets_data = json.load(f)
            
            for ticket_data in tickets_data:
                ticket = Ticket(
                    id=ticket_data.get('id'),
                    company=ticket_data.get('company'),
                    company_name=ticket_data.get('company_name'),
                    problem=ticket_data.get('problem'),
                    priority=ticket_data.get('priority', 'Medium'),
                    raised_by=ticket_data.get('raised_by', 'Unknown User'),  # Default if missing
                    designation=ticket_data.get('designation', 'Employee'),  # Default if missing
                    attachments=json.dumps(ticket_data.get('attachments', [])),
                    status=ticket_data.get('status', 'pending'),
                    created_at=datetime.fromisoformat(ticket_data.get('created_at')) if ticket_data.get('created_at') else datetime.utcnow(),
                    solution=ticket_data.get('solution'),
                    solution_date=datetime.fromisoformat(ticket_data.get('solution_date')) if ticket_data.get('solution_date') else None
                )
                db.session.add(ticket)
            
            db.session.commit()
            logger.info(f'Migrated {len(tickets_data)} tickets to database')
    except Exception as e:
        logger.error(f'Migration error: {str(e)}', exc_info=True)
        db.session.rollback()


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

# ===== JWT FUNCTIONS =====
def create_access_token(username, role):
    """Create a JWT access token."""
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        'iat': datetime.utcnow(),
        'type': 'access'
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def create_refresh_token(username, role):
    """Create a JWT refresh token."""
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(days=JWT_REFRESH_EXPIRATION_DAYS),
        'iat': datetime.utcnow(),
        'type': 'refresh'
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def verify_token(token):
    """Verify and decode a JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        
        # Check if token is blacklisted
        if is_token_blacklisted(payload.get('jti')):
            return None, 'Token has been revoked'
        
        return payload, None
    except jwt.ExpiredSignatureError:
        return None, 'Token has expired'
    except jwt.InvalidTokenError as e:
        return None, f'Invalid token: {str(e)}'

def is_token_blacklisted(jti):
    """Check if a token is blacklisted."""
    if not jti:
        return False
    token = TokenBlacklist.query.filter_by(jti=jti).first()
    return token is not None

def blacklist_token(jti, username, expires_at):
    """Add a token to the blacklist."""
    blacklist_entry = TokenBlacklist(jti=jti, username=username, expires_at=expires_at)
    db.session.add(blacklist_entry)
    db.session.commit()

def token_required(f):
    """Decorator to require valid JWT token."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                logger.warning(f'Invalid authorization header from {request.remote_addr}')
                return jsonify({'error': 'Invalid authorization header'}), 401
        
        if not token:
            logger.warning(f'Missing token from {request.remote_addr}')
            return jsonify({'error': 'Token is missing'}), 401
        
        payload, error = verify_token(token)
        if not payload:
            logger.warning(f'Invalid token from {request.remote_addr}: {error}')
            return jsonify({'error': error}), 401
        
        # Store user info in request context
        request.user = {
            'username': payload.get('username'),
            'role': payload.get('role')
        }
        
        return f(*args, **kwargs)
    
    return decorated_function

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

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors."""
    logger.warning(f'Rate limit exceeded for IP {request.remote_addr} on {request.path}')
    return jsonify({'error': 'Too many requests. Please try again later.'}), 429

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
@limiter.limit("10 per minute")  # Allow 10 login attempts per minute per IP
def login():
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            password = data.get('password', '')
            role = data.get('role', '').strip()
            client_ip = request.remote_addr
            
            # Validate inputs
            is_valid, msg = validate_username(username)
            if not is_valid:
                logger.warning(f'Login attempt with invalid username: {username} from IP: {client_ip}')
                return jsonify({'success': False, 'message': msg}), 400
            
            is_valid, msg = validate_password(password)
            if not is_valid:
                logger.warning(f'Login attempt with invalid password format from IP: {client_ip}')
                return jsonify({'success': False, 'message': msg}), 400
            
            if role not in ['admin', 'company']:
                logger.warning(f'Login attempt with invalid role: {role} from IP: {client_ip}')
                return jsonify({'success': False, 'message': 'Invalid role'}), 400
            
            # Check if this username/IP is blocked due to too many failed attempts
            attempt_check = LoginAttempt(username=username, ip_address=client_ip)
            if attempt_check.is_blocked():
                logger.warning(f'Blocked login attempt for {username} from IP {client_ip} - too many failed attempts')
                return jsonify({'success': False, 'message': 'Account temporarily locked. Try again in 15 minutes.'}), 429
            
            # Query user from database
            user = User.query.filter_by(username=username, role=role).first()
            
            if user:
                try:
                    if verify_password(password, user.password_hash):
                        # Record successful login
                        login_record = LoginAttempt(username=username, ip_address=client_ip, success=True)
                        db.session.add(login_record)
                        db.session.commit()
                        
                        # Create JWT tokens
                        access_token = create_access_token(user.username, user.role)
                        refresh_token = create_refresh_token(user.username, user.role)
                        
                        # Set session for web frontend
                        session['username'] = user.username
                        session['role'] = user.role
                        if user.role == 'company':
                            session['company_name'] = user.company_name or user.username
                        
                        logger.info(f'Successful login: {user.username} ({user.role}) from IP: {client_ip}')
                        return jsonify({
                            'success': True,
                            'access_token': access_token,
                            'refresh_token': refresh_token,
                            'token_type': 'Bearer',
                            'expires_in': JWT_EXPIRATION_HOURS * 3600,  # in seconds
                            'redirect': url_for('admin_dashboard' if user.role == 'admin' else 'company_dashboard')
                        })
                    else:
                        # Record failed login attempt
                        login_record = LoginAttempt(username=username, ip_address=client_ip, success=False)
                        db.session.add(login_record)
                        db.session.commit()
                except Exception as e:
                    logger.error(f'Password verification error for user {username}: {str(e)}', exc_info=True)
            else:
                # Record failed login attempt (user not found)
                login_record = LoginAttempt(username=username, ip_address=client_ip, success=False)
                db.session.add(login_record)
                db.session.commit()
            
            logger.warning(f'Failed login attempt for user: {username} from IP: {client_ip}')
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        except Exception as e:
            logger.error(f'Login endpoint error: {str(e)}', exc_info=True)
            return jsonify({'success': False, 'message': 'An error occurred during login'}), 500
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/logout', methods=['POST'])
@token_required
def api_logout():
    """Logout endpoint for JWT-based clients."""
    try:
        # Get the token from header
        auth_header = request.headers.get('Authorization', '')
        token = auth_header.split(" ")[1] if len(auth_header.split(" ")) > 1 else None
        
        if token:
            # Decode to get JTI and expiration
            payload, _ = verify_token(token)
            if payload:
                jti = payload.get('jti')
                exp_timestamp = payload.get('exp')
                if jti and exp_timestamp:
                    expires_at = datetime.fromtimestamp(exp_timestamp)
                    blacklist_token(jti, request.user['username'], expires_at)
                    logger.info(f'Logout: {request.user["username"]} from IP: {request.remote_addr}')
        
        return jsonify({'success': True, 'message': 'Logged out successfully'})
    except Exception as e:
        logger.error(f'Logout error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Logout failed'}), 500

@app.route('/api/refresh-token', methods=['POST'])
@limiter.limit("100 per hour")  # Allow 100 token refreshes per hour
def refresh_token():
    """Refresh an access token using a refresh token."""
    try:
        data = request.get_json() or {}
        refresh_token_str = data.get('refresh_token', '')
        
        if not refresh_token_str:
            logger.warning(f'Refresh token request without token from IP: {request.remote_addr}')
            return jsonify({'error': 'Refresh token is missing'}), 401
        
        # Verify refresh token
        payload, error = verify_token(refresh_token_str)
        if not payload:
            logger.warning(f'Invalid refresh token from IP: {request.remote_addr}: {error}')
            return jsonify({'error': error}), 401
        
        # Check if it's a refresh token
        if payload.get('type') != 'refresh':
            logger.warning(f'Non-refresh token used for refresh from IP: {request.remote_addr}')
            return jsonify({'error': 'Invalid token type'}), 401
        
        # Create new access token
        username = payload.get('username')
        role = payload.get('role')
        new_access_token = create_access_token(username, role)
        
        logger.info(f'Token refreshed for {username} from IP: {request.remote_addr}')
        return jsonify({
            'success': True,
            'access_token': new_access_token,
            'token_type': 'Bearer',
            'expires_in': JWT_EXPIRATION_HOURS * 3600
        })
    except Exception as e:
        logger.error(f'Token refresh error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Token refresh failed'}), 500

@app.route('/api/verify-token', methods=['POST'])
def verify_token_endpoint():
    """Verify a token without requiring authentication."""
    try:
        data = request.get_json() or {}
        token = data.get('token', '')
        
        if not token:
            return jsonify({'valid': False, 'error': 'Token is missing'}), 400
        
        payload, error = verify_token(token)
        if not payload:
            return jsonify({'valid': False, 'error': error})
        
        return jsonify({
            'valid': True,
            'username': payload.get('username'),
            'role': payload.get('role'),
            'expires_at': payload.get('exp')
        })
    except Exception as e:
        logger.error(f'Token verification error: {str(e)}', exc_info=True)
        return jsonify({'valid': False, 'error': 'Verification failed'}), 500

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

# ===== API ENDPOINTS =====
@app.route('/api/tickets', methods=['GET'])
@login_required
def get_tickets():
    try:
        username = session['username']
        role = session['role']
        
        if role == 'company':
            tickets = Ticket.query.filter_by(company=username).all()
        else:
            tickets = Ticket.query.all()
        
        return jsonify([t.to_dict() for t in tickets])
    except Exception as e:
        logger.error(f'Get tickets error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Failed to fetch tickets'}), 500

@app.route('/api/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket(ticket_id):
    try:
        ticket = Ticket.query.get(ticket_id)
        if ticket:
            return jsonify(ticket.to_dict())
        return jsonify({'error': 'Ticket not found'}), 404
    except Exception as e:
        logger.error(f'Get ticket error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Failed to fetch ticket'}), 500

@app.route('/api/tickets', methods=['POST'])
@limiter.limit("20 per day")  # Allow 20 tickets per day per IP
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
        
        # Get company name
        user = User.query.filter_by(username=session['username']).first()
        company_name = user.company_name if user else session['username']
        
        new_ticket = Ticket(
            company=session['username'],
            company_name=company_name,
            problem=problem,
            priority=priority,
            raised_by=raised_by,
            designation=designation,
            attachments=json.dumps(data.get('attachments', [])),
            status='pending'
        )
        
        db.session.add(new_ticket)
        db.session.commit()
        
        logger.info(f'Ticket created: ID={new_ticket.id} by {session["username"]} with priority {priority}')
        return jsonify({'success': True, 'ticket_id': new_ticket.id}), 201
    except Exception as e:
        logger.error(f'Ticket creation error for user {session.get("username")}: {str(e)}', exc_info=True)
        db.session.rollback()
        return jsonify({'error': 'Failed to create ticket. Please try again.'}), 500

@app.route('/api/tickets/<int:ticket_id>/solution', methods=['POST'])
@limiter.limit("50 per day")  # Allow 50 solution updates per day
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
        
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            logger.warning(f'Solution update attempted for non-existent ticket {ticket_id} by {session["username"]}')
            return jsonify({'error': 'Ticket not found'}), 404
        
        ticket.solution = solution
        ticket.status = 'resolved'
        ticket.solution_date = datetime.utcnow()
        db.session.commit()
        
        logger.info(f'Ticket {ticket_id} resolved by admin {session["username"]}')
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f'Solution update error for ticket {ticket_id}: {str(e)}', exc_info=True)
        db.session.rollback()
        return jsonify({'error': 'Failed to update solution. Please try again.'}), 500

@app.route('/api/received-tickets', methods=['GET'])
@login_required
def get_received_tickets():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        tickets = Ticket.query.filter_by(status='pending').all()
        return jsonify([t.to_dict() for t in tickets])
    except Exception as e:
        logger.error(f'Get received tickets error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Failed to fetch tickets'}), 500

@app.route('/api/resolved-tickets', methods=['GET'])
@login_required
def get_resolved_tickets():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        tickets = Ticket.query.filter_by(status='resolved').all()
        return jsonify([t.to_dict() for t in tickets])
    except Exception as e:
        logger.error(f'Get resolved tickets error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Failed to fetch tickets'}), 500

@app.route('/api/companies', methods=['GET'])
@login_required
def get_companies():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        companies = User.query.filter_by(role='company').all()
        return jsonify([{
            'username': c.username,
            'company_name': c.company_name or c.username
        } for c in companies])
    except Exception as e:
        logger.error(f'Get companies error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Failed to fetch companies'}), 500

@app.route('/api/companies', methods=['POST'])
@limiter.limit("10 per day")  # Allow 10 company creations per day
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

        # Generate username slug from company name
        base = ''.join(c.lower() if c.isalnum() else '_' for c in company_name).strip('_')
        if not base:
            base = 'company'

        username = base
        i = 1
        while User.query.filter_by(username=username).first():
            i += 1
            username = f"{base}{i}"

        # Create new user
        new_user = User(
            username=username,
            password_hash=hash_password(password),
            role='company',
            company_name=company_name
        )
        db.session.add(new_user)
        db.session.commit()
        
        logger.info(f'New company created: {username} ({company_name}) by admin {session["username"]}')
        return jsonify({'success': True, 'username': username}), 201
    except Exception as e:
        logger.error(f'Company creation error: {str(e)}', exc_info=True)
        db.session.rollback()
        return jsonify({'error': 'Failed to create company. Please try again.'}), 500

@app.route('/api/chat', methods=['POST'])
@limiter.limit("30 per day")  # Allow 30 chat requests per day
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
    with app.app_context():
        # Create all database tables
        db.create_all()
        # Run migration from JSON files
        migrate_from_json()
    
    app.run(debug=True, port=5000)
