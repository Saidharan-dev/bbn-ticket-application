from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from datetime import datetime
import json
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

DATA_DIR = 'data'
TICKETS_FILE = os.path.join(DATA_DIR, 'tickets.json')
USERS_FILE = os.path.join(DATA_DIR, 'users.json')

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Initialize data files if they don't exist
def init_data_files():
    if not os.path.exists(USERS_FILE):
        users = {
            "admin": {"password": "admin123", "role": "admin"},
            "client1": {"password": "client123", "role": "client"}
        }
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    
    if not os.path.exists(TICKETS_FILE):
        with open(TICKETS_FILE, 'w') as f:
            json.dump([], f, indent=2)

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
            return redirect(url_for('client_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        
        users = load_users()
        
        if username in users and users[username]['password'] == password and users[username]['role'] == role:
            session['username'] = username
            session['role'] = role
            return jsonify({'success': True, 'redirect': url_for('admin_dashboard' if role == 'admin' else 'client_dashboard')})
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/client-dashboard')
@login_required
def client_dashboard():
    if session.get('role') != 'client':
        return redirect(url_for('login'))
    return render_template('client_dashboard.html', username=session['username'])

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
    
    if role == 'client':
        tickets = [t for t in tickets if t['client'] == username]
    
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
    data = request.get_json()
    tickets = load_tickets()
    
    ticket_id = max([t['id'] for t in tickets], default=0) + 1
    
    new_ticket = {
        'id': ticket_id,
        'client': session['username'],
        'problem': data.get('problem'),
        'attachments': data.get('attachments', []),
        'status': 'pending',
        'created_at': datetime.now().isoformat(),
        'solution': None,
        'solution_date': None
    }
    
    tickets.append(new_ticket)
    save_tickets(tickets)
    
    return jsonify({'success': True, 'ticket_id': ticket_id}), 201

@app.route('/api/tickets/<int:ticket_id>/solution', methods=['POST'])
@login_required
def add_solution(ticket_id):
    if session.get('role') != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    
    data = request.get_json()
    tickets = load_tickets()
    
    for ticket in tickets:
        if ticket['id'] == ticket_id:
            ticket['solution'] = data.get('solution')
            ticket['status'] = 'resolved'
            ticket['solution_date'] = datetime.now().isoformat()
            save_tickets(tickets)
            return jsonify({'success': True})
    
    return jsonify({'error': 'Ticket not found'}), 404

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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
