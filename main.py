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
            "company1": {"password": "company123", "role": "company", "company_name": "Company 1"},
            "company2": {"password": "company456", "role": "company", "company_name": "Company 2"},
            "company3": {"password": "company789", "role": "company", "company_name": "Company 3"}
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
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        
        users = load_users()
        
        if username in users and users[username]['password'] == password and users[username]['role'] == role:
            session['username'] = username
            session['role'] = role
            if role == 'company':
                session['company_name'] = users[username].get('company_name', username)
            return jsonify({'success': True, 'redirect': url_for('admin_dashboard' if role == 'admin' else 'company_dashboard')})
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'})
    
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
    data = request.get_json()
    tickets = load_tickets()
    
    ticket_id = max([t['id'] for t in tickets], default=0) + 1
    
    new_ticket = {
        'id': ticket_id,
        'company': session['username'],
        'company_name': session.get('company_name', session['username']),
        'problem': data.get('problem'),
        'priority': data.get('priority', 'Medium'),
        'raised_by': data.get('raised_by'),
        'designation': data.get('designation'),
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
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json() or {}
    company_name = (data.get('company_name') or '').strip()
    password = data.get('password')

    if not company_name or not password:
        return jsonify({'error': 'company_name and password required'}), 400

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

    users[username] = {'password': password, 'role': 'company', 'company_name': company_name}
    save_users(users)
    return jsonify({'success': True, 'username': username})


@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json() or {}
    message = (data.get('message') or '').strip()
    ticket_id = data.get('ticket_id')

    if not message:
        return jsonify({'error': 'message required'}), 400

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
                    return jsonify({'reply': assistant_text})
                else:
                    return jsonify({'error': 'No text returned from Gemini model.'}), 500
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                print(f"Gemini error: {tb}")
                return jsonify({'error': 'Gemini request failed: ' + str(e)}), 500
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            print(f"Gemini error: {tb}")
            return jsonify({'error': 'Gemini request failed: ' + str(e)}), 500

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

    return jsonify({'reply': fallback_reply(message)})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
