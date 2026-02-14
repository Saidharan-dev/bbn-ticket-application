# Ticket Management System

A simple web-based ticket management application with separate client and admin interfaces.

## Features

### Client Features
- **Login**: Secure login with client credentials
- **Raise Ticket**: Submit new tickets with problem description and file attachments
- **Pending Tickets**: View all pending tickets with status bar showing "Not Resolved"
- **Previous Tickets & Responses**: View resolved tickets with solutions from admin

### Admin Features
- **Login**: Secure login with admin credentials
- **Received Responses**: View all pending tickets from clients
- **Write Solution**: Add solutions to pending tickets
- **Previous Responses**: View all resolved tickets with status bar showing "Resolved"

## Project Structure

```
bbn-ticket-application/
├── main.py                 # Flask backend server
├── requirements.txt        # Python dependencies
├── templates/
│   ├── login.html         # Login page
│   ├── client_dashboard.html  # Client dashboard
│   └── admin_dashboard.html   # Admin dashboard
├── static/
│   ├── css/
│   │   └── style.css      # All styling
│   └── js/
│       ├── client.js      # Client-side JavaScript
│       └── admin.js       # Admin-side JavaScript
└── data/
    ├── users.json         # User credentials (auto-generated)
    └── tickets.json       # Tickets storage (auto-generated)
```

## Setup Instructions

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Application
```bash
python main.py
```

The application will be available at: `http://localhost:5000`

## Demo Credentials

### Admin Login
- **Username**: admin
- **Password**: admin123

### Client Login
- **Username**: client1567
- **Password**: client123

## Usage

### As a Client:
1. Login with client credentials
2. Click "Raise a Ticket" to submit a new issue
3. Describe the problem and optionally attach files
4. Click "Submit Ticket"
5. View pending tickets in "Pending Tickets" section
6. View resolved tickets and solutions in "Previous Tickets & Responses"

### As an Admin:
1. Login with admin credentials
2. View all pending tickets in "Received Responses"
3. Click on a ticket to view details
4. Click "Write Solution" to provide a solution
5. The ticket will move to "Previous Responses" after resolution
6. View all resolved tickets in "Previous Responses"

## Data Storage

- User data is stored in `data/users.json`
- Ticket data is stored in `data/tickets.json`
- Files are referenced by name but not physically stored

## Technology Stack

- **Frontend**: HTML5, CSS3, JavaScript
- **Backend**: Python Flask
- **Storage**: JSON files

## Notes

- This is a simple demonstration application suitable for learning purposes
- For production use, consider:
  - Using a proper database (PostgreSQL, MongoDB, etc.)
  - Implementing proper authentication (JWT tokens, OAuth)
  - Adding file upload functionality
  - Adding email notifications
  - Implementing user roles and permissions more robustly
  - Adding input validation and security measures
