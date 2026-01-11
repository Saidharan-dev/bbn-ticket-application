# Error Handling & Logging Documentation

## Overview
The application now includes comprehensive error handling and structured logging to track all important events, errors, and potential security issues.

---

## Logging System

### Log Files Location
All logs are stored in the `logs/` directory:
- **`logs/app.log`** - All application events (INFO and above)
- **`logs/error.log`** - Errors only (ERROR and above)

### Log File Configuration
- **Max Size**: 10MB per file
- **Backup Count**: 5 previous versions kept
- **Total History**: Up to 50MB per log type
- **Format**: `YYYY-MM-DD HH:MM:SS - [logger] - [LEVEL] - [file:line] - message`

### Log Levels
1. **DEBUG** - Detailed info for debugging (not logged in production)
2. **INFO** - General information (logins, ticket creation, etc.)
3. **WARNING** - Potential issues (validation failures, unauthorized attempts)
4. **ERROR** - Errors that need attention (exceptions, API failures)
5. **CRITICAL** - System-critical errors (not used yet)

---

## What Gets Logged

### 1. Authentication Events
✅ Successful login
```
INFO - Successful login: username (admin)
```

❌ Failed login attempts
```
WARNING - Failed login attempt for user: username from IP: 192.168.1.1
```

❌ Invalid credentials (username too short, invalid password, etc.)
```
WARNING - Login attempt with invalid username: ab
WARNING - Login attempt with invalid password format from IP: 192.168.1.1
```

### 2. Ticket Operations
✅ Ticket creation
```
INFO - Ticket created: ID=42 by company1 with priority High
```

❌ Invalid ticket submission
```
WARNING - Ticket creation failed - invalid problem from user company1: Problem description must be 5-5000 characters
```

✅ Ticket resolution
```
INFO - Ticket 42 resolved by admin admin
```

### 3. Company Management
✅ Company creation
```
INFO - New company created: acme_corp (ACME Corporation) by admin admin
```

❌ Invalid company data
```
WARNING - Invalid company name from admin admin: Company name must be 2-100 characters
```

### 4. Chat Operations
✅ Chat requests
```
INFO - Chat request processed for admin
INFO - Fallback chat response for company1
```

❌ Chat validation failures
```
WARNING - Invalid chat message from admin: Message must be 1-5000 characters
```

### 5. API Errors
```
ERROR - Ticket creation error for user company1: [error details]
ERROR - Chat endpoint error: [error details]
ERROR - Unhandled exception: [error details]
```

### 6. Security Events
```
WARNING - Unauthorized access attempt: /api/companies - User: anonymous
WARNING - Forbidden access: /api/tickets/42 - User: company2
WARNING - Unauthorized company creation attempt by company1
WARNING - Unauthorized solution update attempt by company1 for ticket 42
```

### 7. Resource Not Found
```
WARNING - Resource not found: /api/tickets/99999
WARNING - Solution update attempted for non-existent ticket 42 by admin
```

---

## Log Entry Example

**Full Log Format:**
```
2026-01-11 16:45:23 - __main__ - INFO - [main.py:285] - Successful login: admin (admin)
```

**Breakdown:**
- `2026-01-11 16:45:23` - Timestamp
- `__main__` - Logger name
- `INFO` - Log level
- `main.py:285` - File and line number
- `Successful login: admin (admin)` - Message

---

## Monitoring & Analyzing Logs

### View Recent Logs
```bash
# Last 50 lines of app.log
tail -50 logs/app.log

# Live monitoring
tail -f logs/app.log

# Search for errors
grep "ERROR" logs/error.log

# Find all failed logins
grep "Failed login" logs/app.log
```

### Statistics
```bash
# Count login attempts
grep "login" logs/app.log | wc -l

# Count errors
grep "ERROR" logs/error.log | wc -l

# Find slowest operations
grep "Ticket created" logs/app.log | wc -l
```

### Security Monitoring
```bash
# Find unauthorized access attempts
grep "Unauthorized" logs/app.log

# Find suspicious activity
grep "WARNING" logs/app.log

# Track IP addresses of failed logins
grep "Failed login" logs/app.log | grep "from IP"
```

---

## Global Error Handlers

All HTTP error responses are caught and logged automatically:

### 400 - Bad Request
**When**: Invalid input validation fails
**Logged As**: WARNING
**Response**: `{"error": "Bad request. Invalid input."}`

### 401 - Unauthorized
**When**: User not logged in or invalid credentials
**Logged As**: WARNING
**Response**: `{"error": "Unauthorized. Please log in."}`

### 403 - Forbidden
**When**: User lacks permission for action
**Logged As**: WARNING
**Response**: `{"error": "Forbidden. You do not have access."}`

### 404 - Not Found
**When**: Requested resource doesn't exist
**Logged As**: WARNING
**Response**: `{"error": "Resource not found."}`

### 500 - Internal Server Error
**When**: Unexpected exception occurs
**Logged As**: ERROR (with traceback)
**Response**: `{"error": "Internal server error. Please try again later."}`

---

## Exception Handling Pattern

All endpoints wrap critical code in try-except blocks:

```python
@app.route('/api/tickets', methods=['POST'])
@login_required
def create_ticket():
    try:
        # Validate inputs
        # Process request
        # Save data
        logger.info(f'Ticket created: ID={ticket_id}')
        return jsonify({'success': True}), 201
    except Exception as e:
        logger.error(f'Ticket creation error: {str(e)}', exc_info=True)
        return jsonify({'error': 'Failed to create ticket.'}), 500
```

**Key Points:**
- ✅ Every endpoint has try-except wrapper
- ✅ Errors are logged with full traceback (`exc_info=True`)
- ✅ User-friendly error messages returned
- ✅ No system details leaked to client

---

## IP Tracking

Login failures and access attempts include IP addresses for security:

```
WARNING - Failed login attempt for user: admin from IP: 192.168.1.100
```

**Use Case**: Detect brute force attacks or suspicious login patterns

---

## Performance & Alerting

### Log Rotation
Logs automatically rotate when they reach 10MB, keeping the last 5 backups:
- `app.log` → `app.log.1` → `app.log.2` → ... → `app.log.5`

### Storage
With 5 backups × 10MB = 50MB maximum per log type
- Can store ~1 week of activity (depending on traffic)
- Older logs are automatically deleted

---

## Audit Trail

The logs create an audit trail for:
- ✅ Who did what (username)
- ✅ When (timestamp)
- ✅ What happened (action)
- ✅ Success or failure
- ✅ Error details (if applicable)

---

## Integration with Monitoring Tools (Future)

The logging system is ready to integrate with:
- **Sentry** - Error tracking & alerting
- **ELK Stack** - Log aggregation & analysis
- **DataDog** - APM & monitoring
- **Splunk** - Log analysis & dashboards
- **CloudWatch** - AWS logging service

**Configuration**: Can be added by creating additional handlers to the logger.

---

## Best Practices

1. ✅ Check logs regularly for errors
2. ✅ Set up alerts for ERROR-level logs
3. ✅ Monitor login failures for security
4. ✅ Archive old logs for compliance
5. ✅ Use timestamps to correlate events
6. ✅ Share logs with dev team for debugging

---

## Example: Debugging an Issue

**Scenario**: Admin reports ticket creation failing

**Step 1**: Check error log
```bash
grep "Ticket creation error" logs/error.log
# 2026-01-11 16:50:15 - __main__ - ERROR - [main.py:302] - Ticket creation error: [Errno 2] No such file or directory
```

**Step 2**: Check app log for context
```bash
grep "company1" logs/app.log | tail -20
```

**Step 3**: Find full traceback in error.log
```bash
tail -100 logs/error.log
```

**Result**: Quick diagnosis and fix!

---

## Security Notes

- ⚠️ Logs contain usernames (expected for audit trail)
- ⚠️ Logs contain IP addresses (for security monitoring)
- ⚠️ Logs do NOT contain passwords or sensitive data
- ✅ Logs are stored on disk with proper permissions
- ✅ Old logs should be archived & encrypted for compliance

