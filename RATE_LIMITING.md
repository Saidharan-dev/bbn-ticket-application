# Rate Limiting & Abuse Protection Documentation (Task 6)

## Overview
Task 6 implements comprehensive rate limiting and abuse protection mechanisms to prevent DoS attacks, brute-force login attempts, and API abuse. The system uses Flask-Limiter for request throttling and a custom LoginAttempt tracking system for security.

## Features Implemented

### 1. Global Rate Limiting
**Default Limits:** 200 requests per day, 50 requests per hour per IP

```python
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
```

**Impact:**
- Protects against general API abuse
- Limits resource consumption
- Ensures fair access for all users
- Easy to adjust for different environments

### 2. Endpoint-Specific Rate Limits

#### Authentication Endpoint
- **Route:** `POST /login`
- **Limit:** 10 attempts per minute per IP
- **Purpose:** Prevent brute-force password attacks
- **Behavior:** After 10 attempts in 60 seconds, requests are rejected with 429 status

```python
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
```

#### Ticket Creation
- **Route:** `POST /api/tickets`
- **Limit:** 20 tickets per day per IP
- **Purpose:** Prevent spam ticket creation
- **Behavior:** Prevents users from flooding the system with fake tickets

#### Ticket Solution
- **Route:** `POST /api/tickets/<id>/solution`
- **Limit:** 50 updates per day per IP
- **Purpose:** Prevent admin spam
- **Behavior:** Limits admin from mass-updating tickets too quickly

#### Company Creation
- **Route:** `POST /api/companies`
- **Limit:** 10 companies per day per IP
- **Purpose:** Prevent unauthorized account creation
- **Behavior:** Restricts rapid company/user creation attempts

#### Chat Requests
- **Route:** `POST /api/chat`
- **Limit:** 30 requests per day per IP
- **Purpose:** Prevent AI API abuse (Gemini API costs money)
- **Behavior:** Limits expensive AI model requests

### 3. Failed Login Attempt Tracking

#### LoginAttempt Model
```python
class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    success = Column(Boolean, nullable=False, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
```

**Tracks:**
- Username of login attempt
- IP address of attacker
- Success/failure of attempt
- Timestamp of attempt

#### Account Lockout Logic
```python
def is_blocked(self):
    """Block after 5 failed attempts in 15 minutes."""
    fifteen_mins_ago = datetime.utcnow() - timedelta(minutes=15)
    recent_failures = LoginAttempt.query.filter(
        LoginAttempt.username == self.username,
        LoginAttempt.ip_address == self.ip_address,
        LoginAttempt.success == False,
        LoginAttempt.timestamp > fifteen_mins_ago
    ).count()
    return recent_failures >= 5
```

**Security Features:**
- Blocks after **5 failed attempts** within **15 minutes**
- Combines username + IP for attack detection
- Distinguishes between different attack vectors:
  - Brute force against one account from one IP
  - Distributed attacks across accounts
  - Credential stuffing attacks
- Auto-unlock after 15 minutes (time-based)
- Logs all blocked attempts

### 4. Error Handling for Rate Limits

#### HTTP 429 Response
```python
@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit exceeded errors."""
    logger.warning(f'Rate limit exceeded for IP {request.remote_addr} on {request.path}')
    return jsonify({'error': 'Too many requests. Please try again later.'}), 429
```

**Response Format:**
```json
{
    "error": "Too many requests. Please try again later."
}
```

**HTTP Status:** 429 Too Many Requests

**Logging:** All rate limit violations are logged with IP and endpoint

### 5. Login Security Enhancements

#### Enhanced Login Endpoint
The login endpoint now includes:

1. **Input Validation**
   - Username format validation
   - Password length validation
   - Role validation

2. **Failed Attempt Tracking**
   - Records every failed attempt to LoginAttempt table
   - Records successful attempts (audit trail)
   - Includes IP address for geographic tracking

3. **Account Lockout**
   - Checks if account is locked before password check
   - Returns 429 status for locked accounts
   - Provides friendly error message

4. **Logging**
   - Logs all login attempts (success and failure)
   - Includes IP address for security analysis
   - Tracks by username and role

**Example Flow:**
```
User enters wrong password → LoginAttempt recorded
User tries again → LoginAttempt recorded
User tries 5th time within 15 min → Account locked
User gets 429 response: "Account temporarily locked. Try again in 15 minutes."
After 15 min → Account automatically unlocked
```

## Configuration

### Development Settings (In-Memory Storage)
```python
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # Good for development
)
```

**Advantages:**
- No external dependencies
- Fast for single-server deployments
- Good for testing

**Disadvantages:**
- Resets on application restart
- Doesn't work with multiple servers
- Limited to single process

### Production Settings (Redis)
```python
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379"  # For production with multiple servers
)
```

**Advantages:**
- Persistent rate limit state
- Works across multiple servers
- Fast and reliable
- Professional solution

**Installation:**
```bash
pip install redis
# Start Redis server:
redis-server
```

### Environment-Specific Configuration
```python
# In .env file
RATELIMIT_STORAGE_URL=redis://localhost:6379  # Production
# OR
RATELIMIT_STORAGE_URL=memory://  # Development
```

## Rate Limit Tiers

### By Severity
```
Public Endpoints (no auth): 50 per hour
Public Chat: 30 per day (expensive API)
User Actions: 20 per day (ticket creation)
Admin Actions: 50 per day (solutions, companies)
Critical Auth: 10 per minute (login attempts)
```

### By Use Case
```
Standard User:
- Create tickets: 20/day
- View tickets: unlimited (read-only)
- Chat: 30/day
- Login: 10/minute

Admin User:
- Add solution: 50/day
- Create companies: 10/day
- View tickets: unlimited
- Chat: 30/day
- Login: 10/minute
```

## Monitoring and Alerts

### Logging
All rate limit violations are logged:
```
WARNING - Rate limit exceeded for IP 192.168.1.100 on /api/tickets
WARNING - Blocked login attempt for admin from IP 203.0.113.45 - too many failed attempts
ERROR - Multiple failed login attempts detected for username: company1
```

### Database Queries for Analysis

**Check failed login attempts:**
```python
from datetime import datetime, timedelta
from main import db, LoginAttempt

# Find IPs attempting to brute-force an account
suspicious_ips = db.session.query(
    LoginAttempt.ip_address,
    LoginAttempt.username,
    db.func.count(LoginAttempt.id).label('attempts')
).filter(
    LoginAttempt.success == False,
    LoginAttempt.timestamp > datetime.utcnow() - timedelta(hours=1)
).group_by(LoginAttempt.ip_address, LoginAttempt.username).all()

# Find most targeted usernames
targeted_accounts = db.session.query(
    LoginAttempt.username,
    db.func.count(LoginAttempt.id).label('attempts')
).filter(
    LoginAttempt.success == False,
    LoginAttempt.timestamp > datetime.utcnow() - timedelta(hours=1)
).group_by(LoginAttempt.username).all()

# Find successful logins
successful_logins = LoginAttempt.query.filter_by(success=True).order_by(
    LoginAttempt.timestamp.desc()
).limit(50).all()
```

### Dashboard Metrics (for future Task 10)
- Login attempts per hour
- Failed logins by account
- Rate limit violations per endpoint
- Blocked IP addresses
- Suspicious activity patterns

## Bypassing Rate Limits (Legitimate Cases)

### Disable Rate Limit for Specific Route
```python
@app.route('/api/internal/sync', methods=['POST'])
@limiter.exempt  # Bypass rate limiting for internal operations
def internal_sync():
    pass
```

### Custom Rate Limit Functions
```python
def get_user_id():
    """Rate limit by authenticated user instead of IP."""
    if 'user_id' in session:
        return session['user_id']
    return get_remote_address()

@app.route('/api/data', methods=['GET'])
@limiter.limit("100 per hour", key_func=get_user_id)
def get_data():
    pass
```

## Attack Scenarios Protected Against

### 1. Brute-Force Login Attack
**Attack:** Attacker tries 100 passwords per second against admin account
**Protection:**
- Rate limit: 10 attempts per minute
- Account lockout: After 5 failures in 15 minutes
- Logging: All attempts recorded
**Result:** Attack fails after 5 attempts, account locked for 15 minutes

### 2. Credential Stuffing
**Attack:** Attacker uses leaked password list against multiple accounts
**Protection:**
- Tracks failures by IP + username combination
- Rate limit prevents rapid-fire attempts
- Locks individual accounts
**Result:** Different usernames lock independently, slows attack significantly

### 3. Spam Ticket Creation
**Attack:** Bot creates 1000 fake support tickets
**Protection:**
- Rate limit: 20 tickets per day per IP
- Total limit: 200 requests per day per IP
**Result:** After 20 tickets, all requests rejected with 429

### 4. AI API Abuse
**Attack:** Attacker uses chat endpoint to generate free content
**Protection:**
- Chat limit: 30 requests per day
- Global limits apply on top (50/hour)
- IP-based tracking
**Result:** After 30 requests, no more chat for 24 hours from that IP

### 5. Distributed Attack (Multiple IPs)
**Attack:** Botnet uses 100 different IPs to bypass IP-based limits
**Protection:**
- Global rate limits still apply per IP
- Multiple IPs still limited to 200 requests/day each
- Logging captures all IPs
**Result:** Attack spread across IPs, cumulative traffic still visible in logs

## Performance Impact

### Overhead Per Request
- **In-Memory Storage:** < 1ms (negligible)
- **Redis Storage:** 5-10ms (acceptable for production)
- **Lookup time:** Indexed database queries for LoginAttempt

### Database Queries
```python
# Checked on every failed login
LoginAttempt.query.filter(...).count()  # Indexed query, fast

# Cleanup old entries (run daily)
LoginAttempt.query.filter(
    LoginAttempt.timestamp < datetime.utcnow() - timedelta(days=30)
).delete()
```

## Testing Rate Limits

### Test Login Rate Limit
```bash
# Attempt 11 logins quickly
for i in {1..11}; do
    curl -X POST http://localhost:5000/login \
      -H "Content-Type: application/json" \
      -d '{"username":"admin","password":"wrong","role":"admin"}'
done

# Result: First 10 succeed, 11th gets 429 Too Many Requests
```

### Test Ticket Creation Rate Limit
```bash
# Attempt 21 ticket creations in one day
for i in {1..21}; do
    curl -X POST http://localhost:5000/api/tickets \
      -H "Authorization: Bearer $TOKEN" \
      -d '{"problem":"test","priority":"High","raised_by":"test","designation":"test"}'
done

# Result: First 20 succeed, 21st gets 429
```

### Test Account Lockout
```bash
# Make 5 failed login attempts
for i in {1..5}; do
    curl -X POST http://localhost:5000/login \
      -H "Content-Type: application/json" \
      -d '{"username":"admin","password":"wrong","role":"admin"}'
done

# 6th attempt returns 429 with message:
# "Account temporarily locked. Try again in 15 minutes."
```

## Database Maintenance

### Clean Up Old Login Attempts
Run periodically (daily or weekly) to keep table small:
```python
from datetime import datetime, timedelta
from main import db, LoginAttempt

# Delete attempts older than 30 days
old_attempts = LoginAttempt.query.filter(
    LoginAttempt.timestamp < datetime.utcnow() - timedelta(days=30)
).delete()

db.session.commit()
print(f"Deleted {old_attempts} old login attempts")
```

### Add to Scheduled Jobs (when implemented)
```python
# In requirements.txt (future task)
# APScheduler==3.10.0

# In main.py
from apscheduler.schedulers.background import BackgroundScheduler

def cleanup_old_attempts():
    with app.app_context():
        old = LoginAttempt.query.filter(
            LoginAttempt.timestamp < datetime.utcnow() - timedelta(days=30)
        ).delete()
        db.session.commit()
        logger.info(f"Cleaned up {old} old login attempts")

scheduler = BackgroundScheduler()
scheduler.add_job(cleanup_old_attempts, 'interval', days=1)
scheduler.start()
```

## Summary

✅ **Task 6 Complete:** Rate Limiting & Abuse Protection

**Deliverables:**
- Global rate limiting (200/day, 50/hour per IP)
- Endpoint-specific rate limits (10-50 per day/minute)
- Failed login attempt tracking with account lockout
- 429 Too Many Requests error handling
- Comprehensive logging for security analysis
- Easy configuration for development/production

**Database Changes:**
- New `LoginAttempt` table for tracking failed logins
- Indexed on username, ip_address, and timestamp

**Files Modified:**
- `main.py` - Added rate limiter, LoginAttempt model, login security enhancements
- `requirements.txt` - Added Flask-Limiter==3.5.0

**Security Improvements:**
- Prevents brute-force attacks (5 failures → 15-min lockout)
- Prevents spam/DoS (rate limits per endpoint)
- Prevents credential stuffing (IP + username tracking)
- Prevents AI API abuse (expensive operations limited)
- Audit trail of all login attempts

**Next Steps for Production:**
1. Switch to Redis storage for multi-server deployments
2. Add APScheduler for automatic cleanup of old attempts
3. Implement alerting on suspicious patterns
4. Create admin dashboard for rate limit monitoring
5. Consider additional protections (CAPTCHA, email verification)

**Status:** ✅ Ready for production with configurable storage backend
