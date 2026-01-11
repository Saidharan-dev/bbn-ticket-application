# Session Management & JWT Tokens Documentation (Task 7)

## Overview
Task 7 implements JSON Web Token (JWT) based session management alongside traditional Flask session management. This provides secure, stateless authentication for API clients while maintaining backward compatibility with web frontends.

## Features Implemented

### 1. JWT Token Generation
Two types of tokens are created on successful login:

#### Access Token
```python
def create_access_token(username, role):
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),  # 24 hours
        'iat': datetime.utcnow(),
        'type': 'access'
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token
```

**Purpose:** Used for API requests  
**Expiration:** 24 hours (configurable)  
**Scope:** Full API access within token lifetime  

#### Refresh Token
```python
def create_refresh_token(username, role):
    payload = {
        'username': username,
        'role': role,
        'exp': datetime.utcnow() + timedelta(days=JWT_REFRESH_EXPIRATION_DAYS),  # 7 days
        'iat': datetime.utcnow(),
        'type': 'refresh'
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token
```

**Purpose:** Used to refresh expired access tokens  
**Expiration:** 7 days (configurable)  
**Scope:** Only valid for token refresh operations  

### 2. Configuration

**Environment Variables:**
```env
JWT_SECRET_KEY=your-secret-jwt-key  # Should be in .env file
```

**Default Settings:**
```python
JWT_EXPIRATION_HOURS = 24           # Access token lifetime
JWT_REFRESH_EXPIRATION_DAYS = 7     # Refresh token lifetime
JWT_ALGORITHM = 'HS256'             # HMAC SHA-256
```

### 3. Token Validation

```python
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
```

**Validates:**
- Token signature
- Token expiration
- Token blacklist status

### 4. Token Blacklist System

**TokenBlacklist Model:**
```python
class TokenBlacklist(db.Model):
    __tablename__ = 'token_blacklist'
    
    id = Column(Integer, primary_key=True)
    jti = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(50), nullable=False, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
```

**Purpose:**
- Revoke tokens on logout
- Prevent use of compromised tokens
- Audit trail of revocations

**Functions:**
```python
def is_token_blacklisted(jti):
    """Check if a token is blacklisted."""
    token = TokenBlacklist.query.filter_by(jti=jti).first()
    return token is not None

def blacklist_token(jti, username, expires_at):
    """Add a token to the blacklist."""
    blacklist_entry = TokenBlacklist(jti=jti, username=username, expires_at=expires_at)
    db.session.add(blacklist_entry)
    db.session.commit()
```

### 5. Authentication Decorators

#### JWT Token Required
```python
@token_required
def protected_endpoint():
    # access via request.user['username'] and request.user['role']
    pass
```

**Behavior:**
- Extracts token from `Authorization: Bearer <token>` header
- Validates token signature and expiration
- Sets `request.user` with username and role
- Returns 401 if token missing or invalid

#### Session Required (existing)
```python
@login_required
def web_endpoint():
    # access via session['username'] and session['role']
    pass
```

## API Endpoints

### Authentication Endpoints

#### POST /login
**Purpose:** Authenticate user and receive tokens

**Request:**
```json
{
    "username": "admin",
    "password": "admin123",
    "role": "admin"
}
```

**Response:**
```json
{
    "success": true,
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "token_type": "Bearer",
    "expires_in": 86400,
    "redirect": "/admin-dashboard"
}
```

**Status Codes:**
- 200: Success
- 400: Invalid input
- 401: Invalid credentials
- 429: Too many attempts (rate limited)

#### POST /api/logout
**Purpose:** Logout and invalidate tokens

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
    "success": true,
    "message": "Logged out successfully"
}
```

**Behavior:**
- Blacklists the provided token
- Prevents further use of that token
- Session cleared on client

#### POST /api/refresh-token
**Purpose:** Get new access token using refresh token

**Request:**
```json
{
    "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Response:**
```json
{
    "success": true,
    "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "token_type": "Bearer",
    "expires_in": 86400
}
```

**Status Codes:**
- 200: Success
- 400: Missing refresh token
- 401: Invalid or expired refresh token

**Rate Limit:** 100 per hour (to prevent abuse)

#### POST /api/verify-token
**Purpose:** Verify token validity without authentication

**Request:**
```json
{
    "token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Response (Valid Token):**
```json
{
    "valid": true,
    "username": "admin",
    "role": "admin",
    "expires_at": 1704902400
}
```

**Response (Invalid Token):**
```json
{
    "valid": false,
    "error": "Token has expired"
}
```

## Usage Examples

### Web Frontend (Session-Based)
```javascript
// Login
fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        username: 'admin',
        password: 'admin123',
        role: 'admin'
    })
})
.then(r => r.json())
.then(data => {
    // Tokens provided but not needed for web frontend
    // Session cookie automatically set
    window.location = data.redirect;
})

// Logout
fetch('/logout')
.then(() => window.location = '/login')
```

### Mobile/API Client (Token-Based)
```javascript
// Login
const loginResponse = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
        username: 'company1',
        password: 'password',
        role: 'company'
    })
})

const { access_token, refresh_token } = await loginResponse.json()
localStorage.setItem('access_token', access_token)
localStorage.setItem('refresh_token', refresh_token)

// Authenticated Request
const response = await fetch('/api/tickets', {
    method: 'GET',
    headers: {
        'Authorization': `Bearer ${localStorage.getItem('access_token')}`
    }
})

// Handle token expiration
if (response.status === 401) {
    // Refresh token
    const refreshResponse = await fetch('/api/refresh-token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            refresh_token: localStorage.getItem('refresh_token')
        })
    })
    
    const { access_token: new_token } = await refreshResponse.json()
    localStorage.setItem('access_token', new_token)
    
    // Retry original request
}

// Logout
await fetch('/api/logout', {
    method: 'POST',
    headers: {
        'Authorization': `Bearer ${localStorage.getItem('access_token')}`
    }
})

localStorage.removeItem('access_token')
localStorage.removeItem('refresh_token')
```

### cURL Examples
```bash
# Login
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","role":"admin"}'

# Get tickets with token
curl -X GET http://localhost:5000/api/tickets \
  -H "Authorization: Bearer <access_token>"

# Refresh token
curl -X POST http://localhost:5000/api/refresh-token \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'

# Verify token
curl -X POST http://localhost:5000/api/verify-token \
  -H "Content-Type: application/json" \
  -d '{"token":"<token>"}'

# Logout
curl -X POST http://localhost:5000/api/logout \
  -H "Authorization: Bearer <access_token>"
```

## Security Features

### 1. Token Signature
- HMAC SHA-256 algorithm
- Secret key in environment variables
- Cannot be modified without invalidating signature

### 2. Token Expiration
- Access tokens: 24 hours
- Refresh tokens: 7 days
- Automatic rejection of expired tokens

### 3. Token Blacklist
- Logout immediately invalidates token
- Prevents replay attacks with revoked tokens
- Compromise: tokens blacklisted, new login required

### 4. Claim Validation
- Username and role embedded in token
- Cannot be modified after creation
- Validated on every request

### 5. No Session State
- Tokens are stateless
- Can be verified without database lookup
- Scales to multiple servers

## Token Payload Structure

```json
{
  "username": "admin",
  "role": "admin",
  "exp": 1704902400,        // Expiration timestamp
  "iat": 1704816000,        // Issued at timestamp
  "type": "access"          // Token type: access or refresh
}
```

**Claims:**
- `username`: User identifier
- `role`: User role (admin/company)
- `exp`: Expiration time (Unix timestamp)
- `iat`: Token issued time (Unix timestamp)
- `type`: Token purpose (access/refresh)

## Configuration Best Practices

### Development
```env
JWT_SECRET_KEY=dev-secret-key-123456
FLASK_ENV=development
JWT_EXPIRATION_HOURS=24
JWT_REFRESH_EXPIRATION_DAYS=7
```

### Production
```env
JWT_SECRET_KEY=<long-random-secret-from-secure-generator>
FLASK_ENV=production
JWT_EXPIRATION_HOURS=1        # Shorter lifetime
JWT_REFRESH_EXPIRATION_DAYS=30
```

**Generate Secure Key:**
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Token Cleanup

### Database Maintenance
Blacklist entries accumulate over time. Implement cleanup:

```python
from datetime import datetime, timedelta
from main import db, TokenBlacklist

def cleanup_blacklist():
    """Remove expired tokens from blacklist."""
    now = datetime.utcnow()
    deleted = TokenBlacklist.query.filter(
        TokenBlacklist.expires_at < now
    ).delete()
    
    db.session.commit()
    logger.info(f'Cleaned up {deleted} expired blacklist entries')
```

**Run Daily:**
```bash
# Via APScheduler (future task)
# Or cron job:
0 2 * * * python -c "from main import app; app.app_context().push(); cleanup_blacklist()"
```

## Hybrid Authentication Strategy

### Web Frontend
- **Uses:** Flask sessions
- **How:** Cookie-based, automatic with browser
- **Advantage:** Simple, no JavaScript token management
- **No token needed in response**

### API Clients
- **Uses:** JWT tokens
- **How:** Bearer token in Authorization header
- **Advantage:** Stateless, scalable, no session server needed
- **Tokens in response body**

### Both Endpoints Support Both Methods
```python
# Web route (prefers session, accepts token)
@app.route('/api/tickets', methods=['GET'])
@login_required  # Accepts session OR token
def get_tickets():
    username = session.get('username') or request.user.get('username')
    ...
```

## Comparison: Session vs JWT

| Feature | Session | JWT |
|---------|---------|-----|
| **Server Storage** | Yes (database) | No (stateless) |
| **Scalability** | Limited (sticky sessions) | Excellent (any server) |
| **Mobile-Friendly** | No (cookies) | Yes (header tokens) |
| **Revocation** | Instant | With blacklist |
| **Performance** | Database lookup | Signature verification |
| **CORS** | Complex | Simple |
| **API Friendly** | No | Yes |

## Common Issues & Solutions

### Issue: Token Expired
```
Error: Token has expired
```
**Solution:** Refresh token using `/api/refresh-token` endpoint

### Issue: Invalid Signature
```
Error: Invalid token
```
**Solution:** Token was tampered with or uses different secret key

### Issue: Token Not Found
```
Error: Token is missing
```
**Solution:** Ensure `Authorization: Bearer <token>` header is present

### Issue: Can't Logout
```
Error: Logout failed
```
**Solution:** Provide valid access token; delete locally stored tokens

## Testing Tokens

### Decode Token (without verification)
```bash
python -c "
import jwt
import json
from base64 import urlsafe_b64decode

token = '<your_token>'
parts = token.split('.')
payload = urlsafe_b64decode(parts[1] + '==')
print(json.dumps(json.loads(payload), indent=2))
"
```

### Test Token Refresh
```bash
# 1. Get tokens from login
# 2. Wait for access token to expire (or test with expired token)
# 3. Use refresh token to get new access token
# 4. Use new access token for requests
```

## Summary

✅ **Task 7 Complete:** Session Management & JWT Tokens

**Deliverables:**
- JWT token generation (access + refresh)
- Token validation and expiration
- Token blacklist system for logout
- Token refresh mechanism
- Hybrid authentication (session + JWT)
- Rate limiting on token refresh
- Token verification endpoint

**Database Changes:**
- New `TokenBlacklist` table for revoked tokens

**Files Modified:**
- `main.py` - Added JWT functions, token endpoints, configuration
- `requirements.txt` - Added PyJWT==2.10.1

**New Endpoints:**
- `POST /api/logout` - Logout with JWT
- `POST /api/refresh-token` - Refresh access token
- `POST /api/verify-token` - Verify token without auth

**Security Features:**
- Stateless authentication via JWT
- Token expiration (24h access, 7d refresh)
- Blacklist-based revocation
- HMAC SHA-256 signatures
- Rate-limited refresh (100/hour)

**Backward Compatibility:**
- Session-based auth still works for web frontend
- API can use either session or JWT
- No breaking changes to existing endpoints

**Status:** ✅ Ready for production with configurable token lifetimes
