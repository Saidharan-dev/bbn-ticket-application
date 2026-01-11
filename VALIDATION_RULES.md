# Input Validation & Sanitization Rules

## Overview
All user inputs are now validated and sanitized to prevent:
- XSS (Cross-Site Scripting) attacks
- SQL injection (when migrating to database)
- Buffer overflow attempts
- Invalid data formats
- Malicious input

---

## Validation Rules by Field

### Username
- **Length**: 3-50 characters
- **Characters**: Letters, numbers, underscores only (`[a-zA-Z0-9_]`)
- **Error Code**: 400 Bad Request

### Password
- **Length**: 6-256 characters
- **Type**: Must be string
- **Storage**: Hashed with bcrypt (never stored plain text)
- **Error Code**: 400 Bad Request

### Company Name
- **Length**: 2-100 characters
- **Characters**: Letters, numbers, spaces, hyphens, underscores, ampersand, periods, commas
- **Pattern**: `[a-zA-Z0-9\s\-_&.,]`
- **Error Code**: 400 Bad Request

### Priority
- **Valid Values**: `Low`, `Medium`, `High`
- **Default**: `Medium`
- **Error Code**: 400 Bad Request

### Problem Description
- **Length**: 5-5000 characters
- **Type**: Must be string
- **Sanitization**: HTML escaped to prevent XSS
- **Error Code**: 400 Bad Request

### Solution
- **Length**: 5-5000 characters
- **Type**: Must be string
- **Sanitization**: HTML escaped to prevent XSS
- **Error Code**: 400 Bad Request

### Raised By
- **Length**: 2-100 characters
- **Type**: Must be string
- **Sanitization**: HTML escaped to prevent XSS
- **Error Code**: 400 Bad Request

### Designation
- **Length**: 2-50 characters
- **Characters**: Letters, numbers, spaces, hyphens, underscores, forward slash, ampersand, periods
- **Pattern**: `[a-zA-Z0-9\s\-_/&.]`
- **Sanitization**: HTML escaped to prevent XSS
- **Error Code**: 400 Bad Request

### Chat Message
- **Length**: 1-5000 characters
- **Type**: Must be string
- **Sanitization**: HTML escaped to prevent XSS
- **Error Code**: 400 Bad Request

### Role
- **Valid Values**: `admin`, `company`
- **Error Code**: 400 Bad Request

---

## Sanitization Methods

### HTML Escaping
All text fields are HTML escaped using Python's `html.escape()` function to prevent XSS:
- `<` → `&lt;`
- `>` → `&gt;`
- `&` → `&amp;`
- `"` → `&quot;`
- `'` → `&#x27;`

### Example
```python
from html import escape

# User input
problem = "<script>alert('hacked')</script>"

# After sanitization
problem = escape(problem)
# Result: "&lt;script&gt;alert(&#x27;hacked&#x27;)&lt;/script&gt;"
```

---

## Error Responses

All validation errors return **HTTP 400 Bad Request** with structured JSON:

```json
{
  "error": "Username must be 3-50 characters"
}
```

---

## Protected Endpoints

1. **POST /login** - Validates username, password, role
2. **POST /api/tickets** - Validates problem, priority, raised_by, designation
3. **POST /api/tickets/<id>/solution** - Validates solution text
4. **POST /api/companies** - Validates company_name, password
5. **POST /api/chat** - Validates message

---

## Testing Validation

### Test 1: Invalid Username (Too Short)
```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"ab","password":"password123","role":"admin"}'
```
Expected: `{"error": "Username must be 3-50 characters"}`

### Test 2: Invalid Priority
```bash
curl -X POST http://localhost:5000/api/tickets \
  -H "Content-Type: application/json" \
  -d '{"problem":"Test","priority":"Urgent","raised_by":"John","designation":"Developer"}'
```
Expected: `{"error": "Priority must be one of: Low, Medium, High"}`

### Test 3: Problem Too Short
```bash
curl -X POST http://localhost:5000/api/tickets \
  -H "Content-Type: application/json" \
  -d '{"problem":"abc","priority":"High","raised_by":"John","designation":"Developer"}'
```
Expected: `{"error": "Problem description must be 5-5000 characters"}`

### Test 4: XSS Prevention
```bash
curl -X POST http://localhost:5000/api/tickets \
  -H "Content-Type: application/json" \
  -d '{"problem":"<script>alert(\"hacked\")</script>","priority":"High","raised_by":"John","designation":"Developer"}'
```
Expected: Problem is stored as escaped HTML, rendering safely in UI

---

## Next Steps
- Monitor logs for failed validation attempts (indicates potential attacks)
- Add rate limiting to prevent brute force attempts
- Implement request logging for audit trail
