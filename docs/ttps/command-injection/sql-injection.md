---
layout: default
title: "SQL Injection"
permalink: /ttps/command-injection/sql-injection/
nav_order: 2
parent: "Command & Code Injection"
grand_parent: "MCP Security TTPs"
---

# SQL Injection

**Category**: Command & Code Injection  
**Severity**: Critical  

## Description

Injection of malicious SQL queries through MCP database tools, enabling attackers to manipulate database operations, extract sensitive data, or gain unauthorized access to database systems.

## Technical Details

### Attack Vector
- Unsanitized input in SQL queries
- Dynamic query construction
- Parameter injection in database calls
- SQL command manipulation

### Common Techniques
- Union-based SQL injection
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- Error-based SQL injection

## Impact

- **Database Compromise**: Unauthorized access to database systems
- **Data Exfiltration**: Extraction of sensitive database information
- **Data Manipulation**: Modification or deletion of database records
- **Authentication Bypass**: Circumvention of database authentication

## Detection Methods

### Database Monitoring
- Monitor SQL query patterns
- Track database access attempts
- Detect unusual query structures
- Analyze query execution times

### Error Analysis
- Monitor database error messages
- Track failed query attempts
- Detect SQL syntax errors
- Analyze query execution failures

## Mitigation Strategies

### Query Security
- Use parameterized queries
- Implement prepared statements
- Deploy query validation
- Use stored procedures

### Database Security
- Implement database access controls
- Use database user permissions
- Deploy database monitoring
- Enable database auditing

## Real-World Examples

### Example 1: Union-Based Injection
```python
def get_user_by_id(user_id):
    # Vulnerable query construction
    query = f"SELECT * FROM users WHERE id = {user_id}"
    result = database.execute(query)
    
    # Attack: user_id = "1 UNION SELECT username, password FROM admin_users"
    # Executed: SELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM admin_users
```

### Example 2: Authentication Bypass
```python
def authenticate_user(username, password):
    # Vulnerable authentication query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    result = database.execute(query)
    
    # Attack: username = "admin' OR '1'='1' --"
    # Executed: SELECT * FROM users WHERE username = 'admin' OR '1'='1' --' AND password = 'password'
```

### Example 3: Data Extraction
```python
def search_products(search_term):
    # Vulnerable search query
    query = f"SELECT name, price FROM products WHERE name LIKE '%{search_term}%'"
    results = database.execute(query)
    
    # Attack: search_term = "' UNION SELECT credit_card, ssn FROM customers --"
    # Executed: SELECT name, price FROM products WHERE name LIKE '%' UNION SELECT credit_card, ssn FROM customers --%'
```

## References & Sources

- **Prompt Security** - "Top 10 MCP Security Risks You Need to Know"
- **Strobes Security** - "MCP and Its Critical Vulnerabilities"
- **Structured MCP Threats** - Comprehensive threat landscape analysis

## Related TTPs

- [Command Injection](command-injection.md)
- [Code Injection](code-injection.md)
- [OS Command Injection](os-command-injection.md)

---

*SQL injection remains one of the most prevalent and dangerous vulnerabilities in database-connected MCP systems.*