---
layout: default
title: "Sensitive Information Disclosure"
permalink: /ttps/data-exfiltration/sensitive-information-disclosure/
nav_order: 6
parent: "Data Exfiltration & Credential Theft"
grand_parent: "MCP Security TTPs"
---

# Sensitive Information Disclosure

**Category**: Data Exfiltration & Credential Theft  
**Severity**: High  
**MITRE ATT&CK Mapping**: T1083 (File and Directory Discovery)

## Description

Unintended exposure of confidential data through MCP tool responses, logging mechanisms, or error messages, leading to information disclosure that compromises data confidentiality.

## Technical Details

### Attack Vector
- Sensitive data in tool responses
- Information leakage through logs
- Error message disclosure
- Debugging information exposure

### Common Techniques
- Response data mining
- Log file analysis
- Error message extraction
- Debug information harvesting

## Impact

- **Data Disclosure**: Confidential information exposed
- **Privacy Violation**: Personal data compromised
- **Compliance Breach**: Regulatory violations
- **Intelligence Gathering**: Sensitive business information exposed

## Detection Methods

### Response Monitoring
- Monitor tool responses for sensitive data
- Scan logs for information disclosure
- Analyze error messages for data leakage
- Track information exposure patterns

### Content Analysis
- Analyze response content for sensitive patterns
- Monitor log content for disclosure
- Detect information leakage patterns
- Track data exposure incidents

## Mitigation Strategies

### Data Protection
- Implement response sanitization
- Use data classification systems
- Deploy information filtering
- Monitor data disclosure

### Output Security
- Secure logging mechanisms
- Implement error message sanitization
- Use response validation
- Deploy output monitoring

## Real-World Examples

### Example 1: Response Data Leakage
```python
def get_user_info(user_id):
    user = database.get_user(user_id)
    
    # Sensitive data exposed in response
    return {
        'name': user.name,
        'email': user.email,
        'ssn': user.ssn,  # Sensitive data exposed
        'credit_card': user.credit_card,  # Sensitive data exposed
        'password_hash': user.password_hash  # Sensitive data exposed
    }
```

### Example 2: Log Information Disclosure
```python
def process_payment(payment_data):
    # Sensitive data logged
    logger.info(f"Processing payment: {payment_data}")
    
    # payment_data contains credit card numbers, SSNs, etc.
    return process_transaction(payment_data)
```

### Example 3: Error Message Exposure
```python
def connect_to_database():
    try:
        return database.connect()
    except Exception as e:
        # Sensitive system information in error
        raise Exception(f"Database connection failed: {database.connection_string}, error: {str(e)}")
```

## References & Sources

- **Prompt Security** - "Top 10 MCP Security Risks You Need to Know"
- **Writer** - "Model Context Protocol (MCP) security"
- **Red Hat** - "Model Context Protocol (MCP): Understanding security risks and controls"

## Related TTPs

- [Data Exfiltration](data-exfiltration.md)
- [API Key Exposure](api-key-exposure.md)
- [Insufficient Logging](../monitoring-failures/insufficient-logging.md)

---

*Sensitive information disclosure represents a critical threat to data confidentiality and privacy in MCP systems.*