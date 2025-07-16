---
layout: default
title: "Tool Metadata Specification"
permalink: /build/tool-metadata-spec/
nav_order: 5
parent: "Build Security"
---

# Tool Metadata Specification

**Overview**: Formal specification for secure tool metadata schema and validation.

This specification defines the standardized metadata format for MCP tools, including security requirements, validation rules, and integrity mechanisms to ensure tool authenticity and prevent metadata manipulation attacks.

## Core Metadata Schema

### Basic Tool Metadata Structure

```json
{
  "schema_version": "1.0",
  "tool": {
    "name": "string",
    "version": "string",
    "description": "string",
    "author": {
      "name": "string",
      "email": "string",
      "organization": "string"
    },
    "capabilities": ["string"],
    "parameters": {
      "type": "object",
      "properties": {},
      "required": []
    },
    "security": {
      "required_permissions": ["string"],
      "risk_level": "low|medium|high|critical",
      "sandboxing_required": "boolean",
      "network_access": "none|local|internet",
      "file_access": "none|read|write|full"
    },
    "signature": {
      "algorithm": "string",
      "signature": "string",
      "certificate": "string",
      "timestamp": "string"
    }
  }
}
```

### Enhanced Tool Definition Interface (ETDI)

```python
# Enhanced Tool Definition Interface implementation
import json
import jsonschema
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import time

@dataclass
class ToolMetadata:
    name: str
    version: str
    description: str
    author: Dict[str, str]
    capabilities: List[str]
    parameters: Dict[str, Any]
    security: Dict[str, Any]
    signature: Optional[Dict[str, str]] = None

class ETDIValidator:
    def __init__(self):
        self.schema = self.load_schema()
        self.trusted_certificates = {}
        self.revoked_certificates = set()
        
    def load_schema(self) -> Dict:
        """Load ETDI JSON schema"""
        
        return {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "schema_version": {
                    "type": "string",
                    "pattern": "^\\d+\\.\\d+$"
                },
                "tool": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "pattern": "^[a-zA-Z0-9_-]+$",
                            "minLength": 1,
                            "maxLength": 64
                        },
                        "version": {
                            "type": "string",
                            "pattern": "^\\d+\\.\\d+\\.\\d+$"
                        },
                        "description": {
                            "type": "string",
                            "minLength": 10,
                            "maxLength": 500
                        },
                        "author": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string", "minLength": 1, "maxLength": 100},
                                "email": {"type": "string", "format": "email"},
                                "organization": {"type": "string", "maxLength": 100}
                            },
                            "required": ["name", "email"]
                        },
                        "capabilities": {
                            "type": "array",
                            "items": {
                                "type": "string",
                                "enum": [
                                    "read_file", "write_file", "execute_command",
                                    "network_request", "database_access", "system_info",
                                    "user_interaction", "admin_operation"
                                ]
                            },
                            "minItems": 1,
                            "uniqueItems": True
                        },
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "type": {"const": "object"},
                                "properties": {"type": "object"},
                                "required": {"type": "array", "items": {"type": "string"}}
                            },
                            "required": ["type", "properties"]
                        },
                        "security": {
                            "type": "object",
                            "properties": {
                                "required_permissions": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                },
                                "risk_level": {
                                    "type": "string",
                                    "enum": ["low", "medium", "high", "critical"]
                                },
                                "sandboxing_required": {"type": "boolean"},
                                "network_access": {
                                    "type": "string",
                                    "enum": ["none", "local", "internet"]
                                },
                                "file_access": {
                                    "type": "string",
                                    "enum": ["none", "read", "write", "full"]
                                },
                                "allowed_domains": {
                                    "type": "array",
                                    "items": {"type": "string", "format": "hostname"}
                                },
                                "allowed_paths": {
                                    "type": "array",
                                    "items": {"type": "string"}
                                }
                            },
                            "required": ["required_permissions", "risk_level", "sandboxing_required", "network_access", "file_access"]
                        },
                        "signature": {
                            "type": "object",
                            "properties": {
                                "algorithm": {
                                    "type": "string",
                                    "enum": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
                                },
                                "signature": {"type": "string"},
                                "certificate": {"type": "string"},
                                "timestamp": {"type": "string", "format": "date-time"}
                            },
                            "required": ["algorithm", "signature", "certificate", "timestamp"]
                        }
                    },
                    "required": ["name", "version", "description", "author", "capabilities", "parameters", "security"]
                }
            },
            "required": ["schema_version", "tool"]
        }
    
    def validate_metadata(self, metadata: Dict) -> ValidationResult:
        """Validate tool metadata against ETDI schema"""
        
        try:
            # Schema validation
            jsonschema.validate(metadata, self.schema)
            
            # Additional semantic validation
            semantic_result = self.validate_semantic_rules(metadata)
            if not semantic_result.valid:
                return semantic_result
            
            # Signature validation
            signature_result = self.validate_signature(metadata)
            if not signature_result.valid:
                return signature_result
            
            # Security validation
            security_result = self.validate_security_configuration(metadata)
            if not security_result.valid:
                return security_result
            
            return ValidationResult(valid=True, message="Metadata validation successful")
            
        except jsonschema.ValidationError as e:
            return ValidationResult(valid=False, message=f"Schema validation failed: {e.message}")
        except Exception as e:
            return ValidationResult(valid=False, message=f"Validation error: {str(e)}")
    
    def validate_semantic_rules(self, metadata: Dict) -> ValidationResult:
        """Validate semantic rules for tool metadata"""
        
        tool = metadata.get('tool', {})
        
        # Check name conflicts
        if self.is_name_conflict(tool.get('name')):
            return ValidationResult(valid=False, message="Tool name conflicts with existing tool")
        
        # Validate capability-security alignment
        capabilities = tool.get('capabilities', [])
        security = tool.get('security', {})
        
        if not self.validate_capability_security_alignment(capabilities, security):
            return ValidationResult(valid=False, message="Capabilities and security configuration misaligned")
        
        # Validate parameter schema
        parameters = tool.get('parameters', {})
        if not self.validate_parameter_schema(parameters):
            return ValidationResult(valid=False, message="Invalid parameter schema")
        
        # Check description quality
        description = tool.get('description', '')
        if not self.validate_description_quality(description):
            return ValidationResult(valid=False, message="Description does not meet quality standards")
        
        return ValidationResult(valid=True, message="Semantic validation passed")
    
    def validate_capability_security_alignment(self, capabilities: List[str], security: Dict) -> bool:
        """Validate that capabilities align with security configuration"""
        
        # High-risk capabilities should have appropriate security settings
        high_risk_capabilities = ['execute_command', 'admin_operation', 'system_info']
        
        for capability in capabilities:
            if capability in high_risk_capabilities:
                if security.get('risk_level') not in ['high', 'critical']:
                    return False
                if not security.get('sandboxing_required', False):
                    return False
        
        # Network capabilities should have network access configured
        if 'network_request' in capabilities:
            if security.get('network_access') == 'none':
                return False
        
        # File capabilities should have file access configured
        file_capabilities = ['read_file', 'write_file']
        if any(cap in capabilities for cap in file_capabilities):
            if security.get('file_access') == 'none':
                return False
        
        return True
    
    def validate_signature(self, metadata: Dict) -> ValidationResult:
        """Validate tool metadata signature"""
        
        tool = metadata.get('tool', {})
        signature_info = tool.get('signature')
        
        if not signature_info:
            return ValidationResult(valid=False, message="Tool signature required")
        
        try:
            # Extract signature components
            algorithm = signature_info.get('algorithm')
            signature = signature_info.get('signature')
            certificate = signature_info.get('certificate')
            timestamp = signature_info.get('timestamp')
            
            # Validate certificate
            if not self.validate_certificate(certificate):
                return ValidationResult(valid=False, message="Invalid certificate")
            
            # Check certificate revocation
            if certificate in self.revoked_certificates:
                return ValidationResult(valid=False, message="Certificate has been revoked")
            
            # Validate signature
            if not self.verify_signature(tool, algorithm, signature, certificate):
                return ValidationResult(valid=False, message="Signature verification failed")
            
            # Check timestamp
            if not self.validate_timestamp(timestamp):
                return ValidationResult(valid=False, message="Invalid or expired timestamp")
            
            return ValidationResult(valid=True, message="Signature validation successful")
            
        except Exception as e:
            return ValidationResult(valid=False, message=f"Signature validation error: {str(e)}")
    
    def verify_signature(self, tool: Dict, algorithm: str, signature: str, certificate: str) -> bool:
        """Verify tool metadata signature"""
        
        try:
            # Load certificate
            cert_data = base64.b64decode(certificate)
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            # Get public key
            public_key = cert.public_key()
            
            # Create canonical representation for signing
            canonical_tool = self.create_canonical_representation(tool)
            
            # Verify signature
            signature_bytes = base64.b64decode(signature)
            
            if algorithm.startswith('RS'):
                # RSA signature
                public_key.verify(
                    signature_bytes,
                    canonical_tool.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            else:
                # ECDSA signature
                public_key.verify(
                    signature_bytes,
                    canonical_tool.encode('utf-8'),
                    ec.ECDSA(hashes.SHA256())
                )
            
            return True
            
        except Exception:
            return False
    
    def create_canonical_representation(self, tool: Dict) -> str:
        """Create canonical representation of tool for signing"""
        
        # Create copy without signature
        canonical_tool = tool.copy()
        canonical_tool.pop('signature', None)
        
        # Sort keys for consistent representation
        return json.dumps(canonical_tool, sort_keys=True, separators=(',', ':'))
```

## Security Validation Rules

### Security Configuration Validator

```python
# Security configuration validation
class SecurityConfigValidator:
    def __init__(self):
        self.risk_level_requirements = {
            'low': {
                'max_capabilities': ['read_file', 'user_interaction'],
                'required_sandbox': False,
                'max_network_access': 'local',
                'max_file_access': 'read'
            },
            'medium': {
                'max_capabilities': ['read_file', 'write_file', 'network_request', 'user_interaction'],
                'required_sandbox': True,
                'max_network_access': 'internet',
                'max_file_access': 'write'
            },
            'high': {
                'max_capabilities': ['read_file', 'write_file', 'network_request', 'database_access', 'system_info'],
                'required_sandbox': True,
                'max_network_access': 'internet',
                'max_file_access': 'full'
            },
            'critical': {
                'max_capabilities': ['execute_command', 'admin_operation'],
                'required_sandbox': True,
                'max_network_access': 'internet',
                'max_file_access': 'full'
            }
        }
    
    def validate_security_configuration(self, metadata: Dict) -> ValidationResult:
        """Validate security configuration against risk level"""
        
        tool = metadata.get('tool', {})
        security = tool.get('security', {})
        capabilities = tool.get('capabilities', [])
        
        risk_level = security.get('risk_level')
        requirements = self.risk_level_requirements.get(risk_level)
        
        if not requirements:
            return ValidationResult(valid=False, message=f"Invalid risk level: {risk_level}")
        
        # Check capability restrictions
        if not self.validate_capability_restrictions(capabilities, requirements):
            return ValidationResult(valid=False, message="Capabilities exceed risk level restrictions")
        
        # Check sandbox requirements
        if requirements['required_sandbox'] and not security.get('sandboxing_required', False):
            return ValidationResult(valid=False, message="Sandboxing required for this risk level")
        
        # Check network access restrictions
        if not self.validate_network_access(security.get('network_access'), requirements['max_network_access']):
            return ValidationResult(valid=False, message="Network access exceeds risk level restrictions")
        
        # Check file access restrictions
        if not self.validate_file_access(security.get('file_access'), requirements['max_file_access']):
            return ValidationResult(valid=False, message="File access exceeds risk level restrictions")
        
        return ValidationResult(valid=True, message="Security configuration valid")
    
    def validate_capability_restrictions(self, capabilities: List[str], requirements: Dict) -> bool:
        """Validate capabilities against risk level restrictions"""
        
        max_capabilities = requirements['max_capabilities']
        
        for capability in capabilities:
            if capability not in max_capabilities:
                return False
        
        return True
    
    def validate_network_access(self, requested_access: str, max_access: str) -> bool:
        """Validate network access level"""
        
        access_levels = {'none': 0, 'local': 1, 'internet': 2}
        
        requested_level = access_levels.get(requested_access, 0)
        max_level = access_levels.get(max_access, 0)
        
        return requested_level <= max_level
    
    def validate_file_access(self, requested_access: str, max_access: str) -> bool:
        """Validate file access level"""
        
        access_levels = {'none': 0, 'read': 1, 'write': 2, 'full': 3}
        
        requested_level = access_levels.get(requested_access, 0)
        max_level = access_levels.get(max_access, 0)
        
        return requested_level <= max_level
```

## Metadata Integrity Protection

### Signing and Verification System

```python
# Metadata signing and verification
class MetadataSigningSystem:
    def __init__(self, private_key_path: str, certificate_path: str):
        self.private_key = self.load_private_key(private_key_path)
        self.certificate = self.load_certificate(certificate_path)
        
    def sign_metadata(self, metadata: Dict) -> Dict:
        """Sign tool metadata with digital signature"""
        
        # Create canonical representation
        canonical_data = self.create_canonical_data(metadata)
        
        # Generate signature
        signature = self.generate_signature(canonical_data)
        
        # Add signature to metadata
        metadata['tool']['signature'] = {
            'algorithm': 'RS256',
            'signature': base64.b64encode(signature).decode('utf-8'),
            'certificate': base64.b64encode(self.certificate.public_bytes(
                encoding=serialization.Encoding.DER
            )).decode('utf-8'),
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        return metadata
    
    def generate_signature(self, data: str) -> bytes:
        """Generate digital signature for data"""
        
        signature = self.private_key.sign(
            data.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def verify_metadata_integrity(self, metadata: Dict) -> bool:
        """Verify metadata integrity using signature"""
        
        signature_info = metadata.get('tool', {}).get('signature')
        if not signature_info:
            return False
        
        # Extract signature
        signature = base64.b64decode(signature_info['signature'])
        certificate = base64.b64decode(signature_info['certificate'])
        
        # Load certificate
        cert = x509.load_der_x509_certificate(certificate, default_backend())
        public_key = cert.public_key()
        
        # Create canonical representation without signature
        metadata_copy = metadata.copy()
        metadata_copy['tool'].pop('signature', None)
        canonical_data = self.create_canonical_data(metadata_copy)
        
        try:
            # Verify signature
            public_key.verify(
                signature,
                canonical_data.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    def create_canonical_data(self, metadata: Dict) -> str:
        """Create canonical representation of metadata"""
        
        return json.dumps(metadata, sort_keys=True, separators=(',', ':'))
```

## Reputation System Integration

### Tool Reputation Tracking

```python
# Tool reputation system
class ToolReputationSystem:
    def __init__(self):
        self.reputation_scores = {}
        self.feedback_history = {}
        self.trust_network = {}
        
    def calculate_reputation_score(self, tool_name: str, author: str) -> float:
        """Calculate reputation score for tool"""
        
        # Base score components
        author_reputation = self.get_author_reputation(author)
        usage_statistics = self.get_usage_statistics(tool_name)
        user_feedback = self.get_user_feedback(tool_name)
        security_analysis = self.get_security_analysis(tool_name)
        
        # Weighted calculation
        reputation_score = (
            author_reputation * 0.3 +
            usage_statistics * 0.2 +
            user_feedback * 0.3 +
            security_analysis * 0.2
        )
        
        return min(max(reputation_score, 0.0), 1.0)
    
    def get_author_reputation(self, author: str) -> float:
        """Get reputation score for tool author"""
        
        author_data = self.reputation_scores.get(author, {})
        
        # Factors affecting author reputation
        published_tools = author_data.get('published_tools', 0)
        average_tool_rating = author_data.get('average_tool_rating', 0.5)
        security_incidents = author_data.get('security_incidents', 0)
        community_standing = author_data.get('community_standing', 0.5)
        
        # Calculate author reputation
        reputation = (
            min(published_tools / 10, 1.0) * 0.2 +
            average_tool_rating * 0.4 +
            max(1.0 - security_incidents * 0.1, 0.0) * 0.2 +
            community_standing * 0.2
        )
        
        return reputation
    
    def get_user_feedback(self, tool_name: str) -> float:
        """Get user feedback score for tool"""
        
        feedback = self.feedback_history.get(tool_name, {})
        
        positive_feedback = feedback.get('positive', 0)
        negative_feedback = feedback.get('negative', 0)
        total_feedback = positive_feedback + negative_feedback
        
        if total_feedback == 0:
            return 0.5  # Neutral score for no feedback
        
        # Calculate feedback ratio with confidence adjustment
        ratio = positive_feedback / total_feedback
        confidence = min(total_feedback / 100, 1.0)
        
        return ratio * confidence + 0.5 * (1 - confidence)
    
    def update_reputation(self, tool_name: str, author: str, feedback_type: str, details: Dict):
        """Update reputation based on feedback"""
        
        if feedback_type == 'positive_usage':
            self.record_positive_usage(tool_name, author, details)
        elif feedback_type == 'negative_usage':
            self.record_negative_usage(tool_name, author, details)
        elif feedback_type == 'security_incident':
            self.record_security_incident(tool_name, author, details)
        elif feedback_type == 'community_feedback':
            self.record_community_feedback(tool_name, author, details)
    
    def record_security_incident(self, tool_name: str, author: str, incident_details: Dict):
        """Record security incident affecting reputation"""
        
        # Update author reputation
        if author not in self.reputation_scores:
            self.reputation_scores[author] = {}
        
        author_data = self.reputation_scores[author]
        author_data['security_incidents'] = author_data.get('security_incidents', 0) + 1
        
        # Update tool reputation
        if tool_name not in self.feedback_history:
            self.feedback_history[tool_name] = {}
        
        tool_feedback = self.feedback_history[tool_name]
        tool_feedback['negative'] = tool_feedback.get('negative', 0) + 5  # Heavy penalty
        
        # Broadcast to trust network
        self.broadcast_security_incident(tool_name, author, incident_details)
```

## Registry Integration

### Metadata Registry System

```python
# Metadata registry system
class MetadataRegistry:
    def __init__(self):
        self.registry_db = {}
        self.validator = ETDIValidator()
        self.reputation_system = ToolReputationSystem()
        self.access_control = RegistryAccessControl()
        
    def register_tool(self, metadata: Dict, publisher_credentials: Dict) -> RegistrationResult:
        """Register tool metadata in registry"""
        
        # Validate publisher credentials
        if not self.access_control.validate_publisher(publisher_credentials):
            return RegistrationResult(success=False, message="Invalid publisher credentials")
        
        # Validate metadata
        validation_result = self.validator.validate_metadata(metadata)
        if not validation_result.valid:
            return RegistrationResult(success=False, message=validation_result.message)
        
        # Check for name conflicts
        tool_name = metadata['tool']['name']
        if self.is_name_taken(tool_name):
            return RegistrationResult(success=False, message="Tool name already registered")
        
        # Calculate initial reputation
        author = metadata['tool']['author']['name']
        reputation = self.reputation_system.calculate_reputation_score(tool_name, author)
        
        # Store in registry
        registry_entry = {
            'metadata': metadata,
            'publisher': publisher_credentials['publisher_id'],
            'registration_time': time.time(),
            'reputation_score': reputation,
            'download_count': 0,
            'status': 'active'
        }
        
        self.registry_db[tool_name] = registry_entry
        
        return RegistrationResult(success=True, message="Tool registered successfully")
    
    def search_tools(self, query: Dict) -> List[Dict]:
        """Search tools in registry"""
        
        results = []
        
        # Extract search criteria
        name_pattern = query.get('name_pattern', '')
        capabilities = query.get('capabilities', [])
        risk_level = query.get('max_risk_level', 'critical')
        min_reputation = query.get('min_reputation', 0.0)
        
        for tool_name, entry in self.registry_db.items():
            if self.matches_search_criteria(entry, name_pattern, capabilities, risk_level, min_reputation):
                results.append(self.format_search_result(entry))
        
        # Sort by reputation score
        results.sort(key=lambda x: x['reputation_score'], reverse=True)
        
        return results
    
    def get_tool_metadata(self, tool_name: str, requester_credentials: Dict) -> Optional[Dict]:
        """Get tool metadata from registry"""
        
        # Check access permissions
        if not self.access_control.can_access_tool(tool_name, requester_credentials):
            return None
        
        entry = self.registry_db.get(tool_name)
        if not entry or entry['status'] != 'active':
            return None
        
        # Update download count
        entry['download_count'] += 1
        
        # Return metadata with reputation info
        result = entry['metadata'].copy()
        result['registry_info'] = {
            'reputation_score': entry['reputation_score'],
            'download_count': entry['download_count'],
            'registration_time': entry['registration_time']
        }
        
        return result
    
    def update_tool_reputation(self, tool_name: str, feedback: Dict):
        """Update tool reputation based on feedback"""
        
        entry = self.registry_db.get(tool_name)
        if not entry:
            return
        
        # Update reputation system
        author = entry['metadata']['tool']['author']['name']
        self.reputation_system.update_reputation(
            tool_name,
            author,
            feedback['type'],
            feedback['details']
        )
        
        # Recalculate reputation score
        new_reputation = self.reputation_system.calculate_reputation_score(tool_name, author)
        entry['reputation_score'] = new_reputation
        
        # Take action if reputation drops too low
        if new_reputation < 0.3:
            self.flag_tool_for_review(tool_name, "Low reputation score")
```

## Implementation Guidelines

### Best Practices

1. **Schema Evolution**: Design schema for backward compatibility
2. **Validation Performance**: Optimize validation for high-throughput scenarios
3. **Security by Default**: Enforce secure defaults in metadata
4. **Reputation Integration**: Integrate reputation scoring into tool selection
5. **Monitoring**: Monitor metadata manipulation attempts

### Common Pitfalls

- **Insufficient Validation**: Weak validation leading to metadata manipulation
- **Signature Bypass**: Inadequate signature verification
- **Reputation Gaming**: Vulnerable reputation calculation
- **Schema Rigidity**: Inflexible schema preventing evolution
- **Performance Issues**: Slow validation affecting user experience

### Integration Example

```python
# Complete metadata system integration
class ComprehensiveMetadataSystem:
    def __init__(self):
        self.validator = ETDIValidator()
        self.registry = MetadataRegistry()
        self.reputation_system = ToolReputationSystem()
        self.signing_system = MetadataSigningSystem()
        
    def process_tool_submission(self, metadata: Dict, publisher_credentials: Dict) -> ProcessingResult:
        """Process complete tool submission"""
        
        # Validate metadata
        validation_result = self.validator.validate_metadata(metadata)
        if not validation_result.valid:
            return ProcessingResult(success=False, message=validation_result.message)
        
        # Sign metadata
        signed_metadata = self.signing_system.sign_metadata(metadata)
        
        # Register in registry
        registration_result = self.registry.register_tool(signed_metadata, publisher_credentials)
        
        return ProcessingResult(
            success=registration_result.success,
            message=registration_result.message,
            metadata=signed_metadata if registration_result.success else None
        )
```

---

*Tool Metadata Specification provides a comprehensive framework for secure, standardized tool metadata that enables trust, validation, and integrity verification in MCP ecosystems.*