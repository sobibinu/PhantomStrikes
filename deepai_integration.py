import requests
import json
import logging
import os
from config import Config

logger = logging.getLogger(__name__)

class DeepAIIntegration:
    def __init__(self):
        self.api_key = os.environ.get('DEEPAI_API_KEY', Config.DEEPAI_API_KEY)
        self.text_classification_url = "https://api.deepai.org/api/text-classification"
        self.text_generation_url = "https://api.deepai.org/api/text-generator"
        self.headers = {
            'api-key': self.api_key,
            'Content-Type': 'application/json'
        }
    
    def classify_vulnerability(self, text):
        """
        Classify the vulnerability type and severity using DeepAI.
        
        Args:
            text (str): The vulnerability description text to classify
            
        Returns:
            dict: Classification results with type and severity
        """
        try:
            payload = {
                'text': text
            }
            
            response = requests.post(
                self.text_classification_url,
                headers=self.headers,
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                return self._parse_classification_result(result, text)
            else:
                logger.error(f"DeepAI classification error: {response.status_code}, {response.text}")
                return None
        
        except Exception as e:
            logger.exception(f"Error in vulnerability classification: {str(e)}")
            return None
    
    def _parse_classification_result(self, result, original_text):
        """Parse DeepAI classification result to determine vulnerability type and severity."""
        # This is a simplified implementation
        # In a real scenario, you would process the classification response
        # from DeepAI based on their specific API response format
        
        # For now, we'll do simple keyword matching as a fallback
        vulnerability_types = {
            'sql': 'SQL Injection',
            'xss': 'Cross-Site Scripting',
            'csrf': 'Cross-Site Request Forgery',
            'rfi': 'Remote File Inclusion',
            'lfi': 'Local File Inclusion',
            'traverse': 'Directory Traversal',
            'auth': 'Authentication Issue',
            'password': 'Password Security',
            'config': 'Security Misconfiguration',
            'sensitive': 'Sensitive Data Exposure',
            'idor': 'Insecure Direct Object Reference'
        }
        
        # Determine type based on keywords
        vuln_type = 'Unknown'
        for keyword, type_name in vulnerability_types.items():
            if keyword.lower() in original_text.lower():
                vuln_type = type_name
                break
        
        # Determine severity based on keywords
        severity = 'medium'  # Default
        if any(word in original_text.lower() for word in ['critical', 'high', 'severe']):
            severity = 'high'
        elif any(word in original_text.lower() for word in ['low', 'info', 'informational']):
            severity = 'low'
        
        return {
            'type': vuln_type,
            'severity': severity
        }
    
    def get_remediation_suggestion(self, vulnerability_type, description, evidence):
        """
        Get remediation suggestions for a vulnerability using DeepAI.
        
        Args:
            vulnerability_type (str): The type of vulnerability
            description (str): Description of the vulnerability
            evidence (str): Evidence or example of the vulnerability
            
        Returns:
            dict: Remediation suggestions including explanation and code
        """
        try:
            # Create a prompt for the DeepAI text generator
            prompt = f"""
            Security Vulnerability: {vulnerability_type}
            Description: {description}
            Evidence: {evidence}
            
            Please provide:
            1. A detailed explanation of how to fix this security issue
            2. Example code showing the proper implementation
            """
            
            payload = {
                'text': prompt
            }
            
            response = requests.post(
                self.text_generation_url,
                headers=self.headers,
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                return self._parse_remediation_result(result)
            else:
                logger.error(f"DeepAI remediation error: {response.status_code}, {response.text}")
                return self._get_default_remediation(vulnerability_type)
        
        except Exception as e:
            logger.exception(f"Error in remediation suggestion: {str(e)}")
            return self._get_default_remediation(vulnerability_type)
    
    def _parse_remediation_result(self, result):
        """Parse DeepAI remediation result."""
        # This is a simplified implementation
        # In a real scenario, you would process the text generation response
        # from DeepAI based on their specific API response format
        
        try:
            if 'output' in result:
                text = result['output']
                
                # Split into explanation and code sections
                parts = text.split('Example code:', 1)
                
                explanation = parts[0].strip()
                code = parts[1].strip() if len(parts) > 1 else ""
                
                return {
                    'explanation': explanation,
                    'code': code
                }
            
            return {
                'explanation': "Unable to generate remediation suggestions.",
                'code': ""
            }
            
        except Exception:
            return {
                'explanation': "Error parsing remediation suggestions.",
                'code': ""
            }
    
    def _get_default_remediation(self, vulnerability_type):
        """Get default remediation suggestions when DeepAI fails."""
        default_remediations = {
            'SQL Injection': {
                'explanation': "Use parameterized queries or prepared statements instead of concatenating user input into SQL queries. This prevents attackers from injecting malicious SQL code.",
                'code': "# Example with parameterized query in Python\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n\n# Example with prepared statement in PHP\n$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n$stmt->execute([$user_id]);"
            },
            'XSS': {
                'explanation': "Implement proper output encoding to ensure that user input is not interpreted as active HTML or JavaScript code. Use context-appropriate encoding and Content-Security-Policy (CSP) headers.",
                'code': "<!-- Example with proper encoding in a template engine -->\n<div>{{ user_input|escape }}</div>\n\n<!-- Example CSP header -->\nContent-Security-Policy: default-src 'self';"
            },
            'CSRF': {
                'explanation': "Implement anti-CSRF tokens for forms and state-changing operations. Use SameSite cookie attributes and consider implementing the Double Submit Cookie pattern.",
                'code': "<!-- Example form with CSRF token -->\n<form method=\"POST\">\n  <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token }}\">\n  <!-- other form fields -->\n</form>"
            },
            'Directory Traversal': {
                'explanation': "Validate and sanitize file paths. Do not allow user input to directly specify file paths. Use a whitelist of allowed files or directories.",
                'code': "# Example in Python\nimport os\ndef get_file(filename):\n    base_dir = '/safe/directory/'\n    # Ensure the resolved path is within the base directory\n    file_path = os.path.normpath(os.path.join(base_dir, filename))\n    if not file_path.startswith(base_dir):\n        raise ValueError('Invalid file path')\n    return open(file_path, 'r').read()"
            },
            'Authentication Issue': {
                'explanation': "Implement secure authentication practices: use strong password policies, implement rate limiting, use multi-factor authentication, and ensure secure session management.",
                'code': "# Example rate limiting in Python/Flask\nfrom flask_limiter import Limiter\nlimiter = Limiter(app)\n\n@app.route('/login', methods=['POST'])\n@limiter.limit('5 per minute')\ndef login():\n    # login logic here"
            }
        }
        
        return default_remediations.get(vulnerability_type, {
            'explanation': "Ensure proper input validation, output encoding, and follow the principle of least privilege. Consult OWASP guidelines for specific remediation steps.",
            'code': "// Implement proper validation and sanitization\nvalidateInput(userInput);\n\n// Use safe APIs and avoid dangerous functions\nsafeOperation(validatedInput);"
        })
