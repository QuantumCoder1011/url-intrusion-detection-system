import re
from typing import List, Dict

class DetectionEngine:
    """Core detection engine that analyzes URLs for malicious patterns"""
    
    def __init__(self):
        self.patterns = self._load_attack_patterns()
    
    def _load_attack_patterns(self) -> List[Dict]:
        """Load all attack detection patterns"""
        return [
            # SQL Injection patterns
            {
                'type': 'SQL Injection',
                'severity': 'High',
                'patterns': [
                    r"('|(\\')|(;)|(\\;)|(--)|(\\--)|(/\*)|(\\/\*)|(\*/)|(\\\*/)|(\+)|(\\\+)|(\%)|(\\\%))",
                    r"(union|UNION).*(select|SELECT)",
                    r"(select|SELECT).*(from|FROM)",
                    r"(insert|INSERT).*(into|INTO)",
                    r"(delete|DELETE).*(from|FROM)",
                    r"(update|UPDATE).*(set|SET)",
                    r"(drop|DROP).*(table|TABLE|database|DATABASE)",
                    r"(exec|EXEC|execute|EXECUTE).*\(.*\)",
                    r"(or|OR).*(\d+).*=.*(\d+)",
                    r"'.*or.*'.*='",
                    r"'.*or.*1.*=.*1",
                    r"(\%27|\'|\"|;|\%00|/\*|\*/|xp_|sp_)",
                ]
            },
            # Cross-Site Scripting (XSS) patterns
            {
                'type': 'XSS',
                'severity': 'High',
                'patterns': [
                    r"<script.*>.*</script>",
                    r"<script.*>",
                    r"javascript:",
                    r"onerror\s*=",
                    r"onload\s*=",
                    r"onclick\s*=",
                    r"onmouseover\s*=",
                    r"onfocus\s*=",
                    r"<iframe.*>",
                    r"<img.*src.*=.*javascript:",
                    r"<svg.*onload",
                    r"alert\s*\(",
                    r"document\.cookie",
                    r"document\.write",
                    r"eval\s*\(",
                    r"expression\s*\(",
                    r"vbscript:",
                    r"<body.*onload",
                ]
            },
            # Directory Traversal patterns
            {
                'type': 'Directory Traversal',
                'severity': 'Medium',
                'patterns': [
                    r"\.\./",
                    r"\.\.\\",
                    r"\.\.%2f",
                    r"\.\.%5c",
                    r"\.\.%252f",
                    r"\.\.%255c",
                    r"/etc/passwd",
                    r"/etc/shadow",
                    r"\.\./\.\./\.\./",
                    r"\.\.\\\.\.\\\.\.\\",
                    r"\.\.%2f\.\.%2f",
                    r"\.\.%5c\.\.%5c",
                ]
            },
            # Command Injection patterns
            {
                'type': 'Command Injection',
                'severity': 'High',
                'patterns': [
                    r";\s*(ls|cat|pwd|whoami|id|uname|ps|netstat)",
                    r"\|\s*(ls|cat|pwd|whoami|id|uname|ps|netstat)",
                    r"&&\s*(ls|cat|pwd|whoami|id|uname|ps|netstat)",
                    r"\|\|\s*(ls|cat|pwd|whoami|id|uname|ps|netstat)",
                    r";\s*rm\s+-",
                    r";\s*mkdir",
                    r";\s*chmod",
                    r";\s*chown",
                    r"\$\(",
                    r"`.*`",
                    r"system\s*\(",
                    r"exec\s*\(",
                    r"shell_exec\s*\(",
                    r"passthru\s*\(",
                ]
            },
            # Server-Side Request Forgery (SSRF) patterns
            {
                'type': 'SSRF',
                'severity': 'High',
                'patterns': [
                    r"http://127\.0\.0\.1",
                    r"http://localhost",
                    r"http://0\.0\.0\.0",
                    r"http://169\.254\.169\.254",
                    r"file://",
                    r"gopher://",
                    r"dict://",
                    r"ldap://",
                    r"http://192\.168\.\d+\.\d+",
                    r"http://10\.\d+\.\d+\.\d+",
                    r"http://172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+",
                ]
            },
            # Path Traversal patterns
            {
                'type': 'Path Traversal',
                'severity': 'Medium',
                'patterns': [
                    r"\.\./",
                    r"\.\.\\",
                    r"\.\.%2f",
                    r"\.\.%5c",
                    r"\.\.%252f",
                    r"\.\.%255c",
                    r"/\.\./",
                    r"\\\.\.\\",
                ]
            },
            # File Inclusion patterns
            {
                'type': 'File Inclusion',
                'severity': 'High',
                'patterns': [
                    r"\.\./\.\./\.\./etc/passwd",
                    r"\.\./\.\./\.\./etc/shadow",
                    r"\.\./\.\./\.\./windows/system32",
                    r"php://filter",
                    r"php://input",
                    r"data://",
                    r"expect://",
                    r"zip://",
                    r"phar://",
                ]
            },
            # LDAP Injection patterns
            {
                'type': 'LDAP Injection',
                'severity': 'Medium',
                'patterns': [
                    r"\(.*\|.*\)",
                    r"\(.*&.*\)",
                    r"\(.*!.*\)",
                    r"\(.*=.*\)",
                    r"\*\)",
                    r"\(&",
                    r"\(\|",
                ]
            },
            # XML External Entity (XXE) patterns
            {
                'type': 'XXE',
                'severity': 'High',
                'patterns': [
                    r"<!ENTITY",
                    r"SYSTEM\s+['\"]",
                    r"file://",
                    r"http://",
                    r"<!DOCTYPE",
                    r"ENTITY.*%",
                ]
            },
        ]
    
    def analyze_url(self, url: str) -> List[Dict]:
        """
        Analyze a URL for malicious patterns
        
        Args:
            url: The URL string to analyze
            
        Returns:
            List of detected attacks with their details
        """
        detected_attacks = []
        url_lower = url.lower()
        
        for attack_category in self.patterns:
            attack_type = attack_category['type']
            severity = attack_category['severity']
            
            for pattern in attack_category['patterns']:
                try:
                    if re.search(pattern, url, re.IGNORECASE):
                        detected_attacks.append({
                            'type': attack_type,
                            'severity': severity,
                            'pattern': pattern
                        })
                        # Only report once per attack type
                        break
                except re.error:
                    # Skip invalid regex patterns
                    continue
        
        return detected_attacks
