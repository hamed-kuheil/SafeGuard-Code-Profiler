"""
rules.py — SafeGuard-Code Profiler
Pattern library for efficiency, safety, and ethical compliance checks.
Each rule is a dict: { id, name, pattern, severity, category, message, languages }
"""

import re

# ─── Severity Levels ────────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

# ─── Efficiency Rules ────────────────────────────────────────────────────────
EFFICIENCY_RULES = [
    {
        "id": "EFF-001",
        "name": "Nested Loop (O(n²) Risk)",
        "pattern": r"for\s*[\(\[].*[\)\]]\s*\{?[^{}]*for\s*[\(\[]",
        "severity": HIGH,
        "category": "efficiency",
        "message": "Nested loop detected — potential O(n²) or worse time complexity. Consider algorithmic alternatives.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "EFF-002",
        "name": "Python Nested For-Loop",
        "pattern": r"^\s*for\s+.+:\s*\n(?:\s+.*\n)*?\s+for\s+.+:",
        "severity": HIGH,
        "category": "efficiency",
        "message": "Nested for-loop found in Python — review algorithmic complexity.",
        "languages": ["python"],
        "flags": re.MULTILINE,
    },
    {
        "id": "EFF-003",
        "name": "C++ new Without delete",
        "pattern": r"\bnew\b(?!.*\bdelete\b)",
        "severity": HIGH,
        "category": "efficiency",
        "message": "'new' allocation detected without a visible 'delete' — possible memory leak. Prefer smart pointers.",
        "languages": ["cpp"],
    },
    {
        "id": "EFF-004",
        "name": "Unclosed File Stream (C++)",
        "pattern": r"(ifstream|ofstream|fstream)\s+\w+\s*\([^)]*\)(?!.*\.close\(\))",
        "severity": MEDIUM,
        "category": "efficiency",
        "message": "File stream opened but no explicit .close() detected in scope. Risk of resource leak.",
        "languages": ["cpp"],
    },
    {
        "id": "EFF-005",
        "name": "Unclosed File (Python)",
        "pattern": r"open\s*\([^)]+\)(?!\s*as\b)(?!.*\.close\(\))",
        "severity": MEDIUM,
        "category": "efficiency",
        "message": "File opened without context manager (with ... as). Risk of unclosed file handle.",
        "languages": ["python"],
    },
    {
        "id": "EFF-006",
        "name": "String Concatenation in Loop",
        "pattern": r"for\b.*\b.*\+\s*=\s*['\"]|['\"].*\+.*for\b",
        "severity": MEDIUM,
        "category": "efficiency",
        "message": "String concatenation inside loop — O(n²) string building. Use StringBuilder/join instead.",
        "languages": ["java", "python"],
    },
    {
        "id": "EFF-007",
        "name": "Java String += in Loop",
        "pattern": r"for\s*\(.*\)\s*\{[^}]*\w+\s*\+=\s*\"",
        "severity": MEDIUM,
        "category": "efficiency",
        "message": "String concatenation with += inside a Java loop — use StringBuilder for O(n) performance.",
        "languages": ["java"],
    },
    {
        "id": "EFF-008",
        "name": "Infinite Loop Risk",
        "pattern": r"\bwhile\s*\(\s*true\s*\)|\bwhile\s*\(1\)",
        "severity": MEDIUM,
        "category": "efficiency",
        "message": "Unconditional while(true) loop — ensure a break/return path exists to avoid infinite execution.",
        "languages": ["cpp", "java"],
    },
    {
        "id": "EFF-009",
        "name": "Python While True",
        "pattern": r"\bwhile\s+True\s*:",
        "severity": LOW,
        "category": "efficiency",
        "message": "while True: loop detected — verify an explicit break condition is reachable.",
        "languages": ["python"],
    },
    {
        "id": "EFF-010",
        "name": "Redundant Recomputation in Loop",
        "pattern": r"for\b.*\b(len|size|length)\s*\(",
        "severity": LOW,
        "category": "efficiency",
        "message": "Length/size computed inside loop condition — cache result before loop for clarity.",
        "languages": ["python", "java", "cpp"],
    },
]

# ─── Safety / Security Rules ─────────────────────────────────────────────────
SAFETY_RULES = [
    {
        "id": "SEC-001",
        "name": "Hardcoded Password",
        "pattern": r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',
        "severity": CRITICAL,
        "category": "security",
        "message": "Hardcoded password detected. Use environment variables or a secrets manager.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "SEC-002",
        "name": "Hardcoded API Key / Token",
        "pattern": r'(?i)(api_key|apikey|token|secret|auth_token)\s*=\s*["\'][A-Za-z0-9_\-\.]{8,}["\']',
        "severity": CRITICAL,
        "category": "security",
        "message": "Hardcoded API key or token found. Rotate immediately and use env-vars/vault storage.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "SEC-003",
        "name": "Unsafe C Function: gets()",
        "pattern": r'\bgets\s*\(',
        "severity": CRITICAL,
        "category": "security",
        "message": "gets() is banned (CVE-prone, no bounds checking). Replace with fgets() or std::getline().",
        "languages": ["cpp"],
    },
    {
        "id": "SEC-004",
        "name": "Unsafe C Function: strcpy()",
        "pattern": r'\bstrcpy\s*\(',
        "severity": HIGH,
        "category": "security",
        "message": "strcpy() has no bounds checking — buffer overflow risk. Use strncpy() or std::string.",
        "languages": ["cpp"],
    },
    {
        "id": "SEC-005",
        "name": "Unsafe C Function: sprintf()",
        "pattern": r'\bsprintf\s*\(',
        "severity": HIGH,
        "category": "security",
        "message": "sprintf() lacks bounds checking. Replace with snprintf() with explicit buffer size.",
        "languages": ["cpp"],
    },
    {
        "id": "SEC-006",
        "name": "SQL Injection Risk",
        "pattern": r'(?i)(execute|query|cursor\.execute)\s*\(\s*["\']?\s*(SELECT|INSERT|UPDATE|DELETE).*\+',
        "severity": CRITICAL,
        "category": "security",
        "message": "Possible SQL injection — string concatenation in a SQL query. Use parameterized queries.",
        "languages": ["python", "java"],
    },
    {
        "id": "SEC-007",
        "name": "Shell Injection Risk (Python)",
        "pattern": r'\b(os\.system|subprocess\.call|subprocess\.run)\s*\([^)]*\+',
        "severity": CRITICAL,
        "category": "security",
        "message": "Shell command with string concatenation — command injection risk. Avoid shell=True and sanitize inputs.",
        "languages": ["python"],
    },
    {
        "id": "SEC-008",
        "name": "Eval / Exec Usage",
        "pattern": r'\b(eval|exec)\s*\(',
        "severity": HIGH,
        "category": "security",
        "message": "eval()/exec() executes arbitrary code — remove if possible or sanitize input strictly.",
        "languages": ["python"],
    },
    {
        "id": "SEC-009",
        "name": "Hardcoded IP Address",
        "pattern": r'["\'](\d{1,3}\.){3}\d{1,3}["\']',
        "severity": LOW,
        "category": "security",
        "message": "Hardcoded IP address detected. Externalize network config for portability and security.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "SEC-010",
        "name": "Debug / TODO Left In Code",
        "pattern": r'(?i)\b(TODO|FIXME|HACK|XXX|BUG)\b',
        "severity": LOW,
        "category": "security",
        "message": "Developer note left in production code — review before deployment.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "SEC-011",
        "name": "Java Reflection Usage",
        "pattern": r'\bClass\.forName\s*\(|\b\.getDeclaredMethod\s*\(',
        "severity": MEDIUM,
        "category": "security",
        "message": "Java reflection detected — can bypass access controls. Audit usage carefully.",
        "languages": ["java"],
    },
    {
        "id": "SEC-012",
        "name": "Pickle / Deserialization (Python)",
        "pattern": r'\bpickle\.(load|loads)\s*\(',
        "severity": HIGH,
        "category": "security",
        "message": "pickle.load() on untrusted data enables arbitrary code execution. Use JSON/msgpack instead.",
        "languages": ["python"],
    },
]

# ─── Ethical / PII Rules ─────────────────────────────────────────────────────
ETHICAL_RULES = [
    {
        "id": "ETH-001",
        "name": "PII — Email Address",
        "pattern": r'["\'][A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}["\']',
        "severity": HIGH,
        "category": "ethics",
        "message": "Hardcoded email address (PII) detected. Remove from source code; use anonymized test data.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "ETH-002",
        "name": "PII — Phone Number",
        "pattern": r'["\'][\+]?[\d\s\-\(\)]{10,15}["\']',
        "severity": HIGH,
        "category": "ethics",
        "message": "Possible hardcoded phone number (PII). Replace with synthetic/anonymized test fixtures.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "ETH-003",
        "name": "PII — Social Security / ID Number",
        "pattern": r'["\']?\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b["\']?',
        "severity": CRITICAL,
        "category": "ethics",
        "message": "Potential SSN/National ID format detected. This is sensitive PII — remove immediately.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "ETH-004",
        "name": "Biometric / Sensitive Field Name",
        "pattern": r'(?i)\b(face_id|fingerprint|biometric|facial_recognition|voice_print|dna)\b',
        "severity": HIGH,
        "category": "ethics",
        "message": "Biometric identifier field detected. Ensure GDPR/CCPA compliance and explicit consent handling.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "ETH-005",
        "name": "Race / Gender / Religion Attribute",
        "pattern": r'(?i)\b(race|ethnicity|gender|religion|political_view|sexual_orientation)\s*[=:]',
        "severity": HIGH,
        "category": "ethics",
        "message": "Sensitive demographic attribute found. AI models trained on this may produce discriminatory outputs.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "ETH-006",
        "name": "Consent / GDPR Keyword Missing Pattern",
        "pattern": r'(?i)\b(user_data|personal_info|profile|user_record)\b(?!.*\b(consent|gdpr|anonymize|encrypt)\b)',
        "severity": MEDIUM,
        "category": "ethics",
        "message": "Personal data field used without nearby consent/anonymization reference. Review GDPR obligations.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "ETH-007",
        "name": "Logging Sensitive Data",
        "pattern": r'(?i)(print|log|logger|console\.log|printf|cout)\s*[\(<][^)>]*(password|token|ssn|email|phone)',
        "severity": CRITICAL,
        "category": "ethics",
        "message": "Sensitive data being logged/printed. This exposes PII in logs — redact before output.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "ETH-008",
        "name": "Unencrypted Sensitive Storage",
        "pattern": r'(?i)(write|save|store|dump)\s*\([^)]*\b(password|token|ssn|credit_card)\b',
        "severity": HIGH,
        "category": "ethics",
        "message": "Sensitive data written to storage without visible encryption. Encrypt at rest.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "ETH-009",
        "name": "Third-Party Data Sharing",
        "pattern": r'(?i)\b(send|upload|post|transmit)\s*\([^)]*\b(user|personal|profile|email)\b',
        "severity": MEDIUM,
        "category": "ethics",
        "message": "Data transmission involving user/personal fields — verify third-party data agreements.",
        "languages": ["cpp", "java", "python"],
    },
    {
        "id": "ETH-010",
        "name": "Age / Minor Targeting Risk",
        "pattern": r'(?i)\b(age\s*[<>=!]+\s*1[0-7]|is_minor|underage|child_user)\b',
        "severity": HIGH,
        "category": "ethics",
        "message": "Minor/child targeting logic detected — ensure COPPA compliance and parental consent flows.",
        "languages": ["cpp", "java", "python"],
    },
]

ALL_RULES = EFFICIENCY_RULES + SAFETY_RULES + ETHICAL_RULES

def get_rules_for_language(language: str) -> list:
    """Return rules applicable to the given language."""
    return [r for r in ALL_RULES if language in r.get("languages", [])]
