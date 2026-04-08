# security_rules.py

DANGEROUS_PATTERNS = {
    # Injection & Execution
    "eval(": "Arbitrary code execution risk (eval)",
    "setTimeout(\"": "Potential code execution via string in setTimeout",
    "child_process": "OS Command Injection risk (Node.js)",
    "exec(": "OS Command execution (Node.js)",
    
    # XSS & DOM Manipulation
    "document.cookie": "Potential credential/cookie theft (XSS)",
    "innerHTML": "Potential DOM-based Cross-Site Scripting (XSS)",
    "document.write(": "Direct DOM writing (XSS risk)",
    "window.location": "Potential open redirect vulnerability",
    
    # Suspicious Network & External Calls
    "<iframe": "Clickjacking or malicious iframe injection",
    "fetch('http://": "Insecure unencrypted HTTP request detected",
    ".php?cmd=": "Suspicious command parameter (Web Shell risk)",
    
    # Hardcoded Secrets & Crypto
    "password =": "Potential hardcoded password/secret",
    "api_key": "Potential hardcoded API Key",
    "Bearer ": "Potential hardcoded authorization token",
    "Math.random()": "Insecure randomness used (Do not use for cryptography)"
}