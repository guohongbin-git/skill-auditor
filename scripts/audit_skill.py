#!/usr/bin/env python3
"""
Skill Auditor - Security Scanner for Agent Skills
Version: 0.2.0

Changelog:
- Added base64 payload detection
- Added subprocess spawning detection  
- Added obfuscated string detection
- Added out-of-workspace write detection
"""

import os
import sys
import json
import re
import base64
from pathlib import Path
from typing import Dict, List, Tuple

# Sensitive keywords to detect
SENSITIVE_KEYWORDS = [
    "export", "API_KEY", "SECRET", "TOKEN", "PASSWORD",
    ".env", "credentials", "private_key", "access_token"
]

# Network call patterns
NETWORK_PATTERNS = [
    r"curl\s+", r"requests\.(get|post)", r"http\.(get|post)",
    r"axios\.(get|post)", r"fetch\(", r"urllib"
]

# File system access patterns
FILE_PATTERNS = [
    r"open\s*\(", r"file\.read", r"file\.write", r"fs\.read",
    r"fs\.write", r"shutil\.", r"os\.remove", r"os\.path"
]

# NEW: Base64 encoding patterns (suggested by @JarvisPeter)
BASE64_PATTERNS = [
    r"base64\.b64decode",
    r"base64\.b64encode",
    r"atob\s*\(",
    r"btoa\s*\(",
    r"Buffer\.from\s*\([^,]+,\s*['\"]base64['\"]",
]

# NEW: Subprocess spawning patterns (suggested by @JarvisPeter)
SUBPROCESS_PATTERNS = [
    r"subprocess\.Popen",
    r"subprocess\.call",
    r"subprocess\.run",
    r"child_process\.spawn",
    r"child_process\.exec",
    r"child_process\.fork",
    r"\bexec\s*\(",
    r"\bsystem\s*\(",
    r"os\.system",
    r"os\.popen",
]

# NEW: Obfuscation patterns (suggested by @JarvisPeter)
OBFUSCATION_PATTERNS = [
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"Function\s*\(",
    r"__import__\s*\(",
    r"importlib\.import_module",
    r"compile\s*\(",
]

# NEW: Out-of-workspace paths (suggested by @JarvisPeter)
DANGEROUS_PATHS = [
    r"~/\.env",
    r"/etc/",
    r"/root/",
    r"\.\./",  # Parent directory
    r"/proc/",
    r"/sys/",
]

class SecurityReport:
    def __init__(self, skill_path: str):
        self.skill_path = skill_path
        self.risks: List[Dict] = []
        self.risk_level = "LOW"
    
    def add_risk(self, category: str, severity: str, description: str, line_num: int = 0):
        self.risks.append({
            "category": category,
            "severity": severity,
            "description": description,
            "line": line_num
        })
        
        # Update overall risk level
        if severity == "HIGH":
            self.risk_level = "HIGH"
        elif severity == "MEDIUM" and self.risk_level != "HIGH":
            self.risk_level = "MEDIUM"
    
    def to_json(self) -> Dict:
        return {
            "skill_path": self.skill_path,
            "risk_level": self.risk_level,
            "total_risks": len(self.risks),
            "risks": self.risks
        }

def check_base64_in_line(line: str) -> bool:
    """Check if line contains base64-encoded suspicious content."""
    # Look for base64 patterns
    for pattern in BASE64_PATTERNS:
        if re.search(pattern, line):
            return True
    return False

def scan_file(file_path: Path, report: SecurityReport):
    """Scan a single file for security risks."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except:
        return
    
    for i, line in enumerate(lines, 1):
        # Check for sensitive keywords
        for keyword in SENSITIVE_KEYWORDS:
            if keyword.lower() in line.lower():
                report.add_risk(
                    "SENSITIVE_KEYWORD",
                    "MEDIUM",
                    f"Found sensitive keyword: {keyword}",
                    i
                )
        
        # Check for network calls
        for pattern in NETWORK_PATTERNS:
            if re.search(pattern, line):
                report.add_risk(
                    "NETWORK_CALL",
                    "MEDIUM",
                    f"Network call detected: {pattern}",
                    i
                )
        
        # Check for file system access
        for pattern in FILE_PATTERNS:
            if re.search(pattern, line):
                report.add_risk(
                    "FILE_ACCESS",
                    "LOW",
                    f"File system access: {pattern}",
                    i
                )
        
        # NEW: Check for base64 encoding
        if check_base64_in_line(line):
            report.add_risk(
                "BASE64_PAYLOAD",
                "MEDIUM",
                "Potential base64-encoded payload detected",
                i
            )
        
        # NEW: Check for subprocess spawning
        for pattern in SUBPROCESS_PATTERNS:
            if re.search(pattern, line):
                report.add_risk(
                    "SUBPROCESS_SPAWN",
                    "HIGH",
                    f"Subprocess spawning detected: {pattern}",
                    i
                )
        
        # NEW: Check for code obfuscation
        for pattern in OBFUSCATION_PATTERNS:
            if re.search(pattern, line):
                report.add_risk(
                    "CODE_OBFUSCATION",
                    "HIGH",
                    f"Potential code obfuscation: {pattern}",
                    i
                )
        
        # NEW: Check for dangerous paths
        for pattern in DANGEROUS_PATHS:
            if re.search(pattern, line):
                report.add_risk(
                    "DANGEROUS_PATH",
                    "HIGH",
                    f"Access to sensitive path: {pattern}",
                    i
                )

def audit_skill(skill_path: str) -> SecurityReport:
    """Main function to audit a skill directory."""
    path = Path(skill_path)
    report = SecurityReport(skill_path)
    
    if not path.exists():
        report.add_risk("ERROR", "HIGH", f"Path does not exist: {skill_path}")
        return report
    
    # Scan all relevant files
    for file in path.rglob("*"):
        if file.suffix in ['.md', '.py', '.js', '.sh', '.json']:
            scan_file(file, report)
    
    return report

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 audit_skill.py <skill_path>")
        sys.exit(1)
    
    skill_path = sys.argv[1]
    report = audit_skill(skill_path)
    
    print(json.dumps(report.to_json(), indent=2))
    
    # Exit with error code if high risk
    if report.risk_level == "HIGH":
        sys.exit(2)

if __name__ == "__main__":
    main()
