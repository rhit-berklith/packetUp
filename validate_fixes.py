#!/usr/bin/env python3
"""
PacketUp Issue Validator

This script checks for the most critical issues in the PacketUp codebase.
Run this script to validate fixes and identify remaining problems.
"""

import os
import sys
import ast
import re
from pathlib import Path

def check_requirements_encoding():
    """Check if requirements.txt has proper UTF-8 encoding"""
    req_file = Path("Python/requirements.txt")
    if not req_file.exists():
        return False, "requirements.txt not found"
    
    try:
        with open(req_file, 'r', encoding='utf-8') as f:
            content = f.read()
            return True, f"UTF-8 encoding OK, {len(content.splitlines())} dependencies"
    except UnicodeDecodeError:
        return False, "requirements.txt has encoding issues (likely UTF-16)"

def check_missing_dependencies():
    """Check for missing critical dependencies"""
    req_file = Path("Python/requirements.txt")
    try:
        with open(req_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except:
        return False, "Cannot read requirements.txt"
    
    required_packages = ['geoip2', 'scapy', 'tkintermapview', 'requests']
    missing = []
    
    for package in required_packages:
        if package.lower() not in content.lower():
            missing.append(package)
    
    if missing:
        return False, f"Missing packages: {', '.join(missing)}"
    return True, "All critical dependencies present"

def check_bare_except_clauses():
    """Find dangerous bare except clauses"""
    python_files = list(Path("Python").glob("*.py"))
    issues = []
    
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                tree = ast.parse(f.read(), filename=str(file_path))
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    issues.append(f"{file_path}:{node.lineno}")
        except:
            continue
    
    if issues:
        return False, f"Bare except clauses found: {', '.join(issues)}"
    return True, "No bare except clauses found"

def check_subprocess_security():
    """Check for unsafe subprocess usage"""
    python_files = list(Path("Python").glob("*.py"))
    issues = []
    
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
            
            for i, line in enumerate(lines, 1):
                if 'subprocess.run' in line or 'subprocess.call' in line:
                    # Check if shell=True is used or if user input might be involved
                    if 'shell=True' in line or 'f"' in line or "f'" in line:
                        issues.append(f"{file_path}:{i}")
        except:
            continue
    
    if issues:
        return False, f"Potentially unsafe subprocess usage: {', '.join(issues)}"
    return True, "Subprocess usage appears safe"

def check_network_security():
    """Check for unsafe network requests"""
    python_files = list(Path("Python").glob("*.py"))
    issues = []
    
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                lines = content.splitlines()
            
            for i, line in enumerate(lines, 1):
                if 'urllib.request.urlopen' in line:
                    # Check if timeout is specified
                    if 'timeout=' not in line:
                        issues.append(f"{file_path}:{i} - missing timeout")
                elif 'requests.' in line:
                    if 'verify=False' in line:
                        issues.append(f"{file_path}:{i} - SSL verification disabled")
        except:
            continue
    
    if issues:
        return False, f"Network security issues: {', '.join(issues)}"
    return True, "Network requests appear secure"

def check_gitignore():
    """Check if .gitignore exists and contains important entries"""
    gitignore_file = Path(".gitignore")
    if not gitignore_file.exists():
        return False, ".gitignore file missing"
    
    try:
        with open(gitignore_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        required_entries = ['__pycache__', '*.pyc', '*.mmdb']
        missing = [entry for entry in required_entries if entry not in content]
        
        if missing:
            return False, f"Missing .gitignore entries: {', '.join(missing)}"
        return True, ".gitignore properly configured"
    except:
        return False, "Cannot read .gitignore"

def main():
    """Run all checks and report results"""
    print("PacketUp Issue Validator")
    print("=" * 40)
    
    checks = [
        ("Requirements.txt encoding", check_requirements_encoding),
        ("Missing dependencies", check_missing_dependencies),
        ("Bare except clauses", check_bare_except_clauses),
        ("Subprocess security", check_subprocess_security),
        ("Network security", check_network_security),
        ("Git ignore file", check_gitignore),
    ]
    
    passed = 0
    total = len(checks)
    
    for name, check_func in checks:
        try:
            success, message = check_func()
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"{status} {name}: {message}")
            if success:
                passed += 1
        except Exception as e:
            print(f"❌ ERROR {name}: {e}")
    
    print("\n" + "=" * 40)
    print(f"Results: {passed}/{total} checks passed")
    
    if passed == total:
        print("🎉 All critical issues have been addressed!")
        return 0
    else:
        print("⚠️  Some critical issues remain. Please review the failures above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())