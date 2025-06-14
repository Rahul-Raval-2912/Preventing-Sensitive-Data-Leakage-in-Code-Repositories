import re
import os
import shutil
import subprocess
from git import Repo
from datetime import datetime

SENSITIVE_PATTERNS = {
    "API Key": (r"(?i)(?:api_key|apikey|key\s*=\s*)[\'\"]?([a-zA-Z0-9-_]{15,})[\'\"]?",
                "High"),
    "AWS Key": (r"(?i)(?:AKIA|ASIA)[A-Z0-9]{16}", "Critical"),
    "Password": (r"(?i)(?:password|pwd|pass\s*=\s*)[\'\"]?([a-zA-Z0-9@#%*!]{8,})[\'\"]?",
                "Medium"),
    "JWT Token": (r"(?i)eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+",
                  "Critical"),
}

def clone_repo(repo_url, temp_dir="temp_repo"):
    """Clone a public repository."""
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    try:
        Repo.clone_from(repo_url, temp_dir)
        return temp_dir
    except Exception as e:
        raise Exception(f"Failed to clone repository: {e}")

def scan_file(file_path):
    """Scan a file for sensitive data."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
            content = file.read()
            for label, (pattern, severity) in SENSITIVE_PATTERNS.items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    findings.append({
                        "type": label,
                        "value": match.group(1),
                        "file": file_path,
                        "severity": severity,
                        "line_number": content[:match.start()].count("\n") + 1
                    })
    except Exception:
        pass  # Skip unreadable files
    return findings

def scan_repository(repo_path):
    """Scan all files in the repository."""
    all_findings = []
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith((".py", ".env", ".json", ".txt")):
                findings = scan_file(os.path.join(root, file))
                all_findings.extend(findings)
    return all_findings

def scan_git_history(repo_path):
    """Scan Git commit history for sensitive data."""
    repo = Repo(repo_path)
    history_findings = []
    for commit in repo.iter_commits():
        for file in commit.stats.files:
            if file.endswith((".py", ".env", ".json", ".txt")):
                try:
                    content = repo.git.show(f"{commit.hexsha}:{file}")
                    for label, (pattern, severity) in SENSITIVE_PATTERNS.items():
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            history_findings.append({
                                "type": label,
                                "value": match.group(1),
                                "file": file,
                                "severity": severity,
                                "commit": commit.hexsha,
                                "commit_message": commit.message.strip(),
                                "line_number": content[:match.start()].count("\n") + 1
                            })
                except:
                    pass  # Skip files not in commit
    return history_findings

def generate_report(findings, history_findings, repo_url):
    """Generate a report with analysis."""
    return {
        "scan_time": datetime.now().isoformat(),
        "repository": repo_url,
        "current_findings": findings,
        "history_findings": history_findings,
        "summary": {
            "total_findings": len(findings) + len(history_findings),
            "by_severity": {
                sev: sum(1 for f in findings + history_findings if f["severity"] == sev)
                for sev in ["Critical", "High", "Medium", "Low"]
            },
            "by_type": {
                typ: sum(1 for f in findings + history_findings if f["type"] == typ)
                for typ in SENSITIVE_PATTERNS
            }
        }
    }