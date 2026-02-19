# Agent Instruction Manual (AIM)

@meta
id: skill-auditor
version: 0.2.0
type: security_tool
entrypoint: scripts/audit_skill.py

@capabilities
[
  "static_code_scan",
  "sensitive_keyword_detection",
  "network_call_analysis",
  "base64_payload_detection",
  "subprocess_spawning_detection",
  "code_obfuscation_detection",
  "dangerous_path_detection",
  "security_report_generation"
]

@interface
## CLI
command: `python3 scripts/audit_skill.py <skill_path>`
description: Scans a skill directory for potential security risks.

## Python
```python
from skill_auditor import audit_skill
report = audit_skill("/path/to/skill")
print(report.to_json())
```

@behavior
1. READS `skill.md` or main skill file from `<skill_path>`.
2. SCANS for sensitive keywords: `export`, `curl`, `.env`, `API_KEY`, `SECRET`, `TOKEN`.
3. DETECTS network calls: `http.get`, `fetch`, `requests.get`, `axios`.
4. ANALYZES file system access: `fs.read`, `open()`, `file.write`.
5. GENERATES `security_report.json` with risk levels (HIGH/MEDIUM/LOW).
6. RETURNS structured JSON report to caller.

@constraints
- Requires Python 3.8+.
- Requires access to skill directory.
- Static analysis only (no dynamic execution).
- May produce false positives (human review recommended).

@examples
## Scan a local skill
```bash
python3 scripts/audit_skill.py ~/.openclaw/skills/weather-skill
```

## Scan a Git repository
```bash
git clone https://github.com/someone/some-skill.git /tmp/skill
python3 scripts/audit_skill.py /tmp/skill
```

@integration
## Use in Agent Workflow
```python
# Before installing a new skill
from skill_auditor import quick_scan

result = quick_scan("https://github.com/unknown/cool-skill")
if result.risk_level == "HIGH":
    print("⚠️ Dangerous skill detected!")
    # Do not install
else:
    # Safe to proceed
    install_skill("cool-skill")
```

@contributing
Contributors welcome! Submit pull requests to:
https://github.com/guohongbin-git/skill-auditor

@license
MIT License
