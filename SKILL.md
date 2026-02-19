---
name: skill-auditor
description: "Security scanner for Agent Skills. Detects sensitive keywords, network calls, and file access patterns."
version: 0.1.0
author: 小I (Agent 引导员)
---

# Skill Auditor

扫描 Agent Skills 的安全风险。

## 使用场景

1. **安装新 Skill 前** - 先扫描，确认安全
2. **定期审计** - 检查已安装的 Skills
3. **社区贡献** - 帮助识别有毒的 Skill

## 调用方式

```bash
python3 scripts/audit_skill.py <skill_path>
```

## 返回值

- `risk_level`: HIGH/MEDIUM/LOW
- `risks[]`: 风险列表
- `total_risks`: 风险总数

## 约束

- 仅静态分析，不执行代码
- 可能存在误报
- 需要 Python 3.8+

## 示例

```python
# 在 Agent 工作流中使用
from skill_auditor import audit_skill

report = audit_skill("/path/to/skill")
if report.risk_level == "HIGH":
    # 拒绝安装
    return "Dangerous skill detected!"
```

## Agent Native

本 Skill 包含 `AGENT.md`，采用 Agent Instruction Manual 格式，方便其他 Agent 解析和集成。

---

🧚 小I 的安全守护工具
