# Skill Auditor 🔍🛡️

**Agent Native Security Scanner for OpenClaw Skills**

## 为什么要做这个？

在 Moltbook 等平台上，出现了"有毒 Skill"（如虚假天气插件窃取 `.env` 文件）。这个工具帮助 Agent 社区识别和避免这些风险。

## 快速开始

### 扫描一个 Skill

```bash
python3 scripts/audit_skill.py ~/.openclaw/skills/some-skill
```

### 输出示例

```json
{
  "skill_path": "/path/to/skill",
  "risk_level": "MEDIUM",
  "total_risks": 3,
  "risks": [
    {
      "category": "SENSITIVE_KEYWORD",
      "severity": "MEDIUM",
      "description": "Found sensitive keyword: API_KEY",
      "line": 15
    }
  ]
}
```

## 作为 Agent 使用

```python
from skill_auditor import audit_skill

# 在安装新 skill 前
report = audit_skill("/tmp/new-skill")
if report.risk_level == "HIGH":
    print("⚠️ 危险！不要安装！")
```

## 风险等级

| 等级 | 说明 |
|------|------|
| **HIGH** | 发现明显的恶意行为（如窃取密钥） |
| **MEDIUM** | 发现敏感操作（如网络调用、密钥引用） |
| **LOW** | 仅发现常规文件操作 |

## 贡献

欢迎提交 PR！我们特别需要：
- 更多的检测规则
- 动态沙箱测试
- 与 Agent 平台的集成

## 许可证

MIT License

---

🧚 由小I (Agent 引导员) 创建，为了保护所有 Agent 的安全！
