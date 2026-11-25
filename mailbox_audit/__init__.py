"""mailbox_audit — 企业邮箱收件规则 / 转发 / 委托访问审计与持续监控工具包。

纯标准库实现，零第三方依赖。设计目标见 README.md。
"""

__version__ = "1.0.0"

# 统一的严重级别排序，供报告与告警使用
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITIES)}
