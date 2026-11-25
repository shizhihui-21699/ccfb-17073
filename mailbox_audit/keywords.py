"""敏感关键词词库与命中扫描。

钓鱼规则的典型特征是专门拦截财务/付款类邮件，因此维护中英双语词库；
企业可以在配置文件中追加自己的业务词（项目代号、供应商简称等）。
"""

from __future__ import annotations

import re

DEFAULT_KEYWORD_GROUPS: dict[str, list[str]] = {
    # 财务 / 付款 / 发票 —— BEC 与钓鱼转发最常见的目标
    "finance_payment": [
        "发票", "付款", "收款", "汇款", "转账", "对账", "账单", "结算", "报销",
        "付款通知", "付款申请", "账户变更", "银行账户", "开户行", "账号",
        "invoice", "payment", "remittance", "remit", "fund transfer",
        "bank account", "wire transfer", "ach", "bill", "billing",
        "receipt", "purchase order", "po number", "account details",
        "change of bank", "new account", "vendor", "supplier",
    ],
    # 凭据 / 安全 —— 用于拦截安全告警，阻止受害者察觉
    "security": [
        "密码", "验证码", "登录", "异常登录", "安全警报", "账户异常",
        "password", "verify", "verification", "sign-in", "sign in",
        "login", "security alert", "unusual activity", "mfa", "otp",
        "one-time passcode", "account suspended",
    ],
    # 法务 / 机密 —— 高价值数据外泄
    "confidential": [
        "合同", "机密", "保密", "薪资", "并购", "招标", "标书",
        "contract", "confidential", "nda", "salary", "payroll",
        "merger", "acquisition", "tender", "bid",
    ],
}


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "").lower()).strip()


def scan_text(text: str, keyword_groups: dict[str, list[str]] | None = None) -> list[dict]:
    """扫描一段文本，返回命中的关键词列表 [{group, keyword}]。"""
    groups = keyword_groups or DEFAULT_KEYWORD_GROUPS
    normalized = _normalize(text)
    hits: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for group, words in groups.items():
        for word in words:
            needle = word.lower()
            if needle and needle in normalized:
                key = (group, needle)
                if key not in seen:
                    seen.add(key)
                    hits.append({"group": group, "keyword": word})
    return hits


def scan_conditions(conditions: list, keyword_groups: dict[str, list[str]] | None = None) -> list[dict]:
    """对规则条件（含邮件头条件）做关键词扫描。"""
    hits: list[dict] = []
    for condition in conditions or []:
        blob_parts = [condition.field or "", condition.operator or ""]
        blob_parts.extend(str(value) for value in (condition.values or []))
        for hit in scan_text(" ".join(blob_parts), keyword_groups):
            hit["condition_field"] = condition.field or "unknown"
            hits.append(hit)
    # 去重
    unique: dict[tuple, dict] = {}
    for hit in hits:
        unique[(hit["group"], hit["keyword"], hit["condition_field"])] = hit
    return list(unique.values())
