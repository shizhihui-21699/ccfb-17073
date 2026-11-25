"""审计策略配置加载。

使用 JSON 而非 YAML，保持纯标准库、零依赖。所有字段都有默认值，
最小可用配置只需提供 internal_domains。
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path

from .keywords import DEFAULT_KEYWORD_GROUPS


@dataclass
class AllowRule:
    """单条白名单。任一字段为空表示通配。"""

    mailbox: str = ""            # 支持精确地址；为空表示对所有邮箱生效
    object_type: str = ""        # rule / forwarding / delegate
    object_id_or_name: str = ""  # 规则 ID 或名称（子串匹配）
    destination: str = ""        # 转发目标地址/域名（域名为后缀匹配）
    delegate: str = ""
    reason: str = ""
    ticket: str = ""
    expires: str = ""            # ISO 日期，过期后白名单自动失效


@dataclass
class AuditConfig:
    internal_domains: set[str] = field(default_factory=set)
    trusted_forward_domains: set[str] = field(default_factory=set)
    trusted_service_principals: set[str] = field(default_factory=set)
    keyword_groups: dict[str, list[str]] = field(default_factory=dict)
    allowlist: list[AllowRule] = field(default_factory=list)
    severity_thresholds: dict[str, int] = field(
        default_factory=lambda: {"low": 10, "medium": 30, "high": 55, "critical": 80})
    alert: dict = field(default_factory=dict)
    baseline_db: str = "audit_baseline.db"
    output_dir: str = "output"

    @staticmethod
    def load(path: str | Path) -> "AuditConfig":
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)

        keywords = {group: list(words) for group, words in DEFAULT_KEYWORD_GROUPS.items()}
        for group, words in (data.get("keyword_groups") or {}).items():
            keywords.setdefault(group, [])
            keywords[group].extend(words)

        allowlist = [
            AllowRule(**item) for item in data.get("allowlist", [])
        ]
        thresholds = {
            "low": 10, "medium": 30, "high": 55, "critical": 80,
        }
        thresholds.update(data.get("severity_thresholds") or {})

        return AuditConfig(
            internal_domains=set(data.get("internal_domains", [])),
            trusted_forward_domains=set(data.get("trusted_forward_domains", [])),
            trusted_service_principals=set(data.get("trusted_service_principals", [])),
            keyword_groups=keywords,
            allowlist=allowlist,
            severity_thresholds=thresholds,
            alert=data.get("alert", {}),
            baseline_db=data.get("baseline_db", "audit_baseline.db"),
            output_dir=data.get("output_dir", "output"),
        )

    def is_trusted_destination(self, address: str) -> bool:
        from .domains import normalize_domain
        domain = normalize_domain(address)
        trusted = {normalize_domain(item) for item in self.trusted_forward_domains}
        return domain in trusted or any(
            domain.endswith("." + item) for item in trusted if item
        )

    def find_allow_match(self, mailbox: str, object_type: str, object_id: str,
                         object_name: str, destination: str = "",
                         delegate: str = "") -> AllowRule | None:
        from datetime import date
        today = date.today().isoformat()
        for rule in self.allowlist:
            if rule.expires and rule.expires < today:
                continue  # 过期白名单不再豁免
            if rule.mailbox and rule.mailbox.lower() != mailbox.lower():
                continue
            if rule.object_type and rule.object_type != object_type:
                continue
            token = rule.object_id_or_name
            if token and token.lower() not in object_id.lower() \
                    and token.lower() not in (object_name or "").lower():
                continue
            if rule.destination:
                needle = rule.destination.lower()
                if needle not in destination.lower():
                    continue
            if rule.delegate and rule.delegate.lower() not in delegate.lower():
                continue
            return rule
        return None
