"""检测引擎：规则 / 转发 / 委托的可疑信号识别与加权评分。

设计原则
--------
1. 合法转发与分类规则非常普遍，不能"见转发就报警"。引擎输出的是带权重的
   信号组合与风险分，由分数映射严重级别，并支持白名单豁免。
2. 检测只依赖 models.py 的规范模型，与邮件系统解耦。
3. 每个信号都带证据（命中关键词、外部地址、文件夹名等），报告可直接复核。
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from . import domains as dom
from .config import AuditConfig
from .keywords import scan_conditions, scan_text
from .models import (
    DelegateEntry,
    Finding,
    ForwardingConfig,
    MailboxSnapshot,
    Rule,
    RuleAction,
    Signal,
)

# 信号权重：分值体现"单看这一项的可疑程度"，组合后总分封顶 100
WEIGHTS: dict[str, int] = {
    "EXTERNAL_EGRESS": 40,           # 邮件被转发/重定向到组织外
    "LOOKALIKE_DOMAIN": 55,          # 外部落点仿冒内部域名
    "FREE_MAIL_DEST": 15,            # 落点是个人免费邮箱
    "TRUSTED_PARTNER_EGRESS": 8,     # 外部但属于备案合作方
    "DELETE_ACTION": 25,             # 直接删除
    "HIDE_MOVE_FOLDER": 20,          # 移动到不起眼文件夹
    "NO_LOCAL_COPY": 25,             # 转发后不留副本
    "HIDDEN_RULE": 45,               # 隐藏/MAPI 规则，常规接口不可见
    "SENSITIVE_KEYWORD": 20,         # 条件命中财务/凭据类关键词
    "BROAD_SCOPE": 15,               # 无条件或超宽条件（捕获所有邮件）
    "OBSCURE_HEADER_CONDITION": 18,  # 基于冷僻邮件头的条件（规避人工查看）
    "OBFUSCATED_CONDITION": 15,      # 正则/通配/编码等混淆条件
    "BLANK_OR_GUID_NAME": 8,         # 规则名为空或 GUID（人为隐藏痕迹）
    "FORWARD_ALL": 35,               # 邮箱级自动转发
    "FULL_ACCESS_DELEGATE": 25,      # 完全访问权限委托
    "EXTERNAL_DELEGATE": 35,         # 委托给组织外身份
    "SERVICE_PRINCIPAL_DELEGATE": 20,
    "HIDDEN_DELEGATE": 30,
}

# 名称像 GUID / 空名
_GUID_RE = re.compile(
    r"^[{]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[}]?$"
)
# 冷僻邮件头：人工分类规则几乎不会基于这些头做判断，常见于规避检测
_OBSCURE_HEADERS = {
    "x-ms-exchange-organization-", "x-originating-ip", "x-forefront-antispam-report",
    "received-spf", "authentication-results", "x-exchange-antispam",
    "x-microsoft-antispam", "thread-index", "thread-topic", "x-mailer",
    "x-sender-id", "x-auto-response-suppress",
}
# 不起眼文件夹名（多语言）
_SUSPICIOUS_FOLDER_KEYWORDS = (
    "archive", "rss", "junk", "deleted", "deleted items", "conversation history",
    "notes", "sync issues", "clutter", "junk email", "归档", "已删除", "垃圾邮件",
    "同步问题", "备忘", "其他",
)
# 混淆条件的典型算子
_OBFUSCATION_OPERATORS = {"matches", "regex", "wildcard", "matchesregex"}
_OBFUSCATION_VALUE_RE = re.compile(r"(\.\*|\.\+|\[\^|\(\?|\\x[0-9a-fA-F]{2}|=\?[A-Za-z0-9-]+\?[BQbq]\?)")


def _add(signals: list[Signal], code: str, detail: str, evidence: dict | None = None,
         weight_override: int | None = None) -> None:
    signals.append(Signal(
        code=code,
        weight=weight_override if weight_override is not None else WEIGHTS[code],
        detail=detail,
        evidence=evidence or {},
    ))


def _external_action_addresses(actions: list[RuleAction]) -> list[str]:
    addresses: list[str] = []
    for action in actions:
        if action.type in {"forward", "redirect", "external_recipient"}:
            addresses.extend(dom.extract_email_addresses(action.targets))
    return addresses


def _is_concealment_folder(folder: str | None) -> bool:
    if not folder:
        return False
    lowered = folder.lower().strip()
    return any(keyword in lowered for keyword in _SUSPICIOUS_FOLDER_KEYWORDS)


def _severity_for(score: int, thresholds: dict[str, int]) -> str:
    if score >= thresholds["critical"]:
        return "critical"
    if score >= thresholds["high"]:
        return "high"
    if score >= thresholds["medium"]:
        return "medium"
    if score >= thresholds["low"]:
        return "low"
    return "info"


def _finding_id(mailbox: str, object_type: str, object_id: str) -> str:
    digest = hashlib.sha256(f"{mailbox}|{object_type}|{object_id}".encode("utf-8")).hexdigest()[:16]
    return f"F-{digest}"


# ---------------------------------------------------------------------------
# 规则检测
# ---------------------------------------------------------------------------
def evaluate_rule(rule: Rule, config: AuditConfig) -> Finding | None:
    signals: list[Signal] = []
    keyword_groups = config.keyword_groups
    internal = config.internal_domains

    # 1) 外部出网
    egress_addresses = _external_action_addresses(rule.actions)
    external = dom.external_targets(egress_addresses, internal)
    trusted_hits = [addr for addr in external if config.is_trusted_destination(addr)]
    untrusted = [addr for addr in external if not config.is_trusted_destination(addr)]

    has_external = bool(external)
    if untrusted:
        _add(signals, "EXTERNAL_EGRESS",
             f"规则将邮件转发/重定向到组织外地址：{', '.join(sorted(set(untrusted)))}",
             {"addresses": sorted(set(untrusted))})
    elif trusted_hits:
        _add(signals, "TRUSTED_PARTNER_EGRESS",
             f"转发到已备案合作方域名：{', '.join(sorted(set(trusted_hits)))}",
             {"addresses": sorted(set(trusted_hits))})

    for address in sorted(set(external)):
        lookalike = dom.lookalike_of_internal(address, internal)
        if lookalike:
            _add(signals, "LOOKALIKE_DOMAIN",
                 f"外部地址域名疑似仿冒内部域名 {lookalike['matched_internal']}：{lookalike['domain']}",
                 lookalike)
        if dom.is_free_mail(address):
            _add(signals, "FREE_MAIL_DEST", f"转发落点为个人免费邮箱：{address}",
                 {"address": address})

    # 2) 隐藏 / 删除 / 移动
    action_types = {action.type for action in rule.actions}
    if "delete" in action_types:
        _add(signals, "DELETE_ACTION", "规则动作包含硬删除邮件")

    for action in rule.actions:
        if action.type in {"move", "copy"} and _is_concealment_folder(action.folder):
            _add(signals, "HIDE_MOVE_FOLDER",
                 f"邮件被移动/复制到不显眼文件夹：{action.folder}",
                 {"folder": action.folder})

    if rule.hidden:
        _add(signals, "HIDDEN_RULE", "该规则为隐藏规则（常规管理接口不显示，常见于 MAPI 植入）")

    # 3) 条件分析
    keyword_hits = scan_conditions(rule.conditions, keyword_groups)
    if keyword_hits:
        words = sorted({hit["keyword"] for hit in keyword_hits})
        _add(signals, "SENSITIVE_KEYWORD",
             f"规则条件命中敏感关键词：{', '.join(words[:12])}",
             {"hits": keyword_hits})

    meaningful = [
        condition for condition in rule.conditions
        if condition.field or condition.values
    ]
    if not meaningful:
        _add(signals, "BROAD_SCOPE", "规则无条件，对收件箱所有邮件生效")
    else:
        # 超宽条件：仅按发件域/组织内外，或单条件值为通配
        for condition in meaningful:
            joined = " ".join(map(str, condition.values or [])).lower()
            if joined.strip() in {"*", ".*", "@*"} or (
                condition.field in {"body", "subject"} and joined in {"*", ".*"}
            ):
                _add(signals, "BROAD_SCOPE", "规则条件为通配匹配，覆盖面过宽",
                     {"field": condition.field})
                break

    for condition in meaningful:
        field_name = (condition.field or "").lower()
        if field_name.startswith("header:"):
            header = field_name.split(":", 1)[1]
            if any(token in header for token in _OBSCURE_HEADERS):
                _add(signals, "OBSCURE_HEADER_CONDITION",
                     f"规则基于冷僻邮件头 {header} 做匹配，人工查看规则时极易忽略",
                     {"header": header})
        operator = (condition.operator or "").lower()
        joined_values = " ".join(map(str, condition.values or []))
        if operator in _OBFUSCATION_OPERATORS or _OBFUSCATION_VALUE_RE.search(joined_values):
            _add(signals, "OBFUSCATED_CONDITION",
                 "规则使用正则/通配/编码形式的混淆条件",
                 {"operator": operator, "sample": joined_values[:120]})

    # 4) 规则名异常
    stripped_name = (rule.name or "").strip()
    if not stripped_name or _GUID_RE.match(stripped_name):
        _add(signals, "BLANK_OR_GUID_NAME", f"规则名为空或呈 GUID 形态：{stripped_name!r}")

    if not signals:
        return None

    # 组合修正：敏感词/隐藏单独出现时多为合法，叠加外部出网后才是典型攻击链
    score = min(100, sum(signal.weight for signal in signals))
    if not has_external:
        score = min(score, 45)  # 不出组织的规则风险封顶 medium 档以下
    else:
        score = min(100, score + 5)  # 多信号组合攻击链加成

    severity = _severity_for(score, config.severity_thresholds)
    return Finding(
        finding_id=_finding_id(rule.mailbox, "rule", rule.rule_id),
        mailbox=rule.mailbox,
        object_type="rule",
        object_id=rule.rule_id,
        object_name=rule.name or "(unnamed)",
        severity=severity,
        score=score,
        signals=[signal.__dict__ for signal in signals],
        evidence={
            "hidden": rule.hidden,
            "enabled": rule.enabled,
            "external_addresses": sorted(set(external)),
            "actions": [action.type for action in rule.actions],
            "conditions": [
                {"field": c.field, "operator": c.operator, "values": c.values}
                for c in rule.conditions
            ],
        },
        source_system=rule.system,
    )


# ---------------------------------------------------------------------------
# 邮箱级转发检测
# ---------------------------------------------------------------------------
def evaluate_forwarding(forward: ForwardingConfig, config: AuditConfig) -> Finding | None:
    if not forward.enabled:
        return None
    signals: list[Signal] = []
    destination = forward.destination or ""
    internal = config.internal_domains

    _add(signals, "FORWARD_ALL", f"邮箱级自动转发已启用，目标：{destination or '(未解析)'}",
         {"kind": forward.kind, "destination": destination})

    if destination:
        addresses = dom.extract_email_addresses([destination]) or [destination.lower()]
        external = dom.external_targets(addresses, internal)
        trusted = [addr for addr in external if config.is_trusted_destination(addr)]
        untrusted = [addr for addr in external if not config.is_trusted_destination(addr)]
        if untrusted:
            _add(signals, "EXTERNAL_EGRESS", f"自动转发到组织外：{', '.join(untrusted)}",
                 {"addresses": untrusted})
        elif trusted:
            _add(signals, "TRUSTED_PARTNER_EGRESS",
                 f"自动转发到备案合作方：{', '.join(trusted)}", {"addresses": trusted})
        for address in external:
            lookalike = dom.lookalike_of_internal(address, internal)
            if lookalike:
                _add(signals, "LOOKALIKE_DOMAIN",
                     f"转发目标疑似仿冒内部域名：{lookalike['domain']}", lookalike)
            if dom.is_free_mail(address):
                _add(signals, "FREE_MAIL_DEST", f"转发到个人免费邮箱：{address}",
                     {"address": address})

    if not forward.deliver_to_mailbox_and_forward:
        _add(signals, "NO_LOCAL_COPY", "转发后不在本邮箱保留副本，受害者收件箱无痕迹")
    if forward.hidden:
        _add(signals, "HIDDEN_RULE", "转发配置被标记为隐藏（常规接口不可见）")

    score = min(100, sum(signal.weight for signal in signals))
    severity = _severity_for(score, config.severity_thresholds)
    return Finding(
        finding_id=_finding_id(forward.mailbox, "forwarding", forward.kind),
        mailbox=forward.mailbox,
        object_type="forwarding",
        object_id=forward.kind,
        object_name=f"{forward.kind} → {destination or '?'}",
        severity=severity,
        score=score,
        signals=[signal.__dict__ for signal in signals],
        evidence={"destination": destination, "kind": forward.kind,
                  "deliver_to_mailbox_and_forward": forward.deliver_to_mailbox_and_forward,
                  "hidden": forward.hidden, "source": forward.source},
        source_system=forward.source,
    )


# ---------------------------------------------------------------------------
# 委托访问检测
# ---------------------------------------------------------------------------
def evaluate_delegate(delegate: DelegateEntry, config: AuditConfig) -> Finding | None:
    signals: list[Signal] = []
    internal = config.internal_domains
    delegate_address = delegate.delegate.lower()

    permissions = {item.lower() for item in delegate.permissions}
    if "full_access" in permissions or delegate.access_type == "full_access":
        _add(signals, "FULL_ACCESS_DELEGATE",
             f"被授权人 {delegate.delegate} 拥有完全访问权限",
             {"permissions": sorted(permissions)})

    if delegate_address and not dom.is_internal_address(delegate_address, internal) \
            and not delegate.service_principal:
        _add(signals, "EXTERNAL_DELEGATE", f"委托给组织外身份：{delegate.delegate}")

    if delegate.service_principal:
        trusted = delegate.delegate in config.trusted_service_principals
        _add(signals, "SERVICE_PRINCIPAL_DELEGATE",
             f"应用/服务主体拥有邮箱权限：{delegate.delegate}"
             + ("（已备案）" if trusted else "（未在信任清单中）"),
             {"trusted": trusted})
        if trusted:
            # 已备案服务主体降权处理
            signals[-1].weight = 5

    if delegate.hidden:
        _add(signals, "HIDDEN_DELEGATE", "委托关系被标记为隐藏")

    if not signals:
        return None

    score = min(100, sum(signal.weight for signal in signals))
    severity = _severity_for(score, config.severity_thresholds)
    return Finding(
        finding_id=_finding_id(delegate.mailbox, "delegate",
                               f"{delegate.access_type}:{delegate.delegate}"),
        mailbox=delegate.mailbox,
        object_type="delegate",
        object_id=f"{delegate.access_type}:{delegate.delegate}",
        object_name=f"{delegate.access_type} → {delegate.delegate}",
        severity=severity,
        score=score,
        signals=[signal.__dict__ for signal in signals],
        evidence={"delegate": delegate.delegate,
                  "permissions": sorted(permissions),
                  "service_principal": delegate.service_principal,
                  "hidden": delegate.hidden, "source": delegate.source},
        source_system=delegate.source,
    )


# ---------------------------------------------------------------------------
# 引擎入口
# ---------------------------------------------------------------------------
def evaluate_snapshot(snapshot: MailboxSnapshot, config: AuditConfig) -> list[Finding]:
    findings: list[Finding] = []
    for rule in snapshot.rules:
        finding = evaluate_rule(rule, config)
        if finding:
            findings.append(finding)
    for forward in snapshot.forwarding:
        finding = evaluate_forwarding(forward, config)
        if finding:
            findings.append(finding)
    for delegate in snapshot.delegates:
        finding = evaluate_delegate(delegate, config)
        if finding:
            findings.append(finding)

    # 采集层告警（如接口无法枚举隐藏规则）单独成条，提示覆盖盲区。
    # object_id 使用固定前缀，避免与真实规则的基线 key 冲突
    for index, warning in enumerate(snapshot.warnings):
        signals = [Signal("HIDDEN_RULE", WEIGHTS["HIDDEN_RULE"], warning).__dict__]
        findings.append(Finding(
            finding_id=_finding_id(snapshot.mailbox, "collection_warning",
                                   f"coverage-{index}"),
            mailbox=snapshot.mailbox,
            object_type="collection_warning",
            object_id=f"coverage-warning-{index}",
            object_name="采集覆盖告警",
            severity="high",
            score=WEIGHTS["HIDDEN_RULE"],
            signals=signals,
            evidence={"warning": warning},
            source_system=snapshot.source_system,
        ))

    _apply_allowlist(findings, config)
    findings.sort(key=lambda item: (-item.score, item.mailbox, item.object_type))
    return findings


def _apply_allowlist(findings: list[Finding], config: AuditConfig) -> None:
    for finding in findings:
        destination = ""
        delegate = ""
        if finding.object_type == "forwarding":
            destination = str(finding.evidence.get("destination", ""))
        elif finding.object_type == "delegate":
            delegate = str(finding.evidence.get("delegate", ""))
        elif finding.object_type == "rule":
            destination = " ".join(finding.evidence.get("external_addresses", []))
        match = config.find_allow_match(
            finding.mailbox, finding.object_type, finding.object_id,
            finding.object_name, destination=destination, delegate=delegate,
        )
        if match:
            finding.status = "allowlisted"
            finding.severity = "info"
            finding.evidence["allowlist_reason"] = match.reason
            finding.evidence["allowlist_ticket"] = match.ticket
            finding.evidence["allowlist_expires"] = match.expires
