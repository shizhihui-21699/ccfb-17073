"""规范化数据模型。

不同邮件系统（Exchange Online / 本地 Exchange / Google Workspace）的规则存储
格式差异很大，采集适配器负责把各自的原生结构统一转换成本模块定义的规范模型，
检测引擎只依赖规范模型，从而与具体系统解耦。
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Any, Optional


# ---------------------------------------------------------------------------
# 收件规则
# ---------------------------------------------------------------------------
@dataclass
class RuleCondition:
    """规则条件（命中条件或例外条件统一用该结构）。"""

    field: Optional[str] = None        # subject / body / header:<名称> / sender / recipient ...
    operator: Optional[str] = None     # contains / equals / matches / header_contains ...
    values: list[str] = dataclasses.field(default_factory=list)
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass
class RuleAction:
    """规则动作。

    type 取值（规范词表）：
      forward / redirect / external_recipient  —— 邮件出组织
      delete                                   —— 硬删除
      move / copy                              —— 移动/复制到文件夹（可能用于隐藏）
      mark_read / flag / category / stop / other
    """

    type: str
    targets: list[str] = dataclasses.field(default_factory=list)  # 收件地址或文件夹名
    folder: Optional[str] = None
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass
class Rule:
    rule_id: str
    mailbox: str
    name: str = ""
    enabled: bool = True
    priority: Optional[int] = None
    hidden: bool = False                 # MAPI 隐藏规则 / 不在常规接口暴露的规则
    conditions: list[RuleCondition] = dataclasses.field(default_factory=list)
    exception_conditions: list[RuleCondition] = dataclasses.field(default_factory=list)
    actions: list[RuleAction] = dataclasses.field(default_factory=list)
    system: str = ""                     # 来源系统：exo / exchange_onprem / gmail
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)


# ---------------------------------------------------------------------------
# 转发设置（邮箱级，独立于收件规则）
# ---------------------------------------------------------------------------
@dataclass
class ForwardingConfig:
    mailbox: str
    kind: str                            # smtp_forwarding / mailbox_autoforward / gmail_auto_forward
    enabled: bool
    destination: Optional[str] = None
    deliver_to_mailbox_and_forward: bool = True   # False = 不留副本，更隐蔽
    hidden: bool = False
    source: str = ""
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)


# ---------------------------------------------------------------------------
# 委托访问
# ---------------------------------------------------------------------------
@dataclass
class DelegateEntry:
    mailbox: str
    delegate: str                        # 被授权人邮箱 / SID / 服务主体 ID
    permissions: list[str] = dataclasses.field(default_factory=list)
    access_type: str = ""                # full_access / send_as / send_on_behalf / gmail_delegate
    service_principal: bool = False
    hidden: bool = False
    source: str = ""
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)


# ---------------------------------------------------------------------------
# 单邮箱快照（一次采集的完整结果）
# ---------------------------------------------------------------------------
@dataclass
class MailboxSnapshot:
    mailbox: str
    display_name: str = ""
    collected_at: str = ""
    source_system: str = ""
    rules: list[Rule] = dataclasses.field(default_factory=list)
    forwarding: list[ForwardingConfig] = dataclasses.field(default_factory=list)
    delegates: list[DelegateEntry] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)   # 采集层面的告警，如隐藏规则无法通过当前接口枚举
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)


# ---------------------------------------------------------------------------
# 检测结论
# ---------------------------------------------------------------------------
@dataclass
class Signal:
    code: str
    weight: int
    detail: str
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclass
class Finding:
    finding_id: str
    mailbox: str
    object_type: str                     # rule / forwarding / delegate
    object_id: str
    object_name: str
    severity: str
    score: int
    signals: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)
    status: str = "open"                 # open / allowlisted / resolved
    baseline_state: str = "new"          # new / unchanged / changed / removed
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source_system: str = ""

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


def to_plain(obj: Any) -> Any:
    """dataclass / 列表 / 字典 → 纯 JSON 可序列化结构。"""
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, list):
        return [to_plain(item) for item in obj]
    if isinstance(obj, dict):
        return {key: to_plain(value) for key, value in obj.items()}
    return obj
