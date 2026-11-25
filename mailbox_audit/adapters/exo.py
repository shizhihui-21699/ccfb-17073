"""Exchange Online / 本地 Exchange 适配器（基于 PowerShell 导出）。

为什么以 PowerShell 为主采集面
------------------------------
Microsoft Graph 的 mailFolders/messageRules 接口读不到 MAPI 隐藏规则，
也不暴露邮箱级 SMTP 转发与 Full Access 委托；Exchange Online PowerShell
的 Get-InboxRule -IncludeHidden、Get-Mailbox、Get-EXORecipientPermission
才能覆盖完整攻击面（详见 scripts/collect_exo.ps1 与 README）。

本模块只负责把 PowerShell 的 JSON 导出规范化为 MailboxSnapshot，
在线执行由 scripts/collect_exo.ps1 完成，Python 侧保持纯解析、无凭据依赖。
"""

from __future__ import annotations

from ..models import (
    DelegateEntry,
    ForwardingConfig,
    MailboxSnapshot,
    Rule,
    RuleAction,
    RuleCondition,
)
from . import BaseCollector

# Get-InboxRule 条件字段 → 规范 field/operator
_CONDITION_FIELDS = {
    "SubjectContains": ("subject", "contains"),
    "SubjectOrBodyContains": ("subject_or_body", "contains"),
    "BodyContains": ("body", "contains"),
    "FromContains": ("sender", "contains"),
    "FromAddressContains": ("sender", "contains"),
    "SentToContains": ("recipient", "contains"),
    "HeaderContains": ("header", "header_contains"),
    "AnyOfRecipientAddressContains": ("recipient", "contains"),
    "SubjectMatches": ("subject", "matches"),
    "BodyMatches": ("body", "matches"),
    "FromAddressMatches": ("sender", "matches"),
    "HasClassification": ("classification", "equals"),
    "WithImportance": ("importance", "equals"),
    "FlaggedForAction": ("flag", "equals"),
    "MessageTypeMatches": ("message_type", "equals"),
    "ReceivedWithin": ("received", "window"),
    "WithinSizeRangeMaximum": ("size", "max"),
    "WithinSizeRangeMinimum": ("size", "min"),
}
_EXCEPTION_FIELDS = {
    "ExceptIfSubjectContains": ("subject", "contains"),
    "ExceptIfBodyContains": ("body", "contains"),
    "ExceptIfFromAddressContains": ("sender", "contains"),
    "ExceptIfSentToContains": ("recipient", "contains"),
    "ExceptIfHeaderContains": ("header", "header_contains"),
    "ExceptIfSubjectMatches": ("subject", "matches"),
    "ExceptIfBodyMatches": ("body", "matches"),
}

# Get-InboxRule 动作字段 → 规范动作
_DELETE_ACTIONS = {"DeleteMessage", "SoftDeleteMessage"}
_MOVE_ACTIONS = {"MoveToFolder", "CopyToFolder"}
_FORWARD_ACTIONS = {
    "ForwardTo": "forward",
    "RedirectTo": "redirect",
    "ForwardAsAttachmentTo": "forward",
}


class ExchangeParser:
    """EXO / 本地 Exchange 共用解析逻辑。"""

    system_name = "exo"

    def __init__(self, system_name: str = "exo"):
        self.system_name = system_name

    @staticmethod
    def _string_list(value) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value if item is not None]
        return [str(value)]

    @staticmethod
    def _mailbox_of(raw: dict) -> str:
        return str(raw.get("Mailbox") or raw.get("Identity", "").split("\\")[0] or "").lower()

    def _build_conditions(self, raw: dict, mapping: dict) -> list[RuleCondition]:
        conditions: list[RuleCondition] = []
        for ps_field, (field, operator) in mapping.items():
            if ps_field not in raw or raw[ps_field] in (None, "", []):
                continue
            values = self._string_list(raw[ps_field])
            if ps_field == "HeaderContains" or ps_field == "ExceptIfHeaderContains":
                # PowerShell 输出为 {"HeaderName": "...", "Words": [...]} 形态
                header_name, words = self._split_header(raw[ps_field])
                conditions.append(RuleCondition(
                    field=f"header:{header_name.lower()}", operator=operator,
                    values=words or values, raw={"source_field": ps_field},
                ))
            else:
                conditions.append(RuleCondition(
                    field=field, operator=operator, values=values,
                    raw={"source_field": ps_field},
                ))
        return conditions

    @staticmethod
    def _split_header(value):
        if isinstance(value, dict):
            name = value.get("HeaderName") or value.get("Name") or "unknown"
            words = value.get("Words") or value.get("Values") or []
            if not isinstance(words, list):
                words = [words]
            return str(name), [str(item) for item in words]
        return "unknown", [str(value)]

    def _build_actions(self, raw: dict) -> list[RuleAction]:
        actions: list[RuleAction] = []
        for field in _DELETE_ACTIONS:
            if raw.get(field):
                actions.append(RuleAction(type="delete", raw={"source_field": field}))
        for field in _MOVE_ACTIONS:
            if raw.get(field):
                folder = str(raw[field])
                actions.append(RuleAction(
                    type="move" if field == "MoveToFolder" else "copy",
                    folder=folder, targets=[folder], raw={"source_field": field},
                ))
        for field, action_type in _FORWARD_ACTIONS.items():
            targets = self._string_list(raw.get(field))
            if targets:
                actions.append(RuleAction(
                    type=action_type, targets=targets, raw={"source_field": field},
                ))
        if raw.get("MarkAsRead"):
            actions.append(RuleAction(type="mark_read", raw={"source_field": "MarkAsRead"}))
        if raw.get("StopProcessingRules"):
            actions.append(RuleAction(type="stop", raw={"source_field": "StopProcessingRules"}))
        if raw.get("ApplyCategory"):
            actions.append(RuleAction(
                type="category", targets=self._string_list(raw.get("ApplyCategory")),
                raw={"source_field": "ApplyCategory"},
            ))
        return actions

    def parse_rule(self, raw: dict, hidden: bool) -> Rule:
        mailbox = self._mailbox_of(raw)
        rule_id = str(raw.get("Identity") or raw.get("RuleId") or raw.get("Name") or "")
        return Rule(
            rule_id=rule_id,
            mailbox=mailbox,
            name=str(raw.get("Name", "") or ""),
            enabled=bool(raw.get("Enabled", True)),
            priority=raw.get("Priority"),
            hidden=hidden or bool(raw.get("IsHidden")),
            conditions=self._build_conditions(raw, _CONDITION_FIELDS),
            exception_conditions=self._build_conditions(raw, _EXCEPTION_FIELDS),
            actions=self._build_actions(raw),
            system=self.system_name,
            raw=raw,
        )

    def parse_forwarding(self, mailbox_raw: dict, auto_raw: dict | None) -> list[ForwardingConfig]:
        result: list[ForwardingConfig] = []
        mailbox = str(mailbox_raw.get("Identity") or mailbox_raw.get("PrimarySmtpAddress") or "").lower()
        smtp_destination = mailbox_raw.get("ForwardingSmtpAddress")
        if isinstance(smtp_destination, dict):
            smtp_destination = smtp_destination.get("AddressString") or smtp_destination.get("Value")
        if smtp_destination:
            smtp_destination = str(smtp_destination).removeprefix("smtp:").removeprefix("SMTP:")
            result.append(ForwardingConfig(
                mailbox=mailbox, kind="smtp_forwarding",
                enabled=bool(mailbox_raw.get("DeliverToMailboxAndForward", True))
                or bool(smtp_destination),
                destination=smtp_destination.lower(),
                deliver_to_mailbox_and_forward=bool(
                    mailbox_raw.get("DeliverToMailboxAndForward", True)),
                source="Get-Mailbox",
                raw=mailbox_raw,
            ))
        if auto_raw:
            auto_mailbox = str(auto_raw.get("Identity") or "").lower() or mailbox
            if auto_raw.get("AutoForwardEnabled"):
                result.append(ForwardingConfig(
                    mailbox=auto_mailbox, kind="mailbox_autoforward",
                    enabled=True,
                    deliver_to_mailbox_and_forward=True,
                    source="Get-MailboxAutoReplyConfiguration",
                    raw=auto_raw,
                ))
        return result

    def parse_delegates(self, permission_rows: list[dict]) -> list[DelegateEntry]:
        result: list[DelegateEntry] = []
        for row in permission_rows:
            trustee = str(row.get("Trustee") or "").lower()
            access = row.get("AccessRights") or row.get("AccessRight") or ""
            if isinstance(access, str):
                # PowerShell 单值可能序列化为字符串，容错拆分
                permissions = [part.strip() for part in access.strip("[]").split(",") if part.strip()]
                permissions = [part.strip("'\"") for part in permissions]
            else:
                permissions = [str(item) for item in access]
            identity = str(row.get("Identity") or "").lower()
            is_sp = trustee.startswith("app:") or "@" not in trustee
            result.append(DelegateEntry(
                mailbox=identity,
                delegate=trustee,
                permissions=permissions,
                access_type="full_access" if "FullAccess" in permissions else (
                    permissions[0].lower() if permissions else ""),
                service_principal=is_sp,
                source="Get-EXORecipientPermission / Get-MailboxPermission",
                raw=row,
            ))
        return result

    def parse_export(self, rules: list[dict], hidden_rules: list[dict],
                     forwarding: list[dict], auto_config: list[dict],
                     permissions: list[dict], gmail_filters=None,
                     gmail_forwarding=None, gmail_delegates=None) -> list[MailboxSnapshot]:
        snapshots: dict[str, MailboxSnapshot] = {}

        def snapshot(mailbox: str) -> MailboxSnapshot:
            if mailbox not in snapshots:
                snapshots[mailbox] = MailboxSnapshot(
                    mailbox=mailbox, source_system=self.system_name,
                )
            return snapshots[mailbox]

        # 跨文件按 Identity 去重：-IncludeHidden 的结果包含全部规则（可见+隐藏），
        # 而两次采集间某规则可能从可见文件消失但仍残留在 hidden 文件。
        # 规则是可见还是隐藏，以 hidden 导出中的 IsHidden 标记为准，不能因为
        # 它只出现在 hidden 文件就简单当成隐藏规则。
        parsed: dict[str, Rule] = {}
        for raw in rules:
            rule = self.parse_rule(raw, hidden=False)
            if rule.rule_id and rule.mailbox:
                parsed[f"{rule.mailbox}|{rule.rule_id}"] = rule
        for raw in hidden_rules:
            rule = self.parse_rule(raw, hidden=bool(raw.get("IsHidden")))
            key = f"{rule.mailbox}|{rule.rule_id}"
            if not rule.mailbox or not rule.rule_id:
                continue
            if key in parsed:
                # 保留可见实例，但用 hidden 文件里的 IsHidden 标记补全隐藏属性
                parsed[key].hidden = parsed[key].hidden or rule.hidden
            else:
                parsed[key] = rule
        for rule in parsed.values():
            snapshot(rule.mailbox).rules.append(rule)

        auto_by_mailbox = {
            str(item.get("Identity") or "").lower(): item for item in auto_config
        }
        for raw in forwarding:
            mailbox = str(raw.get("Identity") or raw.get("PrimarySmtpAddress") or "").lower()
            for forward in self.parse_forwarding(raw, auto_by_mailbox.get(mailbox)):
                snapshot(mailbox).forwarding.append(forward)

        for delegate in self.parse_delegates(permissions):
            if delegate.mailbox:
                snapshot(delegate.mailbox).delegates.append(delegate)

        # 覆盖盲区提示：仅当调用方明确没有 hidden 导出时才告警一次，
        # 避免在已采集 -IncludeHidden 的情况下产生误报
        if not hidden_rules and snapshots:
            notice = (
                "本次采集未包含 -IncludeHidden 结果，MAPI 隐藏规则可能漏检；"
                "请用 scripts/collect_exo.ps1 重新采集"
            )
            for snap in snapshots.values():
                snap.warnings.append(notice)
        return list(snapshots.values())


class ExchangeOfflineCollector(BaseCollector):
    """从 PowerShell JSON 导出目录加载 Exchange 数据。"""

    system_name = "exo"

    def __init__(self, export_dir: str, on_premises: bool = False):
        from . import OfflineExportCollector
        self._loader = OfflineExportCollector(
            export_dir, ExchangeParser("exchange_onprem" if on_premises else "exo"),
        )

    def collect(self) -> list[MailboxSnapshot]:
        return self._loader.collect()
