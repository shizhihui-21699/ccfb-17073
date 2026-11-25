"""Microsoft Graph 在线采集器（零第三方依赖，urllib 实现）。

覆盖范围与局限（务必知悉）
--------------------------
- 可读：用户列表、messageRules（可见收件规则）、邮箱设置中的转发配置。
- 不可读：MAPI 隐藏规则（messageRules 不返回 hidden 规则）、
  Full Access/SendAs 委托（Graph 无等价接口）。
- 因此生产审计应以 Exchange PowerShell 适配器为主，本采集器适合
  快速巡检或在没有 Exchange Online 模块权限时补充使用；检测引擎会
  通过 collection_warning 把覆盖盲区显式报出来。

需要的应用权限：MailboxSettings.Read、Mail.Read（应用级）、User.Read.All。
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from ..models import MailboxSnapshot, Rule, RuleAction, RuleCondition
from . import BaseCollector

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class GraphCollector(BaseCollector):
    system_name = "exo-graph"

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 mailbox_filter: str | None = None, timeout: int = 30):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.mailbox_filter = mailbox_filter
        self.timeout = timeout
        self._token: str | None = None

    # ------------------------------------------------------------------
    # HTTP 基础
    # ------------------------------------------------------------------
    def _post_form(self, url: str, data: dict) -> dict:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        request = urllib.request.Request(url, data=encoded, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def _get(self, path: str) -> dict:
        if self._token is None:
            token_url = (
                f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
            )
            payload = self._post_form(token_url, {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            })
            self._token = payload["access_token"]
        url = path if path.startswith("https://") else f"{_GRAPH_BASE}{path}"
        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Bearer {self._token}")
        request.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Graph 请求失败 {exc.code} {url}: {body[:300]}") from exc

    def _get_all(self, path: str) -> list[dict]:
        """处理 @odata.nextLink 分页。"""
        rows: list[dict] = []
        url: str | None = path
        while url:
            page = self._get(url)
            rows.extend(page.get("value", []))
            url = page.get("@odata.nextLink")
            if url:
                url = url.replace(_GRAPH_BASE, "")
        return rows

    # ------------------------------------------------------------------
    # 规范化
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_rule(mailbox: str, raw: dict) -> Rule:
        conditions: list[RuleCondition] = []
        exceptions: list[RuleCondition] = []
        actions_raw = raw.get("actions", {}) or {}

        for field, operator in (
            ("subjectContains", "contains"), ("bodyContains", "contains"),
            ("senderContains", "contains"), ("recipientContains", "contains"),
            ("headerContains", "header_contains"),
        ):
            values = raw.get(field)
            if values:
                target = exceptions if field.startswith("except") else conditions
                target.append(RuleCondition(field=field.replace("Contains", ""),
                                            operator=operator, values=values, raw={}))
        for field in ("subjectMatches", "bodyMatches"):
            if raw.get(field):
                conditions.append(RuleCondition(
                    field=field.replace("Matches", ""), operator="matches",
                    values=raw[field], raw={}))

        actions: list[RuleAction] = []
        for key, action_type in (
            ("forwardTo", "forward"), ("redirectTo", "redirect"),
            ("assignCategories", "category"),
        ):
            targets = actions_raw.get(key)
            if targets:
                addresses = [
                    item.get("emailAddress", {}).get("address", str(item))
                    if isinstance(item, dict) else str(item)
                    for item in targets
                ]
                actions.append(RuleAction(type=action_type, targets=addresses, raw={key: targets}))
        if actions_raw.get("delete"):
            actions.append(RuleAction(type="delete", raw={}))
        if actions_raw.get("moveToFolder"):
            folder = actions_raw["moveToFolder"]
            actions.append(RuleAction(type="move", folder=folder, targets=[folder], raw={}))
        if actions_raw.get("markAsRead"):
            actions.append(RuleAction(type="mark_read", raw={}))
        if actions_raw.get("stopProcessingRules"):
            actions.append(RuleAction(type="stop", raw={}))

        return Rule(
            rule_id=raw.get("id", ""),
            mailbox=mailbox,
            name=raw.get("displayName", ""),
            enabled=raw.get("isEnabled", True),
            priority=raw.get("sequence"),
            hidden=False,  # Graph 永远读不到隐藏规则
            conditions=conditions,
            exception_conditions=exceptions,
            actions=actions,
            system="exo-graph",
            raw=raw,
        )

    # ------------------------------------------------------------------
    # 采集
    # ------------------------------------------------------------------
    def collect(self) -> list[MailboxSnapshot]:
        user_path = "/users?$select=id,mail,userPrincipalName,displayName,accountEnabled"
        if self.mailbox_filter:
            user_path += f"&$filter={urllib.parse.quote(self.mailbox_filter)}"
        users = self._get_all(user_path)

        snapshots: list[MailboxSnapshot] = []
        for user in users:
            mailbox = (user.get("mail") or user.get("userPrincipalName") or "").lower()
            if not mailbox:
                continue
            snapshot = MailboxSnapshot(
                mailbox=mailbox, display_name=user.get("displayName", ""),
                source_system=self.system_name,
            )
            user_id = user["id"]
            try:
                rules_raw = self._get_all(f"/users/{user_id}/mailFolders/inbox/messageRules")
                snapshot.rules = [self._parse_rule(mailbox, item) for item in rules_raw]
            except RuntimeError as exc:
                snapshot.warnings.append(f"messageRules 读取失败：{exc}")

            try:
                settings = self._get(f"/users/{user_id}/mailboxSettings")
                self._parse_mailbox_settings(mailbox, settings, snapshot)
            except RuntimeError as exc:
                snapshot.warnings.append(f"mailboxSettings 读取失败：{exc}")

            snapshot.warnings.append(
                "Graph 接口无法枚举 MAPI 隐藏规则与邮箱委托（FullAccess/SendAs），"
                "请定期用 Exchange PowerShell 适配器补采"
            )
            snapshots.append(snapshot)
        return snapshots

    @staticmethod
    def _parse_mailbox_settings(mailbox: str, settings: dict,
                                snapshot: MailboxSnapshot) -> None:
        from ..models import ForwardingConfig
        forward = settings.get("automaticRepliesSetting") or {}
        # Graph 的 mailboxSettings 中转发信息有限，仅作尽力解析
        forwarding_setting = settings.get("forwardingSettings") or {}
        destination = forwarding_setting.get("forwardTo") or ""
        if destination and forwarding_setting.get("isForwardingEnabled"):
            snapshot.forwarding.append(ForwardingConfig(
                mailbox=mailbox,
                kind="graph_mailbox_forwarding",
                enabled=True,
                destination=destination.lower(),
                deliver_to_mailbox_and_forward=not forwarding_setting.get(
                    "isForwardingEnabled", False) or True,
                source="Graph mailboxSettings",
                raw=forwarding_setting,
            ))
        if forward.get("status") == "alwaysEnabled":
            snapshot.warnings.append(
                f"邮箱启用了自动回复（externalAudience={forward.get('externalAudience')}），"
                "需确认是否同时配置了外部转发"
            )
