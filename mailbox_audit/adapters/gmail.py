"""Google Workspace / Gmail 适配器。

两种使用方式
------------
1. 离线模式：用 scripts/collect_gmail.py（或管理员自己的脚本）调用
   Gmail API 导出 filters / auto-forwarding / delegates 三个 JSON，
   本模块离线解析，审计机不需要任何凭据。
2. 在线模式：域级委派（service account + JWT）。为保持零第三方依赖，
   JWT 断言用标准库 hmac/hashlib/base64 手工拼装，仅需一个服务账号 JSON。

需要的 OAuth scope（在管理控制台为服务账号配置域级委派）：
  https://www.googleapis.com/auth/gmail.settings.basic
  https://www.googleapis.com/auth/gmail.settings.sharing
"""

from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from ..models import (
    DelegateEntry,
    ForwardingConfig,
    MailboxSnapshot,
    Rule,
    RuleAction,
    RuleCondition,
)
from . import BaseCollector, OfflineExportCollector

_GMAIL_BASE = "https://gmail.googleapis.com/gmail/v1/users"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_SCOPES = (
    "https://www.googleapis.com/auth/gmail.settings.basic "
    "https://www.googleapis.com/auth/gmail.settings.sharing"
)


class GmailParser:
    system_name = "gmail"

    # Gmail filter 的 action 字段 → 规范动作
    def parse_filter(self, mailbox: str, raw: dict) -> Rule:
        criteria = raw.get("criteria", {}) or {}
        action = raw.get("action", {}) or {}
        conditions: list[RuleCondition] = []
        for field, key in (
            ("from", "sender"), ("to", "recipient"), ("subject", "subject"),
            ("query", "query"),
        ):
            if criteria.get(field):
                conditions.append(RuleCondition(
                    field=key,
                    operator="matches" if field == "query" else "contains",
                    values=[str(criteria[field])], raw={"source_field": field},
                ))
        if criteria.get("negatedQuery"):
            conditions.append(RuleCondition(
                field="query", operator="not_matches",
                values=[str(criteria["negatedQuery"])], raw={},
            ))

        actions: list[RuleAction] = []
        if action.get("addForwardingEmailAddress"):
            actions.append(RuleAction(
                type="forward",
                targets=[str(action["addForwardingEmailAddress"])], raw={},
            ))
        if action.get("forward"):
            # action.forward=true 与 addForwardingEmailAddress 共同构成转发
            pass
        if action.get("delete"):
            actions.append(RuleAction(type="delete", raw={}))
        if action.get("trash"):
            actions.append(RuleAction(type="delete", raw={"source_field": "trash"}))
        if action.get("archive"):
            actions.append(RuleAction(
                type="move", folder="All Mail（归档，跳过收件箱）",
                targets=["All Mail"], raw={"source_field": "archive"},
            ))
        if action.get("addLabelIds"):
            actions.append(RuleAction(
                type="move", folder=", ".join(action["addLabelIds"]),
                targets=list(action["addLabelIds"]), raw={"source_field": "addLabelIds"},
            ))
        if action.get("removeLabelIds") and "INBOX" in action["removeLabelIds"]:
            actions.append(RuleAction(
                type="move", folder="（移出收件箱）", targets=["INBOX removed"], raw={},
            ))
        if action.get("markRead"):
            actions.append(RuleAction(type="mark_read", raw={}))

        return Rule(
            rule_id=raw.get("id", ""),
            mailbox=mailbox,
            name=f"Gmail filter {raw.get('id', '')}",
            enabled=True,  # Gmail 过滤器没有禁用态，存在即生效
            hidden=False,
            conditions=conditions,
            actions=actions,
            system="gmail",
            raw=raw,
        )

    def parse_auto_forwarding(self, mailbox: str, raw: dict) -> ForwardingConfig | None:
        if not raw or not raw.get("enabled"):
            return None
        return ForwardingConfig(
            mailbox=mailbox,
            kind="gmail_auto_forward",
            enabled=True,
            destination=(raw.get("emailAddress") or "").lower() or None,
            # Gmail 的 auto-forwarding 会保留原件（除非 filter 再 archive/delete）
            deliver_to_mailbox_and_forward=True,
            source="Gmail settings.autoForwarding",
            raw=raw,
        )

    def parse_delegate(self, mailbox: str, raw: dict) -> DelegateEntry:
        delegate = (raw.get("delegateEmail") or "").lower()
        return DelegateEntry(
            mailbox=mailbox,
            delegate=delegate,
            permissions=["gmail_delegate"],
            access_type="gmail_delegate",
            service_principal=False,
            source="Gmail settings.delegates",
            raw={**raw, "verificationStatus": raw.get("verificationStatus", "")},
        )

    def parse_export(self, rules=None, hidden_rules=None, forwarding=None,
                     auto_config=None, permissions=None,
                     gmail_filters=None, gmail_forwarding=None,
                     gmail_delegates=None) -> list[MailboxSnapshot]:
        snapshots: dict[str, MailboxSnapshot] = {}

        def snapshot(mailbox: str) -> MailboxSnapshot:
            if mailbox not in snapshots:
                snapshots[mailbox] = MailboxSnapshot(
                    mailbox=mailbox, source_system=self.system_name)
            return snapshots[mailbox]

        for item in gmail_filters or []:
            mailbox = (item.get("mailbox") or item.get("userId") or "").lower()
            if not mailbox:
                continue
            snapshot(mailbox).rules.append(self.parse_filter(mailbox, item))

        for item in gmail_forwarding or []:
            mailbox = (item.get("mailbox") or item.get("userId") or "").lower()
            if not mailbox:
                continue
            forward = self.parse_auto_forwarding(mailbox, item.get("autoForwarding", item))
            if forward:
                snapshot(mailbox).forwarding.append(forward)

        for item in gmail_delegates or []:
            mailbox = (item.get("mailbox") or item.get("userId") or "").lower()
            if not mailbox:
                continue
            for delegate_raw in item.get("delegates", []):
                snapshot(mailbox).delegates.append(
                    self.parse_delegate(mailbox, delegate_raw))

        return list(snapshots.values())


class GmailOfflineCollector(BaseCollector):
    system_name = "gmail"

    def __init__(self, export_dir: str):
        self._loader = OfflineExportCollector(export_dir, GmailParser())

    def collect(self) -> list[MailboxSnapshot]:
        return self._loader.collect()


class GmailCollector(BaseCollector):
    """在线采集：服务账号域级委派。零依赖 JWT 拼装。"""

    system_name = "gmail"

    def __init__(self, service_account_json: str, subject: str,
                 mailboxes: list[str], timeout: int = 30):
        with open(service_account_json, "r", encoding="utf-8") as handle:
            self.sa = json.load(handle)
        self.subject = subject  # 拥有域管理权限的委派管理员
        self.mailboxes = mailboxes
        self.timeout = timeout
        self._token: str | None = None

    @staticmethod
    def _b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _jwt_assertion(self) -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": self.sa.get("private_key_id", "")}
        now = int(time.time())
        claims = {
            "iss": self.sa["client_email"],
            "scope": _SCOPES,
            "aud": _GOOGLE_TOKEN_URL,
            "iat": now,
            "exp": now + 3600,
            "sub": self.subject,
        }
        signing_input = (
            self._b64url(json.dumps(header, separators=(",", ":")).encode())
            + "." + self._b64url(json.dumps(claims, separators=(",", ":")).encode())
        )
        # RS256 需要 RSA 私钥签名；标准库没有 RSA 签名实现，
        # 因此在线模式要求环境中存在 cryptography（唯一可选依赖），
        # 离线模式完全不需要。
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding
        except ImportError as exc:  # pragma: no cover - 环境相关
            raise RuntimeError(
                "Gmail 在线模式需要可选依赖 cryptography（pip install cryptography）；"
                "或改用离线导出模式，审计机保持零依赖"
            ) from exc
        private_key = serialization.load_pem_private_key(
            self.sa["private_key"].encode(), password=None,
        )
        signature = private_key.sign(
            signing_input.encode(), padding.PKCS1v15(), hashes.SHA256(),
        )
        return signing_input + "." + self._b64url(signature)

    def _access_token(self) -> str:  # pragma: no cover - 依赖网络
        if self._token:
            return self._token
        assertion = self._jwt_assertion()
        encoded = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
        }).encode()
        request = urllib.request.Request(_GOOGLE_TOKEN_URL, data=encoded, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            self._token = json.loads(response.read())["access_token"]
        return self._token

    def _get(self, url: str) -> dict:  # pragma: no cover - 依赖网络
        request = urllib.request.Request(url)
        request.add_header("Authorization", f"Bearer {self._access_token()}")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode())

    def collect(self) -> list[MailboxSnapshot]:  # pragma: no cover - 依赖网络
        parser = GmailParser()
        snapshots: list[MailboxSnapshot] = []
        for mailbox in self.mailboxes:
            encoded = urllib.parse.quote(mailbox, safe="")
            snapshot = MailboxSnapshot(mailbox=mailbox, source_system="gmail")
            filters = self._get(f"{_GMAIL_BASE}/{encoded}/settings/filters")
            for raw in filters.get("filter", []):
                raw["mailbox"] = mailbox
                snapshot.rules.append(parser.parse_filter(mailbox, raw))
            forwarding = self._get(
                f"{_GMAIL_BASE}/{encoded}/settings/autoForwarding")
            forward = parser.parse_auto_forwarding(mailbox, forwarding)
            if forward:
                snapshot.forwarding.append(forward)
            delegates = self._get(f"{_GMAIL_BASE}/{encoded}/settings/delegates")
            for raw in delegates.get("delegates", []):
                snapshot.delegates.append(parser.parse_delegate(mailbox, raw))
            snapshots.append(snapshot)
        return snapshots
