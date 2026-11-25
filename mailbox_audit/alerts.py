"""告警通道：Webhook / SMTP 邮件 / Syslog（全部标准库实现）。

只对达到配置阈值、且非白名单的结论告警；通过 finding_id 去重，
同一对象未发生变化时不重复打扰，状态升级（severity 升高）时再次提醒。
"""

from __future__ import annotations

import json
import logging
import smtplib
import socket
from email.message import EmailMessage
from urllib import request as urlrequest

from . import SEVERITY_RANK
from .models import Finding

logger = logging.getLogger("mailbox_audit.alert")


class Alerter:
    def __init__(self, alert_config: dict):
        self.config = alert_config or {}
        channels = self.config.get("channels", {})
        self.webhook = channels.get("webhook", {})
        self.email = channels.get("email", {})
        self.syslog = channels.get("syslog", {})
        min_severity = self.config.get("min_severity", "high")
        self.min_rank = SEVERITY_RANK.get(min_severity, SEVERITY_RANK["high"])

    def filter_alertable(self, findings: list[Finding]) -> list[Finding]:
        return [
            item for item in findings
            if item.status != "allowlisted"
            and SEVERITY_RANK[item.severity] >= self.min_rank
            and item.baseline_state in {"new", "changed", "removed"}
        ]

    def dispatch(self, findings: list[Finding]) -> int:
        targets = self.filter_alertable(findings)
        if not targets:
            logger.info("没有满足告警阈值的新结论")
            return 0
        for finding in targets:
            if self.webhook.get("enabled"):
                self._send_webhook(finding)
            if self.email.get("enabled"):
                self._send_email(finding)
            if self.syslog.get("enabled"):
                self._send_syslog(finding)
        logger.warning("已对 %d 条结论触发告警", len(targets))
        return len(targets)

    # ------------------------------------------------------------------
    def _send_webhook(self, finding: Finding) -> None:
        url = self.webhook.get("url", "")
        payload = json.dumps({
            "finding_id": finding.finding_id,
            "severity": finding.severity,
            "score": finding.score,
            "mailbox": finding.mailbox,
            "object_type": finding.object_type,
            "object_name": finding.object_name,
            "baseline_state": finding.baseline_state,
            "signals": [s["code"] for s in finding.signals],
            "detail": "; ".join(s["detail"] for s in finding.signals),
        }, ensure_ascii=False).encode("utf-8")
        req = urlrequest.Request(url, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urlrequest.urlopen(req, timeout=15) as response:
                response.read()
        except Exception as exc:  # noqa: BLE001 - 告警失败不能中断审计主流程
            logger.error("Webhook 告警失败：%s", exc)

    def _send_email(self, finding: Finding) -> None:
        message = EmailMessage()
        message["Subject"] = (
            f"[邮箱审计][{finding.severity.upper()}][{finding.baseline_state}] "
            f"{finding.mailbox} 出现可疑{finding.object_type}"
        )
        message["From"] = self.email.get("from", "")
        message["To"] = ", ".join(self.email.get("to", []))
        message.set_content(
            f"邮箱：{finding.mailbox}\n对象：{finding.object_name}\n"
            f"风险分：{finding.score}\n状态：{finding.baseline_state}\n\n"
            + "\n".join(f"- {s['code']}: {s['detail']}" for s in finding.signals)
            + f"\n\n证据：{json.dumps(finding.evidence, ensure_ascii=False, indent=2)}"
        )
        try:
            with smtplib.SMTP(self.email["smtp_host"],
                              self.email.get("smtp_port", 587), timeout=15) as smtp:
                smtp.starttls()
                if self.email.get("username"):
                    smtp.login(self.email["username"], self.email.get("password", ""))
                smtp.send_message(message)
        except Exception as exc:  # noqa: BLE001
            logger.error("邮件告警失败：%s", exc)

    def _send_syslog(self, finding: Finding) -> None:
        # RFC3164 风格 UDP syslog，SIEM 最常见的接收入口
        text = (
            f"mailbox-audit severity={finding.severity} score={finding.score} "
            f"mailbox={finding.mailbox} object={finding.object_type} "
            f"state={finding.baseline_state} id={finding.finding_id}"
        )
        packet = f"<13>{socket.gethostname()} {text}".encode("utf-8")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(packet, (self.syslog["host"],
                                     self.syslog.get("port", 514)))
        except Exception as exc:  # noqa: BLE001
            logger.error("Syslog 告警失败：%s", exc)
