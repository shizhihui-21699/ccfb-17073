#!/usr/bin/env python3
"""生成贴近真实攻击场景的演示导出数据（Exchange Online PowerShell 导出格式）。

场景覆盖
--------
1. finance@   典型 BEC：发票/付款关键词 + 外部转发 + 移到 RSS 文件夹 + 隐藏规则
2. ceo@       邮箱级 SMTP 转发到仿冒域名（homoglyph），且不留副本
3. hr@        合法分类规则（只移动到内部文件夹），用于验证误报控制
4. it@        合法外部转发但命中白名单合作方 + 一个 GUID 名称的可疑规则
5. sales@     外部个人 Gmail 转发 + 删除安全告警邮件
6. boss@      外部 Full Access 委托
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples" / "exo_export"


def rule(identity, mailbox, name, **kwargs):
    base = {
        "Identity": identity, "Mailbox": mailbox, "Name": name,
        "Enabled": True, "Priority": 1, "IsHidden": False,
    }
    base.update(kwargs)
    return base


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    visible = [
        # 1) finance：攻击链核心规则（可见部分）
        rule("fin-rule-1", "finance@contoso.com", "发票处理",
             SubjectOrBodyContains=["发票", "付款", "invoice", "payment"],
             ForwardTo=["ap.helper2026@gmail.com"],
             MoveToFolder="finance@contoso.com\\RSS 订阅"),
        # 3) hr：完全合法的内部分类
        rule("hr-rule-1", "hr@contoso.com", "简历归档",
             SubjectContains=["简历", "resume"],
             MoveToFolder="hr@contoso.com\\招聘\\简历库"),
        # 4) it：合作方转发（可信域名）
        rule("it-rule-1", "it@contoso.com", "合规归档",
             SentToContains=["audit"],
             ForwardTo=["vault@contoso-archive.example"]),
        # 4) it：GUID 名称 + 冷僻邮件头条件
        rule("it-rule-2", "it@contoso.com",
             "a7f3c2e1-9b4d-4f8a-b2c1-6e5d4c3b2a10",
             HeaderContains={"HeaderName": "X-Forefront-Antispam-Report",
                             "Words": ["SFV:SPM"]},
             RedirectTo=["it-backup@proton.me"]),
        # 5) sales：删除安全告警 + 个人邮箱转发
        rule("sales-rule-1", "sales@contoso.com", "清理通知",
             SubjectContains=["security alert", "异常登录", "密码"],
             DeleteMessage=True),
        rule("sales-rule-2", "sales@contoso.com", "客户跟进同步",
             FromContains=["contoso.com"],
             ForwardTo=["sales.contoso@gmail.com"]),
        # 2) ceo：一条普通规则，真正问题在邮箱级转发
        rule("ceo-rule-1", "ceo@contoso.com", "会议材料分类",
             SubjectContains=["meeting"],
             MoveToFolder="ceo@contoso.com\\会议"),
    ]

    # 隐藏规则（-IncludeHidden 才能看到）：finance 邮箱里的 MAPI 植入规则
    hidden = list(visible) + [
        rule("fin-hidden-1", "finance@contoso.com",
             "",  # 空名
             IsHidden=True,
             SubjectOrBodyContains=["银行账户", "bank account", "wire"],
             RedirectTo=["controller@contosο.com"],  # 末尾域名含希腊字母 omicron
             MoveToFolder="finance@contoso.com\\Sync Issues"),
    ]

    forwarding = [
        {"Identity": "finance@contoso.com", "PrimarySmtpAddress": "finance@contoso.com",
         "ForwardingSmtpAddress": None, "ForwardingAddress": None,
         "DeliverToMailboxAndForward": True, "HiddenFromAddressListsEnabled": False},
        {"Identity": "ceo@contoso.com", "PrimarySmtpAddress": "ceo@contoso.com",
         # contosο 中的 ο 是希腊字母，仿冒 contoso.com
         "ForwardingSmtpAddress": "smtp:ceo.office365@contosο.com",
         "ForwardingAddress": None,
         "DeliverToMailboxAndForward": False,  # 不留副本
         "HiddenFromAddressListsEnabled": False},
        {"Identity": "hr@contoso.com", "PrimarySmtpAddress": "hr@contoso.com",
         "ForwardingSmtpAddress": None, "ForwardingAddress": None,
         "DeliverToMailboxAndForward": True, "HiddenFromAddressListsEnabled": False},
        {"Identity": "it@contoso.com", "PrimarySmtpAddress": "it@contoso.com",
         "ForwardingSmtpAddress": None, "ForwardingAddress": None,
         "DeliverToMailboxAndForward": True, "HiddenFromAddressListsEnabled": False},
        {"Identity": "sales@contoso.com", "PrimarySmtpAddress": "sales@contoso.com",
         "ForwardingSmtpAddress": None, "ForwardingAddress": None,
         "DeliverToMailboxAndForward": True, "HiddenFromAddressListsEnabled": False},
        {"Identity": "boss@contoso.com", "PrimarySmtpAddress": "boss@contoso.com",
         "ForwardingSmtpAddress": None, "ForwardingAddress": None,
         "DeliverToMailboxAndForward": True, "HiddenFromAddressListsEnabled": False},
    ]

    auto_config = [
        {"Identity": mbx, "AutoForwardEnabled": False}
        for mbx in ("finance@contoso.com", "ceo@contoso.com", "hr@contoso.com",
                    "it@contoso.com", "sales@contoso.com", "boss@contoso.com")
    ]

    permissions = [
        # 6) boss：外部完全访问委托
        {"Identity": "boss@contoso.com", "Trustee": "consultant@external-vendor.net",
         "AccessRights": ["FullAccess", "ReadPermission"]},
        # 合法内部委托
        {"Identity": "ceo@contoso.com", "Trustee": "ea@contoso.com",
         "AccessRights": ["FullAccess"]},
        # 未备案服务主体
        {"Identity": "finance@contoso.com", "Trustee": "app:8f9c2d4e-aaaa-bbbb-cccc-1234567890ab",
         "AccessRights": ["FullAccess"]},
    ]

    for name, payload in (
        ("inbox_rules.json", visible),
        ("inbox_rules_hidden.json", hidden),
        ("mailbox_forwarding.json", forwarding),
        ("mailbox_auto_config.json", auto_config),
        ("recipients_permission.json", permissions),
        ("remote_domains.json",
         [{"DomainName": "Default", "AutoForwardEnabled": True, "AutoReplyEnabled": True}]),
    ):
        (OUT / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2),
                                encoding="utf-8")
    print(f"[+] 演示数据已写入 {OUT}")


if __name__ == "__main__":
    main()
