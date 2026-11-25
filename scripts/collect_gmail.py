#!/usr/bin/env python3
"""Google Workspace Gmail 采集脚本（在能访问 Google API 的机器上运行）。

与纯标准库的审计核心不同，在线调用 Gmail API 需要 google-api-python-client
与服务账号凭据；该脚本只负责把原生 JSON 导出到目录，审计机仍可离线零依赖解析。

前置条件
--------
1. 服务账号并开启域级委派（DWD），授权 scope：
   gmail.settings.basic、gmail.settings.sharing
2. pip install google-api-python-client google-auth
3. 管理员邮箱作为 --subject

输出（--export-dir）
--------------------
  gmail_filters.json     每用户过滤器（含转发/删除/归档动作）
  gmail_forwarding.json  每用户自动转发设置
  gmail_delegates.json   每用户委托关系
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def build_service(sa_path: str, subject: str):
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    credentials = service_account.Credentials.from_service_account_file(
        sa_path,
        scopes=[
            "https://www.googleapis.com/auth/gmail.settings.basic",
            "https://www.googleapis.com/auth/gmail.settings.sharing",
        ],
    ).with_subject(subject)
    return build("gmail", "v1", credentials=credentials, cache_discovery=False)


def list_user_mails(service, domain: str) -> list[str]:
    # Directory API 需要额外 scope；这里允许调用方直接传用户清单文件兜底
    result = service.users().list().execute()  # 占位：实际用 Admin SDK Directory
    return [u["primaryEmail"] for u in result.get("users", []) if u.get("primaryEmail")]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sa-json", required=True, help="服务账号 JSON 凭据")
    parser.add_argument("--subject", required=True, help="域管理员邮箱（域级委派主体）")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--users-file", help="用户邮箱清单，每行一个；缺省尝试 Directory API")
    parser.add_argument("--export-dir", required=True)
    args = parser.parse_args()

    service = build_service(args.sa_json, args.subject)
    if args.users_file:
        mailboxes = [
            line.strip() for line in Path(args.users_file).read_text(encoding="utf-8").splitlines()
            if line.strip() and "@" in line
        ]
    else:
        mailboxes = list_user_mails(service, args.domain)

    out = Path(args.export_dir)
    out.mkdir(parents=True, exist_ok=True)
    filters_dump, forwarding_dump, delegates_dump = [], [], []

    for mailbox in mailboxes:
        print(f"[*] {mailbox}")
        filters = service.users().settings().filters().list(userId=mailbox).execute()
        for item in filters.get("filter", []):
            filters_dump.append({"mailbox": mailbox, **item})

        auto = service.users().settings().getAutoForwarding(userId=mailbox).execute()
        forwarding_dump.append({"mailbox": mailbox, "autoForwarding": auto})

        delegates = service.users().settings().delegates().list(userId=mailbox).execute()
        delegates_dump.append({"mailbox": mailbox, "delegates": delegates.get("delegates", [])})

    (out / "gmail_filters.json").write_text(
        json.dumps(filters_dump, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "gmail_forwarding.json").write_text(
        json.dumps(forwarding_dump, ensure_ascii=False, indent=2), encoding="utf-8")
    (out / "gmail_delegates.json").write_text(
        json.dumps(delegates_dump, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[+] 完成，导出目录：{out}")


if __name__ == "__main__":
    main()
