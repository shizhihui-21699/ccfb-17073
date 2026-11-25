"""命令行入口。

子命令
------
offline   解析采集脚本导出的 JSON 目录（应急排查/测试/无网环境）
graph     用 Microsoft Graph 应用凭据在线采集（覆盖范围有限，见模块文档）
monitor   与 offline 相同流程，语义上用于定时任务；非零退出码表示发现高危项
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import SEVERITIES, SEVERITY_RANK
from .adapters.exo import ExchangeOfflineCollector
from .adapters.gmail import GmailOfflineCollector
from .config import AuditConfig
from .engine import run_audit


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mailbox_audit",
        description="企业邮箱收件规则 / 转发 / 委托全量审计与持续监控",
    )
    parser.add_argument("-c", "--config", required=True, help="审计策略 JSON 配置文件")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    offline = sub.add_parser("offline", help="离线解析采集脚本导出的 JSON 目录")
    offline.add_argument("--export-dir", required=True)
    offline.add_argument("--system", choices=["exo", "exchange_onprem", "gmail"],
                         default="exo")
    offline.add_argument("--no-alert", action="store_true", help="只出报告不发告警")

    graph = sub.add_parser("graph", help="Microsoft Graph 在线采集")
    graph.add_argument("--tenant-id", required=True)
    graph.add_argument("--client-id", required=True)
    graph.add_argument("--client-secret", required=True)
    graph.add_argument("--filter", default=None, help="Graph $filter 表达式")
    graph.add_argument("--no-alert", action="store_true")

    monitor = sub.add_parser("monitor", help="定时监控（当前等同 offline，便于 cron 区分语义）")
    monitor.add_argument("--export-dir", required=True)
    monitor.add_argument("--system", choices=["exo", "exchange_onprem", "gmail"],
                         default="exo")
    monitor.add_argument("--fail-on", choices=SEVERITIES, default="high",
                         help="达到该严重级别时进程返回非零退出码")
    monitor.add_argument("--no-alert", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    config = AuditConfig.load(args.config)

    if args.command in {"offline", "monitor"}:
        if args.system == "gmail":
            collector = GmailOfflineCollector(args.export_dir)
        else:
            collector = ExchangeOfflineCollector(
                args.export_dir, on_premises=args.system == "exchange_onprem")
        snapshots = collector.collect()
    elif args.command == "graph":
        from .adapters.msgraph import GraphCollector
        collector = GraphCollector(
            args.tenant_id, args.client_id, args.client_secret,
            mailbox_filter=args.filter,
        )
        snapshots = collector.collect()
    else:  # pragma: no cover
        raise SystemExit(2)

    result = run_audit(
        snapshots, config,
        send_alerts=not getattr(args, "no_alert", False),
    )

    summary = {
        "mailboxes": len(result.snapshots),
        "findings": len(result.findings),
        "by_severity": {level: sum(1 for f in result.findings if f.severity == level)
                        for level in SEVERITIES},
        "reports": result.report_paths,
        "alerted": result.alerted,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    if args.command == "monitor":
        # 只对"本次发生变化"的高危结论返回非零，存量未变化问题不重复打断值班
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] >= threshold
               and f.status != "allowlisted"
               and f.baseline_state in {"new", "changed", "removed"}
               for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
