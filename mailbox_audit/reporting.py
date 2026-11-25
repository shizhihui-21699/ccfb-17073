"""报告输出：JSON / CSV / HTML（纯标准库，HTML 自包含无外部资源）。"""

from __future__ import annotations

import csv
import html
import io
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import SEVERITIES, SEVERITY_RANK
from .models import Finding, MailboxSnapshot

_SEVERITY_COLOR = {
    "critical": "#7f1d1d",
    "high": "#c2410c",
    "medium": "#b45309",
    "low": "#1d4ed8",
    "info": "#475569",
}


def write_json(findings: list[Finding], snapshots: list[MailboxSnapshot],
               path: str | Path) -> None:
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mailbox_count": len(snapshots),
        "finding_count": len(findings),
        "severity_summary": dict(Counter(item.severity for item in findings)),
        "findings": [item.to_dict() for item in findings],
    }
    Path(path).write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(findings: list[Finding], path: str | Path) -> None:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "finding_id", "mailbox", "object_type", "object_name", "severity",
        "score", "status", "baseline_state", "first_seen", "last_seen",
        "signal_codes", "evidence",
    ])
    for finding in findings:
        writer.writerow([
            finding.finding_id, finding.mailbox, finding.object_type,
            finding.object_name, finding.severity, finding.score,
            finding.status, finding.baseline_state,
            finding.first_seen or "", finding.last_seen or "",
            "|".join(signal["code"] for signal in finding.signals),
            json.dumps(finding.evidence, ensure_ascii=False),
        ])
    Path(path).write_text(buffer.getvalue(), encoding="utf-8-sig")  # BOM 方便 Excel


def write_html(findings: list[Finding], snapshots: list[MailboxSnapshot],
               path: str | Path) -> None:
    summary = Counter(item.severity for item in findings)
    status_summary = Counter(item.status for item in findings)
    baseline_summary = Counter(item.baseline_state for item in findings)
    rows = []
    for finding in findings:
        signals = "<br>".join(
            f"<span class='signal'>{html.escape(s['code'])}</span> "
            f"({s['weight']}) {html.escape(s['detail'])}"
            for s in finding.signals
        )
        evidence = html.escape(json.dumps(finding.evidence, ensure_ascii=False, indent=1))
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{_SEVERITY_COLOR[finding.severity]}">
            {finding.severity.upper()}</span><br><small>{finding.score} 分</small></td>
          <td>{html.escape(finding.mailbox)}<br><small>{html.escape(finding.object_type)} ·
            {html.escape(finding.baseline_state)} · {html.escape(finding.status)}</small></td>
          <td>{html.escape(finding.object_name)}<br><small>{html.escape(finding.finding_id)}</small></td>
          <td class="signals">{signals}</td>
          <td><pre>{evidence}</pre></td>
        </tr>""")

    document = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>邮箱规则审计报告</title>
<style>
  body {{ font-family: -apple-system, "Segoe UI", "PingFang SC", sans-serif;
         margin: 0; padding: 24px; background: #f8fafc; color: #0f172a; }}
  h1 {{ font-size: 20px; }} h2 {{ font-size: 16px; margin-top: 28px; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; }}
  .card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
           padding: 12px 18px; min-width: 110px; }}
  .card .num {{ font-size: 26px; font-weight: 700; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff;
           border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }}
  th, td {{ border-bottom: 1px solid #e2e8f0; padding: 10px 12px;
            text-align: left; vertical-align: top; font-size: 13px; }}
  th {{ background: #f1f5f9; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 11px; }}
  .signal {{ font-family: ui-monospace, monospace; font-size: 11px;
             background: #eef2ff; border-radius: 4px; padding: 1px 4px; }}
  pre {{ white-space: pre-wrap; word-break: break-all; margin: 0;
         font-size: 11px; max-width: 420px; }}
  .meta {{ color: #64748b; font-size: 12px; }}
</style></head><body>
<h1>企业邮箱收件规则 / 转发 / 委托审计报告</h1>
<p class="meta">生成时间：{datetime.now(timezone.utc).isoformat(timespec="seconds")}（UTC）
· 审计邮箱数：{len(snapshots)}</p>
<div class="cards">
  {_summary_cards(summary, status_summary, baseline_summary)}
</div>
<h2>检测明细（{len(findings)} 条）</h2>
<table>
  <thead><tr><th>风险</th><th>邮箱 / 状态</th><th>对象</th><th>命中信号</th><th>证据</th></tr></thead>
  <tbody>{''.join(rows) or '<tr><td colspan="5">未发现可疑项</td></tr>'}</tbody>
</table>
</body></html>"""
    Path(path).write_text(document, encoding="utf-8")


def _summary_cards(severity: Counter, status: Counter, baseline: Counter) -> str:
    cards = []
    for level in reversed(SEVERITIES):
        cards.append(
            f"<div class='card'><div>{level.upper()}</div>"
            f"<div class='num' style='color:{_SEVERITY_COLOR[level]}'>"
            f"{severity.get(level, 0)}</div></div>"
        )
    cards.append(
        f"<div class='card'><div>白名单豁免</div>"
        f"<div class='num'>{status.get('allowlisted', 0)}</div></div>"
    )
    cards.append(
        f"<div class='card'><div>新增/变更/移除</div>"
        f"<div class='num' style='font-size:16px'>"
        f"{baseline.get('new', 0)}/{baseline.get('changed', 0)}/"
        f"{baseline.get('removed', 0)}</div></div>"
    )
    return "".join(cards)


def write_all(findings: list[Finding], snapshots: list[MailboxSnapshot],
              output_dir: str | Path) -> dict[str, str]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": str(output / "audit_report.json"),
        "csv": str(output / "audit_report.csv"),
        "html": str(output / "audit_report.html"),
    }
    write_json(findings, snapshots, paths["json"])
    write_csv(findings, paths["csv"])
    write_html(findings, snapshots, paths["html"])
    return paths
